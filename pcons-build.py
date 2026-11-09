"""Ninja, built with pcons -- a port of its CMake build.

Produces the same artifacts as CMakeLists.txt:

    build/ninja            the binary (with browse mode where supported)
    build/ninja_test       the test suite, when GTest is findable
    build/*_perftest       the benchmarks, plus build/hash_collision_bench

and covers the same configure logic: the ppoll() probe, warning-flag
probes, optional re2c regeneration of the lexers, and the inline.sh
probe for browse-mode support.

`pcons` also runs tests, installs and builds a tgz:

    pcons test             the GTest suite, one test per discovered case
    pcons run perftests    run every benchmark
    pcons install          CMake's install(TARGETS ninja), plus COPYING
                           and README.md; PCONS_INSTALL_PREFIX picks where
    pcons tarball          package that install tree (no CMake equivalent)

CMake's options carry over as build variables:
  NINJA_BUILD_BINARY, NINJA_FORCE_PSELECT, NINJA_CLANG_TIDY.

Needs pcons 0.29.0 or later (`uvx pcons` gets the latest).
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

from pcons import Configure, Project, get_var, get_variant
from pcons.configure.checks import ToolChecks

win = sys.platform == "win32"
# Python platform.system() should be the same as CMake's CMAKE_SYSTEM_NAME,
# so these hopefully compare the same way CMakeLists.txt does.
# I didn't test these on real systems.
system = platform.system()
aix = system == "AIX"
ibm_i = system in ("AIX", "OS400")

project = Project("ninja")
env = project.Environment(toolchain="c")
env.cxx.set_standard("c++17")
variant = get_variant(default="release")
env.set_variant(variant)

# CMake's option() lines. NINJA_BUILD_BINARY=0 builds the library and tests
# but not the binary; NINJA_FORCE_PSELECT=1 skips the ppoll() probe so the
# pselect() path is used even where ppoll() exists.
build_binary = get_var("NINJA_BUILD_BINARY", True)
force_pselect = get_var("NINJA_FORCE_PSELECT", False)

# CMake's check_ipo_supported + INTERPROCEDURAL_OPTIMIZATION_RELEASE: LTO
# for release builds, where the toolchain supports it.
if variant == "release" and env.has_preset("lto"):
    env.apply_preset("lto")

# Configure cache: in the build directory so the probes below persist.
config = Configure(build_dir=project.build_dir)
checks = ToolChecks(config, env, "cxx")

# CMake's NINJA_CLANG_TIDY / CXX_CLANG_TIDY.
if get_var("NINJA_CLANG_TIDY", False):
    env.use_clang_tidy(args=["--use-color"])

# --- compiler flags (CMakeLists "compiler flags" section) -------------------

msvc_style = env.toolchain.name in ("msvc", "clang-cl")
if msvc_style:
    env.cxx.flags.extend(
        [
            "/W4",
            "/wd4100",
            "/wd4267",
            "/wd4706",
            "/wd4702",
            "/wd4244",
            "/GR-",
            "/Zc:__cplusplus",
        ]
    )
    env.cxx.defines.append("_CRT_SECURE_NO_WARNINGS")
else:
    for flag in ("-Wno-deprecated", "-fdiagnostics-color"):
        if checks.check_flag(flag).success:
            env.cxx.flags.append(flag)
    # ppoll() must be probed as C++: g++/clang++ define _GNU_SOURCE, which
    # <poll.h> needs to expose the symbol, but gcc/clang do not.
    if not force_pselect and checks.check_function("ppoll", headers=["poll.h"]).success:
        env.cxx.defines.append(("USE_PPOLL", "1"))

if win:
    # windows.h min()/max() macros conflict with std::min()/std::max().
    env.cxx.defines.append("NOMINMAX")

# --- optional re2c: regenerate the lexers, or use the shipped ones ----------

# --vernum prints major*10000 + minor*100 + patch; CMake wants re2c 2 or later.
re2c = config.find_program("re2c", version_flag="--vernum")
if re2c is not None and re2c.version and int(re2c.version) >= 20000:
    re2c_sources = []
    for stem in ("depfile_parser", "lexer"):
        generated = env.Command(
            target=f"{stem}.cc",
            source=f"src/{stem}.in.cc",
            command=[
                str(re2c.path),
                "-b",
                "-i",
                "--no-generation-date",
                "--no-version",
                "-o",
                "$TARGET",
                "$SOURCE",
            ],
            name=f"re2c_{stem}",
        )
        re2c_sources.append(generated)
else:
    re2c_sources = ["src/depfile_parser.cc", "src/lexer.cc"]

libninja_re2c = project.ObjectLibrary("libninja-re2c", env, sources=re2c_sources)
libninja_re2c.private.include_dirs.append("src")

# --- browse mode: supported where inline.sh works and fork/pipe exist -------


def browse_mode_supported() -> bool:
    if win:
        return False
    probe = subprocess.run(
        "echo 'TEST' | src/inline.sh var",
        shell=True,
        cwd=project.root_dir,
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        return False
    return (
        checks.check_function("fork", headers=["unistd.h"]).success
        and checks.check_function("pipe", headers=["unistd.h"]).success
    )


browse = browse_mode_supported()
config.save()  # every probe has run by this point, so save to speed up future runs

# --- core library -----------------------------------------------------------

core_sources = [
    f"src/{name}.cc"
    for name in (
        "build_log",
        "build",
        "clean",
        "clparser",
        "dyndep",
        "dyndep_parser",
        "debug_flags",
        "deps_log",
        "disk_interface",
        "edit_distance",
        "elide_middle",
        "eval_env",
        "explanations",
        "graph",
        "graphviz",
        "jobserver",
        "jobserver_pool",
        "json",
        "line_printer",
        "manifest_parser",
        "metrics",
        "missing_deps",
        "parser",
        "real_command_runner",
        "state",
        "status_printer",
        "string_piece_util",
        "util",
        "version",
    )
]
if win:
    core_sources += [
        "src/subprocess-win32.cc",
        "src/includes_normalize-win32.cc",
        "src/jobserver-win32.cc",
        "src/msvc_helper-win32.cc",
        "src/msvc_helper_main-win32.cc",
        "src/minidump-win32.cc",
    ]
else:
    core_sources += ["src/jobserver-posix.cc", "src/subprocess-posix.cc"]

if ibm_i:
    # Without it <cinttypes> hides PRId64 and friends from C++.
    env.cxx.defines.append("__STDC_FORMAT_MACROS")
    env.cc.defines.append("__STDC_FORMAT_MACROS")

libninja = project.ObjectLibrary("libninja", env, sources=core_sources)

if win or ibm_i:
    # No getopt_long in libc there, so ninja ships its own. CMake compiles it
    # as C++ (LANGUAGE CXX) so a C++-only toolchain can build ninja; pcons
    # picks the tool by suffix, so point the C tool at the C++ compiler for
    # this one source file.
    with env.override() as getopt_env:
        getopt_env.cc.cmd = env.cxx.cmd
        getopt_env.cc.flags = [*env.cxx.flags, "/TP" if msvc_style else "-xc++"]
        libninja.add_sources(["src/getopt.c"], env=getopt_env)
if aix:
    # perfstat_cpu_total(), used by GetLoadAverage(). Public: it is the
    # linked binaries that need it, not libninja's own compiles.
    libninja.public.link_libs.append("perfstat")

# --- the ninja binary -------------------------------------------------------

# CMake wraps the binary, its browse support and install in
# if(NINJA_BUILD_BINARY); so does this.
if build_binary:
    ninja = project.Program("ninja", env, sources=["src/ninja.cc"])
    ninja.link(libninja, libninja_re2c)
    if win and msvc_style:
        # The SxS manifest, embedded by the linker (/MANIFESTINPUT): a
        # .manifest source is all pcons needs.
        ninja.add_sources(["windows/ninja.manifest"])

    if browse:
        # Inline src/browse.py into a header; browse.cc includes it as
        # "build/browse_py.h", so the header goes into a "build/" subdirectory
        # of the build dir and the compile gets the build dir as include root.
        browse_py = env.Command(
            target=project.build_dir / "build" / "browse_py.h",
            source="src/browse.py",
            command=[
                "sh",
                "src/inline.sh",
                "kBrowsePy",
                "<",
                "$SOURCE",
                ">",
                "$TARGET",
            ],
            depends=["src/inline.sh"],
            cwd=project.root_dir,
            name="browse_py",
        )
        # Only browse.cc needs the interpreter name and that header; the
        # feature define goes on the whole binary, since ninja.cc registers
        # the tool.
        python = get_var("NINJA_PYTHON", "python")
        browse_env = env.clone(name="browse")
        browse_env.cxx.defines.append(("NINJA_PYTHON", f'"{python}"'))
        browse_env.cxx.includes.append(project.build_dir)
        ninja.add_sources(["src/browse.cc"], env=browse_env)
        ninja.depends(browse_py)
        ninja.private.defines.append("NINJA_HAVE_BROWSE")

    project.Default(ninja)

    # CMake's install(TARGETS ninja): a binary goes to <prefix>/bin.
    # `pcons install` (or `ninja install`) copies it there;
    # Use PCONS_INSTALL_PREFIX to set the prefix, default dist/.
    installed = project.Install("bin", [ninja])
    # There's no man page; doc/manual.html would belong here too, but
    # building it needs asciidoc, which the CMake build doesn't wire
    # up either. Easy to add.
    docs = project.Install("share/doc/ninja", ["COPYING", "README.md"])
    project.Alias("install", installed, docs)

    # Bonus: a release tarball, since it's easy in pcons.
    # `pcons tarball` (or `ninja tarball`) writes ninja-<variant>.tar.gz
    # into the build directory.
    # Packaged from the install tree, so the archive holds bin/ninja and
    # share/doc/... rather than the paths things happened to be built at.
    prefix = Path(get_var("PCONS_INSTALL_PREFIX", project.root_dir / "dist"))
    # base_dir is compared against the paths as the archive step sees them,
    # from the build directory.
    prefix_from_build = Path(
        os.path.relpath(prefix, project.root_dir / project.build_dir)
    )
    tarball = project.Tarfile(
        env,
        output=f"ninja-{variant}.tar.gz",
        sources=[installed, docs],
        base_dir=prefix_from_build,
        compression="gzip",
    )
    project.Alias("tarball", tarball)

# --- tests and benchmarks ---------------------------------------------------

gtest = project.find_package("gtest", required=False)
if gtest is not None:
    test_sources = [
        f"src/{name}.cc"
        for name in (
            "build_log_test",
            "build_test",
            "clean_test",
            "clparser_test",
            "depfile_parser_test",
            "deps_log_test",
            "disk_interface_test",
            "dyndep_parser_test",
            "edit_distance_test",
            "elide_middle_test",
            "explanations_test",
            "graph_test",
            "jobserver_test",
            "jobserver_pool_test",
            "json_test",
            "lexer_test",
            "manifest_parser_test",
            "missing_deps_test",
            "ninja_test",
            "state_test",
            "string_piece_test",
            "string_piece_util_test",
            "subprocess_test",
            "test",
            "util_test",
        )
    ]
    if win:
        test_sources += [
            "src/includes_normalize_test.cc",
            "src/msvc_helper_test.cc",
        ]
    ninja_test = project.Program("ninja_test", env, sources=test_sources)
    ninja_test.link(libninja, libninja_re2c, gtest)
    if win and msvc_style:
        ninja_test.add_sources(["windows/ninja.manifest"])
        # Silence warnings about using unlink rather than _unlink.
        ninja_test.private.defines.append("_CRT_NONSTDC_NO_DEPRECATE")
    if sys.platform == "linux":
        ninja_test.private.link_libs.append("pthread")
    # CMake registers the binary as one CTest entry; pcons can ask gtest for
    # its cases, so each becomes a test that can be filtered, timed and
    # reported on its own.
    # Note: we run these serially because several fixtures (BuildLogTest,
    # DepsLogTest) use a fixed temp filename in the working directory,
    # which made parallel runs fail.
    project.Test("ninja_test", ninja_test, discover="gtest", serial=True)
    project.Default(ninja_test)

# 32-bit AIX only: these two need more than the standard 256M shared
# stack/heap.
AIX_BIG_HEAP = ("hash_collision_bench", "manifest_parser_perftest")
aix32 = aix and sys.maxsize <= 2**32

benches = []
for perftest in (
    "build_log_perftest",
    "canon_perftest",
    "clparser_perftest",
    "depfile_parser_perftest",
    "elide_middle_perftest",
    "escape_perftest",
    "hash_collision_bench",
    "manifest_parser_perftest",
):
    bench = project.Program(perftest, env, sources=[f"src/{perftest}.cc"])
    bench.link(libninja, libninja_re2c)
    if aix32 and perftest in AIX_BIG_HEAP:
        bench.private.link_flags.append("-Wl,-bmaxdata:0x80000000")
    benches.append(bench)
project.Default(*benches)


# --- running the benchmarks -------------------------------------------------
#
# Bonus: run the benchmarks with a `pcons run perftests` command.
# Depends on all the benches, so it'll build them first.


@project.cli_command()
def perftests() -> None:
    """Run every benchmark binary, in order, and stop at the first failure."""
    build = project.root_dir / project.build_dir

    # depfile_parser_perftest parses a depfile over and over, so it needs one
    # to read. Here's a fake one.
    depfile = build / "perftest-sample.d"
    headers = sorted((project.root_dir / "src").glob("*.h"))
    prereqs = " ".join(f"src/{h.name}" for h in headers)
    depfile.write_text(f"obj/ninja.o: src/ninja.cc {prereqs}\n")

    args = {"depfile_parser_perftest": [str(depfile)]}
    for bench in benches:
        name = bench.name
        print(f"\n=== {name} ===", flush=True)
        cmd = [str(build / name), *args.get(name, [])]
        rc = subprocess.run(cmd, check=False).returncode
        if rc != 0:
            raise SystemExit(f"perftests failed: {name} (exit {rc})")


perftests.depends(*benches)
