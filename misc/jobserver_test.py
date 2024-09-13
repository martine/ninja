#!/usr/bin/env python3
# Copyright 2024 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from textwrap import dedent
import os
import platform
import subprocess
import tempfile
import typing as T
import sys
import unittest

_SCRIPT_DIR = os.path.realpath(os.path.dirname(__file__))
_JOBSERVER_POOL_SCRIPT = os.path.join(_SCRIPT_DIR, "jobserver_pool.py")
_JOBSERVER_TEST_HELPER_SCRIPT = os.path.join(_SCRIPT_DIR, "jobserver_test_helper.py")

_PLATFORM_IS_WINDOWS = platform.system() == "Windows"

default_env = dict(os.environ)
default_env.pop("NINJA_STATUS", None)
default_env.pop("MAKEFLAGS", None)
default_env["TERM"] = "dumb"
NINJA_PATH = os.path.abspath("./ninja")


class BuildDir:
    def __init__(self, build_ninja: str):
        self.build_ninja = dedent(build_ninja)
        self.d: T.Optional[tempfile.TemporaryDirectory] = None

    def __enter__(self):
        self.d = tempfile.TemporaryDirectory()
        with open(os.path.join(self.d.name, "build.ninja"), "w") as f:
            f.write(self.build_ninja)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.d.cleanup()

    @property
    def path(self) -> str:
        assert self.d
        return self.d.name

    def run(
        self,
        cmd_flags: T.Sequence[str] = [],
        env: T.Dict[str, str] = default_env,
    ) -> None:
        """Run a command, raise exception on error. Do not capture outputs."""
        ret = subprocess.run(cmd_flags, env=env)
        ret.check_returncode()

    def ninja_run(
        self,
        ninja_args: T.List[str],
        prefix_args: T.List[str] = [],
        extra_env: T.Dict[str, str] = {},
    ) -> "subprocess.CompletedProcess[str]":
        ret = self.ninja_spawn(
            ninja_args,
            prefix_args=prefix_args,
            extra_env=extra_env,
            capture_output=False,
        )
        ret.check_returncode()
        return ret

    def ninja_clean(self) -> None:
        self.ninja_run(["-t", "clean"])

    def ninja_spawn(
        self,
        ninja_args: T.List[str],
        prefix_args: T.List[str] = [],
        extra_env: T.Dict[str, str] = {},
        capture_output: bool = True,
    ) -> "subprocess.CompletedProcess[str]":
        """Run Ninja command and capture outputs."""
        return subprocess.run(
            prefix_args + [NINJA_PATH, "-C", self.path] + ninja_args,
            text=True,
            capture_output=capture_output,
            env={**default_env, **extra_env},
        )


def span_output_file(span_n: int) -> str:
    return "out%02d" % span_n


def generate_build_plan(command_count: int) -> str:
    """Generate a Ninja build plan for |command_count| parallel tasks.

    Each task calls the test helper script which waits for 50ms
    then writes its own start and end time to its output file.
    """
    result = f"""
rule span
    command = {sys.executable} -S {_JOBSERVER_TEST_HELPER_SCRIPT} --duration-ms=50 $out

"""

    for n in range(command_count):
        result += "build %s: span\n" % span_output_file(n)

    result += "build all: phony %s\n" % " ".join(
        [span_output_file(n) for n in range(command_count)]
    )
    return result


def compute_max_overlapped_spans(build_dir: str, command_count: int) -> int:
    """Compute the maximum number of overlapped spanned tasks.

    This reads the output files from |build_dir| and look at their start and end times
    to compute the maximum number of tasks that were run in parallel.
    """
    # Read the output files.
    if command_count < 2:
        return 0

    spans: T.List[T.Tuple[int, int]] = []
    for n in range(command_count):
        with open(os.path.join(build_dir, span_output_file(n)), "rb") as f:
            content = f.read().decode("utf-8")
        lines = content.splitlines()
        assert len(lines) == 2, f"Unexpected output file content: [{content}]"
        spans.append((int(lines[0]), int(lines[1])))

    # Stupid but simple, for each span, count the number of other spans that overlap it.
    max_overlaps = 1
    for n in range(command_count):
        cur_start, cur_end = spans[n]
        cur_overlaps = 1
        for m in range(command_count):
            other_start, other_end = spans[m]
            if n != m and other_end > cur_start and other_start < cur_end:
                cur_overlaps += 1

        if cur_overlaps > max_overlaps:
            max_overlaps = cur_overlaps

    return max_overlaps


class JobserverTest(unittest.TestCase):

    def test_no_jobserver_client(self):
        task_count = 4
        build_plan = generate_build_plan(task_count)
        with BuildDir(build_plan) as b:
            output = b.run([NINJA_PATH, "-C", b.path, f"-j{task_count}", "all"])

            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, task_count)

            b.ninja_clean()
            output = b.run([NINJA_PATH, "-C", b.path, "-j1", "all"])

            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 1)

    def _run_client_test(self, jobserver_args: T.List[str]) -> None:
        task_count = 4
        build_plan = generate_build_plan(task_count)
        with BuildDir(build_plan) as b:
            # First, run the full 10 tasks with with 10 tokens, this should allow all
            # tasks to run in parallel.
            ret = b.ninja_run(
                ninja_args=["all"],
                prefix_args=jobserver_args + [f"--jobs={task_count}"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, task_count)

            # Second, use 2 tokens only, and verify that this was enforced by Ninja.
            b.ninja_clean()
            b.ninja_run(
                ["all"],
                prefix_args=jobserver_args + ["--jobs=2"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 2)

            # Third, verify that --jobs=1 serializes all tasks.
            b.ninja_clean()
            b.ninja_run(
                ["all"],
                prefix_args=jobserver_args + ["--jobs=1"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 1)

            # Finally, verify that -j1 overrides the pool.
            b.ninja_clean()
            b.ninja_run(
                ["-j1", "all"],
                prefix_args=jobserver_args + [f"--jobs={task_count}"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 1)

    @unittest.skipIf(_PLATFORM_IS_WINDOWS, "These test methods do not work on Windows")
    def test_jobserver_client_with_posix_pipe(self):
        self._run_client_test([sys.executable, "-S", _JOBSERVER_POOL_SCRIPT, "--pipe"])

    @unittest.skipIf(_PLATFORM_IS_WINDOWS, "These test methods do not work on Windows")
    def test_jobserver_client_with_posix_fifo(self):
        self._run_client_test([sys.executable, "-S", _JOBSERVER_POOL_SCRIPT])

    def _test_MAKEFLAGS_value(
        self, ninja_args: T.List[str] = [], prefix_args: T.List[str] = []
    ):
        build_plan = r"""
rule print
    command = echo MAKEFLAGS="[$$MAKEFLAGS]"

build all: print
"""
        with BuildDir(build_plan) as b:
            ret = b.ninja_spawn(
                ninja_args + ["--quiet", "all"], prefix_args=prefix_args
            )
            self.assertEqual(ret.returncode, 0)
            output = ret.stdout.strip()
            pos = output.find("MAKEFLAGS=[")
            self.assertNotEqual(pos, -1, "Could not find MAKEFLAGS in output!")
            makeflags, sep, _ = output[pos + len("MAKEFLAGS=[") :].partition("]")
            self.assertEqual(sep, "]", "Missing ] in output!: " + output)
            self.assertTrue(
                "--jobserver-auth=" in makeflags,
                f"Missing --jobserver-auth from MAKEFLAGS [{makeflags}]\nSTDOUT [{ret.stdout}]\nSTDERR [{ret.stderr}]",
            )

    def test_client_passes_MAKEFLAGS(self):
        self._test_MAKEFLAGS_value(
            prefix_args=[sys.executable, "-S", _JOBSERVER_POOL_SCRIPT]
        )


if __name__ == "__main__":
    unittest.main()
