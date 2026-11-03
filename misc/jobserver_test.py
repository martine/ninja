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

from contextlib import ExitStack
from textwrap import dedent
import os
import platform
import subprocess
import tempfile
import typing as T
import shlex
import sys
import unittest

_SCRIPT_DIR = os.path.realpath(os.path.dirname(__file__))
_JOBSERVER_POOL_SCRIPT = os.path.join(_SCRIPT_DIR, "jobserver_pool.py")
_JOBSERVER_TEST_HELPER_SCRIPT = os.path.join(_SCRIPT_DIR, "jobserver_test_helper.py")

_PLATFORM_IS_WINDOWS = platform.system() == "Windows"

# Set this to True to debug command invocations.
_DEBUG = False
_DEBUG = True

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
        cmd_args = prefix_args + [NINJA_PATH, "-C", self.path] + ninja_args
        if _DEBUG:
            cmd_str = " ".join(shlex.quote(c) for c in cmd_args)
            print(f"CMD [{cmd_str}]", file=sys.stderr)
        return subprocess.run(
            cmd_args,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            env={**default_env, **extra_env},
        )

    def ninja_popen(
        self,
        ninja_args: T.List[str],
        prefix_args: T.List[str] = [],
        extra_env: T.Dict[str, str] = {},
        capture_output: bool = True,
    ) -> subprocess.Popen[str]:
        """Start Ninja command and return the Popen object (i.e. without blocking)."""
        cmd_args = prefix_args + [NINJA_PATH, "-C", self.path] + ninja_args
        if _DEBUG:
            cmd_str = " ".join(shlex.quote(c) for c in cmd_args)
            print(f"CMD [{cmd_str}]", file=sys.stderr)
        return subprocess.Popen(
            cmd_args,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            env={**default_env, **extra_env},
        )


def span_output_file(span_n: int) -> str:
    return "out%02d" % span_n


def generate_build_plan(command_count: int, prefix: str = "") -> str:
    """Generate a Ninja build plan for |command_count| parallel tasks.

    Each task calls the test helper script which waits then writes its
    own start and end time to its output file.

    400ms (not 50ms): GitHub Actions containers often share CPUs with
    sibling ninja_test processes. Short spans finish before the next
    task is scheduled, so max_overlaps never reaches task_count (#2827).
    """
    result = prefix + f"""
rule span
    command = {sys.executable} -S {_JOBSERVER_TEST_HELPER_SCRIPT} --duration-ms=400 $out

"""

    for n in range(command_count):
        result += "build %s: span\n" % span_output_file(n)

    result += "build all: phony %s\n" % " ".join(
        [span_output_file(n) for n in range(command_count)]
    )
    return result

def generate_double_build_plan(
        wait_1_ms: int = 500,
        wait_2_ms: int = 500,
        offset: int = 0,
    ) -> str:

    """Generate a Ninja build plan that invokes the test helper script in two parallel commands, each one with its own duration argument

    - `wait_1_ms` and `wait_2_ms` control task durations.
    - `offset`: start index of the output files generated by this plan, allows multiple plans without conflicting filenames.
    """
    result = f"""
rule short
    command = {sys.executable} -S {_JOBSERVER_TEST_HELPER_SCRIPT} --duration-ms={wait_1_ms} $out

rule long
    command = {sys.executable} -S {_JOBSERVER_TEST_HELPER_SCRIPT} --duration-ms={wait_2_ms} $out
"""

    result += "build %s: long\n" % span_output_file(offset)
    result += "build %s: short\n" % span_output_file(offset + 1)

    result += "build all: phony %s\n" % " ".join(
        [span_output_file(n + offset) for n in range(2)]
    )

    return result

def get_spans(build_dir: str, command_count: int) -> T.List[T.Tuple[int, int]]:
    """
    Get span outputs for a single build directory.

    - `build_dir`: Directory containing span output files.
    - `command_count`: Number of commands executed in the build.

    Returns a list of (start, end) tuples parsed from the span output files, sorted by start time.
    """
    return get_spans_for_multiple_builds([build_dir], [command_count])

def get_spans_for_multiple_builds(build_dirs: T.List[str], command_counts: T.List[int]) -> T.List[T.Tuple[int, int]]:
    """
    Get span outputs across multiple build directories. Assumes that the output files
    in each build directory are named sequentially according to the `span_output_file` function,
    and that the total number of output files across all build directories is equal to the sum of `command_counts`.

    - `build_dirs`: Build directories containing span output files.
    - `command_counts`: Number of commands executed in each build.

    Returns a list of (start, end) span tuples in increasing order by start time.
    """
    spans: T.List[T.Tuple[int, int]] = []
    offset:int = 0
    for b_path, command_count in zip(build_dirs, command_counts):
        for n in range(command_count):
            out_file = os.path.join(b_path, span_output_file(n + offset))
            with open(out_file, "rb") as f:
                content = f.read().decode("utf-8")
            lines = content.splitlines()
            assert len(lines) == 2, f"Unexpected output file content: [{content}]"
            spans.append((int(lines[0]), int(lines[1])))

        # Update the offset for the next build directory to ensure unique output file names.
        offset += command_count
    return sorted(spans, key=lambda x: x[0])

def compute_max_overlapped_spans(build_dir: str, command_count: int) -> int:
    """Compute the maximum number of overlapped spanned tasks.

    This reads the output files from |build_dir| and look at their start and end times
    to compute the maximum number of tasks that were run in parallel.
    """
    # Read the output files.
    if command_count < 2:
        return 0

    spans: T.List[T.Tuple[int, int]] = get_spans(build_dir, command_count)
    # The most spans running at the same time. At equal times, ends
    # come before starts.
    events = sorted([(start, 1) for start, _ in spans] +
                    [(end, -1) for _, end in spans])
    max_overlaps = running = 0
    for _, delta in events:
        running += delta
        max_overlaps = max(max_overlaps, running)

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
            # First, run the full tasks with with {task_count} tokens, this should allow all
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

            # On Linux, use taskset to limit the number of available cores to 1
            # and verify that the jobserver overrides the default Ninja parallelism
            # and that {task_count} tasks are still spawned in parallel.
            if platform.system() == "Linux":
                # First, run without a jobserver, with a single CPU, Ninja will
                # use a parallelism of 2 in this case (GuessParallelism() in ninja.cc)
                b.ninja_clean()
                b.ninja_run(
                    ["all"],
                    prefix_args=["taskset", "-c", "0"],
                )
                max_overlaps = compute_max_overlapped_spans(b.path, task_count)
                self.assertEqual(max_overlaps, 2)

                # Now with a jobserver with {task_count} tasks.
                b.ninja_clean()
                b.ninja_run(
                    ["all"],
                    prefix_args=jobserver_args
                    + [f"--jobs={task_count}"]
                    + ["taskset", "-c", "0"],
                )
                max_overlaps = compute_max_overlapped_spans(b.path, task_count)
                self.assertEqual(max_overlaps, task_count)

    @unittest.skipIf(_PLATFORM_IS_WINDOWS, "These test methods do not work on Windows")
    def test_jobserver_client_with_posix_fifo(self):
        self._run_client_test([sys.executable, "-S", _JOBSERVER_POOL_SCRIPT])

    @unittest.skipIf(_PLATFORM_IS_WINDOWS, "These test methods do not work on Windows")
    def test_jobserver_client_with_posix_pipe(self):
        # Verify that setting up a --pipe server does not make Ninja exit with an error.
        # Instead, a warning is printed.
        task_count = 4
        build_plan = generate_build_plan(task_count)
        with BuildDir(build_plan) as b:

            prefix_args = [
                sys.executable,
                "-S",
                _JOBSERVER_POOL_SCRIPT,
                "--pipe",
                f"--jobs={task_count}",
            ]

            def run_ninja_with_jobserver_pipe(args):
                ret = b.ninja_spawn(args, prefix_args=prefix_args)
                ret.check_returncode()
                return ret.stdout, ret.stderr

            output, error = run_ninja_with_jobserver_pipe(["-v", "all"])
            if _DEBUG:
                print(f"OUTPUT [{output}]\nERROR [{error}]\n", file=sys.stderr)
            self.assertTrue(error.find("Pipe-based protocol is not supported!") >= 0)

            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, task_count)

            # Using an explicit -j<N> ignores the jobserver pool.
            b.ninja_clean()
            output, error = run_ninja_with_jobserver_pipe(["-v", "-j1", "all"])
            if _DEBUG:
                print(f"OUTPUT [{output}]\nERROR [{error}]\n", file=sys.stderr)
            self.assertFalse(error.find("Pipe-based protocol is not supported!") >= 0)

            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 1)

    @unittest.skipIf(_PLATFORM_IS_WINDOWS, "These test methods do not work on Windows")
    def test_jobserver_client_with_posix_fifo_token_efficiency(self):
        # Due to implicit slots, the max number of parallel tasks is task_count + num_clients - 1
        task_count = 2
        client_tasks = 2

        with ExitStack() as stack:
            tmp_dir = tempfile.mkdtemp()
            stack.callback(os.rmdir, tmp_dir)

            fifo_path = os.path.join(tmp_dir, "jobserver_fifo_test")

            # Create FIFO for Jobserver - see notes about implicit slots above
            os.mkfifo(fifo_path)  # type: ignore
            stack.callback(lambda: os.path.exists(fifo_path) and os.remove(fifo_path))

            read_fd = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
            stack.callback(os.close, read_fd)

            write_fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            stack.callback(os.close, write_fd)

            os.write(write_fd, (task_count - 1) * b"x")

            env = dict(os.environ)
            env["MAKEFLAGS"] = f" -j{task_count} --jobserver-auth=fifo:" + fifo_path

            # First build plan has 2 short tasks, second build plan has 2 long tasks
            build_plan_1 = generate_double_build_plan(wait_1_ms=1000, wait_2_ms=1000, offset=0)
            build_plan_2 = generate_double_build_plan(wait_1_ms=2000, wait_2_ms=2000, offset=client_tasks)

            with BuildDir(build_plan_1) as b1, BuildDir(build_plan_2) as b2:
                # Start all builds in parallel, with the same jobserver environment.
                p1 = b1.ninja_popen(["all"], extra_env=env)
                p2 = b2.ninja_popen(["all"], extra_env=env)

                # Wait for all builds to finish and verify they all succeeded.
                p1.communicate()
                p2.communicate()

                self.assertEqual(p1.returncode, 0, "Build 1 failed")
                self.assertEqual(p2.returncode, 0, "Build 2 failed")

                """
                As noted above, with implicit slots, the max number of parallel tasks
                is task_count + num_clients - 1, which in this case is 3.
                The expected behavior is that 3 tasks run in parallel at the beginning as follows:

                |---A---|           (Client 1, 2000ms)
                |---B---|           (Client 1, 2000ms)
                |-------C-------|   (Client 2, 4000ms)

                Once first 2 of 3 tasks finishes (i.e. the short sleeps), the 4th task can start,
                and this should start before the long task finishes.

                |---A---|                    (Client 1, 2000ms)
                |---B---|                    (Client 1, 2000ms)
                |-------C-------|            (Client 2, 4000ms)
                           |-------D-------| (Client 2, 4000ms)

                Make sure D starts after A and B finishes, but before C finishes.
                """

                spans = get_spans_for_multiple_builds(
                    [b1.path, b2.path], [client_tasks, client_tasks]
                )
                spans.sort(key=lambda s: s[0])

                initial_tasks = spans[: task_count + client_tasks - 1]
                last_task = spans[-1]

                earliest_end = min(task[1] for task in initial_tasks)
                latest_end = max(task[1] for task in initial_tasks)

                # Assert last task starts after at least one initial task finishes,
                # but before all initial tasks finish.
                self.assertTrue(
                    last_task[0] >= earliest_end and last_task[0] < latest_end
                )

    def test_jobserver_pool_mode_with_flag(self):
        task_count = 4
        build_plan = generate_build_plan(task_count)
        with BuildDir(build_plan) as b:
            # First, run the full tasks with with {task_count} tokens, this should allow all
            # tasks to run in parallel.
            ret = b.ninja_run(
                ninja_args=["--jobserver-pool", f"-j{task_count}", "all"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, task_count)

            # Second, use 2 tokens only, and verify that this was enforced by Ninja and
            # that both a pool and a client were setup by Ninja.
            b.ninja_clean()
            ret = b.ninja_spawn(
                ["-j2", "--jobserver-pool", "--verbose", "all"],
                capture_output=True,
            )
            self.assertEqual(ret.returncode, 0)
            self.assertTrue(
                "ninja: Creating jobserver pool for 2 parallel jobs" in ret.stdout,
                msg="Ninja failed to setup jobserver pool!",
            )
            self.assertTrue(
                "ninja: Jobserver mode detected: " in ret.stdout,
                msg="Ninja failed to setup jobserver client!",
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 2)

            # Third, verify that --jobs=1 serializes all tasks.
            b.ninja_clean()
            b.ninja_run(
                ["--jobserver-pool", "-j1", "all"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 1)

            # On Linux, use taskset to limit the number of available cores to 1
            # and verify that the jobserver overrides the default Ninja parallelism
            # and that {task_count} tasks are still spawned in parallel.
            if platform.system() == "Linux":
                # First, run without a jobserver, with a single CPU, Ninja will
                # use a parallelism of 2 in this case (GuessParallelism() in ninja.cc)
                b.ninja_clean()
                b.ninja_run(
                    ["all"],
                    prefix_args=["taskset", "-c", "0"],
                )
                max_overlaps = compute_max_overlapped_spans(b.path, task_count)
                self.assertEqual(max_overlaps, 2)

                # Now with a jobserver with {task_count} tasks.
                b.ninja_clean()
                b.ninja_run(
                    ["--jobserver-pool", f"-j{task_count}", "all"],
                    prefix_args=["taskset", "-c", "0"],
                )
                max_overlaps = compute_max_overlapped_spans(b.path, task_count)
                self.assertEqual(max_overlaps, task_count)

    def test_jobserver_pool_mode_ignored_with_existing_pool(self):
        task_count = 4
        build_plan = generate_build_plan(task_count)
        with BuildDir(build_plan) as b:
            # Setup a top-level pool with 2 jobs, and verify that `--jobserver-pool` respected it.
            ret = b.ninja_run(
                ninja_args=["--jobserver-pool", "all"],
                prefix_args=[sys.executable, "-S", _JOBSERVER_POOL_SCRIPT, "--jobs=2"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 2)

    def test_jobserver_pool_mode_with_variable(self):
        task_count = 4
        build_plan = generate_build_plan(task_count, prefix = "enable_jobserver_pool = 1\n")
        with BuildDir(build_plan) as b:
            # First, run the full tasks with with {task_count} tokens, this should allow all
            # tasks to run in parallel.
            ret = b.ninja_run(
                ninja_args=["all"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, task_count)

            # Second, use 2 tokens only, and verify that this was enforced by Ninja.
            b.ninja_clean()
            b.ninja_run(
                ["-j2", "all"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 2)

            # Third, verify that --jobs=1 serializes all tasks.
            b.ninja_clean()
            b.ninja_run(
                ["-j1", "all"],
            )
            max_overlaps = compute_max_overlapped_spans(b.path, task_count)
            self.assertEqual(max_overlaps, 1)

            # On Linux, use taskset to limit the number of available cores to 1
            # and verify that the jobserver overrides the default Ninja parallelism
            # and that {task_count} tasks are still spawned in parallel.
            if platform.system() == "Linux":
                # First, run without a jobserver, with a single CPU, Ninja will
                # use a parallelism of 2 in this case (GuessParallelism() in ninja.cc)
                b.ninja_clean()
                b.ninja_run(
                    ["all"],
                    prefix_args=["taskset", "-c", "0"],
                )
                max_overlaps = compute_max_overlapped_spans(b.path, task_count)
                self.assertEqual(max_overlaps, 2)

                # Now with a jobserver with {task_count} tasks.
                b.ninja_clean()
                b.ninja_run(
                    [f"-j{task_count}", "all"],
                    prefix_args=["taskset", "-c", "0"],
                )
                max_overlaps = compute_max_overlapped_spans(b.path, task_count)
                self.assertEqual(max_overlaps, task_count)

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
