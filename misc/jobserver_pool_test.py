#!/usr/bin/env python3

"""Regression tests for the jobserver_pool.py script."""

import os
import re
import platform
import subprocess
import sys
import tempfile
import unittest
import typing as T

_SCRIPT_DIR = os.path.dirname(__file__)
_JOBSERVER_SCRIPT = os.path.join(_SCRIPT_DIR, "jobserver_pool.py")
_JOBSERVER_CMD = [sys.executable, _JOBSERVER_SCRIPT]

_IS_WINDOWS = sys.platform == "win32"

# This is only here to avoid depending on the non-standard
# scanf package which does the job properly :-)


def _simple_scanf(pattern: str, input: str) -> T.Sequence[T.Any]:
    """Extract values from input using a scanf-like pattern.

    This is very basic and only used to avoid depending on the
    non-standard scanf package which does the job properly.
    Only supports %d, %s and %%, does not support any fancy
    escaping.
    """
    re_pattern = ""
    groups = ""
    from_pos = 0

    # Just in case.
    assert "." not in pattern, f"Dots in pattern not supported."
    assert "?" not in pattern, f"Question marks in pattern not supported."

    while True:
        next_percent = pattern.find("%", from_pos)
        if next_percent < 0 or next_percent + 1 >= len(pattern):
            re_pattern += pattern[from_pos:]
            break

        re_pattern += pattern[from_pos:next_percent]

        from_pos = next_percent + 2
        formatter = pattern[next_percent + 1]
        if formatter == "%":
            re_pattern += "%"
        elif formatter == "d":
            groups += formatter
            re_pattern += "(\\d+)"
        elif formatter == "s":
            groups += formatter
            re_pattern += "(\\S+)"
        else:
            assert False, f"Unsupported scanf formatter: %{formatter}"

    m = re.match(re_pattern, input)
    if not m:
        return None

    result = []
    for group_index, formatter in enumerate(groups, start=1):
        if formatter == "d":
            result.append(int(m.group(group_index)))
        elif formatter == "s":
            result.append(m.group(group_index))
        else:
            assert False, f"Unsupported formatter {formatter}"

    return result


class JobserverPool(unittest.TestCase):
    def _run_jobserver_echo_MAKEFLAGS(
        self, cmd_args_prefix
    ) -> "subprocess.CompletedProcess[str]":
        if _IS_WINDOWS:
            cmd_args = cmd_args_prefix + ["cmd.exe", "/c", "echo %MAKEFLAGS%"]
        else:
            cmd_args = cmd_args_prefix + ["sh", "-c", 'echo "$MAKEFLAGS"']

        ret = subprocess.run(
            cmd_args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        ret.check_returncode()
        return ret

    def _test_echo_MAKEFLAGS(self, cmd_args_prefix, expected_core_count: int):
        ret = self._run_jobserver_echo_MAKEFLAGS(cmd_args_prefix)
        makeflags = ret.stdout.rstrip()

        if expected_core_count == 0:
            if _IS_WINDOWS:
                # On Windows, echo %FOO% prints "%FOO%" if FOO is not defined!
                self.assertEqual(makeflags.strip(), "%MAKEFLAGS%")
            else:
                self.assertEqual(makeflags.strip(), "")

        else:  # expected_core_count > 0
            if _IS_WINDOWS:
                expected_format = " -j%d --jobserver-auth=%s"
            else:
                expected_format = " -j%d --jobserver-fds=%d,%d --jobserver-auth=%d,%d"

            m = _simple_scanf(expected_format, makeflags)
            self.assertTrue(
                m,
                f"Invalid MAKEFLAGS value, expected format [{expected_format}], got: [{makeflags}]",
            )

            if _IS_WINDOWS:
                sem_name = m[1]
            else:
                _, read1, write1, read2, write2 = m
                self.assertTrue(
                    read1 == read2 and write1 == write2,
                    f"Inconsistent file descriptors in MAKEFLAGS: {makeflags}",
                )

            core_count = m[0]
            self.assertEqual(
                core_count,
                expected_core_count,
                f"Invalid core count {core_count}, expected {expected_core_count}",
            )

    def test_MAKEFLAGS_default(self):
        self._test_echo_MAKEFLAGS(_JOBSERVER_CMD, os.cpu_count())

    def test_MAKEFLAGS_with_10_jobs(self):
        self._test_echo_MAKEFLAGS(_JOBSERVER_CMD + ["-j10"], 10)
        self._test_echo_MAKEFLAGS(_JOBSERVER_CMD + ["--jobs=10"], 10)
        self._test_echo_MAKEFLAGS(_JOBSERVER_CMD + ["--jobs", "10"], 10)

    def test_MAKEFLAGS_with_no_jobs(self):
        self._test_echo_MAKEFLAGS(_JOBSERVER_CMD + ["-j0"], 0)
        self._test_echo_MAKEFLAGS(_JOBSERVER_CMD + ["--jobs=0"], 0)
        self._test_echo_MAKEFLAGS(_JOBSERVER_CMD + ["--jobs", "0"], 0)

    @unittest.skipIf(_IS_WINDOWS, "--fifo is not supported on Windows")
    def test_MAKEFLAGS_with_fifo(self):
        fifo_name = "test_fifo"
        fifo_path = os.path.abspath(fifo_name)
        ret = self._run_jobserver_echo_MAKEFLAGS(
            _JOBSERVER_CMD + ["-j10", "--fifo", fifo_name]
        )
        makeflags = ret.stdout.rstrip()
        self.assertEqual(makeflags, " -j10 --jobserver-auth=fifo:" + fifo_path)

    @unittest.skipIf(not _IS_WINDOWS, "--name is not supported on Posix")
    def test_MAKEFLAGS_with_name(self):
        sem_name = "test_semaphore"
        ret = self._run_jobserver_echo_MAKEFLAGS(
            _JOBSERVER_CMD + ["-j10", "--name", sem_name]
        )
        makeflags = ret.stdout.rstrip()
        self.assertEqual(makeflags, " -j10 --jobserver-auth=" + sem_name)


if __name__ == "__main__":
    unittest.main()
