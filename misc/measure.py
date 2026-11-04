#!/usr/bin/env python3

# Copyright 2011 Google Inc. All Rights Reserved.
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

"""measure the runtime and peak memory of a command by repeatedly running it.
"""

import time
import subprocess
import sys
from typing import Dict, Union, List

Command = Union[str, List[str]]

if sys.platform == 'win32':
    import ctypes
    from ctypes import wintypes

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in (
                'PeakWorkingSetSize', 'WorkingSetSize',
                'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage',
                'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage',
                'PagefileUsage', 'PeakPagefileUsage')]

    def run_once(cmd: Command) -> Dict[str, int]:
        """Run cmd and return its peak memory use in bytes."""
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        p.wait()
        counters = PROCESS_MEMORY_COUNTERS(cb=ctypes.sizeof(PROCESS_MEMORY_COUNTERS))
        # The process has exited, but while its handle is open its final
        # counters can still be read.
        ctypes.windll.psapi.GetProcessMemoryInfo(
            wintypes.HANDLE(int(p._handle)), ctypes.byref(counters), counters.cb)
        return {'peak memory': counters.PeakWorkingSetSize,
                'peak commit': counters.PeakPagefileUsage}
else:
    import os

    def run_once(cmd: Command) -> Dict[str, int]:
        """Run cmd and return its peak memory use in bytes."""
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        _, status, usage = os.wait4(p.pid, 0)
        p.returncode = os.waitstatus_to_exitcode(status)
        # ru_maxrss is in KiB on Linux, but in bytes on macOS.
        scale = 1 if sys.platform == 'darwin' else 1024
        return {'peak memory': usage.ru_maxrss * scale}

def run(cmd: Command, repeat: int = 10) -> None:
    print('sampling:', end=' ')
    sys.stdout.flush()

    samples = []
    memory: Dict[str, int] = {}
    for _ in range(repeat):
        start = time.time()
        for name, value in run_once(cmd).items():
            memory[name] = max(memory.get(name, 0), value)
        end = time.time()
        dt = (end - start) * 1000
        print('%dms' % int(dt), end=' ')
        sys.stdout.flush()
        samples.append(dt)
    print()

    # We're interested in the 'pure' runtime of the code, which is
    # conceptually the smallest time we'd see if we ran it enough times
    # such that it got the perfect time slices / disk cache hits.
    best = min(samples)
    # Also print how varied the outputs were in an attempt to make it
    # more obvious if something has gone terribly wrong.
    err = sum(s - best for s in samples) / float(len(samples))
    print('estimate: %dms (mean err %.1fms)' % (best, err))
    # Memory use barely varies between runs, so report the largest seen.
    for name, value in memory.items():
        print('%s: %.1f MiB' % (name, value / (1 << 20)))

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: measure.py command args...')
        sys.exit(1)
    run(cmd=sys.argv[1:])
