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

"""Simple utility used by the jobserver test. Wait for specific time, then write start/stop times to output file."""

import argparse
import time
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--duration-ms",
        default="50",
        help="sleep duration in milliseconds (default 50)",
    )
    parser.add_argument("output_file", type=Path, help="output file name.")
    args = parser.parse_args()

    now_time_ns = time.time_ns()
    time.sleep(int(args.duration_ms) / 1000.0)
    args.output_file.write_text(f"{now_time_ns}\n{time.time_ns()}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
