// Copyright 2026 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstdio>

#include <chrono>
#include <string>
#include <string_view>

#include "util.h"

namespace {

struct TestPath {
  const char* name;
  const char* path;
};

const TestPath kPaths[] = {
  { "Short safe", "foo.o" },
  { "Safe", "obj/browser/sync_view_layer.render_master_manager.o" },
  { "Long safe",
    "../../third_party/WebKit/Source/WebCore/"
    "platform/leveldb/LevelDBWriteBatch.cpp" },
  { "Space", "out/My Project/obj/browser/sync_view_layer.o" },
  { "Backslash", "out\\Release\\obj\\browser\\sync_view_layer.o" },
  { "Quote", "out/obj/browser/user's_view_layer.render_manager.o" },
  { "Doublequote", "out/obj/browser/\"quoted\"/sync_view_layer.o" },
};

typedef void (*EscapeFunction)(std::string_view, std::string*);

/// Return the fastest time in nanoseconds per call of \a escape on \a input.
double TimeEscape(EscapeFunction escape, const std::string& input) {
  const int kRuns = 5;
  const int kNumRepetitions = 5000000;
  std::string result;
  size_t total_size = 0;
  double best = 0;
  for (int run = 0; run < kRuns; ++run) {
    std::chrono::steady_clock::time_point start =
        std::chrono::steady_clock::now();
    for (int i = 0; i < kNumRepetitions; ++i) {
      result.clear();
      escape(input, &result);
      total_size += result.size();
    }
    double ns = std::chrono::duration<double, std::nano>(
                    std::chrono::steady_clock::now() - start).count() /
                kNumRepetitions;
    if (run == 0 || ns < best)
      best = ns;
  }
  // Use the result so the calls can't be optimized away.
  if (total_size == 0)
    std::printf("unexpected empty result\n");
  return best;
}

}  // namespace

int main() {
  std::printf("%-12s %12s %12s\n", "Path", "Shell (ns)", "Win32 (ns)");
  for (const TestPath& p : kPaths) {
    const std::string input = p.path;
    const double shell = TimeEscape(GetShellEscapedString, input);
    const double win32 = TimeEscape(GetWin32EscapedString, input);
    std::printf("%-12s %12.1f %12.1f\n", p.name, shell, win32);
  }
  return 0;
}
