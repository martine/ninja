// Copyright 2012 Google Inc. All Rights Reserved.
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

#include <stdio.h>
#include <string.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <numeric>
#include <vector>

#include "string_piece.h"
#include "metrics.h"
#include "util.h"

const std::string kPaths[] = {
  // Small Relative
  "third_party/WebKit/smalll/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // Small Relative
  "third_party/WebKit/small/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // Relative
  "third_party/WebKit/Source/WebCore/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // Relative long
  "third_party/WebKit/Source/WebCore/"
  "third_party/WebKit/Source/WebCore/"
  "third_party/WebKit/Source/WebCore/"
  "third_party/WebKit/Source/WebCore/"
  "third_party/WebKit/Source/WebCore/"
  "third_party/WebKit/Source/WebCore/"
  "third_party/WebKit/Source/WebCore/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // Absolute
  "/third_party/WebKit/Source/WebCore/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // Leading ../
  "../../third_party/WebKit/Source/WebCore/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // Leading ./ (causing us actually copy bytes)
  "./third_party/WebKit/Source/WebCore/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // ../ in the middle
  "third_party/WebKit/Source/WebCore/"
  "platform/leveldb/UnnecessarySubDirectory/../LevelDBWriteBatch.cpp",
  // Empty directories
  "third_party//WebKit///Source/WebCore/"
  "platform/leveldb/LevelDBWriteBatch.cpp",
  // Trailing separator (a directory)
  "third_party/WebKit/Source/WebCore/"
  "platform/leveldb/",

  // Handle the same paths again but with backslashes
  // Relative
  "third_party\\WebKit\\Source\\WebCore\\"
  "platform\\leveldb\\LevelDBWriteBatch.cpp",
  // Absolute
  "\\third_party\\WebKit\\Source\\WebCore\\"
  "platform\\leveldb\\LevelDBWriteBatch.cpp",
  // Leading ..\ dir
  "..\\..\\third_party\\WebKit\\Source\\WebCore\\"
  "platform\\leveldb\\LevelDBWriteBatch.cpp",
  // Leading .\ (causing us actually copy bytes)
  ".\\third_party\\WebKit\\Source\\WebCore\\"
  "platform\\leveldb\\LevelDBWriteBatch.cpp",
  // ..\ in the middle
  "third_party\\WebKit\\Source\\WebCore\\"
  "platform\\leveldb\\UnnecessarySubDirectory\\..\\LevelDBWriteBatch.cpp",
  // Empty directories
  "third_party\\\\WebKit\\\\\\Source\\WebCore\\"
  "platform\\leveldb\\LevelDBWriteBatch.cpp",

  // Mixture of slashes
  "third_party\\WebKit/Source\\WebCore\\"
  "platform\\leveldb/LevelDBWriteBatch.cpp",
};

void disambiguation(char* path, std::size_t* len, std::uint64_t* slash_bits) {
  // Disambiguate between overloads of CanonicalizePath
  CanonicalizePath(path, len, slash_bits);
}

void disambiguationFallback(char* path, std::size_t* len,
                            std::uint64_t* slash_bits) {
  // Disambiguate between overloads of CanonicalizePathFallback
  CanonicalizePathFallback(path, len, slash_bits);
}

const int kNumRepetitions = 1000000;
const int kNumRepeats = 20;

template <typename CANONICALIZE_PATH>
void runBenchmarks(CANONICALIZE_PATH&& f, const char* name,
                   std::string& pathCopies) {
  printf("\n%s\n", name);

  int sum_of_min = 0;
  int sum_of_max = 0;
  double sum_of_avg = 0.0;

  for (const std::string& path : kPaths) {
    printf("%s\n", path.c_str());
    int min = std::numeric_limits<int>::max();
    int max = std::numeric_limits<int>::min();
    double total = 0;

    for (int j = 0; j < kNumRepeats; ++j) {
      auto out = pathCopies.begin();
      for (int i = 0; i < kNumRepetitions; ++i) {
        out = std::copy(path.begin(), path.end(), out);
      }

      const std::int64_t start = GetTimeMillis();
      for (int i = 0; i < kNumRepetitions; ++i) {
        std::uint64_t slash_bits;
        std::size_t len = path.size();
        f(&pathCopies[i * len], &len, &slash_bits);
      }

      const int delta = static_cast<int>(GetTimeMillis() - start);
      min = std::min(delta, min);
      max = std::max(delta, max);
      total += delta;
    }

    const double avg = total / kNumRepeats;
    printf("  min %dms  max %dms  avg %.1fms\n", min, max, avg);

    sum_of_min += min;
    sum_of_max += max;
    sum_of_avg += avg;
  }

  const std::size_t size = sizeof(kPaths) / sizeof(kPaths[0]);
  printf("AVERAGE:\n  min %dms  max %dms  avg %.1fms\n",
         static_cast<int>(sum_of_min / size),
         static_cast<int>(sum_of_max / size), sum_of_avg / size);
}

int main() {
  std::size_t max_size = 0;
  for (const std::string& path : kPaths) {
    max_size = std::max(max_size, path.size());
  }

  std::string pathCopies;
  pathCopies.resize(kNumRepetitions * max_size);
  runBenchmarks(disambiguation, "CanonicalizePath (SWAR)", pathCopies);
  runBenchmarks(disambiguationFallback, "CanonicalizePathFallback (scalar)",
                pathCopies);

  // add additional implementations here for comparison
}
