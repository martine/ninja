// Copyright 2024 Google Inc. All Rights Reserved.
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

#include "elide_middle.h"

#include "test.h"

namespace {

std::string ElideMiddle(const std::string& str, size_t width) {
  std::string result = str;
  ElideMiddleInPlace(result, width);
  return result;
}

}  // namespace


TEST(ElideMiddle, NothingToElide) {
  std::string input = "Nothing to elide in this short string.";
  EXPECT_EQ(input, ElideMiddle(input, 80));
  EXPECT_EQ(input, ElideMiddle(input, 38));
  EXPECT_EQ("", ElideMiddle(input, 0));
  EXPECT_EQ(".", ElideMiddle(input, 1));
  EXPECT_EQ("..", ElideMiddle(input, 2));
  EXPECT_EQ("...", ElideMiddle(input, 3));
}

TEST(ElideMiddle, ElideInTheMiddle) {
  std::string input = "01234567890123456789";
  EXPECT_EQ("...9", ElideMiddle(input, 4));
  EXPECT_EQ("0...9", ElideMiddle(input, 5));
  EXPECT_EQ("012...789", ElideMiddle(input, 9));
  EXPECT_EQ("012...6789", ElideMiddle(input, 10));
  EXPECT_EQ("0123...6789", ElideMiddle(input, 11));
  EXPECT_EQ("01234567...23456789", ElideMiddle(input, 19));
  EXPECT_EQ("01234567890123456789", ElideMiddle(input, 20));
}

TEST(ElideMiddle, Utf8EmojiWidth) {
  const char* kThread = "\xF0\x9F\xA7\xB5";  // 🧵
  const char* kStopwatch = "\xE2\x8F\xB1\xEF\xB8\x8F";  // ⏱️ (with VS16)
  std::string input = std::string("A") + kThread + "B";
  EXPECT_EQ(input, ElideMiddle(input, 4));
  EXPECT_EQ("...", ElideMiddle(input, 3));

  input = std::string("A") + kStopwatch + "B";
  EXPECT_EQ(input, ElideMiddle(input, 4));

  input = std::string("0") + kThread + "1234567";
  EXPECT_EQ(std::string("0") + kThread + "...567", ElideMiddle(input, 9));
}

// A few ANSI escape sequences. These macros make the following
// test easier to read and understand.
#define MAGENTA "\x1B[0;35m"
#define NOTHING "\33[m"
#define RED "\x1b[1;31m"
#define RESET "\x1b[0m"

TEST(ElideMiddle, ElideAnsiEscapeCodes) {
  std::string input = "012345" MAGENTA "67890123456789";
  EXPECT_EQ("012..." MAGENTA "6789", ElideMiddle(input, 10));
  EXPECT_EQ("012345" MAGENTA "67...23456789", ElideMiddle(input, 19));

  EXPECT_EQ("Nothing " NOTHING " string.",
            ElideMiddle("Nothing " NOTHING " string.", 18));
  EXPECT_EQ("0" NOTHING "12...6789",
            ElideMiddle("0" NOTHING "1234567890123456789", 10));

  input = "abcd" RED "efg" RESET "hlkmnopqrstuvwxyz";
  EXPECT_EQ("" RED RESET, ElideMiddle(input, 0));
  EXPECT_EQ("." RED RESET, ElideMiddle(input, 1));
  EXPECT_EQ(".." RED RESET, ElideMiddle(input, 2));
  EXPECT_EQ("..." RED RESET, ElideMiddle(input, 3));
  EXPECT_EQ("..." RED RESET "z", ElideMiddle(input, 4));
  EXPECT_EQ("a..." RED RESET "z", ElideMiddle(input, 5));
  EXPECT_EQ("a..." RED RESET "yz", ElideMiddle(input, 6));
  EXPECT_EQ("ab..." RED RESET "yz", ElideMiddle(input, 7));
  EXPECT_EQ("ab..." RED RESET "xyz", ElideMiddle(input, 8));
  EXPECT_EQ("abc..." RED RESET "xyz", ElideMiddle(input, 9));
  EXPECT_EQ("abc..." RED RESET "wxyz", ElideMiddle(input, 10));
  EXPECT_EQ("abcd..." RED RESET "wxyz", ElideMiddle(input, 11));
  EXPECT_EQ("abcd..." RED RESET "vwxyz", ElideMiddle(input, 12));

  EXPECT_EQ("abcd" RED "ef..." RESET "uvwxyz", ElideMiddle(input, 15));
  EXPECT_EQ("abcd" RED "ef..." RESET "tuvwxyz", ElideMiddle(input, 16));
  EXPECT_EQ("abcd" RED "efg..." RESET "tuvwxyz", ElideMiddle(input, 17));
  EXPECT_EQ("abcd" RED "efg..." RESET "stuvwxyz", ElideMiddle(input, 18));
  EXPECT_EQ("abcd" RED "efg" RESET "h...stuvwxyz", ElideMiddle(input, 19));

  input = "abcdef" RED "A" RESET "BC";
  EXPECT_EQ("..." RED RESET "C", ElideMiddle(input, 4));
  EXPECT_EQ("a..." RED RESET "C", ElideMiddle(input, 5));
  EXPECT_EQ("a..." RED RESET "BC", ElideMiddle(input, 6));
  EXPECT_EQ("ab..." RED RESET "BC", ElideMiddle(input, 7));
  EXPECT_EQ("ab..." RED "A" RESET "BC", ElideMiddle(input, 8));
  EXPECT_EQ("abcdef" RED "A" RESET "BC", ElideMiddle(input, 9));
}

TEST(ElideMiddle, Utf8EmojiWithAnsi) {
  const char* kThread = "\xF0\x9F\xA7\xB5";  // 🧵
  std::string input = std::string("A") + RED + kThread + RESET + "B";
  EXPECT_EQ(input, ElideMiddle(input, 4));
}

#undef RESET
#undef RED
#undef NOTHING
#undef MAGENTA
