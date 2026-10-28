// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "util.h"

#include "test.h"

#include <cassert>
#include <random>

using namespace std;

namespace {

void CanonicalizePath(string* path) {
  uint64_t unused;
  ::CanonicalizePath(path, &unused);
}

}  // namespace

TEST(CanonicalizePath, PathSamples) {
  string path;

  CanonicalizePath(&path);
  EXPECT_EQ("", path);

  path = "foo.h";
  CanonicalizePath(&path);
  EXPECT_EQ("foo.h", path);

  path = "./foo.h";
  CanonicalizePath(&path);
  EXPECT_EQ("foo.h", path);

  path = "./foo/./bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("foo/bar.h", path);

  path = "./x/foo/../bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("x/bar.h", path);

  path = "./x/foo/../../bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("bar.h", path);

  path = "foo//bar";
  CanonicalizePath(&path);
  EXPECT_EQ("foo/bar", path);

  path = "foo//.//..///bar";
  CanonicalizePath(&path);
  EXPECT_EQ("bar", path);

  path = "./x/../foo/../../bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("../bar.h", path);

  path = "foo/./.";
  CanonicalizePath(&path);
  EXPECT_EQ("foo", path);

  path = "foo/bar/..";
  CanonicalizePath(&path);
  EXPECT_EQ("foo", path);

  path = "foo/.hidden_bar";
  CanonicalizePath(&path);
  EXPECT_EQ("foo/.hidden_bar", path);

  path = "/foo";
  CanonicalizePath(&path);
  EXPECT_EQ("/foo", path);

  path = "//foo";
  CanonicalizePath(&path);
#ifdef _WIN32
  EXPECT_EQ("//foo", path);
#else
  EXPECT_EQ("/foo", path);
#endif

  path = "..";
  CanonicalizePath(&path);
  EXPECT_EQ("..", path);

  path = "../";
  CanonicalizePath(&path);
  EXPECT_EQ("..", path);

  path = "../foo";
  CanonicalizePath(&path);
  EXPECT_EQ("../foo", path);

  path = "../foo/";
  CanonicalizePath(&path);
  EXPECT_EQ("../foo", path);

  path = "../..";
  CanonicalizePath(&path);
  EXPECT_EQ("../..", path);

  path = "../../";
  CanonicalizePath(&path);
  EXPECT_EQ("../..", path);

  path = "./../";
  CanonicalizePath(&path);
  EXPECT_EQ("..", path);

  path = "/..";
  CanonicalizePath(&path);
  EXPECT_EQ("/..", path);

  path = "/../";
  CanonicalizePath(&path);
  EXPECT_EQ("/..", path);

  path = "/../..";
  CanonicalizePath(&path);
  EXPECT_EQ("/../..", path);

  path = "/../../";
  CanonicalizePath(&path);
  EXPECT_EQ("/../..", path);

  path = "/";
  CanonicalizePath(&path);
  EXPECT_EQ("/", path);

  path = "/foo/..";
  CanonicalizePath(&path);
  EXPECT_EQ("/", path);

  path = ".";
  CanonicalizePath(&path);
  EXPECT_EQ(".", path);

  path = "./.";
  CanonicalizePath(&path);
  EXPECT_EQ(".", path);

  path = "foo/..";
  CanonicalizePath(&path);
  EXPECT_EQ(".", path);

  path = "foo/.._bar";
  CanonicalizePath(&path);
  EXPECT_EQ("foo/.._bar", path);
}

#ifdef _WIN32
TEST(CanonicalizePath, PathSamplesWindows) {
  string path;

  CanonicalizePath(&path);
  EXPECT_EQ("", path);

  path = "foo.h";
  CanonicalizePath(&path);
  EXPECT_EQ("foo.h", path);

  path = ".\\foo.h";
  CanonicalizePath(&path);
  EXPECT_EQ("foo.h", path);

  path = ".\\foo\\.\\bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("foo/bar.h", path);

  path = ".\\x\\foo\\..\\bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("x/bar.h", path);

  path = ".\\x\\foo\\..\\..\\bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("bar.h", path);

  path = "foo\\\\bar";
  CanonicalizePath(&path);
  EXPECT_EQ("foo/bar", path);

  path = "foo\\\\.\\\\..\\\\\\bar";
  CanonicalizePath(&path);
  EXPECT_EQ("bar", path);

  path = ".\\x\\..\\foo\\..\\..\\bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("../bar.h", path);

  path = "foo\\.\\.";
  CanonicalizePath(&path);
  EXPECT_EQ("foo", path);

  path = "foo\\bar\\..";
  CanonicalizePath(&path);
  EXPECT_EQ("foo", path);

  path = "foo\\.hidden_bar";
  CanonicalizePath(&path);
  EXPECT_EQ("foo/.hidden_bar", path);

  path = "\\foo";
  CanonicalizePath(&path);
  EXPECT_EQ("/foo", path);

  // UNC prefix must stay as backslashes for Win32 file APIs (#2800).
  path = "\\\\foo";
  CanonicalizePath(&path);
  EXPECT_EQ("\\\\foo", path);

  path = "\\\\foo\\bar\\baz\\patchlevel.h";
  CanonicalizePath(&path);
  EXPECT_EQ("\\\\foo/bar/baz/patchlevel.h", path);

  path = "\\";
  CanonicalizePath(&path);
  EXPECT_EQ("/", path);
}

TEST(CanonicalizePath, SlashTracking) {
  string path;
  uint64_t slash_bits;

  path = "foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("foo.h", path);
  EXPECT_EQ(0, slash_bits);

  path = "a\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/foo.h", path);
  EXPECT_EQ(1, slash_bits);

  path = "a/bcd/efh\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/bcd/efh/foo.h", path);
  EXPECT_EQ(4, slash_bits);

  path = "a\\bcd/efh\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/bcd/efh/foo.h", path);
  EXPECT_EQ(5, slash_bits);

  path = "a\\bcd\\efh\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/bcd/efh/foo.h", path);
  EXPECT_EQ(7, slash_bits);

  path = "a/bcd/efh/foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/bcd/efh/foo.h", path);
  EXPECT_EQ(0, slash_bits);

  path = "a\\./efh\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/efh/foo.h", path);
  EXPECT_EQ(3, slash_bits);

  path = "a\\../efh\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("efh/foo.h", path);
  EXPECT_EQ(1, slash_bits);

  path = "a\\b\\c\\d\\e\\f\\g\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/b/c/d/e/f/g/foo.h", path);
  EXPECT_EQ(127, slash_bits);

  path = "a\\b\\c\\..\\..\\..\\g\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("g/foo.h", path);
  EXPECT_EQ(1, slash_bits);

  path = "a\\b/c\\../../..\\g\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("g/foo.h", path);
  EXPECT_EQ(1, slash_bits);

  path = "a\\b/c\\./../..\\g\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/g/foo.h", path);
  EXPECT_EQ(3, slash_bits);

  path = "a\\b/c\\./../..\\g/foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/g/foo.h", path);
  EXPECT_EQ(1, slash_bits);

  path = "a\\\\\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/foo.h", path);
  EXPECT_EQ(1, slash_bits);

  path = "a/\\\\foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/foo.h", path);
  EXPECT_EQ(0, slash_bits);

  path = "a\\//foo.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ("a/foo.h", path);
  EXPECT_EQ(1, slash_bits);
}

TEST(CanonicalizePath, CanonicalizeNotExceedingLen) {
  // Make sure searching \/ doesn't go past supplied len.
  char buf[] = "foo/bar\\baz.h\\";  // Last \ past end.
  uint64_t slash_bits;
  size_t size = 13;
  ::CanonicalizePath(buf, &size, &slash_bits);
  EXPECT_EQ(0, strncmp("foo/bar/baz.h", buf, size));
  EXPECT_EQ(2, slash_bits);  // Not including the trailing one.
}

TEST(CanonicalizePath, TooManyComponents) {
  string path;
  uint64_t slash_bits;

  // 64 is OK.
  path = "a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./"
         "a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./x.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, 0x0);

  // Backslashes version.
  path =
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\"
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\"
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\"
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\x.h";

  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, 0xffffffff);

  // 65 is OK if #component is less than 60 after path canonicalization.
  path = "a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./"
         "a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./a/./x/y.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, 0x0);

  // Backslashes version.
  path =
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\"
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\"
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\"
      "a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\a\\.\\x\\y.h";
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, uint64_t(0x1ffffffff));


  // 59 after canonicalization is OK.
  path = "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
         "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/x/y.h";
  EXPECT_EQ(58, std::count(path.begin(), path.end(), '/'));
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, 0x0);

  // Backslashes version.
  path =
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\x\\y.h";
  EXPECT_EQ(58, std::count(path.begin(), path.end(), '\\'));
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, uint64_t(0x3ffffffffffffff));

  // More than 60 components is now completely ok too.
  path =
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\"
      "a\\a\\a\\a\\a\\a\\a\\a\\a\\x\\y.h";
  EXPECT_EQ(218, std::count(path.begin(), path.end(), '\\'));
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, 0xffffffffffffffff);
}
#else   // !_WIN32
TEST(CanonicalizePath, TooManyComponents) {
  string path;
  uint64_t slash_bits;

  // More than 60 components is now completely ok.
  path =
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/"
      "a/a/a/a/a/a/a/a/a/x/y.h";
  EXPECT_EQ(218, std::count(path.begin(), path.end(), '/'));
  CanonicalizePath(&path, &slash_bits);
  EXPECT_EQ(slash_bits, 0x0);
}
#endif  // !_WIN32

TEST(CanonicalizePath, UpDir) {
  string path, err;
  path = "../../foo/bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("../../foo/bar.h", path);

  path = "test/../../foo/bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("../foo/bar.h", path);
}

TEST(CanonicalizePath, AbsolutePath) {
  string path = "/usr/include/stdio.h";
  string err;
  CanonicalizePath(&path);
  EXPECT_EQ("/usr/include/stdio.h", path);
}

TEST(CanonicalizePath, NotNullTerminated) {
  string path;
  size_t len;
  uint64_t unused;

  path = "foo/. bar/.";
  len = strlen("foo/.");  // Canonicalize only the part before the space.
  CanonicalizePath(&path[0], &len, &unused);
  EXPECT_EQ(strlen("foo"), len);
  EXPECT_EQ("foo/. bar/.", string(path));

  // Verify that foo/..file gets canonicalized to 'file' without
  // touching the rest of the string.
  path = "foo/../file bar/.";
  len = strlen("foo/../file");
  CanonicalizePath(&path[0], &len, &unused);
  EXPECT_EQ(strlen("file"), len);
  EXPECT_EQ("file../file bar/.", string(path));
}

TEST(PathEscaping, TortureTest) {
  string result;

  GetWin32EscapedString("foo bar\\\"'$@d!st!c'\\path'\\", &result);
  EXPECT_EQ("\"foo bar\\\\\\\"'$@d!st!c'\\path'\\\\\"", result);
  result.clear();

  GetShellEscapedString("foo bar\"/'$@d!st!c'/path'", &result);
  EXPECT_EQ("'foo bar\"/'\\''$@d!st!c'\\''/path'\\'''", result);
}

TEST(PathEscaping, SensiblePathsAreNotNeedlesslyEscaped) {
  const char* path = "some/sensible/path/without/crazy/characters.c++";
  string result;

  GetWin32EscapedString(path, &result);
  EXPECT_EQ(path, result);
  result.clear();

  GetShellEscapedString(path, &result);
  EXPECT_EQ(path, result);
}

TEST(PathEscaping, SensibleWin32PathsAreNotNeedlesslyEscaped) {
  const char* path = "some\\sensible\\path\\without\\crazy\\characters.c++";
  string result;

  GetWin32EscapedString(path, &result);
  EXPECT_EQ(path, result);
}

namespace {

// The original implementations of GetShellEscapedString and
// GetWin32EscapedString to compare with.

void ReferenceShellEscape(std::string_view input, string* result) {
  assert(result);

  if (!StringNeedsShellEscapingFallback(input)) {
    result->append(input);
    return;
  }

  const char kQuote = '\'';
  const char kEscapeSequence[] = "'\\'";

  result->push_back(kQuote);

  std::string_view::const_iterator span_begin = input.begin();
  for (std::string_view::const_iterator it = input.begin(), end = input.end();
       it != end; ++it) {
    if (*it == kQuote) {
      result->append(span_begin, it);
      result->append(kEscapeSequence);
      span_begin = it;
    }
  }
  result->append(span_begin, input.end());
  result->push_back(kQuote);
}

void ReferenceWin32Escape(std::string_view input, string* result) {
  assert(result);
  if (!StringNeedsWin32EscapingFallback(input)) {
    result->append(input);
    return;
  }

  const char kQuote = '"';
  const char kBackslash = '\\';

  result->push_back(kQuote);
  size_t consecutive_backslash_count = 0;
  std::string_view::const_iterator span_begin = input.begin();
  for (std::string_view::const_iterator it = input.begin(), end = input.end();
       it != end; ++it) {
    switch (*it) {
      case kBackslash:
        ++consecutive_backslash_count;
        break;
      case kQuote:
        result->append(span_begin, it);
        result->append(consecutive_backslash_count + 1, kBackslash);
        span_begin = it;
        consecutive_backslash_count = 0;
        break;
      default:
        consecutive_backslash_count = 0;
        break;
    }
  }
  result->append(span_begin, input.end());
  result->append(consecutive_backslash_count, kBackslash);
  result->push_back(kQuote);
}

void ExpectEscapesLikeReference(std::string_view input) {
  string expected;
  string actual;
  ReferenceShellEscape(input, &expected);
  GetShellEscapedString(input, &actual);
  EXPECT_EQ(expected, actual);

  expected.clear();
  actual.clear();
  ReferenceWin32Escape(input, &expected);
  GetWin32EscapedString(input, &actual);
  EXPECT_EQ(expected, actual);
}

}  // namespace

TEST(PathEscaping, EveryByteAtEveryPosition) {
  // Each byte value at every position of strings around a word in length.
  for (int c = 0; c < 256; ++c) {
    for (std::size_t len = 1; len <= 17; ++len) {
      for (std::size_t pos = 0; pos < len; ++pos) {
        std::string input(len, 'a');
        input[pos] = static_cast<char>(c);
        ExpectEscapesLikeReference(input);
        if (HasFailure())
          return;
      }
    }
  }
}

TEST(PathEscaping, Random) {
  std::mt19937 rng(42);
  const char kCommon[] = "aZ09_+-./\\ \"',:$";
  for (int i = 0; i < 20000; ++i) {
    std::string input(rng() % 40, 'x');
    for (char& c : input) {
      // Mostly common path characters, with any byte sometimes.
      c = rng() % 8 ? kCommon[rng() % (sizeof(kCommon) - 1)]
                    : static_cast<char>(rng() % 256);
    }
    ExpectEscapesLikeReference(input);
    if (HasFailure())
      return;
  }
}

TEST(StripAnsiEscapeCodes, EscapeAtEnd) {
  string stripped = StripAnsiEscapeCodes("foo\33");
  EXPECT_EQ("foo", stripped);

  stripped = StripAnsiEscapeCodes("foo\33[");
  EXPECT_EQ("foo", stripped);
}

TEST(StripAnsiEscapeCodes, StripColors) {
  // An actual clang warning.
  string input = "\33[1maffixmgr.cxx:286:15: \33[0m\33[0;1;35mwarning: "
                 "\33[0m\33[1musing the result... [-Wparentheses]\33[0m";
  string stripped = StripAnsiEscapeCodes(input);
  EXPECT_EQ("affixmgr.cxx:286:15: warning: using the result... [-Wparentheses]",
            stripped);
}
