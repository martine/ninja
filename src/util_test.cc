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

#ifdef NINJA_WINDOWS_STYLE_PATHS
  path = ".\\foo.h";
  CanonicalizePath(&path);
  EXPECT_EQ("foo.h", path);
#endif

  path = "../";
  CanonicalizePath(&path);
  EXPECT_EQ("..", path);

  path = "../..";
  CanonicalizePath(&path);
  EXPECT_EQ("../..", path);

  path = "a/foo/../bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("a/bar.h", path);

  path = "./x/../bar.h";
  CanonicalizePath(&path);
  EXPECT_EQ("bar.h", path);

  path = "";
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

  path = "aa/b/c/.";
  CanonicalizePath(&path);
  EXPECT_EQ("aa/b/c", path);

  path = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/b/c/.";
  CanonicalizePath(&path);
  EXPECT_EQ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/b/c",
            path);

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
#ifdef NINJA_WINDOWS_STYLE_PATHS
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

  path = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/x/y/z/../../../c.h";
  CanonicalizePath(&path);
  EXPECT_EQ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/c.h", path);
}

#ifdef NINJA_WINDOWS_STYLE_PATHS
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
#else   // !NINJA_WINDOWS_STYLE_PATHS
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
#endif  // !NINJA_WINDOWS_STYLE_PATHS

// Compare CanonicalizePath() against CanonicalizePathFallback() on random
// paths, at lengths around the 8-byte word boundaries of the fast check.
// '\\' is an ordinary byte on POSIX, but stays in the alphabet there to check
// that no Windows backslash handling leaks in.
TEST(CanonicalizePath, DifferentialAgainstReference) {
  // '?' stands for any byte at all, so we also check that no byte (e.g. one
  // with the high bit set) is mistaken for a separator or dot.
  const char alphabet[] = { 'a', 'b', '/', '.', '\\', '?' };
  // Default seeded, so every run and every platform generates the same paths.
  std::mt19937_64 rng;
  const int lengths[] = { 1,   2,   3,   8,   31,  55,  60,  61,  62,  63,
                          64,  65,  66,  67,  70,  80,  100, 126, 127, 128,
                          129, 130, 190, 191, 192, 193, 200, 255, 256, 257 };
  for (std::size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); ++li) {
    const int len = lengths[li];
    for (int iter = 0; iter < 2000; ++iter) {
      std::string in;
      in.reserve(len);
      for (int k = 0; k < len; ++k) {
        const char c = alphabet[rng() % sizeof(alphabet)];
        in += c == '?' ? static_cast<char>(rng() % 256) : c;
      }
      std::string ref = in, swar = in;
      std::uint64_t ref_bits = 0, swar_bits = 0;
      CanonicalizePathFallback(&ref, &ref_bits);
      CanonicalizePath(&swar, &swar_bits);
      ASSERT_EQ(ref, swar) << "input=[" << in << "]";
      ASSERT_EQ(ref_bits, swar_bits)
          << "input=[" << in << "] out=[" << ref << "]";
    }
  }
}

// Directory names longer than a word, cancelled by later ".." components,
// with the ".." at every alignment within the 8-byte words of the fast check.
TEST(CanonicalizePath, BoundarySpanningParent) {
  std::string path, expected;
  std::uint64_t slash_bits;

  for (int i = 1; i < 140; ++i) {
    path.assign(i, 'a');
    expected = path + "/c";
    path += "/bbbbbbbbbbbbbbbbbbbb/../c";
    CanonicalizePath(&path, &slash_bits);
    EXPECT_EQ(expected, path) << "i=" << i;
    EXPECT_EQ(0u, slash_bits);
  }

  for (int i = 1; i < 140; ++i) {
    // A ".." cascade that pops components several words earlier.
    path.assign(i, 'a');
    expected = path;
    path += "/bbbbbbbbbb/cccccccccc/dddddddddd/../../..";
    CanonicalizePath(&path, &slash_bits);
    EXPECT_EQ(expected, path) << "i=" << i;
    EXPECT_EQ(0u, slash_bits);
  }
}

// A ".." that empties the output, at every alignment, followed by a further
// "dir/.." that must still be resolved.
TEST(CanonicalizePath, PopToEmptyAtBoundary) {
  std::string path;
  std::uint64_t slash_bits;
  for (int i = 1; i < 140; ++i) {
    path.assign(i, 'a');
    path += "/../x/../y";
    CanonicalizePath(&path, &slash_bits);
    EXPECT_EQ("y", path) << "i=" << i;
    EXPECT_EQ(0u, slash_bits);
  }
}

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
