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

  path = "\\\\foo";
  CanonicalizePath(&path);
  EXPECT_EQ("//foo", path);

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
  EXPECT_EQ(slash_bits, 0x1ffffffff);


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
  EXPECT_EQ(slash_bits, 0x3ffffffffffffff);

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

#ifdef _WIN32
TEST(UTF8ToWin32Unicode, UTF8ToWin32Unicode) {
  static const struct {
    const char* input;
    const wchar_t* expected;
  } kData[] = {
    { "foo", L"foo" },
    { "foo/bar", L"foo/bar" },
    { "\x62\xc3\xa9\x62\xc3\xa9", L"\u0062\u00e9\u0062\u00e9" },  // bébé
  };
  for (const auto& data : kData) {
    std::string input = data.input;
    std::wstring expected = data.expected;
    EXPECT_EQ(expected, UTF8ToWin32Unicode(input)) << input;
  }
}

TEST(Win32UnicodeToUTF8, Win32UnicodeToUTF8) {
  static const struct {
    const wchar_t* input;
    const char* expected;
  } kData[] = {
    { L"foo", "foo" },
    { L"foo/bar", "foo/bar" },
    { L"\u0062\u00e9\u0062\u00e9", "\x62\xc3\xa9\x62\xc3\xa9" },  // bébé
  };
  for (const auto& data : kData) {
    std::wstring input = data.input;
    std::string expected = data.expected;
    EXPECT_EQ(expected, Win32UnicodeToUTF8(input)) << input;
  }
}
#endif  // _WIN32
