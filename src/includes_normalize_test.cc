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

#include "includes_normalize.h"

#include <algorithm>

#include <direct.h>

#include "string_piece_util.h"
#include "test.h"
#include "util.h"

using namespace std;

namespace {

string GetCurDir() {
  char buf[_MAX_PATH];
  _getcwd(buf, sizeof(buf));
  vector<StringPiece> parts = SplitStringPiece(buf, '\\');
  return parts[parts.size() - 1].AsString();
}

string NormalizeAndCheckNoError(const string& input) {
  string result, err;
  IncludesNormalize normalizer(".");
  EXPECT_TRUE(normalizer.Normalize(input, &result, &err));
  EXPECT_EQ("", err);
  return result;
}

string NormalizeRelativeAndCheckNoError(const string& input,
                                        const string& relative_to) {
  string result, err;
  IncludesNormalize normalizer(relative_to);
  EXPECT_TRUE(normalizer.Normalize(input, &result, &err));
  EXPECT_EQ("", err);
  return result;
}

}  // namespace

TEST(IncludesNormalize, Simple) {
  EXPECT_EQ("b", NormalizeAndCheckNoError("a\\..\\b"));
  EXPECT_EQ("b", NormalizeAndCheckNoError("a\\../b"));
  EXPECT_EQ("a/b", NormalizeAndCheckNoError("a\\.\\b"));
  EXPECT_EQ("a/b", NormalizeAndCheckNoError("a\\./b"));
}

TEST(IncludesNormalize, WithRelative) {
  string err;
  string currentdir = GetCurDir();
  EXPECT_EQ("c", NormalizeRelativeAndCheckNoError("a/b/c", "a/b"));
  EXPECT_EQ("a",
            NormalizeAndCheckNoError(IncludesNormalize::AbsPath("a", &err)));
  EXPECT_EQ("", err);
  EXPECT_EQ(string("../") + currentdir + string("/a"),
            NormalizeRelativeAndCheckNoError("a", "../b"));
  EXPECT_EQ(string("../") + currentdir + string("/a/b"),
            NormalizeRelativeAndCheckNoError("a/b", "../c"));
  EXPECT_EQ("../../a", NormalizeRelativeAndCheckNoError("a", "b/c"));
  EXPECT_EQ(".", NormalizeRelativeAndCheckNoError("a", "a"));
}

TEST(IncludesNormalize, Case) {
  EXPECT_EQ("b", NormalizeAndCheckNoError("Abc\\..\\b"));
  EXPECT_EQ("BdEf", NormalizeAndCheckNoError("Abc\\..\\BdEf"));
  EXPECT_EQ("A/b", NormalizeAndCheckNoError("A\\.\\b"));
  EXPECT_EQ("a/b", NormalizeAndCheckNoError("a\\./b"));
  EXPECT_EQ("A/B", NormalizeAndCheckNoError("A\\.\\B"));
  EXPECT_EQ("A/B", NormalizeAndCheckNoError("A\\./B"));
}

TEST(IncludesNormalize, DifferentDrive) {
  EXPECT_EQ("stuff.h",
            NormalizeRelativeAndCheckNoError("p:\\vs08\\stuff.h", "p:\\vs08"));
  EXPECT_EQ("stuff.h",
            NormalizeRelativeAndCheckNoError("P:\\Vs08\\stuff.h", "p:\\vs08"));
  EXPECT_EQ("p:/vs08/stuff.h",
            NormalizeRelativeAndCheckNoError("p:\\vs08\\stuff.h", "c:\\vs08"));
  EXPECT_EQ("P:/vs08/stufF.h", NormalizeRelativeAndCheckNoError(
                                   "P:\\vs08\\stufF.h", "D:\\stuff/things"));
  EXPECT_EQ("P:/vs08/stuff.h", NormalizeRelativeAndCheckNoError(
                                   "P:/vs08\\stuff.h", "D:\\stuff/things"));
  EXPECT_EQ("P:/wee/stuff.h",
            NormalizeRelativeAndCheckNoError("P:/vs08\\../wee\\stuff.h",
                                             "D:\\stuff/things"));
}

TEST(IncludesNormalize, LongInvalidPath) {
  const char kLongInputString[] =
      "C:\\Program Files (x86)\\Microsoft Visual Studio "
      "12.0\\VC\\INCLUDEwarning #31001: The dll for reading and writing the "
      "pdb (for example, mspdb110.dll) could not be found on your path. This "
      "is usually a configuration error. Compilation will continue using /Z7 "
      "instead of /Zi, but expect a similar error when you link your program.";
  // Too long, won't be canonicalized. Ensure doesn't crash.
  string result, err;
  IncludesNormalize normalizer(".");
  EXPECT_TRUE(normalizer.Normalize(kLongInputString, &result, &err));
  EXPECT_EQ("", err);

  // Construct max size path having cwd prefix.
  // kExactlyMaxPath = "$cwd\\a\\aaaa...aaaa\0";
  char kExactlyMaxPath[_MAX_PATH + 1];
  ASSERT_STRNE(_getcwd(kExactlyMaxPath, sizeof kExactlyMaxPath), NULL);

  int cwd_len = strlen(kExactlyMaxPath);
  ASSERT_LE(cwd_len + 3 + 1, _MAX_PATH);
  kExactlyMaxPath[cwd_len] = '\\';
  kExactlyMaxPath[cwd_len + 1] = 'a';
  kExactlyMaxPath[cwd_len + 2] = '\\';

  kExactlyMaxPath[cwd_len + 3] = 'a';

  for (int i = cwd_len + 4; i < _MAX_PATH; ++i) {
    if (i > cwd_len + 4 && i < _MAX_PATH - 1 && i % 10 == 0)
      kExactlyMaxPath[i] = '\\';
    else
      kExactlyMaxPath[i] = 'a';
  }

  kExactlyMaxPath[_MAX_PATH] = '\0';
  EXPECT_EQ(strlen(kExactlyMaxPath), _MAX_PATH);

  string forward_slashes(kExactlyMaxPath);
  replace(forward_slashes.begin(), forward_slashes.end(), '\\', '/');
  // Make sure a path that's exactly _MAX_PATH long is canonicalized.
  EXPECT_EQ(forward_slashes.substr(cwd_len + 1),
            NormalizeAndCheckNoError(kExactlyMaxPath));
}

TEST(IncludesNormalize, ShortRelativeButTooLongAbsolutePath) {
  string result, err;
  IncludesNormalize normalizer(".");
  // A short path should work
  EXPECT_TRUE(normalizer.Normalize("a", &result, &err));
  EXPECT_EQ("", err);

  // Construct max size path having cwd prefix.
  // kExactlyMaxPath = "aaaa\\aaaa...aaaa\0";
  const size_t kMaxPathSize = _MAX_PATH * 2;
  char kExactlyMaxPath[kMaxPathSize + 1];
  for (int i = 0; i < kMaxPathSize; ++i) {
    if (i < kMaxPathSize - 1 && i % 10 == 4)
      kExactlyMaxPath[i] = '\\';
    else
      kExactlyMaxPath[i] = 'a';
  }
  kExactlyMaxPath[kMaxPathSize] = '\0';
  EXPECT_EQ(strlen(kExactlyMaxPath), kMaxPathSize);

  // Make sure a path that's larger than _MAX_PATH long does not fail.
  EXPECT_TRUE(normalizer.Normalize(kExactlyMaxPath, &result, &err));
  EXPECT_EQ("", err);
}
