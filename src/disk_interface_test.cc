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

#include <assert.h>
#include <stdio.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#include <direct.h>
#endif

#include "disk_interface.h"
#include "graph.h"
#include "test.h"

using namespace std;

namespace {

struct DiskInterfaceTest : public testing::Test {
  virtual void SetUp() {
    // These tests do real disk accesses, so create a temp dir.
    temp_dir_.CreateAndEnter("Ninja-DiskInterfaceTest");
  }

  virtual void TearDown() {
    temp_dir_.Cleanup();
  }

  bool Touch(const char* path) {
    FILE *f = fopen(path, "w");
    if (!f)
      return false;
    return fclose(f) == 0;
  }

  ScopedTempDir temp_dir_;
  RealDiskInterface disk_;
};

TEST_F(DiskInterfaceTest, StatMissingFile) {
  string err;
  EXPECT_EQ(0, disk_.Stat("nosuchfile", &err));
  EXPECT_EQ("", err);

  // On Windows, the errno for a file in a nonexistent directory
  // is different.
  EXPECT_EQ(0, disk_.Stat("nosuchdir/nosuchfile", &err));
  EXPECT_EQ("", err);

  // On POSIX systems, the errno is different if a component of the
  // path prefix is not a directory.
  ASSERT_TRUE(Touch("notadir"));
  EXPECT_EQ(0, disk_.Stat("notadir/nosuchfile", &err));
  EXPECT_EQ("", err);
}

TEST_F(DiskInterfaceTest, StatMissingFileWithCache) {
  disk_.AllowStatCache(true);
  string err;

  // On Windows, the errno for FindFirstFileExA, which is used when the stat
  // cache is enabled, is different when the directory name is not a directory.
  ASSERT_TRUE(Touch("notadir"));
  EXPECT_EQ(0, disk_.Stat("notadir/nosuchfile", &err));
  EXPECT_EQ("", err);
}

TEST_F(DiskInterfaceTest, StatBadPath) {
  string err;
#ifdef _WIN32
  string bad_path("cc:\\foo");
  EXPECT_EQ(-1, disk_.Stat(bad_path, &err));
  EXPECT_NE("", err);
#else
  string too_long_name(512, 'x');
  EXPECT_EQ(-1, disk_.Stat(too_long_name, &err));
  EXPECT_NE("", err);
#endif
}

TEST_F(DiskInterfaceTest, StatExistingFile) {
  string err;
  ASSERT_TRUE(Touch("file"));
  EXPECT_GT(disk_.Stat("file", &err), 1);
  EXPECT_EQ("", err);
}

#ifdef _WIN32
TEST_F(DiskInterfaceTest, StatExistingFileWithLongPath) {
  string err;
  char currentdir[32767];
  _getcwd(currentdir, sizeof(currentdir));
  const string filename = string(currentdir) +
"\\filename_with_256_characters_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\
xxxxxxxxxxxxxxxxxxxxx";
  const string prefixed = "\\\\?\\" + filename;
  ASSERT_TRUE(Touch(prefixed.c_str()));
  EXPECT_GT(disk_.Stat(disk_.AreLongPathsEnabled() ?
    filename : prefixed, &err), 1);
  EXPECT_EQ("", err);
}
#endif

TEST_F(DiskInterfaceTest, StatExistingDir) {
  string err;
  ASSERT_TRUE(disk_.MakeDir("subdir"));
  ASSERT_TRUE(disk_.MakeDir("subdir/subsubdir"));
  EXPECT_GT(disk_.Stat("..", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat(".", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat("subdir", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat("subdir/subsubdir", &err), 1);
  EXPECT_EQ("", err);

  EXPECT_EQ(disk_.Stat("subdir", &err),
            disk_.Stat("subdir/.", &err));
  EXPECT_EQ(disk_.Stat("subdir", &err),
            disk_.Stat("subdir/subsubdir/..", &err));
  EXPECT_EQ(disk_.Stat("subdir/subsubdir", &err),
            disk_.Stat("subdir/subsubdir/.", &err));
}

#ifdef _WIN32
TEST_F(DiskInterfaceTest, StatCache) {
  string err;

  ASSERT_TRUE(Touch("file1"));
  ASSERT_TRUE(Touch("fiLE2"));
  ASSERT_TRUE(disk_.MakeDir("subdir"));
  ASSERT_TRUE(disk_.MakeDir("subdir/subsubdir"));
  ASSERT_TRUE(Touch("subdir\\subfile1"));
  ASSERT_TRUE(Touch("subdir\\SUBFILE2"));
  ASSERT_TRUE(Touch("subdir\\SUBFILE3"));

  disk_.AllowStatCache(false);
  TimeStamp parent_stat_uncached = disk_.Stat("..", &err);
  disk_.AllowStatCache(true);

  EXPECT_GT(disk_.Stat("FIle1", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat("file1", &err), 1);
  EXPECT_EQ("", err);

  EXPECT_GT(disk_.Stat("subdir/subfile2", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat("sUbdir\\suBFile1", &err), 1);
  EXPECT_EQ("", err);

  EXPECT_GT(disk_.Stat("..", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat(".", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat("subdir", &err), 1);
  EXPECT_EQ("", err);
  EXPECT_GT(disk_.Stat("subdir/subsubdir", &err), 1);
  EXPECT_EQ("", err);

#ifndef _WIN32  // TODO: Investigate why. Also see
                // https://github.com/ninja-build/ninja/pull/1423
  EXPECT_EQ(disk_.Stat("subdir", &err),
            disk_.Stat("subdir/.", &err));
  EXPECT_EQ("", err);
  EXPECT_EQ(disk_.Stat("subdir", &err),
            disk_.Stat("subdir/subsubdir/..", &err));
#endif
  EXPECT_EQ("", err);
  EXPECT_EQ(disk_.Stat("..", &err), parent_stat_uncached);
  EXPECT_EQ("", err);
  EXPECT_EQ(disk_.Stat("subdir/subsubdir", &err),
            disk_.Stat("subdir/subsubdir/.", &err));
  EXPECT_EQ("", err);

  // Test error cases.
  string bad_path("cc:\\foo");
  EXPECT_EQ(-1, disk_.Stat(bad_path, &err));
  EXPECT_NE("", err); err.clear();
  EXPECT_EQ(-1, disk_.Stat(bad_path, &err));
  EXPECT_NE("", err); err.clear();
  EXPECT_EQ(0, disk_.Stat("nosuchfile", &err));
  EXPECT_EQ("", err);
  EXPECT_EQ(0, disk_.Stat("nosuchdir/nosuchfile", &err));
  EXPECT_EQ("", err);
}
#endif

TEST_F(DiskInterfaceTest, ReadFile) {
  string err;
  std::string content;
  ASSERT_EQ(DiskInterface::NotFound,
            disk_.ReadFile("foobar", &content, &err));
  EXPECT_EQ("", content);
  EXPECT_NE("", err); // actual value is platform-specific
  err.clear();

  const char* kTestFile = "testfile";
  FILE* f = fopen(kTestFile, "wb");
  ASSERT_TRUE(f);
  const char* kTestContent = "test content\nok";
  fprintf(f, "%s", kTestContent);
  ASSERT_EQ(0, fclose(f));

  ASSERT_EQ(DiskInterface::Okay,
            disk_.ReadFile(kTestFile, &content, &err));
  EXPECT_EQ(kTestContent, content);
  EXPECT_EQ("", err);
}

TEST_F(DiskInterfaceTest, MakeDirs) {
  string path = "path/with/double//slash/";
  EXPECT_TRUE(disk_.MakeDirs(path));
  FILE* f = fopen((path + "a_file").c_str(), "w");
  EXPECT_TRUE(f);
  EXPECT_EQ(0, fclose(f));
#ifdef _WIN32
  string path2 = "another\\with\\back\\\\slashes\\";
  EXPECT_TRUE(disk_.MakeDirs(path2));
  FILE* f2 = fopen((path2 + "a_file").c_str(), "w");
  EXPECT_TRUE(f2);
  EXPECT_EQ(0, fclose(f2));
#endif
}

TEST_F(DiskInterfaceTest, RemoveFile) {
  const char* kFileName = "file-to-remove";
  ASSERT_TRUE(Touch(kFileName));
  EXPECT_EQ(0, disk_.RemoveFile(kFileName));
  EXPECT_EQ(1, disk_.RemoveFile(kFileName));
  EXPECT_EQ(1, disk_.RemoveFile("does not exist"));
#ifdef _WIN32
  ASSERT_TRUE(Touch(kFileName));
  EXPECT_EQ(0, system((std::string("attrib +R ") + kFileName).c_str()));
  EXPECT_EQ(0, disk_.RemoveFile(kFileName));
  EXPECT_EQ(1, disk_.RemoveFile(kFileName));
#endif
}

TEST_F(DiskInterfaceTest, RemoveDirectory) {
  const char* kDirectoryName = "directory-to-remove";
  EXPECT_TRUE(disk_.MakeDir(kDirectoryName));
  EXPECT_EQ(0, disk_.RemoveFile(kDirectoryName));
  EXPECT_EQ(1, disk_.RemoveFile(kDirectoryName));
  EXPECT_EQ(1, disk_.RemoveFile("does not exist"));
}

TEST_F(DiskInterfaceTest, OpenFile) {
  // Scoped FILE pointer, ensure instance is closed
  // when test exits, even in case of failure.
  struct ScopedFILE {
    ScopedFILE(FILE* f) : f_(f) {}
    ~ScopedFILE() { Close(); }

    void Close() {
      if (f_) {
        fclose(f_);
        f_ = nullptr;
      }
    }

    FILE* get() const { return f_; }

    explicit operator bool() const { return !!f_; }

    FILE* f_;
  };

  const char kFileName[] = "file-to-open";
  std::string kContent = "something to write to a file\n";

  // disk_.WriteFile() opens the FILE instance in binary mode, which
  // will not convert the final \n into \r\n on Windows. However,
  // disk_.OpenFile() can write in text mode which will do the
  // translation on this platform.
  ASSERT_TRUE(disk_.WriteFile(kFileName, kContent));
  std::string kExpected = "something to write to a file\n";
#ifdef _WIN32
  std::string kExpectedText = "something to write to a file\r\n";
#else
  std::string kExpectedText = "something to write to a file\n";
#endif

  std::string contents;
  std::string err;
  ASSERT_EQ(FileReader::Okay, disk_.ReadFile(kFileName, &contents, &err))
      << err;
  ASSERT_EQ(contents, kExpected);

  // Read a file.
  {
    ScopedFILE f(disk_.OpenFile(kFileName, "rb"));
    ASSERT_TRUE(f);
    ASSERT_EQ(fseek(f.get(), 0, SEEK_END), 0) << strerror(errno);
    long file_size_long = ftell(f.get());
    ASSERT_GE(file_size_long, 0) << strerror(errno);

    size_t file_size = static_cast<size_t>(file_size_long);
    ASSERT_EQ(file_size, kExpected.size());
    ASSERT_EQ(fseek(f.get(), 0, SEEK_SET), 0) << strerror(errno);

    contents.clear();
    contents.resize(file_size);
    ASSERT_EQ(fread(const_cast<char*>(contents.data()), file_size, 1, f.get()),
              1)
        << strerror(errno);
    ASSERT_EQ(contents, kExpected);
  }

  // Write a file opened file disk_.OpenFile() in binary mode, then verify its
  // content.
  const char kFileToWrite[] = "file-to-write";
  {
    ScopedFILE f(disk_.OpenFile(kFileToWrite, "wb"));
    ASSERT_TRUE(f) << strerror(errno);
    ASSERT_EQ(fwrite(kContent.data(), kContent.size(), 1, f.get()), 1);
  }

  contents.clear();
  ASSERT_EQ(FileReader::Okay, disk_.ReadFile(kFileToWrite, &contents, &err))
      << err;
  ASSERT_EQ(contents, kContent);

  // Write a file opened file disk_.OpenFile() in text mode, then verify its
  // content.
  {
    ScopedFILE f(disk_.OpenFile(kFileToWrite, "wt"));
    ASSERT_TRUE(f) << strerror(errno);
    ASSERT_EQ(fwrite(kContent.data(), kContent.size(), 1, f.get()), 1);
  }

  contents.clear();
  ASSERT_EQ(FileReader::Okay, disk_.ReadFile(kFileToWrite, &contents, &err))
      << err;
  ASSERT_EQ(contents, kExpectedText);

  // Append to the same file, in text mode too.
  {
    ScopedFILE f(disk_.OpenFile(kFileToWrite, "at"));
    ASSERT_TRUE(f) << strerror(errno);
    ASSERT_EQ(fwrite(kContent.data(), kContent.size(), 1, f.get()), 1);
  }
  std::string expected = kExpectedText + kExpectedText;
  contents.clear();
  ASSERT_EQ(FileReader::Okay, disk_.ReadFile(kFileToWrite, &contents, &err))
      << err;
  ASSERT_EQ(contents, expected);
}

TEST_F(DiskInterfaceTest, RenameFile) {
  // Rename a simple file.
  std::string kFileA = "a-file";
  std::string kFileB = "b-file";

  // NOTE: Do not put a newline in this string to avoid dealing
  // with \r\n conversions on Win32.
  std::string kContent = "something something";

  ASSERT_TRUE(disk_.WriteFile(kFileA, kContent));
  std::string err;
  TimeStamp stamp_a = disk_.Stat(kFileA, &err);
  ASSERT_GT(stamp_a, 0);

  ASSERT_TRUE(disk_.RenameFile(kFileA, kFileB));
  EXPECT_EQ(0, disk_.Stat(kFileA, &err));
  EXPECT_EQ(err, "");

  TimeStamp stamp_b = disk_.Stat(kFileB, &err);
  ASSERT_GT(stamp_b, 0) << err;

  // Due to limited granularity on certain filesystems, use >= instead of >
  // in the comparison below.
  ASSERT_GE(stamp_b, stamp_a);

  std::string contents;
  ASSERT_EQ(disk_.ReadFile(kFileB, &contents, &err), FileReader::Okay) << err;
  ASSERT_EQ(contents, kContent);

  // Now write something else to the first file, and rename
  // the second one to the first. This should work on Posix, and
  // fail with EEXIST on Win32!
  ASSERT_TRUE(disk_.WriteFile(kFileA, "something else entirely"));
  stamp_a = disk_.Stat(kFileA, &err);
  ASSERT_GT(stamp_a, 0) << err;
  ASSERT_GE(stamp_a, stamp_b) << err;  // see comment above.

#ifdef _WIN32
  ASSERT_FALSE(disk_.RenameFile(kFileB, kFileA));
  EXPECT_EQ(errno, EEXIST);
#else   // !_WIN32
  ASSERT_TRUE(disk_.RenameFile(kFileB, kFileA)) << strerror(errno);
  EXPECT_EQ(0, disk_.Stat(kFileB, &err)) << err;

  contents.clear();
  ASSERT_EQ(disk_.ReadFile(kFileA, &contents, &err), FileReader::Okay) << err;
  ASSERT_EQ(contents, kContent);
#endif  // !_WIN32
}

struct StatTest : public StateTestWithBuiltinRules, public NullDiskInterface {
  StatTest() : scan_(&state_, NULL, NULL, this, NULL, NULL) {}

  // DiskInterface implementation.
  TimeStamp Stat(const string& path, string* err) const override;

  DependencyScan scan_;
  map<string, TimeStamp> mtimes_;
  mutable vector<string> stats_;
};

TimeStamp StatTest::Stat(const string& path, string* err) const {
  stats_.push_back(path);
  map<string, TimeStamp>::const_iterator i = mtimes_.find(path);
  if (i == mtimes_.end())
    return 0;  // File not found.
  return i->second;
}

TEST_F(StatTest, Simple) {
  ASSERT_NO_FATAL_FAILURE(AssertParse(&state_,
"build out: cat in\n"));

  Node* out = GetNode("out");
  string err;
  EXPECT_TRUE(out->Stat(this, &err));
  EXPECT_EQ("", err);
  ASSERT_EQ(1u, stats_.size());
  scan_.RecomputeDirty(out, NULL, NULL);
  ASSERT_EQ(2u, stats_.size());
  ASSERT_EQ("out", stats_[0]);
  ASSERT_EQ("in",  stats_[1]);
}

TEST_F(StatTest, TwoStep) {
  ASSERT_NO_FATAL_FAILURE(AssertParse(&state_,
"build out: cat mid\n"
"build mid: cat in\n"));

  Node* out = GetNode("out");
  string err;
  EXPECT_TRUE(out->Stat(this, &err));
  EXPECT_EQ("", err);
  ASSERT_EQ(1u, stats_.size());
  scan_.RecomputeDirty(out, NULL, NULL);
  ASSERT_EQ(3u, stats_.size());
  ASSERT_EQ("out", stats_[0]);
  ASSERT_TRUE(GetNode("out")->dirty());
  ASSERT_EQ("mid",  stats_[1]);
  ASSERT_TRUE(GetNode("mid")->dirty());
  ASSERT_EQ("in",  stats_[2]);
}

TEST_F(StatTest, Tree) {
  ASSERT_NO_FATAL_FAILURE(AssertParse(&state_,
"build out: cat mid1 mid2\n"
"build mid1: cat in11 in12\n"
"build mid2: cat in21 in22\n"));

  Node* out = GetNode("out");
  string err;
  EXPECT_TRUE(out->Stat(this, &err));
  EXPECT_EQ("", err);
  ASSERT_EQ(1u, stats_.size());
  scan_.RecomputeDirty(out, NULL, NULL);
  ASSERT_EQ(1u + 6u, stats_.size());
  ASSERT_EQ("mid1", stats_[1]);
  ASSERT_TRUE(GetNode("mid1")->dirty());
  ASSERT_EQ("in11", stats_[2]);
}

TEST_F(StatTest, Middle) {
  ASSERT_NO_FATAL_FAILURE(AssertParse(&state_,
"build out: cat mid\n"
"build mid: cat in\n"));

  mtimes_["in"] = 1;
  mtimes_["mid"] = 0;  // missing
  mtimes_["out"] = 1;

  Node* out = GetNode("out");
  string err;
  EXPECT_TRUE(out->Stat(this, &err));
  EXPECT_EQ("", err);
  ASSERT_EQ(1u, stats_.size());
  scan_.RecomputeDirty(out, NULL, NULL);
  ASSERT_FALSE(GetNode("in")->dirty());
  ASSERT_TRUE(GetNode("mid")->dirty());
  ASSERT_TRUE(GetNode("out")->dirty());
}

}  // namespace
