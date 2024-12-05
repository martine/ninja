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

#include "build_log.h"

#include "util.h"
#include "test.h"

#include <sys/stat.h>
#ifdef _WIN32
#include <fcntl.h>
#include <share.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif
#include <cassert>

using namespace std;

namespace {

const char kTestFilename[] = "BuildLogTest-tempfile";

struct BuildLogTest : public StateTestWithBuiltinRules, public BuildLogUser {
  virtual void SetUp() {
    // In case a crashing test left a stale file behind.
    disk_interface_.RemoveFile(kTestFilename);
  }
  virtual void TearDown() { disk_interface_.RemoveFile(kTestFilename); }
  virtual bool IsPathDead(StringPiece s) const { return false; }

  BuildLog CreateBuildLog() { return BuildLog(disk_interface_); }

  SystemDiskInterface disk_interface_;
};

TEST_F(BuildLogTest, WriteRead) {
  AssertParse(&state_,
"build out: cat mid\n"
"build mid: cat in\n");

  BuildLog log1(disk_interface_);
  string err;
  EXPECT_TRUE(log1.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  log1.RecordCommand(state_.edges_[0], 15, 18);
  log1.RecordCommand(state_.edges_[1], 20, 25);
  log1.Close();

  BuildLog log2(disk_interface_);
  EXPECT_TRUE(log2.Load(kTestFilename, &err));
  ASSERT_EQ("", err);

  ASSERT_EQ(2u, log1.entries().size());
  ASSERT_EQ(2u, log2.entries().size());
  BuildLog::LogEntry* e1 = log1.LookupByOutput("out");
  ASSERT_TRUE(e1);
  BuildLog::LogEntry* e2 = log2.LookupByOutput("out");
  ASSERT_TRUE(e2);
  ASSERT_TRUE(*e1 == *e2);
  ASSERT_EQ(15, e1->start_time);
  ASSERT_EQ("out", e1->output);
}

TEST_F(BuildLogTest, FirstWriteAddsSignature) {
  const char kExpectedVersion[] = "# ninja log vX\n";
  const size_t kVersionPos = strlen(kExpectedVersion) - 2;  // Points at 'X'.

  BuildLog log(disk_interface_);
  string contents, err;

  EXPECT_TRUE(log.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  log.Close();

  ASSERT_EQ(0, ReadFile(kTestFilename, &contents, &err));
  ASSERT_EQ("", err);
  if (contents.size() >= kVersionPos)
    contents[kVersionPos] = 'X';
  EXPECT_EQ(kExpectedVersion, contents);

  // Opening the file anew shouldn't add a second version string.
  EXPECT_TRUE(log.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  log.Close();

  contents.clear();
  ASSERT_EQ(0, ReadFile(kTestFilename, &contents, &err));
  ASSERT_EQ("", err);
  if (contents.size() >= kVersionPos)
    contents[kVersionPos] = 'X';
  EXPECT_EQ(kExpectedVersion, contents);
}

TEST_F(BuildLogTest, DoubleEntry) {
  FILE* f = disk_interface_.OpenFile(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "0\t1\t2\tout\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command abc"));
  fprintf(f, "0\t1\t2\tout\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command def"));
  fclose(f);

  string err;
  BuildLog log(disk_interface_);
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_EQ("", err);

  BuildLog::LogEntry* e = log.LookupByOutput("out");
  ASSERT_TRUE(e);
  ASSERT_NO_FATAL_FAILURE(AssertHash("command def", e->command_hash));
}

TEST_F(BuildLogTest, Truncate) {
  AssertParse(&state_,
"build out: cat mid\n"
"build mid: cat in\n");

  {
    BuildLog log1(disk_interface_);
    string err;
    EXPECT_TRUE(log1.OpenForWrite(kTestFilename, *this, &err));
    ASSERT_EQ("", err);
    log1.RecordCommand(state_.edges_[0], 15, 18);
    log1.RecordCommand(state_.edges_[1], 20, 25);
    log1.Close();
  }
#ifdef __USE_LARGEFILE64
  struct stat64 statbuf;
  ASSERT_EQ(0, stat64(kTestFilename, &statbuf));
#else
  struct stat statbuf;
  ASSERT_EQ(0, stat(kTestFilename, &statbuf));
#endif
  ASSERT_GT(statbuf.st_size, 0);

  // For all possible truncations of the input file, assert that we don't
  // crash when parsing.
  for (off_t size = statbuf.st_size; size > 0; --size) {
    BuildLog log2(disk_interface_);
    string err;
    EXPECT_TRUE(log2.OpenForWrite(kTestFilename, *this, &err));
    ASSERT_EQ("", err);
    log2.RecordCommand(state_.edges_[0], 15, 18);
    log2.RecordCommand(state_.edges_[1], 20, 25);
    log2.Close();

    ASSERT_TRUE(Truncate(kTestFilename, size, &err));

    BuildLog log3(disk_interface_);
    err.clear();
    ASSERT_TRUE(log3.Load(kTestFilename, &err) == LOAD_SUCCESS || !err.empty());
  }
}

TEST_F(BuildLogTest, ObsoleteOldVersion) {
  FILE* f = disk_interface_.OpenFile(kTestFilename, "wb");
  fprintf(f, "# ninja log v3\n");
  fprintf(f, "123 456 0 out command\n");
  fclose(f);

  string err;
  BuildLog log(disk_interface_);
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_NE(err.find("version"), string::npos);
}

TEST_F(BuildLogTest, SpacesInOutput) {
  FILE* f = disk_interface_.OpenFile(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "123\t456\t456\tout with space\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command"));
  fclose(f);

  string err;
  BuildLog log(disk_interface_);
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_EQ("", err);

  BuildLog::LogEntry* e = log.LookupByOutput("out with space");
  ASSERT_TRUE(e);
  ASSERT_EQ(123, e->start_time);
  ASSERT_EQ(456, e->end_time);
  ASSERT_EQ(456, e->mtime);
  ASSERT_NO_FATAL_FAILURE(AssertHash("command", e->command_hash));
}

TEST_F(BuildLogTest, DuplicateVersionHeader) {
  // Old versions of ninja accidentally wrote multiple version headers to the
  // build log on Windows. This shouldn't crash, and the second version header
  // should be ignored.
  FILE* f = disk_interface_.OpenFile(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "123\t456\t456\tout\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command"));
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "456\t789\t789\tout2\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command2"));
  fclose(f);

  string err;
  BuildLog log(disk_interface_);
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_EQ("", err);

  BuildLog::LogEntry* e = log.LookupByOutput("out");
  ASSERT_TRUE(e);
  ASSERT_EQ(123, e->start_time);
  ASSERT_EQ(456, e->end_time);
  ASSERT_EQ(456, e->mtime);
  ASSERT_NO_FATAL_FAILURE(AssertHash("command", e->command_hash));

  e = log.LookupByOutput("out2");
  ASSERT_TRUE(e);
  ASSERT_EQ(456, e->start_time);
  ASSERT_EQ(789, e->end_time);
  ASSERT_EQ(789, e->mtime);
  ASSERT_NO_FATAL_FAILURE(AssertHash("command2", e->command_hash));
}

struct TestDiskInterface : public RealDiskInterface {
  void EnableMockTimestamps() { enable_mock_ = true; }

  TimeStamp Stat(const string& path, string* err) const override {
    if (enable_mock_)
      return 4;
    else
      return this->RealDiskInterface::Stat(path, err);
  }

 private:
  bool enable_mock_ = false;
};

TEST_F(BuildLogTest, Restat) {
  FILE* f = disk_interface_.OpenFile(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n"
             "1\t2\t3\tout\tcommand\n");
  fclose(f);
  std::string err;
  TestDiskInterface testDiskInterface;
  BuildLog log(testDiskInterface);
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  BuildLog::LogEntry* e = log.LookupByOutput("out");
  ASSERT_EQ(3, e->mtime);

  char out2[] = { 'o', 'u', 't', '2', 0 };
  char* filter2[] = { out2 };
  testDiskInterface.EnableMockTimestamps();
  EXPECT_TRUE(log.Restat(kTestFilename, 1, filter2, &err));
  ASSERT_EQ("", err);
  e = log.LookupByOutput("out");
  ASSERT_EQ(3, e->mtime); // unchanged, since the filter doesn't match

  EXPECT_TRUE(log.Restat(kTestFilename, 0, NULL, &err));
  ASSERT_EQ("", err);
  e = log.LookupByOutput("out");
  ASSERT_EQ(4, e->mtime);
}

TEST_F(BuildLogTest, VeryLongInputLine) {
  // Ninja's build log buffer is currently 256kB. Lines longer than that are
  // silently ignored, but don't affect parsing of other lines.
  FILE* f = disk_interface_.OpenFile(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "123\t456\t456\tout\tcommand start");
  for (size_t i = 0; i < (512 << 10) / strlen(" more_command"); ++i)
    fputs(" more_command", f);
  fprintf(f, "\n");
  fprintf(f, "456\t789\t789\tout2\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command2"));
  fclose(f);

  string err;
  BuildLog log(disk_interface_);
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_EQ("", err);

  BuildLog::LogEntry* e = log.LookupByOutput("out");
  ASSERT_EQ(NULL, e);

  e = log.LookupByOutput("out2");
  ASSERT_TRUE(e);
  ASSERT_EQ(456, e->start_time);
  ASSERT_EQ(789, e->end_time);
  ASSERT_EQ(789, e->mtime);
  ASSERT_NO_FATAL_FAILURE(AssertHash("command2", e->command_hash));
}

TEST_F(BuildLogTest, MultiTargetEdge) {
  AssertParse(&state_,
"build out out.d: cat\n");

  BuildLog log(disk_interface_);
  log.RecordCommand(state_.edges_[0], 21, 22);

  ASSERT_EQ(2u, log.entries().size());
  BuildLog::LogEntry* e1 = log.LookupByOutput("out");
  ASSERT_TRUE(e1);
  BuildLog::LogEntry* e2 = log.LookupByOutput("out.d");
  ASSERT_TRUE(e2);
  ASSERT_EQ("out", e1->output);
  ASSERT_EQ("out.d", e2->output);
  ASSERT_EQ(21, e1->start_time);
  ASSERT_EQ(21, e2->start_time);
  ASSERT_EQ(22, e2->end_time);
  ASSERT_EQ(22, e2->end_time);
}

struct BuildLogRecompactTest : public BuildLogTest {
  virtual bool IsPathDead(StringPiece s) const { return s == "out2"; }
};

TEST_F(BuildLogRecompactTest, Recompact) {
  AssertParse(&state_,
"build out: cat in\n"
"build out2: cat in\n");

  BuildLog log1(disk_interface_);
  string err;
  EXPECT_TRUE(log1.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  // Record the same edge several times, to trigger recompaction
  // the next time the log is opened.
  for (int i = 0; i < 200; ++i)
    log1.RecordCommand(state_.edges_[0], 15, 18 + i);
  log1.RecordCommand(state_.edges_[1], 21, 22);
  log1.Close();

  // Load...
  BuildLog log2(disk_interface_);
  EXPECT_TRUE(log2.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  ASSERT_EQ(2u, log2.entries().size());
  ASSERT_TRUE(log2.LookupByOutput("out"));
  ASSERT_TRUE(log2.LookupByOutput("out2"));
  // ...and force a recompaction.
  EXPECT_TRUE(log2.OpenForWrite(kTestFilename, *this, &err));
  log2.Close();

  // "out2" is dead, it should've been removed.
  BuildLog log3(disk_interface_);
  EXPECT_TRUE(log2.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  ASSERT_EQ(1u, log2.entries().size());
  ASSERT_TRUE(log2.LookupByOutput("out"));
  ASSERT_FALSE(log2.LookupByOutput("out2"));
}

}  // anonymous namespace
