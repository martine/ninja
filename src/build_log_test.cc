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

namespace {

const char kTestFilename[] = "BuildLogTest-tempfile";

struct BuildLogTest : public StateTestWithBuiltinRules, public BuildLogUser {
  virtual void SetUp() {
    // In case a crashing test left a stale file behind.
    platformAwareUnlink(kTestFilename);
  }
  virtual void TearDown() {
    platformAwareUnlink(kTestFilename);
  }
  virtual bool IsPathDead(StringPiece s) const { return false; }
};

TEST_F(BuildLogTest, WriteRead) {
  AssertParse(&state_,
"build out: cat mid\n"
"build mid: cat in\n");

  BuildLog log1;
  std::string err;
  EXPECT_TRUE(log1.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  log1.RecordCommand(state_.edges_[0], 15, 18);
  log1.RecordCommand(state_.edges_[1], 20, 25);
  log1.Close();

  BuildLog log2;
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

  BuildLog log;
  std::string contents, err;

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
  FILE* f = fopen(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "0\t1\t2\tout\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command abc"));
  fprintf(f, "0\t1\t2\tout\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command def"));
  fclose(f);

  std::string err;
  BuildLog log;
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
    BuildLog log1;
    std::string err;
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
    BuildLog log2;
    std::string err;
    EXPECT_TRUE(log2.OpenForWrite(kTestFilename, *this, &err));
    ASSERT_EQ("", err);
    log2.RecordCommand(state_.edges_[0], 15, 18);
    log2.RecordCommand(state_.edges_[1], 20, 25);
    log2.Close();

    ASSERT_TRUE(Truncate(kTestFilename, size, &err));

    BuildLog log3;
    err.clear();
    ASSERT_TRUE(log3.Load(kTestFilename, &err) == LOAD_SUCCESS || !err.empty());
  }
}

TEST_F(BuildLogTest, ObsoleteOldVersion) {
  FILE* f = fopen(kTestFilename, "wb");
  fprintf(f, "# ninja log v3\n");
  fprintf(f, "123 456 0 out command\n");
  fclose(f);

  std::string err;
  BuildLog log;
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_NE(err.find("version"), std::string::npos);
}

TEST_F(BuildLogTest, SpacesInOutput) {
  FILE* f = fopen(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "123\t456\t456\tout with space\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command"));
  fclose(f);

  std::string err;
  BuildLog log;
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
  FILE* f = fopen(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "123\t456\t456\tout\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command"));
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "456\t789\t789\tout2\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command2"));
  fclose(f);

  std::string err;
  BuildLog log;
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

struct TestDiskInterface : public DiskInterface {
  TimeStamp Stat(const std::string& path, std::string* err) const override {
    return 4;
  }
  TimeStamp StatDirectory(const std::string& path,
                          std::string* err) const override {
    assert(false);
    return 0;
  }
  bool WriteFile(const std::string& path, const std::string& contents,
                 bool crlf_on_windows) override {
    assert(false);
    return true;
  }
  bool MakeDir(const std::string& path) override {
    assert(false);
    return false;
  }
  Status ReadFile(const std::string& path, std::string* contents,
                  std::string* err) override {
    assert(false);
    return NotFound;
  }
  int RemoveFile(const std::string& path) override {
    assert(false);
    return 0;
  }
};

TEST_F(BuildLogTest, Restat) {
  FILE* f = fopen(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n"
             "1\t2\t3\tout\tcommand\n");
  fclose(f);
  std::string err;
  BuildLog log;
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  BuildLog::LogEntry* e = log.LookupByOutput("out");
  ASSERT_EQ(3, e->mtime);

  TestDiskInterface testDiskInterface;
  char out2[] = { 'o', 'u', 't', '2', 0 };
  char* filter2[] = { out2 };
  EXPECT_TRUE(log.Restat(kTestFilename, testDiskInterface, 1, filter2, &err));
  ASSERT_EQ("", err);
  e = log.LookupByOutput("out");
  ASSERT_EQ(3, e->mtime); // unchanged, since the filter doesn't match

  EXPECT_TRUE(log.Restat(kTestFilename, testDiskInterface, 0, NULL, &err));
  ASSERT_EQ("", err);
  e = log.LookupByOutput("out");
  ASSERT_EQ(4, e->mtime);
}

TEST_F(BuildLogTest, VeryLongInputLine) {
  // Ninja's build log buffer is currently 256kB. Lines longer than that are
  // silently ignored, but don't affect parsing of other lines.
  FILE* f = fopen(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "123\t456\t456\tout\tcommand start");
  for (size_t i = 0; i < (512 << 10) / strlen(" more_command"); ++i)
    fputs(" more_command", f);
  fprintf(f, "\n");
  fprintf(f, "456\t789\t789\tout2\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command2"));
  fclose(f);

  std::string err;
  BuildLog log;
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

  BuildLog log;
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

TEST_F(BuildLogTest, MissingDirectories) {
  AssertParse(&state_,
"build out out.d: cat present/ missing/ ./missing/ | missing_implicit/ "
"|| missing_order_only/\n"
"build out2: cat in\n");

  VirtualFileSystem fs;
  fs.CreateDir("present");
  std::string err;
  for (Node* input : state_.edges_[0]->inputs_) {
    EXPECT_TRUE(input->StatIfNecessary(&fs, &err));
  }
  ASSERT_EQ("", err);

  BuildLog log1;
  EXPECT_TRUE(log1.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  log1.RecordCommand(state_.edges_[0], 15, 18);
  log1.RecordCommand(state_.edges_[1], 20, 25);
  log1.Close();

  std::string contents;
  ReadFile(kTestFilename, &contents, &err);
  ASSERT_EQ("", err);
  EXPECT_NE(contents.find("\tout\t"), std::string::npos);
  EXPECT_NE(contents.find("\nmissing\tout\tmissing/\n"
                          "missing\tout\tmissing_implicit/\n"),
            std::string::npos);
  EXPECT_NE(contents.find("\nmissing\tout.d\tmissing/\n"
                          "missing\tout.d\tmissing_implicit/\n"),
            std::string::npos);
  EXPECT_EQ(contents.find("present/"), std::string::npos);
  EXPECT_EQ(contents.find("missing_order_only/"), std::string::npos);

  BuildLog log2;
  EXPECT_TRUE(log2.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  for (BuildLog* log : { &log1, &log2 }) {
    for (const char* output : { "out", "out.d" }) {
      EXPECT_TRUE(log->WasDirectoryMissing(output, "missing/"));
      EXPECT_TRUE(log->WasDirectoryMissing(output, "missing_implicit/"));
      EXPECT_FALSE(log->WasDirectoryMissing(output, "present/"));
      EXPECT_FALSE(log->WasDirectoryMissing(output, "missing_order_only/"));
    }
    EXPECT_FALSE(log->WasDirectoryMissing("out2", "missing/"));
  }

  // Recording the command again without missing directories forgets them.
  fs.CreateDir("missing");
  fs.CreateDir("missing_implicit");
  state_.Reset();
  for (Node* input : state_.edges_[0]->inputs_) {
    EXPECT_TRUE(input->StatIfNecessary(&fs, &err));
  }
  EXPECT_TRUE(log2.OpenForWrite(kTestFilename, *this, &err));
  log2.RecordCommand(state_.edges_[0], 30, 35);
  log2.Close();
  EXPECT_FALSE(log2.WasDirectoryMissing("out", "missing/"));

  BuildLog log3;
  EXPECT_TRUE(log3.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  EXPECT_FALSE(log3.WasDirectoryMissing("out", "missing/"));
  EXPECT_FALSE(log3.WasDirectoryMissing("out.d", "missing_implicit/"));
}

TEST_F(BuildLogTest, MissingDirectoriesLoad) {
  FILE* f = fopen(kTestFilename, "wb");
  fprintf(f, "# ninja log v7\n");
  fprintf(f, "0\t1\t2\tout\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command"));
  fprintf(f, "missing\tout\ta dir/\n");
  // Ignored: unknown output, missing directory.
  fprintf(f, "missing\tunknown\tb/\n");
  fprintf(f, "missing\tout\t\n");
  fprintf(f, "missing\tout\n");
  fprintf(f, "0\t1\t2\tout2\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command2"));
  fprintf(f, "missing\tout2\tc/\n");
  // A newer entry replaces the missing directories of the older one.
  fprintf(f, "3\t4\t5\tout2\t%" PRIx64 "\n",
      BuildLog::LogEntry::HashCommand("command2"));
  fclose(f);

  std::string err;
  BuildLog log;
  EXPECT_TRUE(log.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  ASSERT_EQ(2u, log.entries().size());
  EXPECT_FALSE(log.LookupByOutput("unknown"));
  EXPECT_TRUE(log.WasDirectoryMissing("out", "a dir/"));
  EXPECT_FALSE(log.WasDirectoryMissing("out", ""));
  EXPECT_FALSE(log.WasDirectoryMissing("unknown", "b/"));
  EXPECT_FALSE(log.WasDirectoryMissing("out2", "c/"));
  BuildLog::LogEntry* e = log.LookupByOutput("out");
  ASSERT_TRUE(e);
  ASSERT_NO_FATAL_FAILURE(AssertHash("command", e->command_hash));
}

struct BuildLogRecompactTest : public BuildLogTest {
  virtual bool IsPathDead(StringPiece s) const { return s == "out2"; }
};

TEST_F(BuildLogRecompactTest, Recompact) {
  AssertParse(&state_,
"build out: cat in\n"
"build out2: cat in\n");

  BuildLog log1;
  std::string err;
  EXPECT_TRUE(log1.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  // Record the same edge several times, to trigger recompaction
  // the next time the log is opened.
  for (int i = 0; i < 200; ++i)
    log1.RecordCommand(state_.edges_[0], 15, 18 + i);
  log1.RecordCommand(state_.edges_[1], 21, 22);
  log1.Close();

  // Load...
  BuildLog log2;
  EXPECT_TRUE(log2.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  ASSERT_EQ(2u, log2.entries().size());
  ASSERT_TRUE(log2.LookupByOutput("out"));
  ASSERT_TRUE(log2.LookupByOutput("out2"));
  // ...and force a recompaction.
  EXPECT_TRUE(log2.OpenForWrite(kTestFilename, *this, &err));
  log2.Close();

  // "out2" is dead, it should've been removed.
  BuildLog log3;
  EXPECT_TRUE(log2.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  ASSERT_EQ(1u, log2.entries().size());
  ASSERT_TRUE(log2.LookupByOutput("out"));
  ASSERT_FALSE(log2.LookupByOutput("out2"));
}

TEST_F(BuildLogRecompactTest, RecompactMissingDirectories) {
  AssertParse(&state_,
"build out: cat dir/\n"
"build out2: cat dir/\n");
  state_.LookupNode("dir/")->MarkMissing();

  BuildLog log1;
  std::string err;
  EXPECT_TRUE(log1.OpenForWrite(kTestFilename, *this, &err));
  ASSERT_EQ("", err);
  for (int i = 0; i < 200; ++i) {
    log1.RecordCommand(state_.edges_[0], 15, 18 + i);
  }
  log1.RecordCommand(state_.edges_[1], 21, 22);
  log1.Close();

  BuildLog log2;
  EXPECT_TRUE(log2.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  EXPECT_TRUE(log2.WasDirectoryMissing("out2", "dir/"));
  EXPECT_TRUE(log2.OpenForWrite(kTestFilename, *this, &err));
  log2.Close();
  EXPECT_FALSE(log2.WasDirectoryMissing("out2", "dir/"));

  std::string contents;
  ReadFile(kTestFilename, &contents, &err);
  ASSERT_EQ("", err);
  EXPECT_EQ(contents.find("out2"), std::string::npos);

  BuildLog log3;
  EXPECT_TRUE(log3.Load(kTestFilename, &err));
  ASSERT_EQ("", err);
  ASSERT_EQ(1u, log3.entries().size());
  EXPECT_TRUE(log3.WasDirectoryMissing("out", "dir/"));
}

}  // anonymous namespace
