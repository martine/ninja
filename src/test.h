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

#ifndef NINJA_TEST_H_
#define NINJA_TEST_H_

#include <gtest/gtest.h>

#include "disk_interface.h"
#include "manifest_parser.h"
#include "state.h"

// Support utilities for tests.

struct Node;

/// A base test fixture that includes a State object with a
/// builtin "cat" rule.
struct StateTestWithBuiltinRules : public testing::Test {
  StateTestWithBuiltinRules();

  /// Add a "cat" rule to \a state.  Used by some tests; it's
  /// otherwise done by the ctor to state_.
  void AddCatRule(State* state);

  /// Short way to get a Node by its path from state_.
  Node* GetNode(const std::string& path);

  State state_;
};

void AssertParse(State* state, const char* input,
                 ManifestParserOptions = ManifestParserOptions());
void AssertHash(const char* expected, uint64_t actual);
void VerifyGraph(const State& state);

/// An implementation of DiskInterface that uses an in-memory representation
/// of disk state.  It also logs file accesses and directory creations
/// so it can be used by tests to verify disk access patterns.
struct VirtualFileSystem : public NullDiskInterface {
  VirtualFileSystem() : now_(1) {}

  /// "Create" a file with contents.
  void Create(const std::string& path, const std::string& contents);

  /// Tick "time" forwards; subsequent file operations will be newer than
  /// previous ones.
  int Tick() {
    return ++now_;
  }

  // DiskInterface
  TimeStamp Stat(const std::string& path, std::string* err) const override;
  bool WriteFile(const std::string& path, const std::string& contents) override;
  bool MakeDir(const std::string& path) override;
  Status ReadFile(const std::string& path, std::string* contents,
                  std::string* err) override;
  int RemoveFile(const std::string& path) override;

  // NOTE: This implementation does not support write or append mode!
  // It will assert() in debug builds, and return NULL/EINVAL otherwise.
  FILE* OpenFile(const std::string& path, const char* mode) override;

  /// An entry for a single in-memory file.
  struct Entry {
    int mtime;
    std::string stat_error;  // If mtime is -1.
    std::string contents;
  };

  std::vector<std::string> directories_made_;
  std::vector<std::string> files_read_;
  typedef std::map<std::string, Entry> FileMap;
  FileMap files_;
  std::set<std::string> files_removed_;
  std::set<std::string> files_created_;

  /// A simple fake timestamp for file operations.
  int now_;
};

struct ScopedTempDir {
  /// Create a temporary directory and chdir into it.
  void CreateAndEnter(const std::string& name);

  /// Clean up the temporary directory.
  void Cleanup();

  /// The temp directory containing our dir.
  std::string start_dir_;
  /// The subdirectory name for our dir, or empty if it hasn't been set up.
  std::string temp_dir_name_;
};

/// A class that records a file path and ensures that it is removed
/// on destruction. This ensures that tests do not keep stale files in the
/// current directory where they run, even in case of assertion failure.
struct ScopedFilePath {
  /// Constructor just records the file path.
  ScopedFilePath(const std::string& path) : path_(path) {}
  ScopedFilePath(const char* path) : path_(path) {}

  /// Allow move operations.
  ScopedFilePath(ScopedFilePath&&) noexcept;
  ScopedFilePath& operator=(ScopedFilePath&&) noexcept;

  /// Destructor destroys the file, unless Release() was called.
  ~ScopedFilePath();

  /// Release the file, the destructor will not remove the file.
  void Release();

  const char* c_str() const { return path_.c_str(); }
  const std::string& path() const { return path_; }
  bool released() const { return released_; }

 private:
  std::string path_;
  bool released_ = false;
};

#endif // NINJA_TEST_H_
