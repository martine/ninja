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

#ifndef NINJA_BUILD_LOG_H_
#define NINJA_BUILD_LOG_H_

#include <stdio.h>

#include <memory>
#include <string>
#include <vector>

#include "hash_map.h"
#include "load_status.h"
#include "timestamp.h"
#include "util.h"  // uint64_t

struct DiskInterface;
struct Edge;

/// Can answer questions about the manifest for the BuildLog.
struct BuildLogUser {
  /// Return if a given output is no longer part of the build manifest.
  /// This is only called during recompaction and doesn't have to be fast.
  virtual bool IsPathDead(StringPiece s) const = 0;
};

/// Store a log of every command ran for every build.
/// It has a few uses:
///
/// 1) (hashes of) command lines for existing output files, so we know
///    when we need to rebuild due to the command changing
/// 2) timing information, perhaps for generating reports
/// 3) restat information
/// 4) which directory inputs were missing, so we know when we need to rebuild
///    due to one being created or removed
struct BuildLog {
  BuildLog();
  ~BuildLog();

  /// Prepares writing to the log file without actually opening it - that will
  /// happen when/if it's needed
  bool OpenForWrite(const std::string& path, const BuildLogUser& user,
                    std::string* err);
  bool RecordCommand(Edge* edge, int start_time, int end_time,
                     TimeStamp mtime = 0);
  void Close();

  /// Load the on-disk log.
  LoadStatus Load(const std::string& path, std::string* err);

  struct LogEntry {
    std::string output;
    uint64_t command_hash = 0;
    int start_time = 0;
    int end_time = 0;
    TimeStamp mtime = 0;

    static uint64_t HashCommand(StringPiece command);

    // Used by tests.
    bool operator==(const LogEntry& o) const {
      return output == o.output && command_hash == o.command_hash &&
          start_time == o.start_time && end_time == o.end_time &&
          mtime == o.mtime;
    }

    explicit LogEntry(std::string output);
    LogEntry(const std::string& output, uint64_t command_hash,
             int start_time, int end_time, TimeStamp mtime);
  };

  /// Lookup a previously-run command by its output path.
  LogEntry* LookupByOutput(const std::string& path) const;

  /// Return whether the directory input |dir| (see Node::is_directory()) was
  /// missing when the command for |output| last ran.
  bool WasDirectoryMissing(const std::string& output,
                           const std::string& dir) const;

  /// Serialize an entry, followed by the directory inputs that were missing
  /// for it, into a log file.
  bool WriteEntry(FILE* f, const LogEntry& entry);

  /// Rewrite the known log entries, throwing away old data.
  bool Recompact(const std::string& path, const BuildLogUser& user,
                 std::string* err);

  /// Restat all outputs in the log
  bool Restat(StringPiece path, const DiskInterface& disk_interface,
              int output_count, char** outputs, std::string* err);

  typedef ExternalStringHashMap<std::unique_ptr<LogEntry>>::Type Entries;
  const Entries& entries() const { return entries_; }

 private:
  /// Should be called before using log_file_. When false is returned, errno
  /// will be set.
  bool OpenForWriteIfNeeded();

  Entries entries_;

  /// Directory inputs that were missing when the command for an output last
  /// ran. Only contains outputs with at least one missing directory input.
  /// The keys point to LogEntry::output in |entries_|.
  typedef ExternalStringHashMap<std::vector<std::string>>::Type
      MissingDirectories;
  MissingDirectories missing_dirs_;

  FILE* log_file_ = nullptr;
  std::string log_file_path_;
  bool needs_recompaction_ = false;
};

#endif // NINJA_BUILD_LOG_H_
