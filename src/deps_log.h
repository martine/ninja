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

#ifndef NINJA_DEPS_LOG_H_
#define NINJA_DEPS_LOG_H_

#include <stdio.h>

#include <memory>
#include <string>
#include <vector>

#include "disk_interface.h"
#include "load_status.h"
#include "timestamp.h"

struct Node;
struct State;

/// As build commands run they can output extra dependency information
/// (e.g. header dependencies for C source) dynamically.  DepsLog collects
/// that information at build time and uses it for subsequent builds.
///
/// The on-disk format is based on two primary design constraints:
/// - it must be written to as a stream (during the build, which may be
///   interrupted);
/// - it can be read all at once on startup.  (Alternative designs, where
///   it contains indexing information, were considered and discarded as
///   too complicated to implement; if the file is small than reading it
///   fully on startup is acceptable.)
/// Here are some stats from the Windows Chrome dependency files, to
/// help guide the design space.  The total text in the files sums to
/// 90mb so some compression is warranted to keep load-time fast.
/// There's about 10k files worth of dependencies that reference about
/// 40k total paths totalling 2mb of unique strings.
///
/// Based on these stats, here's the current design.
/// The file is structured as version header followed by a sequence of records.
/// Each record is either a path string or a dependency list.
/// Numbering the path strings in file order gives them dense integer ids.
/// A dependency list maps an output id to a list of input ids.
///
/// Concretely, a record is:
///    four bytes record length, high bit indicates record type
///      (but max record sizes are capped at 512kB)
///    path records contain the string name of the path, followed by up to 3
///      padding bytes to align on 4 byte boundaries, followed by the
///      one's complement of the expected index of the record (to detect
///      concurrent writes of multiple ninja processes to the log).
///    dependency records are an array of 4-byte integers
///      [output path id,
///       output path mtime (lower 4 bytes), output path mtime (upper 4 bytes),
///       input path id, input path id...]
///      (The mtime is compared against the on-disk output path mtime
///      to verify the stored data is up-to-date.)
/// If two records reference the same output the latter one in the file
/// wins, allowing updates to just be appended to the file.  A separate
/// repacking step can run occasionally to remove dead records.
struct DepsLog {
  /// No default constructor.
  DepsLog() = delete;

  /// Constructor takes a DiskInterface reference.
  DepsLog(DiskInterface& disk_interface);

  /// Destructor
  ~DepsLog();

  // Writing (build-time) interface.
  bool OpenForWrite(const std::string& path, std::string* err);
  bool RecordDeps(Node* node, TimeStamp mtime, const std::vector<Node*>& nodes);
  bool RecordDeps(Node* node, TimeStamp mtime, int node_count,
                  Node* const* nodes);
  void Close();

  // Reading (startup-time) interface.
  struct Deps {
    Deps(int64_t mtime, int node_count)
        : mtime(mtime), node_count(node_count), nodes(new Node*[node_count]) {}
    ~Deps() { delete [] nodes; }
    TimeStamp mtime;
    int node_count;
    Node** nodes;
  };
  LoadStatus Load(const std::string& path, State* state, std::string* err);
  Deps* GetDeps(Node* node);
  Node* GetFirstReverseDepsNode(Node* node);

  /// Rewrite the known log entries, throwing away old data.
  bool Recompact(const std::string& path, std::string* err);

  /// Returns if the deps entry for a node is still reachable from the manifest.
  ///
  /// The deps log can contain deps entries for files that were built in the
  /// past but are no longer part of the manifest.  This function returns if
  /// this is the case for a given node.  This function is slow, don't call
  /// it from code that runs on every build.
  static bool IsDepsEntryLiveFor(const Node* node);

  /// Used for tests.
  const std::vector<Node*>& nodes() const { return nodes_; }
  const std::vector<Deps*>& deps() const { return deps_; }

 private:
  // Updates the in-memory representation.  Takes ownership of |deps|.
  // Returns true if a prior deps record was deleted.
  bool UpdateDeps(int out_id, Deps* deps);
  // Write a node name record, assigning it an id.
  bool RecordId(Node* node);

  /// Should be called before using file_. When false is returned, errno will
  /// be set.
  bool OpenForWriteIfNeeded();

  DiskInterface* disk_interface_ = nullptr;

  bool needs_recompaction_ = false;
  FILE* file_ = nullptr;
  std::string file_path_;

  /// Maps id -> Node.
  std::vector<Node*> nodes_;
  /// Maps id -> deps of that id.
  std::vector<Deps*> deps_;

  friend struct DepsLogTest;
};

#endif  // NINJA_DEPS_LOG_H_
