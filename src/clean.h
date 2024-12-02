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

#ifndef NINJA_CLEAN_H_
#define NINJA_CLEAN_H_

#include <set>
#include <string>

#include "build.h"
#include "dyndep.h"
#include "build_log.h"

struct State;
struct Node;
struct Rule;
struct DiskInterface;

struct Cleaner {
  /// Build a cleaner object with the given @a disk_interface
  Cleaner(State* state,
          const BuildConfig& config,
          DiskInterface* disk_interface);

  /// Clean the given @a target and all the file built for it.
  /// @return non-zero if an error occurs.
  int CleanTarget(Node* target);
  /// Clean the given target @a target.
  /// @return non-zero if an error occurs.
  int CleanTarget(const char* target);
  /// Clean the given target @a targets.
  /// @return non-zero if an error occurs.
  int CleanTargets(int target_count, char* targets[]);

  /// Clean all built files, except for files created by generator rules.
  /// @param generator If set, also clean files created by generator rules.
  /// @return non-zero if an error occurs.
  int CleanAll(bool generator = false);

  /// Clean all the file built with the given rule @a rule.
  /// @return non-zero if an error occurs.
  int CleanRule(const Rule* rule);
  /// Clean the file produced by the given @a rule.
  /// @return non-zero if an error occurs.
  int CleanRule(const char* rule);
  /// Clean the file produced by the given @a rules.
  /// @return non-zero if an error occurs.
  int CleanRules(int rule_count, char* rules[]);
  /// Clean the files produced by previous builds that are no longer in the
  /// manifest.
  /// @return non-zero if an error occurs.
  int CleanDead(const BuildLog::Entries& entries);

  /// @return the number of file cleaned.
  int cleaned_files_count() const {
    return cleaned_files_count_;
  }

  /// @return whether the cleaner is in verbose mode.
  bool IsVerbose() const {
    return (config_.verbosity != BuildConfig::QUIET
            && (config_.verbosity == BuildConfig::VERBOSE || config_.dry_run));
  }

 private:
  /// Remove the file @a path.
  /// @return whether the file has been removed.
  int RemoveFile(const std::string& path);
  /// @returns whether the file @a path exists.
  bool FileExists(const std::string& path);
  void Report(const std::string& path);

  /// Remove the given @a path file only if it has not been already removed.
  void Remove(const std::string& path);
  /// @return whether the given @a path has already been removed.
  bool IsAlreadyRemoved(const std::string& path);
  /// Remove the depfile and rspfile for an Edge.
  void RemoveEdgeFiles(Edge* edge);

  /// Perform actual file removal
  void RemoveAllPending();

  /// Helper recursive method for CleanTarget().
  void DoCleanTarget(Node* target);
  void PrintHeader();
  void PrintFooter();
  void DoCleanRule(const Rule* rule);
  void Reset();

  /// Load dependencies from dyndep bindings.
  void LoadDyndeps();

  State* state_;
  const BuildConfig& config_;
  DyndepLoader dyndep_loader_;
  std::set<std::string> removed_;
  std::set<Node*> cleaned_;
  std::vector<std::string> pending_;
  int cleaned_files_count_;
  DiskInterface* disk_interface_;
  int status_;
};

#endif  // NINJA_CLEAN_H_
