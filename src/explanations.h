// Copyright 2024 Google Inc. All Rights Reserved.
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

#pragma once

#include <stdarg.h>

#include <string>
#include <unordered_map>
#include <vector>

struct Edge;
struct Node;
struct Status;

/// A class used to record a list of explanation strings associated
/// with a given 'item' pointer. This is used to implement the
/// `-d explain` feature.
struct Explanations {
 public:
  Explanations(Status* status = nullptr);

  /// Record an explanation for |item| if this instance is enabled.
  void Record(const void* item, const char* fmt, ...);

  /// Same as Record(), but uses a va_list to pass formatting arguments.
  void RecordArgs(const void* item, const char* fmt, va_list args);

  void Remove(const void* item);

  /// Print recorded explanations for an edge.
  void ExplainEdge(const Edge* edge);

  /// Lookup the explanations recorded for |item|, and append them
  /// to |*out|, if any.
  void LookupAndAppend(const void* item, std::vector<std::string>* out);

  /// Print explanation for loading a dyndep file.
  void ExplainDyndepLoad(const Node* node);

  const std::unordered_map<const void*, std::vector<std::string>>& getMap() const {
    return map_;
  }

  // testing only
  void clear() { map_.clear(); }

 private:
  std::unordered_map<const void*, std::vector<std::string>> map_;
  Status* status_;
};

/// Convenience wrapper for an Explanations pointer, which can be null
/// if no explanations need to be recorded.
struct OptionalExplanations {
  OptionalExplanations(Explanations* explanations);

  void Record(const void* item, const char* fmt, ...);

  void RecordArgs(const void* item, const char* fmt, va_list args);

  void Remove(const void* item);

  void LookupAndAppend(const void* item, std::vector<std::string>* out);

  void ExplainDyndepLoad(const Node* node);

  Explanations* ptr() const { return explanations_; }

 private:
  Explanations* explanations_;
};
