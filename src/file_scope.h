// Copyright 2026 Google Inc. All Rights Reserved.
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

#ifndef NINJA_FILE_SCOPE_H_
#define NINJA_FILE_SCOPE_H_

#include "string_piece.h"
#include "string_piece_util.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>

struct Rule;

/// The scope of a manifest file: the top-level file, or one included with
/// "subninja".  It holds the variables and rules declared in it.
struct FileScope {
  explicit FileScope(FileScope* parent = nullptr);
  ~FileScope();

  FileScope(const FileScope&) = delete;
  FileScope& operator=(const FileScope&) = delete;

  std::string LookupVariable(StringPiece var) const;
  void AddBinding(const std::string& key, StringPiece val);

  void AddRule(std::unique_ptr<const Rule> rule);
  const Rule* LookupRule(StringPiece rule_name);
  const Rule* LookupRuleCurrentScope(StringPiece rule_name);
  const std::map<std::string_view, std::unique_ptr<const Rule>>& GetRules()
      const;

private:
  /// A map rather than a sorted vector, as variables are added and looked up
  /// as the file is parsed, and a file may have many of them.
  std::map<std::string, std::string, StringPieceLess> variables_;
  /// Keyed by each rule's own name, which never changes.
  std::map<std::string_view, std::unique_ptr<const Rule>> rules_;
  /// The enclosing file, whose variables and rules are visible in this one.
  FileScope* parent_;
};

#endif  // NINJA_FILE_SCOPE_H_
