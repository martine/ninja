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

#include "file_scope.h"

#include "eval_env.h"

#include <cassert>

namespace {

std::string_view AsStringView(StringPiece s) {
  return std::string_view(s.str_, s.len_);
}

}  // anonymous namespace

FileScope::FileScope(FileScope* parent) : parent_(parent) {}

FileScope::~FileScope() = default;

std::string FileScope::LookupVariable(StringPiece var) const {
  const auto i = variables_.find(var);
  if (i != variables_.end())
    return i->second;
  if (parent_)
    return parent_->LookupVariable(var);
  return "";
}

void FileScope::AddBinding(const std::string& key, StringPiece val) {
  variables_[key].assign(val.begin(), val.end());
}

void FileScope::AddRule(std::unique_ptr<const Rule> rule) {
  assert(LookupRuleCurrentScope(rule->name()) == nullptr);
  const std::string_view name = rule->name();
  rules_.emplace(name, std::move(rule));
}

const Rule* FileScope::LookupRuleCurrentScope(StringPiece rule_name) {
  auto i = rules_.find(AsStringView(rule_name));
  if (i == rules_.end())
    return nullptr;
  return i->second.get();
}

const Rule* FileScope::LookupRule(StringPiece rule_name) {
  auto i = rules_.find(AsStringView(rule_name));
  if (i != rules_.end())
    return i->second.get();
  if (parent_)
    return parent_->LookupRule(rule_name);
  return nullptr;
}

const std::map<std::string_view, std::unique_ptr<const Rule>>&
FileScope::GetRules() const {
  return rules_;
}
