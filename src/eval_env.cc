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

#include "eval_env.h"

using namespace std;

void Rule::AddBinding(const string& key, const EvalString& val) {
  bindings_[key] = val;
}

const EvalString* Rule::GetBinding(StringPiece key) const {
  Bindings::const_iterator i = bindings_.find(key);
  if (i == bindings_.end())
    return NULL;
  return &i->second;
}

std::unique_ptr<Rule> Rule::Phony() {
  auto rule = std::unique_ptr<Rule>(new Rule("phony"));
  rule->phony_ = true;
  return rule;
}

bool Rule::IsPhony() const {
  return phony_;
}

// static
bool Rule::IsReservedBinding(StringPiece var) {
  return var == "command" ||
      var == "depfile" ||
      var == "dyndep" ||
      var == "description" ||
      var == "deps" ||
      var == "generator" ||
      var == "pool" ||
      var == "restat" ||
      var == "rspfile" ||
      var == "rspfile_content" ||
      var == "msvc_deps_prefix";
}

void EvalString::AddText(StringPiece text) {
  if (parsed_.empty()) {
    single_token_.append(text.begin(), text.end());
  } else if (!parsed_.empty() && parsed_.back().second == RAW) {
    parsed_.back().first.append(text.begin(), text.end());
  } else {
    parsed_.push_back(std::make_pair(text.AsString(), RAW));
  }
}

void EvalString::AddSpecial(StringPiece text) {
  if (parsed_.empty() && !single_token_.empty()) {
    // Going from one to two tokens, so we can no longer apply
    // our single_token_ optimization and need to push everything
    // onto the vector.
    parsed_.push_back(std::make_pair(std::move(single_token_), RAW));
  }
  parsed_.push_back(std::make_pair(text.AsString(), SPECIAL));
}

string EvalString::Serialize() const {
  string result;
  if (parsed_.empty() && !single_token_.empty()) {
    result.append("[");
    result.append(single_token_);
    result.append("]");
  } else {
    for (const auto& pair : parsed_) {
      result.append("[");
      if (pair.second == SPECIAL)
        result.append("$");
      result.append(pair.first.begin(), pair.first.end());
      result.append("]");
    }
  }
  return result;
}

string EvalString::Unparse() const {
  string result;
  if (parsed_.empty() && !single_token_.empty()) {
    result.append(single_token_.begin(), single_token_.end());
  } else {
    for (TokenList::const_iterator i = parsed_.begin();
         i != parsed_.end(); ++i) {
      bool special = (i->second == SPECIAL);
      if (special)
        result.append("${");
      result.append(i->first.begin(), i->first.end());
      if (special)
        result.append("}");
    }
  }
  return result;
}
