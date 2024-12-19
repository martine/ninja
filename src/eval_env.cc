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

#include <assert.h>

#include "eval_env.h"

using namespace std;

string BindingEnv::LookupVariable(const string& var) {
  map<string, string>::iterator i = bindings_.find(var);
  if (i != bindings_.end())
    return i->second;
  if (parent_)
    return parent_->LookupVariable(var);
  return "";
}

void BindingEnv::AddBinding(const string& key, const string& val) {
  bindings_[key] = val;
}

void BindingEnv::AddRule(std::unique_ptr<const Rule> rule) {
  assert(LookupRuleCurrentScope(rule->name()) == NULL);
  rules_[rule->name()] = std::move(rule);
}

const Rule* BindingEnv::LookupRuleCurrentScope(const string& rule_name) {
  auto i = rules_.find(rule_name);
  if (i == rules_.end())
    return NULL;
  return i->second.get();
}

const Rule* BindingEnv::LookupRule(const string& rule_name) {
  auto i = rules_.find(rule_name);
  if (i != rules_.end())
    return i->second.get();
  if (parent_)
    return parent_->LookupRule(rule_name);
  return NULL;
}

void Rule::AddBinding(const string& key, const EvalString& val) {
  bindings_[key] = val;
}

const EvalString* Rule::GetBinding(const string& key) const {
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
bool Rule::IsReservedBinding(const string& var) {
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

const map<string, std::unique_ptr<const Rule>>& BindingEnv::GetRules() const {
  return rules_;
}

string BindingEnv::LookupWithFallback(const string& var,
                                      const EvalString* eval,
                                      Env* env) {
  map<string, string>::iterator i = bindings_.find(var);
  if (i != bindings_.end())
    return i->second;

  if (eval)
    return eval->Evaluate(env);

  if (parent_)
    return parent_->LookupVariable(var);

  return "";
}

string EvalString::Evaluate(Env* env) const {
  if (parsed_.empty()) {
    return single_token_;
  }

  string result;
  for (TokenList::const_iterator i = parsed_.begin(); i != parsed_.end(); ++i) {
    if (i->second == RAW)
      result.append(i->first);
    else
      result.append(env->LookupVariable(i->first));
  }
  return result;
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
