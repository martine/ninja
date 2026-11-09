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

#ifndef NINJA_EVAL_ENV_H_
#define NINJA_EVAL_ENV_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "eval_string.h"
#include "string_piece.h"
#include "string_piece_util.h"

struct Rule;

/// An interface for a scope for variable (e.g. "$foo") lookups.
struct Env {
  virtual ~Env() {}
  virtual std::string LookupVariable(StringPiece var) = 0;
};

/// An invocable build command and associated metadata (description, etc.).
struct Rule {
  explicit Rule(const std::string& name) : name_(name) {}

  static std::unique_ptr<Rule> Phony();

  bool IsPhony() const;

  const std::string& name() const { return name_; }

  void AddBinding(const std::string& key, const EvalString& val);

  static bool IsReservedBinding(StringPiece var);

  const EvalString* GetBinding(StringPiece key) const;

 private:
  // Allow the parsers to reach into this object and fill out its fields.
  friend struct ManifestParser;

  std::string name_;
  typedef std::map<std::string, EvalString, StringPieceLess> Bindings;
  Bindings bindings_;
  bool phony_ = false;
};

/// An Env which contains a mapping of variables to values
/// as well as a pointer to a parent scope.
struct BindingEnv : public Env {
  BindingEnv() : parent_(NULL) {}
  explicit BindingEnv(BindingEnv* parent) : parent_(parent) {}

  virtual ~BindingEnv() {}
  virtual std::string LookupVariable(StringPiece var);

  void AddRule(std::unique_ptr<const Rule> rule);
  const Rule* LookupRule(StringPiece rule_name);
  const Rule* LookupRuleCurrentScope(StringPiece rule_name);
  const std::map<std::string, std::unique_ptr<const Rule>, StringPieceLess>&
  GetRules() const;

  void AddBinding(const std::string& key, StringPiece val);

  /// This is tricky.  Edges want lookup scope to go in this order:
  /// 1) value set on edge itself (edge_->env_)
  /// 2) value set on rule, with expansion in the edge's scope
  /// 3) value set on enclosing scope of edge (edge_->env_->parent_)
  /// This function takes as parameters the necessary info to do (2).
  std::string LookupWithFallback(StringPiece var, const EvalString* eval,
                                 Env* env);

private:
  std::map<std::string, std::string, StringPieceLess> bindings_;
  std::map<std::string, std::unique_ptr<const Rule>, StringPieceLess> rules_;
  BindingEnv* parent_;
};

#endif  // NINJA_EVAL_ENV_H_
