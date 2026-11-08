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
#include <utility>
#include <vector>

#include "string_piece.h"
#include "string_piece_util.h"

struct Rule;

/// A tokenized string that contains variable references.
/// Can be evaluated relative to a scope.
struct EvalString {
  /// @return The evaluated string, with each variable expanded to the value
  ///         returned by `scope->LookupVariable(name)`.  A scope is any type
  ///         with a `std::string LookupVariable(StringPiece)` member.
  template <typename Scope>
  std::string Evaluate(Scope* scope) const;

  /// @return The string with variables not expanded.
  std::string Unparse() const;

  void Clear() { parsed_.clear(); single_token_.clear(); }
  bool empty() const { return parsed_.empty() && single_token_.empty(); }

  void AddText(StringPiece text);
  void AddSpecial(StringPiece text);

  /// Construct a human-readable representation of the parsed state,
  /// for use in tests.
  std::string Serialize() const;

private:
  enum TokenType { RAW, SPECIAL };
  typedef std::vector<std::pair<std::string, TokenType> > TokenList;
  TokenList parsed_;

  // If we hold only a single RAW token, then we keep it here instead of
  // pushing it on TokenList. This saves a bunch of allocations for
  // what is a common case. If parsed_ is nonempty, then this value
  // must be ignored.
  std::string single_token_;
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

template <typename Scope>
std::string EvalString::Evaluate(Scope* scope) const {
  if (parsed_.empty()) {
    return single_token_;
  }

  std::string result;
  for (TokenList::const_iterator i = parsed_.begin(); i != parsed_.end(); ++i) {
    if (i->second == RAW)
      result.append(i->first);
    else
      result.append(scope->LookupVariable(i->first));
  }
  return result;
}

#endif  // NINJA_EVAL_ENV_H_
