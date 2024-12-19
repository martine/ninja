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

#ifndef NINJA_MANIFEST_PARSER_H_
#define NINJA_MANIFEST_PARSER_H_

#include "parser.h"

#include <memory>
#include <vector>

#include "arena.h"

struct BindingEnv;
struct EvalString;

enum DupeEdgeAction {
  kDupeEdgeActionWarn,
  kDupeEdgeActionError,
};

enum PhonyCycleAction {
  kPhonyCycleActionWarn,
  kPhonyCycleActionError,
};

struct ManifestParserOptions {
  PhonyCycleAction phony_cycle_action_ = kPhonyCycleActionWarn;
};

/// Parses .ninja files.
struct ManifestParser : public Parser {
  ManifestParser(State* state, FileReader* file_reader,
                 ManifestParserOptions options = ManifestParserOptions());

  /// Parse a text string of input.  Used by tests.
  bool ParseTest(const std::string& input, std::string* err) {
    quiet_ = true;
    return Parse("input", input, err);
  }

private:
  /// Parse a file, given its contents as a string.
  bool Parse(const std::string& filename, const std::string& input,
             std::string* err);

  /// Parse various statement types.
  bool ParsePool(std::string* err);
  bool ParseRule(std::string* err);
  bool ParseLet(std::string* key, EvalString* val, std::string* err);
  bool ParseEdge(std::string* err);
  bool ParseDefault(std::string* err);

  /// Parse either a 'subninja' or 'include' line.
  bool ParseFileInclude(bool new_scope, std::string* err);

  BindingEnv* env_;
  ManifestParserOptions options_;
  bool quiet_;

  // ins_/out_/validations_ are reused across invocations to ParseEdge(),
  // to save on the otherwise constant memory reallocation.
  // subparser_ is reused solely to get better reuse out ins_/outs_/validation_.
  Arena arena_;
  std::unique_ptr<ManifestParser> subparser_;
  std::vector<EvalString> ins_, outs_, validations_;
};

#endif  // NINJA_MANIFEST_PARSER_H_
