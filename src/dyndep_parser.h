// Copyright 2015 Google Inc. All Rights Reserved.
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

#ifndef NINJA_DYNDEP_PARSER_H_
#define NINJA_DYNDEP_PARSER_H_

#include "eval_env.h"
#include "parser.h"

struct DyndepFile;
struct EvalString;

/// Parses dyndep files.
struct DyndepParser: public Parser {
  DyndepParser(State* state, FileReader* file_reader,
               DyndepFile* dyndep_file);

  /// Parse a text string of input.  Used by tests.
  bool ParseTest(const std::string& input, std::string* err) {
    return Parse("input", input, err);
  }

private:
  /// Parse a file, given its contents as a string.
  bool Parse(const std::string& filename, const std::string& input,
             std:: string* err);

  bool ParseDyndepVersion(std::string* err);
  bool ParseLet(std::string* key, EvalString* val, std::string* err);
  bool ParseEdge(std::string* err);

  Arena arena_;
  DyndepFile* dyndep_file_;
  BindingEnv env_;
};

#endif  // NINJA_DYNDEP_PARSER_H_
