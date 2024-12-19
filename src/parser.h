// Copyright 2018 Google Inc. All Rights Reserved.
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

#ifndef NINJA_PARSER_H_
#define NINJA_PARSER_H_

#include <string>

#include "lexer.h"

struct FileReader;
struct State;

/// Base class for parsers.
struct Parser {
  Parser(State* state, FileReader* file_reader, Arena *arena)
      : state_(state), file_reader_(file_reader), lexer_(arena) {}
  virtual ~Parser() {}

  /// Load and parse a file.
  bool Load(const std::string& filename, std::string* err, Lexer* parent = NULL);

protected:
  /// If the next token is not \a expected, produce an error string
  /// saying "expected foo, got bar".
  bool ExpectToken(Lexer::Token expected, std::string* err);

  State* state_;
  FileReader* file_reader_;
  Lexer lexer_;

private:
  /// Parse a file, given its contents as a string.
  virtual bool Parse(const std::string& filename, const std::string& input,
                     std::string* err) = 0;
};

#endif  // NINJA_PARSER_H_
