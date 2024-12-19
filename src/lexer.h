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

#ifndef NINJA_LEXER_H_
#define NINJA_LEXER_H_

#include "arena.h"
#include "string_piece.h"

// Windows may #define ERROR.
#ifdef ERROR
#undef ERROR
#endif

struct EvalString;

struct Lexer {
  explicit Lexer(Arena* arena) : arena_(arena) {}
  /// Helper ctor useful for tests.
  explicit Lexer(Arena* arena, const char* input);

  enum Token {
    ERROR,
    BUILD,
    COLON,
    DEFAULT,
    EQUALS,
    IDENT,
    INCLUDE,
    INDENT,
    NEWLINE,
    PIPE,
    PIPE2,
    PIPEAT,
    POOL,
    RULE,
    SUBNINJA,
    TEOF,
  };

  /// Return a human-readable form of a token, used in error messages.
  static const char* TokenName(Token t);

  /// Return a human-readable token hint, used in error messages.
  static const char* TokenErrorHint(Token expected);

  /// If the last token read was an ERROR token, provide more info
  /// or the empty string.
  std::string DescribeLastError();

  /// Start parsing some input.
  void Start(StringPiece filename, StringPiece input);

  /// Read a Token from the Token enum.
  Token ReadToken();

  /// Rewind to the last read Token.
  void UnreadToken();

  /// If the next token is \a token, read it and return true.
  bool PeekToken(Token token);

  /// Read a simple identifier (a rule or variable name).
  /// Returns false if a name can't be read.
  bool ReadIdent(std::string* out);

  /// Read a path (complete with $escapes).
  /// Returns false only on error, returned path may be empty if a delimiter
  /// (space, newline) is hit.
  bool ReadPath(EvalString* path, std::string* err) {
    return ReadEvalString(path, true, err);
  }

  /// Read the value side of a var = value line (complete with $escapes).
  /// Returns false only on error.
  bool ReadVarValue(EvalString* value, std::string* err) {
    return ReadEvalString(value, false, err);
  }

  /// Construct an error message with context.
  bool Error(const std::string& message, std::string* err);

private:
  /// Skip past whitespace (called after each read token/ident/etc.).
  void EatWhitespace();

  /// Read a $-escaped string.
  bool ReadEvalString(EvalString* eval, bool path, std::string* err);

  Arena* arena_ = nullptr;
  StringPiece filename_;
  StringPiece input_;
  const char* ofs_;
  const char* last_token_;
};

#endif // NINJA_LEXER_H_
