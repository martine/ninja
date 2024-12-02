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

#include "lexer.h"

#include "eval_env.h"
#include "test.h"

using namespace std;

TEST(Lexer, ReadVarValue) {
  Lexer lexer("plain text $var $VaR ${x}\n");
  EvalString eval;
  string err;
  EXPECT_TRUE(lexer.ReadVarValue(&eval, &err));
  EXPECT_EQ("", err);
  EXPECT_EQ("[plain text ][$var][ ][$VaR][ ][$x]",
            eval.Serialize());
}

TEST(Lexer, ReadEvalStringEscapes) {
  Lexer lexer("$ $$ab c$: $\ncd\r$|e\n");
  EvalString eval;
  string err;
  EXPECT_TRUE(lexer.ReadVarValue(&eval, &err));
  EXPECT_EQ("", err);
  EXPECT_EQ("[ $ab c: cd\r\ne]",
            eval.Serialize());
}

TEST(Lexer, WindowsNewline) {
  Lexer lexer("foo\r\n");
  EvalString eval;
  string err;
  EXPECT_TRUE(lexer.ReadVarValue(&eval, &err));
  EXPECT_EQ("", err);
  EXPECT_EQ("[foo]",
            eval.Serialize());
}

TEST(Lexer, EndsInCarriageReturn) {
  Lexer lexer("foo\r\r\n");
  EvalString eval;
  string err;
  EXPECT_TRUE(lexer.ReadVarValue(&eval, &err));
  EXPECT_EQ("", err);
  EXPECT_EQ("[foo\r]",
            eval.Serialize());
}

TEST(Lexer, ReadIdent) {
  Lexer lexer("foo baR baz_123 foo-bar");
  string ident;
  EXPECT_TRUE(lexer.ReadIdent(&ident));
  EXPECT_EQ("foo", ident);
  EXPECT_TRUE(lexer.ReadIdent(&ident));
  EXPECT_EQ("baR", ident);
  EXPECT_TRUE(lexer.ReadIdent(&ident));
  EXPECT_EQ("baz_123", ident);
  EXPECT_TRUE(lexer.ReadIdent(&ident));
  EXPECT_EQ("foo-bar", ident);
}

TEST(Lexer, ReadIdentCurlies) {
  // Verify that ReadIdent includes dots in the name,
  // but in an expansion $bar.dots stops at the dot.
  Lexer lexer("foo.dots $bar.dots ${bar.dots}\n");
  string ident;
  EXPECT_TRUE(lexer.ReadIdent(&ident));
  EXPECT_EQ("foo.dots", ident);

  EvalString eval;
  string err;
  EXPECT_TRUE(lexer.ReadVarValue(&eval, &err));
  EXPECT_EQ("", err);
  EXPECT_EQ("[$bar][.dots ][$bar.dots]",
            eval.Serialize());
}

TEST(Lexer, Error) {
  Lexer lexer("foo$\nbad $");
  EvalString eval;
  string err;
  ASSERT_FALSE(lexer.ReadVarValue(&eval, &err));
  EXPECT_EQ("input:2: bad $-escape (literal $ must be written as $$)\n"
            "bad $\n"
            "    ^ near here"
            , err);
}

TEST(Lexer, CommentEOF) {
  // Verify we don't run off the end of the string when the EOF is
  // mid-comment.
  Lexer lexer("# foo");
  Lexer::Token token = lexer.ReadToken();
  EXPECT_EQ(Lexer::ERROR, token);
}

TEST(Lexer, Tabs) {
  // Verify we print a useful error on a disallowed character.
  Lexer lexer("   \tfoobar");
  Lexer::Token token = lexer.ReadToken();
  EXPECT_EQ(Lexer::INDENT, token);
  token = lexer.ReadToken();
  EXPECT_EQ(Lexer::ERROR, token);
  EXPECT_EQ("tabs are not allowed, use spaces", lexer.DescribeLastError());
}
