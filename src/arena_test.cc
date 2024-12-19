// Copyright 2024 Google Inc. All Rights Reserved.
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

#include "arena.h"

#include "test.h"

TEST(ArenaTest, SimpleAlloc) {
  Arena arena;

  char *a = arena.Alloc(1);
  memcpy(a, "a", 1);
  char *b = arena.Alloc(2);
  memcpy(b, "bc", 2);
  char *c = arena.Alloc(8);
  memcpy(c, "defghijk", 8);
  char *d = arena.Alloc(8);
  memcpy(d, "12345678", 8);

  EXPECT_EQ("a", StringPiece(a, 1).AsString());
  EXPECT_EQ("bc", StringPiece(b, 2).AsString());
  EXPECT_EQ("defghijk", StringPiece(c, 8).AsString());
  EXPECT_EQ("12345678", StringPiece(d, 8).AsString());
}

TEST(ArenaTest, LargeAlloc) {
  Arena arena;

  char *small = arena.Alloc(1);
  memcpy(small, "a", 1);
  char *large = arena.Alloc(1048576);
  memset(large, 0x55, 1048576);
  char *small2 = arena.Alloc(1);
  memcpy(small2, "b", 1);

  EXPECT_EQ("a", StringPiece(small, 1).AsString());
  EXPECT_EQ("b", StringPiece(small2, 1).AsString());

  for (int i = 0; i < 1048576; ++i) {
    EXPECT_EQ(0x55, large[i]);
  }
}

TEST(ArenaTest, Persist) {
  Arena arena;

  char *str = strdup("some string that will go away");
  StringPiece persisted = arena.PersistStringPiece(str);
  memset(str, 0x55, strlen(str));
  free(str);

  EXPECT_EQ("some string that will go away", persisted.AsString());
}
