// Copyright 2026 Google Inc. All Rights Reserved.
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

#include "pointer_variant.h"

#include "test.h"

#include <cstdint>
#include <type_traits>

namespace {

struct alignas(8) A {
  int64_t value = 1;
};

struct alignas(8) B {
  int64_t value = 2;
};

struct alignas(8) Derived : A {};

using Two = PointerVariant<A*, B*>;

static_assert(sizeof(PointerVariant<A*>) == sizeof(void*), "");
static_assert(sizeof(Two) == sizeof(void*), "");
static_assert(sizeof(PointerVariant<A*, B*, const A*, const B*>) ==
                  sizeof(void*),
              "");

// The pointers aren't owned, so copies are cheap and safe.
static_assert(std::is_trivially_copyable<Two>::value, "");

// Only exact alternatives convert.
static_assert(std::is_convertible<A*, Two>::value, "");
static_assert(std::is_assignable<Two&, B*>::value, "");
static_assert(!std::is_constructible<Two, const A*>::value, "");
static_assert(!std::is_constructible<Two, Derived*>::value, "");
static_assert(!std::is_constructible<PointerVariant<A*>, B*>::value, "");
static_assert(!std::is_constructible<Two, int>::value, "");

}  // anonymous namespace

TEST(PointerVariantTest, IndexBasedAccess) {
  A a;
  B b;
  Two v(&b);
  EXPECT_EQ(1u, v.index());
  EXPECT_EQ(&b, get<1>(v));
  EXPECT_EQ(&b, get_if<1>(&v));
  EXPECT_EQ(nullptr, get_if<0>(&v));

  v = &a;
  EXPECT_EQ(0u, v.index());
  EXPECT_EQ(&a, get<0>(v));
  EXPECT_EQ(nullptr, get_if<1>(&v));
}

TEST(PointerVariantTest, TypeBasedAccess) {
  A a;
  B b;
  Two v(&a);
  EXPECT_TRUE(holds_alternative<A*>(v));
  EXPECT_FALSE(holds_alternative<B*>(v));
  EXPECT_EQ(&a, get<A*>(v));
  EXPECT_EQ(&a, get_if<A*>(&v));
  EXPECT_EQ(nullptr, get_if<B*>(&v));

  v = &b;
  EXPECT_TRUE(holds_alternative<B*>(v));
  EXPECT_EQ(&b, get<B*>(v));
  EXPECT_EQ(nullptr, get_if<A*>(&v));
}

TEST(PointerVariantTest, CopiesPointToTheSameObject) {
  A a;
  B b;
  Two v(&a);
  Two copy = v;
  EXPECT_EQ(&a, get<A*>(copy));

  copy = &b;
  EXPECT_EQ(&a, get<A*>(v));
  EXPECT_EQ(&b, get<B*>(copy));
}

TEST(PointerVariantTest, ManyAlternatives) {
  // Five alternatives need three tag bits, so 8-byte alignment.
  struct alignas(8) C {
    int64_t unused = 0;
  };
  struct alignas(8) D {
    int64_t unused = 0;
  };
  struct alignas(8) E {
    int64_t unused = 0;
  };
  A a;
  B b;
  C c;
  D d;
  E e;
  using Five = PointerVariant<A*, B*, C*, D*, E*>;
  static_assert(sizeof(Five) == sizeof(void*), "");
  Five v(&e);
  EXPECT_EQ(4u, v.index());
  EXPECT_EQ(&e, get<E*>(v));
  v = &a;
  EXPECT_EQ(&a, get<A*>(v));
  v = &b;
  EXPECT_EQ(&b, get<B*>(v));
  v = &c;
  EXPECT_EQ(&c, get<C*>(v));
  v = &d;
  EXPECT_EQ(&d, get<D*>(v));
}
