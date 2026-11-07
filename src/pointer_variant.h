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

#ifndef NINJA_POINTER_VARIANT_H_
#define NINJA_POINTER_VARIANT_H_

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <tuple>
#include <type_traits>

/// PointerVariant<Ts...> is a minimal std::variant<Ts...> where every
/// alternative is a raw pointer, and the whole variant is the size of a single
/// pointer.  The index of the active alternative is kept in the low bits of the
/// pointer, which are always zero because of alignment: with N alternatives,
/// every pointed-to type needs an alignment of at least N rounded up to a power
/// of two (checked at compile time).
///
/// The pointers aren't owned, so copying a PointerVariant copies the pointer.
/// They must not be null, so that get_if returning null always means that the
/// alternative isn't active.  get<I> and get_if<I> return the pointer itself.
/// A pointer converts to an alternative only if its type is exactly that
/// alternative.
template <typename... Ts>
class PointerVariant;

namespace detail {

/// The number of low bits needed to store any index less than `n`.
constexpr int TagBits(size_t n) {
  int bits = 0;
  while ((static_cast<size_t>(1) << bits) < n)
    ++bits;
  return bits;
}

/// The index of T in Ts if it appears exactly once, otherwise sizeof...(Ts).
template <typename T, typename... Ts>
constexpr size_t IndexOf() {
  constexpr bool kMatches[] = { std::is_same<T, Ts>::value... };
  size_t index = sizeof...(Ts);
  for (size_t i = 0; i < sizeof...(Ts); ++i) {
    if (kMatches[i]) {
      if (index != sizeof...(Ts))
        return sizeof...(Ts);
      index = i;
    }
  }
  return index;
}

}  // namespace detail

template <typename... Ts>
class PointerVariant {
  static_assert(sizeof...(Ts) > 0, "PointerVariant needs an alternative");
  static_assert((std::is_pointer<Ts>::value && ...),
                "PointerVariant alternatives must be pointers");

 public:
  /// The type pointed to by alternative I.
  template <size_t I>
  using Element =
      std::remove_pointer_t<std::tuple_element_t<I, std::tuple<Ts...>>>;

  /// Hold `p`, whose type must be exactly one of the alternatives.
  /// @pre p != nullptr
  template <typename T,
            size_t I = detail::IndexOf<T*, Ts...>(),
            typename = std::enable_if_t<I != sizeof...(Ts)>>
  PointerVariant(T* p) : data_(Tag<I>(p)) {
    assert(p != nullptr && "PointerVariant can't hold a null pointer");
  }

  /// The index of the active alternative.
  size_t index() const { return static_cast<size_t>(data_ & kTagMask); }

 private:
  template <size_t I, typename... Us>
  friend typename PointerVariant<Us...>::template Element<I>* get(
      const PointerVariant<Us...>& v);
  template <size_t I, typename... Us>
  friend typename PointerVariant<Us...>::template Element<I>* get_if(
      const PointerVariant<Us...>* v);

  static constexpr int kTagBits = detail::TagBits(sizeof...(Ts));
  static constexpr uintptr_t kTagMask =
      (static_cast<uintptr_t>(1) << kTagBits) - 1;

  /// Return `p` with I, the index of its alternative, in its low bits.
  template <size_t I>
  static uintptr_t Tag(Element<I>* p) {
    static_assert(std::is_object<Element<I>>::value,
                  "PointerVariant can only point to object types");
    static_assert(alignof(Element<I>) > kTagMask,
                  "every type pointed to needs an alignment of at least the "
                  "number of alternatives, rounded up to a power of two");
    const uintptr_t bits = reinterpret_cast<uintptr_t>(p);
    assert((bits & kTagMask) == 0 && "pointer is not suitably aligned");
    return bits | I;
  }

  /// The pointer held, assuming alternative I is active.
  template <size_t I>
  Element<I>* pointer() const {
    return reinterpret_cast<Element<I>*>(data_ & ~kTagMask);
  }

  /// The pointer held, with the index of the active alternative in its low
  /// kTagBits bits.
  uintptr_t data_;
};

/// Return the pointer held by alternative I, which must be active.
template <size_t I, typename... Ts>
typename PointerVariant<Ts...>::template Element<I>* get(
    const PointerVariant<Ts...>& v) {
  assert(v.index() == I && "PointerVariant: alternative is not active");
  return v.template pointer<I>();
}

/// Return the pointer held by alternative I, or null if alternative I isn't
/// active.
template <size_t I, typename... Ts>
typename PointerVariant<Ts...>::template Element<I>* get_if(
    const PointerVariant<Ts...>* v) {
  if (v->index() != I)
    return nullptr;
  return v->template pointer<I>();
}

/// Return whether the active alternative is T, which must appear exactly once
/// in the alternatives.
template <typename T, typename... Ts>
bool holds_alternative(const PointerVariant<Ts...>& v) {
  constexpr size_t I = detail::IndexOf<T, Ts...>();
  static_assert(I != sizeof...(Ts),
                "T must appear exactly once in the alternatives");
  return v.index() == I;
}

/// Return the pointer held by the alternative of type T, which must be active.
template <typename T, typename... Ts>
T get(const PointerVariant<Ts...>& v) {
  constexpr size_t I = detail::IndexOf<T, Ts...>();
  static_assert(I != sizeof...(Ts),
                "T must appear exactly once in the alternatives");
  return get<I>(v);
}

/// Return the pointer held by the alternative of type T, or null if that
/// alternative isn't active.
template <typename T, typename... Ts>
T get_if(const PointerVariant<Ts...>* v) {
  constexpr size_t I = detail::IndexOf<T, Ts...>();
  static_assert(I != sizeof...(Ts),
                "T must appear exactly once in the alternatives");
  return get_if<I>(v);
}

#endif  // NINJA_POINTER_VARIANT_H_
