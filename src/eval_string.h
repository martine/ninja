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

#ifndef NINJA_EVAL_STRING_H_
#define NINJA_EVAL_STRING_H_

#include <cstddef>
#include <iterator>
#include <string>
#include <utility>

#include "string_piece.h"

/// `EvalString` is a tokenized string consisting of a sequence
/// of raw text and variable references. It can be evaluated relative to an
/// `Env`. An `EvalString` can be viewed as an input range of
/// `(StringPiece, TokenType)` pairs.
struct EvalString {
  using Offset = std::size_t;

  enum class TokenType {
    RAW = 0,      ///< Raw text
    SPECIAL = 1,  ///< A variable
  };

  struct const_iterator {
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = std::pair<StringPiece, TokenType>;
    using pointer = const value_type*;
    using reference = const value_type&;

    const_iterator();
    const_iterator(const char* pos);
    std::pair<StringPiece, TokenType> operator*() const;
    const_iterator& operator++();
    const_iterator operator++(int);
    friend bool operator==(const_iterator lhs, const_iterator rhs);
    friend bool operator!=(const_iterator lhs, const_iterator rhs);

   private:
    const char* pos_;
  };

  /// Create an empty EvalString with no tokens.
  EvalString();

  /// Return whether this object has no tokens.
  bool empty() const;

  /// Clear all tokens.
  /// @post `empty()`
  void Clear();

  /// Return an iterator to the first token.
  const_iterator begin() const;

  /// Return an iterator to one past the last token.
  const_iterator end() const;

  /// Append (or extend if the last token is already raw text) a raw text
  /// token to the end of the held EvalString.
  /// @pre `!text.empty()`
  void AddText(StringPiece text);

  /// Append a special variable token to the end of the held EvalString.
  /// @pre `!text.empty()`.
  void AddSpecial(StringPiece text);

  /// Return a string with all variables expanded using the given \a Env.
  /// @pre `E` has a method with the signature `std::string
  /// LookupVariable(StringRef)`
  template <typename E>
  std::string Evaluate(E* env) const {
    std::string result;
    for (const auto& token : *this) {
      if (token.second == TokenType::RAW) {
        result.append(token.first.str_, token.first.len_);
      } else {
        result.append(env->LookupVariable(token.first));
      }
    }
    return result;
  }

  /// @return The string with variables not expanded.
  std::string Unparse() const;

  /// Construct a human-readable representation of the parsed state
  /// for use in tests.
  std::string Serialize() const;

 private:
  std::string tokens_;
  EvalString::Offset last_text_segment_len_ = 0;
};

#endif  // NINJA_EVAL_STRING_H_
