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

#include "eval_string.h"

#include <cassert>
#include <cstring>
#include <limits>

#include "string_piece.h"

// The format of EvalString is a sequence of tokens. Each segment is
// prefixed with the length of the token, stored as an Offset type.  The
// leading bit of this is set to 1 if the token is a variable, otherwise it is
// 0 if the token is text.  last_text_segment_len_ has the length of the last
// text section or 0 if the last section was not text. This allows us to jump
// back to the last token to extend it.
//
// This has the benefit that EvalString if very cache-friendly when iterating
// and requires only one allocation.  Moves and copies should be as cheap as
// possible as well.
//
// The final benefit is that when we call Clear() we don't free any memory
// meaning that an EvalString that is constantly reused will be very
// unlikely to allocate.

namespace {

const EvalString::Offset leadingBit =
    static_cast<EvalString::Offset>(1)
    << (std::numeric_limits<EvalString::Offset>::digits - 1u);

EvalString::Offset clearLeadingBit(EvalString::Offset in) {
  return in & ~leadingBit;
}

EvalString::Offset setLeadingBit(EvalString::Offset in) {
  return in | leadingBit;
}

bool hasLeadingBit(EvalString::Offset in) {
  return in >> (std::numeric_limits<EvalString::Offset>::digits - 1u);
}

void appendSegment(std::string& str, EvalString::Offset length,
                   StringPiece text) {
#if __cpp_lib_string_resize_and_overwrite >= 202110L
  str.resize_and_overwrite(
      str.size() + sizeof(length) + text.size(),
      [oldSize = str.size(), length, text](char* start, std::size_t) noexcept {
        char* out = start + oldSize;
        memcpy(out, &length, sizeof(length));
        out += sizeof(length);
        memcpy(out, text.str_, text.len_);
        out += text.len_;
        return out - start;
      });
#else
  str.append(reinterpret_cast<const char*>(&length), sizeof(length));
  str.append(text.str_, text.len_);
#endif
}

}  // namespace

EvalString::const_iterator::const_iterator() : pos_(nullptr) {}

EvalString::const_iterator::const_iterator(const char* pos) : pos_(pos) {}

std::pair<StringPiece, EvalString::TokenType>
EvalString::const_iterator::operator*() const {
  Offset length;
  memcpy(&length, pos_, sizeof(length));
  return { { pos_ + sizeof(length), clearLeadingBit(length) },
           static_cast<TokenType>(hasLeadingBit(length)) };
}

EvalString::const_iterator& EvalString::const_iterator::operator++() {
  Offset length;
  memcpy(&length, pos_, sizeof(length));
  pos_ += sizeof(length) + clearLeadingBit(length);
  return *this;
}

EvalString::const_iterator EvalString::const_iterator::operator++(int) {
  const const_iterator copy = *this;
  ++*this;
  return copy;
}

bool operator==(EvalString::const_iterator lhs,
                EvalString::const_iterator rhs) {
  return lhs.pos_ == rhs.pos_;
}

bool operator!=(EvalString::const_iterator lhs,
                EvalString::const_iterator rhs) {
  return !(lhs == rhs);
}

EvalString::EvalString() = default;

bool EvalString::empty() const {
  return tokens_.empty();
}

void EvalString::Clear() {
  tokens_.clear();
  last_text_segment_len_ = 0;
}

EvalString::const_iterator EvalString::begin() const {
  return const_iterator(tokens_.data());
}

EvalString::const_iterator EvalString::end() const {
  return const_iterator(tokens_.data() + tokens_.size());
}

void EvalString::AddText(StringPiece text) {
  assert(!text.empty());
  if (last_text_segment_len_ > 0) {
    // If the `last_text_segment_len` is positive, the last token was raw
    // text and we can just extend it.
    const EvalString::Offset newLength = last_text_segment_len_ + text.size();
    memcpy(&tokens_[tokens_.size() - sizeof(EvalString::Offset) -
                    last_text_segment_len_],
           &newLength, sizeof(newLength));
    tokens_.append(text.str_, text.len_);
    last_text_segment_len_ = newLength;
  } else {
    // Otherwise write new raw text token.
    const EvalString::Offset length = text.size();
    appendSegment(tokens_, length, text);
    last_text_segment_len_ = length;
  }
}

void EvalString::AddSpecial(StringPiece text) {
  assert(!text.empty());
  appendSegment(tokens_, setLeadingBit(text.size()), text);
  last_text_segment_len_ = 0;
}

std::string EvalString::Serialize() const {
  std::string result;
  for (const auto& token : *this) {
    result.append("[");
    if (token.second == TokenType::SPECIAL) {
      result.append("$");
    }
    result.append(token.first.str_, token.first.len_);
    result.append("]");
  }
  return result;
}

std::string EvalString::Unparse() const {
  std::string result;
  for (const auto& token : *this) {
    const bool special = (token.second == TokenType::SPECIAL);
    if (special) {
      result.append("${");
    }
    result.append(token.first.str_, token.first.len_);
    if (special) {
      result.append("}");
    }
  }
  return result;
}
