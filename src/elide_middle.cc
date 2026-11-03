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

#include "elide_middle.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace {

size_t Utf8CharSize(const char* ptr, const char* end) {
  // Decode the leading byte using UTF-8 prefix masks:
  // 0xxxxxxx (0x80)      -> 1 byte
  // 110xxxxx (0xE0/0xC0) -> 2 bytes
  // 1110xxxx (0xF0/0xE0) -> 3 bytes
  // 11110xxx (0xF8/0xF0) -> 4 bytes
  const unsigned char lead = static_cast<unsigned char>(*ptr);
  if (lead < 0x80)
    return 1;

  size_t size = 0;
  if ((lead & 0xE0) == 0xC0) {
    size = 2;
  } else if ((lead & 0xF0) == 0xE0) {
    size = 3;
  } else if ((lead & 0xF8) == 0xF0) {
    size = 4;
  } else {
    // Invalid leading byte, fall back to single-byte consumption.
    return 1;
  }

  if (ptr + size > end)
    return 1;

  // Validate UTF-8 continuation bytes (10xxxxxx).
  for (size_t i = 1; i < size; ++i) {
    const unsigned char ch = static_cast<unsigned char>(ptr[i]);
    if ((ch & 0xC0) != 0x80)
      return 1;
  }

  return size;
}

uint32_t Utf8Decode(const char* ptr, const char* end, size_t* size) {
  // Determine sequence length and decode the codepoint from UTF-8 bytes.
  *size = Utf8CharSize(ptr, end);
  const unsigned char lead = static_cast<unsigned char>(*ptr);
  if (*size == 1) {
    // ASCII or invalid byte (map invalid to U+FFFD).
    return lead < 0x80 ? lead : 0xFFFD;
  }
  if (*size == 2) {
    // 110xxxxx 10xxxxxx
    return ((lead & 0x1F) << 6) |
           (static_cast<unsigned char>(ptr[1]) & 0x3F);
  }
  if (*size == 3) {
    // 1110xxxx 10xxxxxx 10xxxxxx
    return ((lead & 0x0F) << 12) |
           ((static_cast<unsigned char>(ptr[1]) & 0x3F) << 6) |
           (static_cast<unsigned char>(ptr[2]) & 0x3F);
  }
  // 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
  return ((lead & 0x07) << 18) |
         ((static_cast<unsigned char>(ptr[1]) & 0x3F) << 12) |
         ((static_cast<unsigned char>(ptr[2]) & 0x3F) << 6) |
         (static_cast<unsigned char>(ptr[3]) & 0x3F);
}

// Returns terminal column width for a decoded Unicode codepoint.
size_t Utf8CodepointWidth(uint32_t ucs) {
  // NUL has no printable width.
  if (ucs == 0)
    return 0;
  // Zero-width joiner and variation selectors render no columns.
  if (ucs == 0x200D || (ucs >= 0xFE00 && ucs <= 0xFE0F))
    return 0;
  // C0/C1 control ranges are non-printing.
  if (ucs < 32 || (ucs >= 0x7F && ucs < 0xA0))
    return 0;
  // Treat common emoji ranges as double-width.
  if ((ucs >= 0x1F300 && ucs <= 0x1FAFF) ||
      (ucs >= 0x2600 && ucs <= 0x27BF) ||
      (ucs >= 0x2300 && ucs <= 0x23FF)) {
    return 2;
  }
  // Default to single-column width.
  return 1;
}

size_t Utf8VisibleWidth(const std::string& input) {
  const char* ptr = input.data();
  const char* end = ptr + input.size();
  size_t width = 0;
  while (ptr < end) {
    size_t size = 0;
    const uint32_t codepoint = Utf8Decode(ptr, end, &size);
    ptr += size;
    width += Utf8CodepointWidth(codepoint);
  }
  return width;
}

// Returns byte index for a given visible column boundary.
// If |ceil| is false, the index stops before crossing the boundary.
// If |ceil| is true, the index advances to the next visible boundary.
size_t Utf8ByteIndexForVisiblePos(const std::string& input,
                                  size_t visible_pos,
                                  bool ceil) {
  if (visible_pos == 0)
    return 0;
  const char* ptr = input.data();
  const char* end = ptr + input.size();
  size_t width = 0;
  size_t index = 0;
  while (ptr < end) {
    size_t size = 0;
    const uint32_t codepoint = Utf8Decode(ptr, end, &size);
    const size_t char_width = Utf8CodepointWidth(codepoint);
    // For floor, stop before crossing the requested visible column.
    if (!ceil && char_width > 0 && width + char_width > visible_pos)
      break;
    // For ceil, always advance until the column is at or past the target.
    ptr += size;
    index += size;
    width += char_width;
    // Stop once we've reached the boundary on a visible character.
    if (char_width > 0 && width >= visible_pos)
      break;
  }
  // Include trailing zero-width codepoints (e.g. variation selectors)
  // that immediately follow a visible character.
  while (ptr < end) {
    size_t size = 0;
    const uint32_t codepoint = Utf8Decode(ptr, end, &size);
    if (Utf8CodepointWidth(codepoint) != 0)
      break;
    ptr += size;
    index += size;
  }
  return index;
}

// Byte index for the last codepoint fully before |visible_pos|, using
// UTF-8 decoding to map visible column positions to byte offsets.
size_t Utf8ByteIndexForVisiblePosFloor(const std::string& input,
                                       size_t visible_pos) {
  return Utf8ByteIndexForVisiblePos(input, visible_pos, false);
}

// Byte index for the first codepoint at or after |visible_pos|, using
// UTF-8 decoding to map visible column positions to byte offsets.
size_t Utf8ByteIndexForVisiblePosCeil(const std::string& input,
                                      size_t visible_pos) {
  return Utf8ByteIndexForVisiblePos(input, visible_pos, true);
}

}  // namespace

// Convenience class used to iterate over the ANSI color sequences
// of an input string. Note that this ignores non-color related
// ANSI sequences. Usage is:
//
//  - Create instance, passing the input string to the constructor.
//  - Loop over each sequence with:
//
//        AnsiColorSequenceIterator iter;
//        while (iter.HasSequence()) {
//          .. use iter.SequenceStart() and iter.SequenceEnd()
//          iter.NextSequence();
//        }
//
struct AnsiColorSequenceIterator {
  // Constructor takes input string .
  AnsiColorSequenceIterator(const std::string& input)
      : input_(input.data()), input_end_(input_ + input.size()) {
    FindNextSequenceFrom(input_);
  }

  // Return true if an ANSI sequence was found.
  bool HasSequence() const { return cur_end_ != 0; }

  // Start of the current sequence.
  size_t SequenceStart() const { return cur_start_; }

  // End of the current sequence (index of the first character
  // following the sequence).
  size_t SequenceEnd() const { return cur_end_; }

  // Size of the current sequence in characters.
  size_t SequenceSize() const { return cur_end_ - cur_start_; }

  // Returns true if |input_index| belongs to the current sequence.
  bool SequenceContains(size_t input_index) const {
    return (input_index >= cur_start_ && input_index < cur_end_);
  }

  // Find the next sequence, if any, from the input.
  // Returns false is there is no more sequence.
  bool NextSequence() {
    if (FindNextSequenceFrom(input_ + cur_end_))
      return true;

    cur_start_ = 0;
    cur_end_ = 0;
    return false;
  }

  // Reset iterator to start of input.
  void Reset() {
    cur_start_ = cur_end_ = 0;
    FindNextSequenceFrom(input_);
  }

 private:
  // Find the next sequence from the input, |from| being the starting position
  // for the search, and must be in the [input_, input_end_] interval. On
  // success, returns true after setting cur_start_ and cur_end_, on failure,
  // return false.
  bool FindNextSequenceFrom(const char* from) {
    assert(from >= input_ && from <= input_end_);
    auto* seq =
        static_cast<const char*>(::memchr(from, '\x1b', input_end_ - from));
    if (!seq)
      return false;

    // The smallest possible color sequence if '\x1c[0m` and has four
    // characters.
    if (seq + 4 > input_end_)
      return false;

    if (seq[1] != '[')
      return FindNextSequenceFrom(seq + 1);

    // Skip parameters (digits + ; separator)
    auto is_parameter_char = [](char ch) -> bool {
      return (ch >= '0' && ch <= '9') || ch == ';';
    };

    const char* end = seq + 2;
    while (is_parameter_char(end[0])) {
      if (++end == input_end_)
        return false;  // Incomplete sequence (no command).
    }

    if (*end++ != 'm') {
      // Not a color sequence. Restart the search after the first
      // character following the [, in case this was a 3-char ANSI
      // sequence (which is ignored here).
      return FindNextSequenceFrom(seq + 3);
    }

    // Found it!
    cur_start_ = seq - input_;
    cur_end_ = end - input_;
    return true;
  }

  size_t cur_start_ = 0;
  size_t cur_end_ = 0;
  const char* input_;
  const char* input_end_;
};

// A class used to iterate over all characters of an input string,
// and return its visible position in the terminal, and whether that
// specific character is visible (or otherwise part of an ANSI color sequence).
//
// Example sequence and iterations, where 'ANSI' represents an ANSI Color
// sequence, and | is used to express concatenation
//
//   |abcd|ANSI|efgh|ANSI|ijk|      input string
//
//                11 1111 111
//    0123 4567 8901 2345 678       input indices
//
//                          1
//    0123 4444 4567 8888 890       visible positions
//
//    TTTT FFFF TTTT FFFF TTT       is_visible
//
// Usage is:
//
//     VisibleInputCharsIterator iter(input);
//     while (iter.HasChar()) {
//       ... use iter.InputIndex() to get input index of current char.
//       ... use iter.VisiblePosition() to get its visible position.
//       ... use iter.IsVisible() to check whether the current char is visible.
//
//       NextChar();
//     }
//
struct VisibleInputCharsIterator {
  VisibleInputCharsIterator(const std::string& input)
      : input_(input.data()),
        input_end_(input_ + input.size()),
        input_size_(input.size()),
        ansi_iter_(input) {
    UpdateCurrent();
  }

  // Return true if there is a character in the sequence.
  bool HasChar() const { return input_index_ < input_size_; }

  // Return current input index.
  size_t InputIndex() const { return input_index_; }

  // Return current visible position.
  size_t VisiblePosition() const { return visible_pos_; }

  // Return true if the current input character is visible
  // (i.e. not part of an ANSI color sequence).
  bool IsVisible() const { return current_is_visible_; }

  // Return terminal column width of the current visible character.
  size_t VisibleWidth() const { return current_visible_width_; }

  // Return size in bytes of current input character or ANSI sequence.
  size_t InputSize() const { return current_size_; }

  // Find next character from the input.
  void NextChar() {
    visible_pos_ += current_visible_width_;
    input_index_ += current_size_;
    UpdateCurrent();
  }

 private:
  void UpdateCurrent() {
    if (input_index_ >= input_size_) {
      current_size_ = 0;
      current_is_visible_ = false;
      current_visible_width_ = 0;
      return;
    }

    if (ansi_iter_.HasSequence() &&
        input_index_ == ansi_iter_.SequenceStart()) {
      // Skip entire ANSI color sequences as zero-width.
      current_is_visible_ = false;
      current_size_ = ansi_iter_.SequenceSize();
      current_visible_width_ = 0;
      ansi_iter_.NextSequence();
      return;
    }

    // Consume a single UTF-8 codepoint and compute its display width.
    current_is_visible_ = true;
    size_t size = 0;
    const uint32_t codepoint =
        Utf8Decode(input_ + input_index_, input_end_, &size);
    current_size_ = size;
    current_visible_width_ = Utf8CodepointWidth(codepoint);
  }

  const char* input_;
  const char* input_end_;
  size_t input_size_;
  size_t input_index_ = 0;
  size_t visible_pos_ = 0;
  size_t current_size_ = 0;
  size_t current_visible_width_ = 0;
  bool current_is_visible_ = false;
  AnsiColorSequenceIterator ansi_iter_;
};

void ElideMiddleInPlace(std::string& str, size_t max_width) {
  // Look for an ESC character. If there is none, use a fast path
  // that avoids any intermediate allocations.
  if (str.find('\x1b') == std::string::npos) {
    const size_t visible_width = Utf8VisibleWidth(str);
    if (visible_width <= max_width)
      return;

    const int ellipsis_width = 3;  // Space for "...".

    // If max width is too small, do not keep anything from the input.
    if (max_width <= ellipsis_width) {
      str.assign("...", max_width);
      return;
    }

    // Keep only |max_width - ellipsis_size| visible characters from the input
    // which will be split into two spans separated by "...".
    const size_t remaining_size = max_width - ellipsis_width;
    const size_t left_span_size = remaining_size / 2;
    const size_t right_span_size = remaining_size - left_span_size;

    // Replace the gap in the input between the spans with "..."
    const size_t gap_start =
        Utf8ByteIndexForVisiblePosFloor(str, left_span_size);
    const size_t gap_end =
        Utf8ByteIndexForVisiblePosCeil(str, visible_width - right_span_size);
    str.replace(gap_start, gap_end - gap_start, "...");
    return;
  }

  // Compute visible width.
  size_t visible_width = 0;
  for (VisibleInputCharsIterator iter(str); iter.HasChar(); iter.NextChar())
    visible_width += iter.VisibleWidth();

  if (visible_width <= max_width)
    return;

  // Compute the widths of the ellipsis, left span and right span
  // visible space.
  const size_t ellipsis_width = max_width < 3 ? max_width : 3;
  const size_t visible_left_span_size = (max_width - ellipsis_width) / 2;
  const size_t visible_right_span_size =
      (max_width - ellipsis_width) - visible_left_span_size;

  // Compute the gap of visible characters that will be replaced by
  // the ellipsis in visible space.
  const size_t visible_gap_start = visible_left_span_size;
  size_t visible_gap_end = visible_width - visible_right_span_size;

  // Round the right span start forward to the next character boundary to
  // avoid splitting wide codepoints.
  if (visible_gap_end > 0 && visible_gap_end < visible_width) {
    size_t adjusted_gap_end = visible_gap_end;
    for (VisibleInputCharsIterator gap_iter(str); gap_iter.HasChar();
         gap_iter.NextChar()) {
      const size_t pos = gap_iter.VisiblePosition();
      const size_t width = gap_iter.VisibleWidth();
      if (width == 0)
        continue;
      if (pos == visible_gap_end) {
        adjusted_gap_end = visible_gap_end;
        break;
      }
      if (pos + width >= visible_gap_end) {
        adjusted_gap_end = pos + width;
        break;
      }
    }
    visible_gap_end = adjusted_gap_end;
  }

  std::string result;
  result.reserve(str.size());

  // Parse the input chars info to:
  //
  // 1) Append any characters belonging to the left span (visible or not).
  //
  // 2) Add the ellipsis ("..." truncated to ellipsis_width).
  //    Note that its color is inherited from the left span chars
  //    which will never end with an ANSI sequence.
  //
  // 3) Append any ANSI sequence that appears inside the gap. This
  //    ensures the characters after the ellipsis appear with
  //    the right color,
  //
  // 4) Append any remaining characters (visible or not) to the result.
  //
  VisibleInputCharsIterator iter(str);

  // Step 1 - determine left span length in input chars.
  for (; iter.HasChar(); iter.NextChar()) {
    const size_t pos = iter.VisiblePosition();
    const size_t width = iter.VisibleWidth();
    if (!iter.IsVisible() && pos == visible_gap_start)
      break;
    if (width > 0 && pos + width > visible_gap_start)
      break;
  }
  result.append(str.begin(), str.begin() + iter.InputIndex());

  // Step 2 - Append the possibly-truncated ellipsis.
  result.append("...", ellipsis_width);

  // Step 3 - Append elided ANSI sequences to the result.
  for (; iter.HasChar(); iter.NextChar()) {
    const size_t pos = iter.VisiblePosition();
    const size_t width = iter.VisibleWidth();
    if (!iter.IsVisible() && pos == visible_gap_end)
      break;
    if (width > 0 && pos + width > visible_gap_end)
      break;
    if (!iter.IsVisible())
      result.append(str.data() + iter.InputIndex(), iter.InputSize());
  }

  // Step 4 - Append anything else.
  result.append(str.begin() + iter.InputIndex(), str.end());

  str = std::move(result);
}
