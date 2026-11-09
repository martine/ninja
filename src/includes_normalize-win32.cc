// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "includes_normalize.h"

#include "string_piece.h"
#include "string_piece_util.h"
#include "util.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <sstream>

#include <windows.h>

namespace {

// Attempt to get the full path name of |file_name| and load it into |buffer|,
// which has size |buffer_length|.  If successful, return true and set
// |new_len| to the length of the result, otherwise return false and set |err|
// to an appropriate error message.
// @pre |err| is empty;
bool InternalGetFullPathName(const char* file_name, char* buffer,
                             std::size_t buffer_length, std::size_t* new_len,
                             std::string* err) {
  assert(err->empty());
  DWORD result_size = GetFullPathNameA(
      file_name, static_cast<DWORD>(buffer_length), buffer, NULL);
  if (result_size == 0) {
    *err = "GetFullPathNameA(";
    *err += file_name;
    *err += "): ";
    *err += GetLastErrorString();
    return false;
  } else if (result_size > buffer_length) {
    *err = "path too long";
    return false;
  }
  if (new_len) {
    *new_len = result_size;
  }
  return true;
}

// Return true if paths |a| and |b| are on the same windows drive.
// Return false if this function cannot check
// whether or not on the same windows drive.
// @pre |a| and |b| are absolute paths in canonical form, see CanonicalizePath.
bool SameDriveFast(StringPiece a, StringPiece b) {
  if (a.size() < 3 || b.size() < 3) {
    return false;
  }

  if (!islatinalpha(a[0]) || !islatinalpha(b[0])) {
    return false;
  }

  if (ToLowerASCII(a[0]) != ToLowerASCII(b[0])) {
    return false;
  }

  if (a[1] != ':' || b[1] != ':') {
    return false;
  }

  return a[2] == '/' && b[2] == '/';
}

// Return whether if paths |a| and |b| are on the same Windows drive.
// If function fails to check, return false and load an error message
// to |err|.
// @pre |a| and |b| are absolute paths in canonical form, see CanonicalizePath.
// @pre |err| is empty;
bool SameDrive(const std::string& a, const std::string& b, std::string* err) {
  assert(err->empty());
  if (SameDriveFast(a, b)) {
    return true;
  }

  char a_absolute[_MAX_PATH];
  char b_absolute[_MAX_PATH];
  if (!InternalGetFullPathName(a.c_str(), a_absolute, sizeof(a_absolute),
                               nullptr, err)) {
    return false;
  }
  if (!InternalGetFullPathName(b.c_str(), b_absolute, sizeof(b_absolute),
                               nullptr, err)) {
    return false;
  }
  char a_drive[_MAX_DRIVE];
  char b_drive[_MAX_DRIVE];
  _splitpath(a_absolute, a_drive, NULL, NULL, NULL);
  _splitpath(b_absolute, b_drive, NULL, NULL, NULL);
  return _stricmp(a_drive, b_drive) == 0;
}

// Check path |s| is FullPath style returned by GetFullPathName.
// This is used not to call very slow GetFullPathName API.
// @pre |s| is in canonical form, see CanonicalizePath.
bool IsFullPathName(StringPiece s) {
  return s.size() >= 3 && islatinalpha(s[0]) && s[1] == ':' && s[2] == '/';
}

#ifdef NDEBUG
void AssertIsAbsoluteInDebug(StringPiece) {
#else
void AssertIsAbsoluteInDebug(StringPiece s) {
  std::string err;
  std::string copy = s.AsString();
  IncludesNormalize::MakePathAbsolute(&copy, &err);
  assert(StringPiece(copy) == s);
#endif
}

#ifdef NDEBUG
void AssertIsCanonicalInDebug(StringPiece) {
#else
void AssertIsCanonicalInDebug(StringPiece original) {
  std::string actual = original.AsString();
  std::uint64_t slash_bits;
  CanonicalizePath(&actual, &slash_bits);
  assert(StringPiece(actual) == original);
#endif
}

// A C++ range for iterating over the path segments of a path.
// Paths must be have forward slashes as path separators.
// Note, can be replaced with std::ranges::lazy_split_view
// when C++20 is available.
struct PathSegmentRange {

  // The nested iterator class for iterating over the path segments.
  struct const_iterator {
    using iterator_category = std::forward_iterator_tag;
    using value_type        = StringPiece;
    using difference_type   = std::ptrdiff_t;
    using pointer           = const StringPiece*;
    using reference         = const StringPiece&;

    const_iterator(StringPiece str, const char *end)
        : str_(str), end_(end) {}

    const_iterator& operator++() {
      if (str_.end() == end_) {
        str_ = StringPiece();
      } else {
        const char* start = str_.end() + 1;
        const char* slash =
            static_cast<const char*>(memchr(start, '/', end_ - start));
        const std::size_t len = slash ? slash - start : end_ - start;
        str_ = StringPiece(start, len);
      }
      return *this;
    }

    reference operator*() const {
      return str_;
    }

    pointer operator->() const { return &str_; }

    friend bool operator==(
        const const_iterator& lhs, const const_iterator& rhs) {
      return lhs.str_.str_ == rhs.str_.str_;
    }

    friend bool operator!=(
        const const_iterator& lhs, const const_iterator& rhs) {
      return !(lhs == rhs);
    }

    StringPiece str_;
    const char* end_;
  };

  explicit PathSegmentRange(StringPiece str)
    : str_(str) {}

  const_iterator begin() const {
    const char* slash =
        static_cast<const char*>(memchr(str_.begin(), '/', str_.size()));
    const std::size_t len = slash ? slash - str_.begin() : str_.size();
    return const_iterator(StringPiece(str_.begin(), len), str_.end());
  }

  const_iterator end() const {
    return const_iterator(StringPiece(), str_.end());
  }

  StringPiece str_;
};

}  // anonymous namespace

IncludesNormalize::IncludesNormalize(StringPiece relative_to)
 : relative_to_(relative_to.str_, relative_to.len_) {
  std::uint64_t slash_bits;
  CanonicalizePath(&relative_to_, &slash_bits);
  std::string err;
  if (!MakePathAbsolute(&relative_to_, &err)) {
    Fatal("Initializing IncludesNormalize(): %s", err.c_str());
  }
  const PathSegmentRange components(relative_to_);
  split_relative_to_.assign(components.begin(), components.end());
}

bool IncludesNormalize::MakePathAbsolute(std::string* s, std::string* err) {
  assert(err->empty());
  AssertIsCanonicalInDebug(*s);
  if (IsFullPathName(*s)) {
    return true;
  }

  std::size_t len;
  char result[_MAX_PATH];
  if (!InternalGetFullPathName(s->c_str(), result, sizeof(result), &len, err)) {
    s->clear();
    return false;
  }

  // Fixup all backslashes with forward slashes introduced with `GetFullPathNameA`.
  char* bs = result;
  const char* end = result + len;
  while ((bs = static_cast<char*>(memchr(bs, '\\', end - bs))) !=
         nullptr) {
    *bs++ = '/';
  }
  s->assign(result, len);
  return true;
}

void IncludesNormalize::Relativize(std::string* abs_path,
                                   const std::vector<StringPiece>& start_list) {
  AssertIsAbsoluteInDebug(*abs_path);
  AssertIsCanonicalInDebug(*abs_path);

  const PathSegmentRange path_list(*abs_path);

  // `Relativize` only callable when `abs_path` and `start_list` are on the
  // same drive.  Skip comparing them each time and start from the 2nd
  // component.
  assert(EqualsCaseInsensitiveASCII(*path_list.begin(), *start_list.begin()));
  const auto diff = std::mismatch(std::next(path_list.begin()), path_list.end(),
                                  std::next(start_list.begin()),
                                  start_list.end(), EqualsCaseInsensitiveASCII);

  // The length of the common path prefix, in abs_path characters.
  const std::size_t common_prefix_len =
      (diff.first == path_list.end()) ? abs_path->size()
                                      : diff.first->str_ - abs_path->data();

  // The number of ../ to be inserted at the start of the result, corresponding
  // to the number of path segments after the common prefix from start_list.
  const std::size_t dotdot_count = start_list.end() - diff.second;

  const std::size_t dotdot_len = 3 * dotdot_count;

  // The following must remove the common prefix characters, then prepend
  // a sequence of |dotdot_count| "../" segments into the result. The end result
  // is [<dotdot_len>][<non_common_path>].

  // First relocate the non common path to the right position, removing
  // or inserting bytes if needed.
  if (common_prefix_len > dotdot_len) {
    abs_path->erase(0, common_prefix_len - dotdot_len);
  } else if (common_prefix_len < dotdot_len) {
    abs_path->insert(0, dotdot_len - common_prefix_len, '\0');
  }

  if (abs_path->empty()) {
    *abs_path = '.';
  } else {
    // Now write the ../ sequence in place.
    char* data = &*abs_path->begin();
    for (std::size_t remaining = dotdot_count; remaining > 0; --remaining) {
      memcpy(data, "../", 3);
      data += 3;
    }
  }
}

bool IncludesNormalize::Normalize(StringPiece input, std::string* result,
                                  std::string* err) const {
  assert(err->empty());
  char copy[_MAX_PATH + 1];
  std::size_t len = input.size();
  if (len > _MAX_PATH) {
    *err = "path too long";
    return false;
  }
  memcpy(copy, input.str_, input.len_);
  copy[len] = '\0';
  std::uint64_t slash_bits;
  CanonicalizePath(copy, &len, &slash_bits);
  result->assign(copy, len);
  if (!MakePathAbsolute(result, err))
    return false;

  if (!SameDrive(*result, relative_to_, err)) {
    if (!err->empty())
      return false;
    result->assign(copy, len);
    return true;
  }
  Relativize(result, split_relative_to_);
  return true;
}
