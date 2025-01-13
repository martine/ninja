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
#include <iterator>
#include <sstream>

#include <windows.h>

namespace {

bool InternalGetFullPathName(const StringPiece& file_name, char* buffer,
                             size_t buffer_length, std::string* err) {
  DWORD result_size = GetFullPathNameA(file_name.AsString().c_str(),
                                       buffer_length, buffer, NULL);
  if (result_size == 0) {
    *err = "GetFullPathNameA(" + file_name.AsString() + "): " +
        GetLastErrorString();
    return false;
  } else if (result_size > buffer_length) {
    *err = "path too long";
    return false;
  }
  return true;
}

bool IsPathSeparator(char c) {
  return c == '/' ||  c == '\\';
}

// Return true if paths a and b are on the same windows drive.
// Return false if this function cannot check
// whether or not on the same windows drive.
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

  return IsPathSeparator(a[2]) && IsPathSeparator(b[2]);
}

// Return true if paths a and b are on the same Windows drive.
bool SameDrive(StringPiece a, StringPiece b, std::string* err) {
  if (SameDriveFast(a, b)) {
    return true;
  }

  char a_absolute[_MAX_PATH];
  char b_absolute[_MAX_PATH];
  if (!InternalGetFullPathName(a, a_absolute, sizeof(a_absolute), err)) {
    return false;
  }
  if (!InternalGetFullPathName(b, b_absolute, sizeof(b_absolute), err)) {
    return false;
  }
  char a_drive[_MAX_DIR];
  char b_drive[_MAX_DIR];
  _splitpath(a_absolute, a_drive, NULL, NULL, NULL);
  _splitpath(b_absolute, b_drive, NULL, NULL, NULL);
  return _stricmp(a_drive, b_drive) == 0;
}

// Check path |s| is FullPath style returned by GetFullPathName.
// This ignores difference of path separator.
// This is used not to call very slow GetFullPathName API.
bool IsFullPathName(StringPiece s) {
  if (s.size() < 3 ||
      !islatinalpha(s[0]) ||
      s[1] != ':' ||
      !IsPathSeparator(s[2])) {
    return false;
  }

  // Check "." or ".." is contained in path.
  for (size_t i = 2; i < s.size(); ++i) {
    if (!IsPathSeparator(s[i])) {
      continue;
    }

    // Check ".".
    if (i + 1 < s.size() && s[i+1] == '.' &&
        (i + 2 >= s.size() || IsPathSeparator(s[i+2]))) {
      return false;
    }

    // Check "..".
    if (i + 2 < s.size() && s[i+1] == '.' && s[i+2] == '.' &&
        (i + 3 >= s.size() || IsPathSeparator(s[i+3]))) {
      return false;
    }
  }

  return true;
}

}  // anonymous namespace

IncludesNormalize::IncludesNormalize(const std::string& relative_to) {
  std::string err;
  relative_to_ = AbsPath(relative_to, &err);
  if (!err.empty()) {
    Fatal("Initializing IncludesNormalize(): %s", err.c_str());
  }
  split_relative_to_ = SplitStringPiece(relative_to_, '/');
}

std::string IncludesNormalize::AbsPath(StringPiece s, std::string* err) {
  if (IsFullPathName(s)) {
    std::string result = s.AsString();
    for (size_t i = 0; i < result.size(); ++i) {
      if (result[i] == '\\') {
        result[i] = '/';
      }
    }
    return result;
  }

  char result[_MAX_PATH];
  if (!InternalGetFullPathName(s, result, sizeof(result), err)) {
    return "";
  }
  for (char* c = result; *c; ++c)
    if (*c == '\\')
      *c = '/';
  return result;
}

std::string IncludesNormalize::Relativize(
    StringPiece path, const std::vector<StringPiece>& start_list,
    std::string* err) {
  std::string abs_path = AbsPath(path, err);
  if (!err->empty())
    return "";
  std::vector<StringPiece> path_list = SplitStringPiece(abs_path, '/');
  int i;
  for (i = 0;
       i < static_cast<int>(std::min(start_list.size(), path_list.size()));
       ++i) {
    if (!EqualsCaseInsensitiveASCII(start_list[i], path_list[i])) {
      break;
    }
  }

  std::vector<StringPiece> rel_list;
  rel_list.reserve(start_list.size() - i + path_list.size() - i);
  for (int j = 0; j < static_cast<int>(start_list.size() - i); ++j)
    rel_list.push_back("..");
  for (int j = i; j < static_cast<int>(path_list.size()); ++j)
    rel_list.push_back(path_list[j]);
  if (rel_list.size() == 0)
    return ".";
  return JoinStringPiece(rel_list, '/');
}

bool IncludesNormalize::Normalize(const std::string& input, std::string* result,
                                  std::string* err) const {
  char copy[_MAX_PATH + 1];
  size_t len = input.size();
  if (len > _MAX_PATH) {
    *err = "path too long";
    return false;
  }
  strncpy(copy, input.c_str(), input.size() + 1);
  uint64_t slash_bits;
  CanonicalizePath(copy, &len, &slash_bits);
  StringPiece partially_fixed(copy, len);
  std::string abs_input = AbsPath(partially_fixed, err);
  if (!err->empty())
    return false;

  if (!SameDrive(abs_input, relative_to_, err)) {
    if (!err->empty())
      return false;
    *result = partially_fixed.AsString();
    return true;
  }
  *result = Relativize(abs_input, split_relative_to_, err);
  if (!err->empty())
    return false;
  return true;
}
