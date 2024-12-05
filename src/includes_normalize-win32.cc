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

using namespace std;

namespace {

std::wstring InternalGetFullPathName(StringPiece file_name, std::string* err) {
  std::wstring result;
  std::wstring wide_filename = UTF8ToWin32Unicode(file_name.AsString());
  DWORD len = GetFullPathNameW(wide_filename.c_str(), 0, NULL, NULL);
  if (!len) {
    *err = "GetFullPathNameW(" + file_name.AsString() +
           "): " + GetLastErrorString();
  } else {
    // The value of len is the buffer wide character size including the
    // terminating L'\0'. However, the second call may return a final
    // length that is smaller than |len - 1| for some reason.
    result.resize(static_cast<size_t>(len) - 1);
    DWORD final_len = GetFullPathNameW(
        wide_filename.c_str(), len, const_cast<wchar_t*>(result.data()), NULL);
    result.resize(static_cast<size_t>(final_len));
  }
  return result;
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
bool SameDrive(StringPiece a, StringPiece b, string* err)  {
  if (SameDriveFast(a, b)) {
    return true;
  }

  std::wstring a_absolute = InternalGetFullPathName(a, err);
  if (a_absolute.empty())
    return false;

  std::wstring b_absolute = InternalGetFullPathName(b, err);
  if (b_absolute.empty())
    return false;

  wchar_t a_drive[_MAX_DIR];
  wchar_t b_drive[_MAX_DIR];
  _wsplitpath(a_absolute.data(), a_drive, NULL, NULL, NULL);
  _wsplitpath(b_absolute.data(), b_drive, NULL, NULL, NULL);
  return _wcsicmp(a_drive, b_drive) == 0;
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

IncludesNormalize::IncludesNormalize(const string& relative_to) {
  string err;
  relative_to_ = AbsPath(relative_to, &err);
  if (!err.empty()) {
    Fatal("Initializing IncludesNormalize(): %s", err.c_str());
  }
  split_relative_to_ = SplitStringPiece(relative_to_, '/');
}

string IncludesNormalize::AbsPath(StringPiece s, string* err) {
  if (IsFullPathName(s)) {
    std::string result = s.AsString();
    for (char& c : result) {
      if (c == '\\')
        c = '/';
    }
    return result;
  }

  std::wstring result = InternalGetFullPathName(s, err);
  if (result.empty())
    return "";

  for (wchar_t& c : result) {
    if (c == L'\\')
      c = L'/';
  }
  return Win32UnicodeToUTF8(result);
}

string IncludesNormalize::Relativize(
    StringPiece path, const vector<StringPiece>& start_list, string* err) {
  string abs_path = AbsPath(path, err);
  if (!err->empty())
    return "";
  vector<StringPiece> path_list = SplitStringPiece(abs_path, '/');
  int i;
  for (i = 0; i < static_cast<int>(min(start_list.size(), path_list.size()));
       ++i) {
    if (!EqualsCaseInsensitiveASCII(start_list[i], path_list[i])) {
      break;
    }
  }

  vector<StringPiece> rel_list;
  rel_list.reserve(start_list.size() - i + path_list.size() - i);
  for (int j = 0; j < static_cast<int>(start_list.size() - i); ++j)
    rel_list.push_back("..");
  for (int j = i; j < static_cast<int>(path_list.size()); ++j)
    rel_list.push_back(path_list[j]);
  if (rel_list.size() == 0)
    return ".";
  return JoinStringPiece(rel_list, '/');
}

bool IncludesNormalize::Normalize(const string& input,
                                  string* result, string* err) const {
  std::string copy = input;
  uint64_t slash_bits;
  CanonicalizePath(&copy, &slash_bits);
  StringPiece partially_fixed(copy);
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
