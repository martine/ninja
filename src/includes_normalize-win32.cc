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

#include <string.h>
#include <windows.h>

#include <algorithm>
#include <iterator>
#include <sstream>

#include "includes_normalize.h"
#include "string_piece.h"
#include "string_piece_util.h"
#include "util.h"

namespace {

// Get the full path of a given filename. On success set |*path| and return
// true. On failure, clear |path|, set |*err| then result false.
bool InternalGetFullPathName(const StringPiece& file_name, std::string* path,
                             std::string* err) {
  // IMPORTANT: Using GetFullPathNameA() with a long paths will fail with
  // "The filename or extension is too long" even if long path supported is
  // enabled. GetFullPathNameW() must be used for this function to work!
#if 1
  path->clear();
  // Convert to wide filename first.
  std::string filename_str = file_name.AsString();
  std::wstring wide_filename;
  if (!ConvertUTF8ToWin32Unicode(filename_str, &wide_filename, err))
    return false;

  // Call GetFullPathNameW()
  DWORD wide_full_size = GetFullPathNameW(wide_filename.c_str(), 0, NULL, NULL);
  if (wide_full_size == 0) {
    *err = "GetFullPathNameW(" +
           std::string(wide_filename.begin(), wide_filename.end()) +
           "): " + GetLastErrorString();
    return false;
  }

  // NOTE: wide_full_size includes the null-terminating character.
  std::wstring wide_path;
  wide_path.resize(static_cast<size_t>(wide_full_size - 1));
  DWORD wide_full_size2 =
      GetFullPathNameW(wide_filename.c_str(), wide_full_size,
                       const_cast<wchar_t*>(wide_path.data()), NULL);
  if (wide_full_size2 == 0) {
    *err = "GetFullPathNameA(" + filename_str + "): " + GetLastErrorString();
    path->clear();
    return false;
  }

  // Convert wide_path to Unicode.
  return ConvertWin32UnicodeToUTF8(wide_path, path, err);
#else
  path->clear();
  std::string filename_str = file_name.AsString();
  DWORD full_size = GetFullPathNameA(filename_str.c_str(), 0, NULL, NULL);
  if (full_size == 0) {
    *err = "GetFullPathNameA(" + filename_str + "): " + GetLastErrorString();
    return false;
  }

  // NOTE: full_size includes the null-terminating character.
  path->resize(static_cast<size_t>(full_size - 1));
  DWORD result2 = GetFullPathNameA(filename_str.c_str(), full_size,
                                   const_cast<char*>(path->data()), NULL);
  if (result2 == 0) {
    *err = "GetFullPathNameA(" + filename_str + "): " + GetLastErrorString();
    return false;
  }

  path->resize(static_cast<size_t>(result2));
  return true;
#endif
}

// Get the drive prefix of a given filename. On success set |*drive| then return
// true. On failure, clear |*drive|, set |*err| then return false.
bool InternalGetDrive(const StringPiece& file_name, std::string* drive,
                      std::string* err) {
  std::string path;
  if (!InternalGetFullPathName(file_name, &path, err))
    return false;

  char drive_buffer[_MAX_DRIVE];
  errno_t ret = _splitpath_s(path.data(), drive_buffer, sizeof(drive_buffer),
                             NULL, 0, NULL, 0, NULL, 0);
  if (ret != 0) {
    *err = "_splitpath_s() returned " + std::string(strerror(ret)) +
           " for path: " + path;
    drive->clear();
    return false;
  }
  drive->assign(drive_buffer);
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

  std::string a_drive;
  std::string b_drive;
  if (!InternalGetDrive(a, &a_drive, err) ||
      !InternalGetDrive(b, &b_drive, err)) {
    return false;
  }
  return _stricmp(a_drive.c_str(), b_drive.c_str()) == 0;
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

  std::string result;
  if (!InternalGetFullPathName(s, &result, err)) {
    return "";
  }
  for (char& c : result) {
    if (c == '\\')
      c = '/';
  }
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
  std::string copy = input;
  uint64_t slash_bits;
  CanonicalizePath(&copy, &slash_bits);
  std::string abs_input = AbsPath(copy, err);
  if (!err->empty())
    return false;

  if (!SameDrive(abs_input, relative_to_, err)) {
    if (!err->empty())
      return false;
    *result = copy;
    return true;
  }
  *result = Relativize(abs_input, split_relative_to_, err);
  if (!err->empty())
    return false;
  return true;
}
