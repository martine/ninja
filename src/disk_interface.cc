// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "disk_interface.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>

#ifdef _WIN32
#include <direct.h>  // _mkdir
#include <windows.h>

#include <cwctype>
#include <sstream>
#else
#include <unistd.h>
#endif

#include "metrics.h"
#include "util.h"

using namespace std;

namespace {

std::string DirName(const std::string& path) {
#ifdef _WIN32
  auto is_sep = [](char ch) -> bool { return ch == '/' || ch == '\\'; };
#else   // !_WIN32
  auto is_sep = [](char ch) -> bool { return ch == '/'; };
#endif  // !_WIN32
  size_t pos = path.size();
  while (pos > 0 && !is_sep(path[pos - 1]))  // skip non-separators.
    --pos;
  while (pos > 0 && is_sep(path[pos - 1]))  // skip separators.
    --pos;
  return path.substr(0, pos);
}

int MakeDir(const string& path) {
#ifdef _WIN32
  return _wmkdir(UTF8ToWin32Unicode(path).c_str());
#else
  return mkdir(path.c_str(), 0777);
#endif
}

#ifdef _WIN32
std::wstring Win32DirName(const std::wstring& path) {
  auto is_sep = [](wchar_t ch) { return ch == L'/' || ch == L'\\'; };

  size_t pos = path.size();
  while (pos > 0 && !is_sep(path[pos - 1]))
    --pos;

  while (pos > 0 && is_sep(path[pos - 1]))
    --pos;

  return path.substr(0, pos);
}

std::wstring ToLowercase(const std::wstring& path) {
  std::wstring result;
  result.resize(path.size());
  std::transform(path.begin(), path.end(), result.begin(), std::towlower);
  return result;
}

TimeStamp TimeStampFromFileTime(const FILETIME& filetime) {
  // FILETIME is in 100-nanosecond increments since the Windows epoch.
  // We don't much care about epoch correctness but we do want the
  // resulting value to fit in a 64-bit integer.
  uint64_t mtime = ((uint64_t)filetime.dwHighDateTime << 32) |
    ((uint64_t)filetime.dwLowDateTime);
  // 1600 epoch -> 2000 epoch (subtract 400 years).
  return (TimeStamp)mtime - 12622770400LL * (1000000000LL / 100);
}

TimeStamp StatSingleFile(const std::wstring& path, std::string* err) {
  WIN32_FILE_ATTRIBUTE_DATA attrs;
  if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attrs)) {
    DWORD win_err = GetLastError();
    if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND)
      return 0;
    *err = "GetFileAttributesEx(" + Win32UnicodeToUTF8(path) +
           "): " + GetLastErrorString();
    return -1;
  }
  return TimeStampFromFileTime(attrs.ftLastWriteTime);
}

bool IsWindows7OrLater() {
  OSVERSIONINFOEX version_info =
      { sizeof(OSVERSIONINFOEX), 6, 1, 0, 0, {0}, 0, 0, 0, 0, 0};
  DWORDLONG comparison = 0;
  VER_SET_CONDITION(comparison, VER_MAJORVERSION, VER_GREATER_EQUAL);
  VER_SET_CONDITION(comparison, VER_MINORVERSION, VER_GREATER_EQUAL);
  return VerifyVersionInfo(
      &version_info, VER_MAJORVERSION | VER_MINORVERSION, comparison);
}

bool StatAllFilesInDir(const std::wstring& dir,
                       std::map<std::wstring, TimeStamp>* stamps,
                       std::string* err) {
  // FindExInfoBasic is 30% faster than FindExInfoStandard.
  static bool can_use_basic_info = IsWindows7OrLater();
  // This is not in earlier SDKs.
  const FINDEX_INFO_LEVELS kFindExInfoBasic =
      static_cast<FINDEX_INFO_LEVELS>(1);
  FINDEX_INFO_LEVELS level =
      can_use_basic_info ? kFindExInfoBasic : FindExInfoStandard;
  WIN32_FIND_DATAW ffd;
  HANDLE find_handle = FindFirstFileExW((dir + L"\\*").c_str(), level, &ffd,
                                        FindExSearchNameMatch, NULL, 0);

  if (find_handle == INVALID_HANDLE_VALUE) {
    DWORD win_err = GetLastError();
    if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND ||
        win_err == ERROR_DIRECTORY)
      return true;
    *err = "FindFirstFileExW(" + Win32UnicodeToUTF8(dir) +
           "): " + GetLastErrorString();
    return false;
  }
  do {
    std::wstring lowername = ToLowercase(std::wstring(ffd.cFileName));
    if (lowername == L"..") {
      // Seems to just copy the timestamp for ".." from ".", which is wrong.
      // This is the case at least on NTFS under Windows 7.
      continue;
    }
    stamps->insert(make_pair(lowername,
                             TimeStampFromFileTime(ffd.ftLastWriteTime)));
  } while (FindNextFileW(find_handle, &ffd));
  FindClose(find_handle);
  return true;
}
#endif  // _WIN32

}  // namespace

// DiskInterface ---------------------------------------------------------------

bool DiskInterface::MakeDirs(const string& path) {
  string dir = DirName(path);
  if (dir.empty())
    return true;  // Reached root; assume it's there.
  string err;
  TimeStamp mtime = Stat(dir, &err);
  if (mtime < 0) {
    Error("%s", err.c_str());
    return false;
  }
  if (mtime > 0)
    return true;  // Exists already; we're done.

  // Directory doesn't exist.  Try creating its parent first.
  bool success = MakeDirs(dir);
  if (!success)
    return false;
  return MakeDir(dir);
}

// SystemDiskInterface
// -----------------------------------------------------------
SystemDiskInterface::SystemDiskInterface() {
#ifdef _WIN32
  // Probe ntdll.dll for RtlAreLongPathsEnabled, and call it if it exists.
  HINSTANCE ntdll_lib = ::GetModuleHandleW(L"ntdll");
  if (ntdll_lib) {
    typedef BOOLEAN(WINAPI FunctionType)();
    auto* func_ptr = reinterpret_cast<FunctionType*>(
        ::GetProcAddress(ntdll_lib, "RtlAreLongPathsEnabled"));
    if (func_ptr) {
      long_paths_enabled_ = (*func_ptr)();
    }
  }
#endif  // _WIN32
}

TimeStamp SystemDiskInterface::Stat(const string& path, string* err) const {
  METRIC_RECORD("node stat");
#ifdef _WIN32
  // MSDN: "Naming Files, Paths, and Namespaces"
  // http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
  if (!path.empty() && !long_paths_enabled_ && path[0] != '\\' &&
      path.size() > MAX_PATH) {
    *err =
        "Stat(" + path + ": Filename longer than " + std::to_string(MAX_PATH);
    return -1;
  }
  return StatSingleFile(UTF8ToWin32Unicode(path), err);
#else
#ifdef __USE_LARGEFILE64
  struct stat64 st;
  if (stat64(path.c_str(), &st) < 0) {
#else
  struct stat st;
  if (stat(path.c_str(), &st) < 0) {
#endif
    if (errno == ENOENT || errno == ENOTDIR)
      return 0;
    *err = "stat(" + path + "): " + strerror(errno);
    return -1;
  }
  // Some users (Flatpak) set mtime to 0, this should be harmless
  // and avoids conflicting with our return value of 0 meaning
  // that it doesn't exist.
  if (st.st_mtime == 0)
    return 1;
#if defined(_AIX)
  return (int64_t)st.st_mtime * 1000000000LL + st.st_mtime_n;
#elif defined(__APPLE__)
  return ((int64_t)st.st_mtimespec.tv_sec * 1000000000LL +
          st.st_mtimespec.tv_nsec);
#elif defined(st_mtime) // A macro, so we're likely on modern POSIX.
  return (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec;
#else
  return (int64_t)st.st_mtime * 1000000000LL + st.st_mtimensec;
#endif
#endif
}

bool SystemDiskInterface::WriteFile(const string& path,
                                    const string& contents) {
#ifdef _WIN32
  FILE* fp = _wfopen(UTF8ToWin32Unicode(path).c_str(), L"wb");
#else   // !_WIN32
  FILE* fp = fopen(path.c_str(), "wb");
#endif  // !_WIN32
  if (fp == NULL) {
    Error("WriteFile(%s): Unable to create file. %s",
          path.c_str(), strerror(errno));
    return false;
  }

  if (fwrite(contents.data(), 1, contents.length(), fp) < contents.length())  {
    Error("WriteFile(%s): Unable to write to the file. %s",
          path.c_str(), strerror(errno));
    fclose(fp);
    return false;
  }

  if (fclose(fp) == EOF) {
    Error("WriteFile(%s): Unable to close the file. %s",
          path.c_str(), strerror(errno));
    return false;
  }

  return true;
}

bool SystemDiskInterface::MakeDir(const string& path) {
  if (::MakeDir(path) < 0) {
    if (errno == EEXIST) {
      return true;
    }
    Error("mkdir(%s): %s", path.c_str(), strerror(errno));
    return false;
  }
  return true;
}

FileReader::Status SystemDiskInterface::ReadFile(const string& path,
                                                 string* contents,
                                                 string* err) {
  switch (::ReadFile(path, contents, err)) {
  case 0:       return Okay;
  case -ENOENT: return NotFound;
  default:      return OtherError;
  }
}

int SystemDiskInterface::RemoveFile(const string& path) {
#ifdef _WIN32
  std::wstring native_path = UTF8ToWin32Unicode(path);
  DWORD attributes = GetFileAttributesW(native_path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    DWORD win_err = GetLastError();
    if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND) {
      return 1;
    }
  } else if (attributes & FILE_ATTRIBUTE_READONLY) {
    // On non-Windows systems, remove() will happily delete read-only files.
    // On Windows Ninja should behave the same:
    //   https://github.com/ninja-build/ninja/issues/1886
    // Skip error checking.  If this fails, accept whatever happens below.
    SetFileAttributesW(native_path.c_str(),
                       attributes & ~FILE_ATTRIBUTE_READONLY);
  }
  if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
    // remove() deletes both files and directories. On Windows we have to
    // select the correct function (DeleteFile will yield Permission Denied when
    // used on a directory)
    // This fixes the behavior of ninja -t clean in some cases
    // https://github.com/ninja-build/ninja/issues/828
    if (!RemoveDirectoryW(native_path.c_str())) {
      DWORD win_err = GetLastError();
      if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND) {
        return 1;
      }
      // Report remove(), not RemoveDirectory(), for cross-platform consistency.
      Error("remove(%s): %s", path.c_str(), GetLastErrorString().c_str());
      return -1;
    }
  } else {
    if (!DeleteFileW(native_path.c_str())) {
      DWORD win_err = GetLastError();
      if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND) {
        return 1;
      }
      // Report as remove(), not DeleteFile(), for cross-platform consistency.
      Error("remove(%s): %s", path.c_str(), GetLastErrorString().c_str());
      return -1;
    }
  }
#else
  if (remove(path.c_str()) < 0) {
    switch (errno) {
      case ENOENT:
        return 1;
      default:
        Error("remove(%s): %s", path.c_str(), strerror(errno));
        return -1;
    }
  }
#endif
  return 0;
}

FILE* SystemDiskInterface::OpenFile(const std::string& path, const char* mode) {
#ifdef _WIN32
  std::wstring wide_path = UTF8ToWin32Unicode(path);
  std::wstring wide_mode = UTF8ToWin32Unicode(mode);
  return _wfopen(wide_path.c_str(), wide_mode.c_str());
#else   // !_WIN32
  return fopen(path.c_str(), mode);
#endif  // !_WIN32
}

bool SystemDiskInterface::RenameFile(const std::string& from,
                                     const std::string& to) {
#ifdef _WIN32
  std::wstring wide_from = UTF8ToWin32Unicode(from);
  std::wstring wide_to = UTF8ToWin32Unicode(to);
  return !_wrename(wide_from.c_str(), wide_to.c_str());
#else   // !_WIN32
  return !rename(from.c_str(), to.c_str());
#endif  // !_WIN32
}

#ifdef _WIN32
bool SystemDiskInterface::AreLongPathsEnabled(void) const {
  return long_paths_enabled_;
}
#endif

TimeStamp NullDiskInterface::Stat(const std::string& path,
                                  std::string* err) const {
  assert(false);
  return -1;
}

bool NullDiskInterface::WriteFile(const std::string& path,
                                  const std::string& contents) {
  assert(false);
  return true;
}

bool NullDiskInterface::MakeDir(const std::string& path) {
  assert(false);
  errno = EINVAL;
  return false;
}
FileReader::Status NullDiskInterface::ReadFile(const std::string& path,
                                               std::string* contents,
                                               std::string* err) {
  assert(false);
  return NotFound;
}
int NullDiskInterface::RemoveFile(const std::string& path) {
  assert(false);
  return 0;
}

FILE* NullDiskInterface::OpenFile(const std::string& path, const char* mode) {
  assert(false);
  (void)path;
  (void)mode;
  return nullptr;
}

bool NullDiskInterface::RenameFile(const std::string& from,
                                   const std::string& to) {
  assert(false);
  (void)from;
  (void)to;
  return false;
}

void RealDiskInterface::AllowStatCache(bool allow) {
#ifdef _WIN32
  use_cache_ = allow;
  if (!use_cache_)
    cache_.clear();
#else
  (void)allow;
#endif
}

#ifdef _WIN32
TimeStamp RealDiskInterface::Stat(const string& path, string* err) const {
  METRIC_RECORD("node stat");
  // MSDN: "Naming Files, Paths, and Namespaces"
  // http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
  if (!path.empty() && !long_paths_enabled_ && path[0] != '\\' &&
      path.size() > MAX_PATH) {
    *err =
        "Stat(" + path + ": Filename longer than " + std::to_string(MAX_PATH);
    return -1;
  }
  std::wstring native_path = UTF8ToWin32Unicode(path);
  if (!use_cache_)
    return StatSingleFile(native_path, err);

  std::wstring dir = Win32DirName(native_path);
  std::wstring base(native_path.substr(dir.size() ? dir.size() + 1 : 0));
  if (base == L"..") {
    // StatAllFilesInDir does not report any information for base = "..".
    base = L".";
    dir = native_path;
  }

  std::wstring dir_lowercase = ToLowercase(dir);
  base = ToLowercase(base);

  Cache::iterator ci = cache_.find(dir_lowercase);
  if (ci == cache_.end()) {
    ci = cache_.insert(std::make_pair(dir_lowercase, DirCache())).first;
    if (!StatAllFilesInDir(dir.empty() ? L"." : dir, &ci->second, err)) {
      cache_.erase(ci);
      return -1;
    }
  }
  DirCache::iterator di = ci->second.find(base);
  return di != ci->second.end() ? di->second : 0;
}
#endif  // _WIN32
