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

#include <algorithm>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
#include <direct.h>  // _mkdir
#include <windows.h>

#include <sstream>
#else
#include <unistd.h>
#endif

#include "metrics.h"
#include "util.h"

using namespace std;

namespace {

string DirName(const string& path) {
#ifdef _WIN32
  static const char kPathSeparators[] = "\\/";
#else
  static const char kPathSeparators[] = "/";
#endif
  static const char* const kEnd = kPathSeparators + sizeof(kPathSeparators) - 1;

  string::size_type slash_pos = path.find_last_of(kPathSeparators);
  if (slash_pos == string::npos)
    return string();  // Nothing to do.
  while (slash_pos > 0 &&
         std::find(kPathSeparators, kEnd, path[slash_pos - 1]) != kEnd)
    --slash_pos;
  return path.substr(0, slash_pos);
}

int MakeDir(const string& path) {
#ifdef _WIN32
  return _mkdir(path.c_str());
#else
  return mkdir(path.c_str(), 0777);
#endif
}

#ifdef _WIN32
TimeStamp TimeStampFromFileTime(const FILETIME& filetime) {
  // FILETIME is in 100-nanosecond increments since the Windows epoch.
  // We don't much care about epoch correctness but we do want the
  // resulting value to fit in a 64-bit integer.
  uint64_t mtime = ((uint64_t)filetime.dwHighDateTime << 32) |
    ((uint64_t)filetime.dwLowDateTime);
  // 1600 epoch -> 2000 epoch (subtract 400 years).
  return (TimeStamp)mtime - 12622770400LL * (1000000000LL / 100);
}

TimeStamp StatSingleFile(const string& path, string* err) {
  WIN32_FILE_ATTRIBUTE_DATA attrs;
  if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &attrs)) {
    DWORD win_err = GetLastError();
    if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND)
      return 0;
    *err = "GetFileAttributesEx(" + path + "): " + GetLastErrorString();
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

bool StatAllFilesInDir(const string& dir, map<string, TimeStamp>* stamps,
                       string* err) {
  // FindExInfoBasic is 30% faster than FindExInfoStandard.
  static bool can_use_basic_info = IsWindows7OrLater();
  // This is not in earlier SDKs.
  const FINDEX_INFO_LEVELS kFindExInfoBasic =
      static_cast<FINDEX_INFO_LEVELS>(1);
  FINDEX_INFO_LEVELS level =
      can_use_basic_info ? kFindExInfoBasic : FindExInfoStandard;
  WIN32_FIND_DATAA ffd;
  HANDLE find_handle = FindFirstFileExA((dir + "\\*").c_str(), level, &ffd,
                                        FindExSearchNameMatch, NULL, 0);

  if (find_handle == INVALID_HANDLE_VALUE) {
    DWORD win_err = GetLastError();
    if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND ||
        win_err == ERROR_DIRECTORY)
      return true;
    *err = "FindFirstFileExA(" + dir + "): " + GetLastErrorString();
    return false;
  }
  do {
    string lowername = ffd.cFileName;
    if (lowername == "..") {
      // Seems to just copy the timestamp for ".." from ".", which is wrong.
      // This is the case at least on NTFS under Windows 7.
      continue;
    }
    transform(lowername.begin(), lowername.end(), lowername.begin(), ::tolower);
    stamps->insert(make_pair(lowername,
                             TimeStampFromFileTime(ffd.ftLastWriteTime)));
  } while (FindNextFileA(find_handle, &ffd));
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

// RealDiskInterface -----------------------------------------------------------
RealDiskInterface::RealDiskInterface()
#ifdef _WIN32
: use_cache_(false), long_paths_enabled_(false) {
  // Probe ntdll.dll for RtlAreLongPathsEnabled, and call it if it exists.
  HINSTANCE ntdll_lib = ::GetModuleHandleW(L"ntdll");
  if (ntdll_lib) {
    typedef BOOLEAN(WINAPI FunctionType)();
    auto* func_ptr = FunctionCast<FunctionType*>(
        ::GetProcAddress(ntdll_lib, "RtlAreLongPathsEnabled"));
    if (func_ptr) {
      long_paths_enabled_ = (*func_ptr)();
    }
  }
}
#else
{}
#endif

TimeStamp RealDiskInterface::Stat(const string& path, string* err) const {
  METRIC_RECORD("node stat");
#ifdef _WIN32
  // MSDN: "Naming Files, Paths, and Namespaces"
  // http://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
  if (!path.empty() && !AreLongPathsEnabled() && path[0] != '\\' &&
      path.size() > MAX_PATH) {
    ostringstream err_stream;
    err_stream << "Stat(" << path << "): Filename longer than " << MAX_PATH
               << " characters";
    *err = err_stream.str();
    return -1;
  }
  if (!use_cache_)
    return StatSingleFile(path, err);

  string dir = DirName(path);
  string base(path.substr(dir.size() ? dir.size() + 1 : 0));
  if (base == "..") {
    // StatAllFilesInDir does not report any information for base = "..".
    base = ".";
    dir = path;
  }

  string dir_lowercase = dir;
  transform(dir.begin(), dir.end(), dir_lowercase.begin(), ::tolower);
  transform(base.begin(), base.end(), base.begin(), ::tolower);

  Cache::iterator ci = cache_.find(dir_lowercase);
  if (ci == cache_.end()) {
    ci = cache_.insert(make_pair(dir_lowercase, DirCache())).first;
    if (!StatAllFilesInDir(dir.empty() ? "." : dir, &ci->second, err)) {
      cache_.erase(ci);
      return -1;
    }
  }
  DirCache::iterator di = ci->second.find(base);
  return di != ci->second.end() ? di->second : 0;
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

bool RealDiskInterface::WriteFile(const string& path, const string& contents) {
  FILE* fp = fopen(path.c_str(), "wb");
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

bool RealDiskInterface::MakeDir(const string& path) {
  if (::MakeDir(path) < 0) {
    if (errno == EEXIST) {
      return true;
    }
    Error("mkdir(%s): %s", path.c_str(), strerror(errno));
    return false;
  }
  return true;
}

FileReader::Status RealDiskInterface::ReadFile(const string& path,
                                               string* contents,
                                               string* err) {
  switch (::ReadFile(path, contents, err)) {
  case 0:       return Okay;
  case -ENOENT: return NotFound;
  default:      return OtherError;
  }
}

int RealDiskInterface::RemoveFile(const string& path) {
#ifdef _WIN32
  DWORD attributes = GetFileAttributesA(path.c_str());
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
    SetFileAttributesA(path.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
  }
  if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
    // remove() deletes both files and directories. On Windows we have to
    // select the correct function (DeleteFile will yield Permission Denied when
    // used on a directory)
    // This fixes the behavior of ninja -t clean in some cases
    // https://github.com/ninja-build/ninja/issues/828
    if (!RemoveDirectoryA(path.c_str())) {
      DWORD win_err = GetLastError();
      if (win_err == ERROR_FILE_NOT_FOUND || win_err == ERROR_PATH_NOT_FOUND) {
        return 1;
      }
      // Report remove(), not RemoveDirectory(), for cross-platform consistency.
      Error("remove(%s): %s", path.c_str(), GetLastErrorString().c_str());
      return -1;
    }
  } else {
    if (!DeleteFileA(path.c_str())) {
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
      case ENOTEMPTY:
        Warning("remove(%s) ignored: %s", path.c_str(), strerror(errno));
        return 0;
      default:
        Error("remove(%s): %s", path.c_str(), strerror(errno));
        return -1;
    }
  }
#endif
  return 0;
}

void RealDiskInterface::AllowStatCache(bool allow) {
#ifdef _WIN32
  use_cache_ = allow;
  if (!use_cache_)
    cache_.clear();
#endif
}

#ifdef _WIN32
bool RealDiskInterface::AreLongPathsEnabled(void) const {
  return long_paths_enabled_;
}
#endif
