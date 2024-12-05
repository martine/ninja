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

#ifndef NINJA_DISK_INTERFACE_H_
#define NINJA_DISK_INTERFACE_H_

#include <map>
#include <string>

#include "timestamp.h"

/// Interface for reading files from disk.  See DiskInterface for details.
/// This base offers the minimum interface needed just to read files.
struct FileReader {
  virtual ~FileReader() {}

  /// Result of ReadFile.
  enum Status {
    Okay,
    NotFound,
    OtherError
  };

  /// Read and store in given string.  On success, return Okay.
  /// On error, return another Status and fill |err|.
  virtual Status ReadFile(const std::string& path, std::string* contents,
                          std::string* err) = 0;
};

/// Interface for accessing the disk.
///
/// Abstract so it can be mocked out for tests.  The real implementation
/// is SystemDiskInterface.
struct DiskInterface: public FileReader {
  /// stat() a file, returning the mtime, or 0 if missing and -1 on
  /// other errors.
  virtual TimeStamp Stat(const std::string& path, std::string* err) const = 0;

  /// Create a directory, returning false on failure.
  virtual bool MakeDir(const std::string& path) = 0;

  /// Create a file, with the specified name and contents
  /// Returns true on success, false on failure
  virtual bool WriteFile(const std::string& path,
                         const std::string& contents) = 0;

  /// Remove the file named @a path. It behaves like 'rm -f path' so no errors
  /// are reported if it does not exists.
  /// @returns 0 if the file has been removed,
  ///          1 if the file does not exist, and
  ///          -1 if an error occurs.
  virtual int RemoveFile(const std::string& path) = 0;

  /// Open new C standard i/o FILE instance for |path|.
  virtual FILE* OpenFile(const std::string& path, const char* mode) = 0;

  /// Rename a file. Return true on success, or false/errno on failure.
  /// NOTE: On Win32, this fails with EEXIST if the destination file already
  /// exists (contrary to the Win32 documentation which states that the error
  /// should be EACCES). On Posix, an existing file is always replaced
  /// (unless trying to rename a file to an existing directory, or a
  /// directory to a file or a non-empty one directory).
  virtual bool RenameFile(const std::string& from, const std::string& to) = 0;

  /// Create all the parent directories for path; like mkdir -p
  /// `basename path`.
  bool MakeDirs(const std::string& path);
};

/// Implementation of DiskInterface that actually hits the disk.
struct SystemDiskInterface : public DiskInterface {
  SystemDiskInterface();
  virtual ~SystemDiskInterface() {}
  TimeStamp Stat(const std::string& path, std::string* err) const override;
  bool MakeDir(const std::string& path) override;
  bool WriteFile(const std::string& path, const std::string& contents) override;
  Status ReadFile(const std::string& path, std::string* contents,
                  std::string* err) override;
  int RemoveFile(const std::string& path) override;
  FILE* OpenFile(const std::string& path, const char* mode) override;
  bool RenameFile(const std::string& from, const std::string& to) override;

#ifdef _WIN32
  /// Whether long paths are enabled.  Only has an effect on Windows.
  bool AreLongPathsEnabled() const;
#endif

 protected:
#ifdef _WIN32
  /// Whether long paths are enabled. Auto-detected by constructor.
  bool long_paths_enabled_ = false;
#endif
};

/// A null DiskInterface implementation that is only useful for tests.
/// All functions do nothing except returning an error. Tests can sub-class
/// this one to add their own method overrides.
struct NullDiskInterface : public DiskInterface {
  TimeStamp Stat(const std::string& path, std::string* err) const override;
  bool WriteFile(const std::string& path, const std::string& contents) override;
  bool MakeDir(const std::string& path) override;
  Status ReadFile(const std::string& path, std::string* contents,
                  std::string* err) override;
  int RemoveFile(const std::string& path) override;
  FILE* OpenFile(const std::string& path, const char* mode) override;
  bool RenameFile(const std::string& from, const std::string& to) override;
};

/// Implementation of SystemDiskInterface that speeds up Stat() calls by using
/// a small cache. Note: the cache is never flushed / updated!!
struct RealDiskInterface : public SystemDiskInterface {
  /// Whether stat information can be cached.  Only has an effect on Windows.
  void AllowStatCache(bool allow);

#ifdef _WIN32
  TimeStamp Stat(const std::string& path, std::string* err) const override;
#endif  // _WIN32

 private:
#ifdef _WIN32
  /// Whether stat information can be cached.
  bool use_cache_ = false;

  typedef std::map<std::wstring, TimeStamp> DirCache;
  // TODO: Neither a map nor a hashmap seems ideal here.  If the statcache
  // works out, come up with a better data structure.
  typedef std::map<std::wstring, DirCache> Cache;
  mutable Cache cache_;
#endif  // _WIN32
};

#endif  // NINJA_DISK_INTERFACE_H_
