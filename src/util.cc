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

#include "util.h"

#ifdef __CYGWIN__
#include <windows.h>
#include <io.h>
#elif defined( _WIN32)
#include <windows.h>
#include <io.h>
#include <share.h>
#include <direct.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#endif

#include <vector>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#elif defined(__SVR4) && defined(__sun)
#include <unistd.h>
#include <sys/loadavg.h>
#elif defined(_AIX) && !defined(__PASE__)
#include <libperfstat.h>
#elif defined(__linux__) || defined(__GLIBC__)
#include <sys/sysinfo.h>
#include <fstream>
#include <map>
#include "string_piece_util.h"
#endif

#if defined(__FreeBSD__)
#include <sys/cpuset.h>
#endif

#include "edit_distance.h"

using namespace std;

void Fatal(const char* msg, ...) {
  va_list ap;
  fprintf(stderr, "ninja: fatal: ");
  va_start(ap, msg);
  vfprintf(stderr, msg, ap);
  va_end(ap);
  fprintf(stderr, "\n");
#ifdef _WIN32
  // On Windows, some tools may inject extra threads.
  // exit() may block on locks held by those threads, so forcibly exit.
  fflush(stderr);
  fflush(stdout);
  ExitProcess(1);
#else
  exit(1);
#endif
}

void Warning(const char* msg, va_list ap) {
  fprintf(stderr, "ninja: warning: ");
  vfprintf(stderr, msg, ap);
  fprintf(stderr, "\n");
}

void Warning(const char* msg, ...) {
  va_list ap;
  va_start(ap, msg);
  Warning(msg, ap);
  va_end(ap);
}

void Error(const char* msg, va_list ap) {
  fprintf(stderr, "ninja: error: ");
  vfprintf(stderr, msg, ap);
  fprintf(stderr, "\n");
}

void Error(const char* msg, ...) {
  va_list ap;
  va_start(ap, msg);
  Error(msg, ap);
  va_end(ap);
}

void Info(const char* msg, va_list ap) {
  fprintf(stdout, "ninja: ");
  vfprintf(stdout, msg, ap);
  fprintf(stdout, "\n");
}

void Info(const char* msg, ...) {
  va_list ap;
  va_start(ap, msg);
  Info(msg, ap);
  va_end(ap);
}

void CanonicalizePath(string* path, uint64_t* slash_bits) {
  size_t len = path->size();
  char* str = 0;
  if (len > 0)
    str = &(*path)[0];
  CanonicalizePath(str, &len, slash_bits);
  path->resize(len);
}

static bool IsPathSeparator(char c) {
#ifdef _WIN32
  return c == '/' || c == '\\';
#else
  return c == '/';
#endif
}

void CanonicalizePath(char* path, size_t* len, uint64_t* slash_bits) {
  // WARNING: this function is performance-critical; please benchmark
  // any changes you make to it.
  if (*len == 0) {
    return;
  }

  char* start = path;
  char* dst = start;
  char* dst_start = dst;
  const char* src = start;
  const char* end = start + *len;
  const char* src_next;

  // For absolute paths, skip the leading directory separator
  // as this one should never be removed from the result.
  if (IsPathSeparator(*src)) {
#ifdef _WIN32
    // Windows network path starts with //
    if (src + 2 <= end && IsPathSeparator(src[1])) {
      src += 2;
      dst += 2;
    } else {
      ++src;
      ++dst;
    }
#else
    ++src;
    ++dst;
#endif
    dst_start = dst;
  } else {
    // For relative paths, skip any leading ../ as these are quite common
    // to reference source files in build plans, and doing this here makes
    // the loop work below faster in general.
    while (src + 3 <= end && src[0] == '.' && src[1] == '.' &&
           IsPathSeparator(src[2])) {
      src += 3;
      dst += 3;
    }
  }

  // Loop over all components of the paths _except_ the last one, in
  // order to simplify the loop's code and make it faster.
  int component_count = 0;
  char* dst0 = dst;
  for (; src < end; src = src_next) {
#ifndef _WIN32
    // Use memchr() for faster lookups thanks to optimized C library
    // implementation. `hyperfine canon_perftest` shows a significant
    // difference (e,g, 484ms vs 437ms).
    const char* next_sep =
        static_cast<const char*>(::memchr(src, '/', end - src));
    if (!next_sep) {
      // This is the last component, will be handled out of the loop.
      break;
    }
#else
    // Need to check for both '/' and '\\' so do not use memchr().
    // Cannot use strpbrk() because end[0] can be \0 or something else!
    const char* next_sep = src;
    while (next_sep != end && !IsPathSeparator(*next_sep))
      ++next_sep;
    if (next_sep == end) {
      // This is the last component, will be handled out of the loop.
      break;
    }
#endif
    // Position for next loop iteration.
    src_next = next_sep + 1;
    // Length of the component, excluding trailing directory.
    size_t component_len = next_sep - src;

    if (component_len <= 2) {
      if (component_len == 0) {
        continue;  // Ignore empty component, e.g. 'foo//bar' -> 'foo/bar'.
      }
      if (src[0] == '.') {
        if (component_len == 1) {
          continue;  // Ignore '.' component, e.g. './foo' -> 'foo'.
        } else if (src[1] == '.') {
          // Process the '..' component if found. Back up if possible.
          if (component_count > 0) {
            // Move back to start of previous component.
            --component_count;
            while (--dst > dst0 && !IsPathSeparator(dst[-1])) {
              // nothing to do here, decrement happens before condition check.
            }
          } else {
            dst[0] = '.';
            dst[1] = '.';
            dst[2] = src[2];
            dst += 3;
          }
          continue;
        }
      }
    }
    ++component_count;

    // Copy or skip component, including trailing directory separator.
    if (dst != src) {
      ::memmove(dst, src, src_next - src);
    }
    dst += src_next - src;
  }

  // Handling the last component that does not have a trailing separator.
  // The logic here is _slightly_ different since there is no trailing
  // directory separator.
  size_t component_len = end - src;
  do {
    if (component_len == 0)
      break;  // Ignore empty component (e.g. 'foo//' -> 'foo/')
    if (src[0] == '.') {
      if (component_len == 1)
        break;  // Ignore trailing '.' (e.g. 'foo/.' -> 'foo/')
      if (component_len == 2 && src[1] == '.') {
        // Handle '..'. Back up if possible.
        if (component_count > 0) {
          while (--dst > dst0 && !IsPathSeparator(dst[-1])) {
            // nothing to do here, decrement happens before condition check.
          }
        } else {
          dst[0] = '.';
          dst[1] = '.';
          dst += 2;
          // No separator to add here.
        }
        break;
      }
    }
    // Skip or copy last component, no trailing separator.
    if (dst != src) {
      ::memmove(dst, src, component_len);
    }
    dst += component_len;
  } while (0);

  // Remove trailing path separator if any, but keep the initial
  // path separator(s) if there was one (or two on Windows).
  if (dst > dst_start && IsPathSeparator(dst[-1]))
    dst--;

  if (dst == start) {
    // Handle special cases like "aa/.." -> "."
    *dst++ = '.';
  }

  *len = dst - start;  // dst points after the trailing char here.
#ifdef _WIN32
  uint64_t bits = 0;
  uint64_t bits_mask = 1;

  for (char* c = start; c < start + *len; ++c) {
    switch (*c) {
      case '\\':
        bits |= bits_mask;
        *c = '/';
        NINJA_FALLTHROUGH;
      case '/':
        bits_mask <<= 1;
    }
  }

  *slash_bits = bits;
#else
  *slash_bits = 0;
#endif
}

static inline bool IsKnownShellSafeCharacter(char ch) {
  if ('A' <= ch && ch <= 'Z') return true;
  if ('a' <= ch && ch <= 'z') return true;
  if ('0' <= ch && ch <= '9') return true;

  switch (ch) {
    case '_':
    case '+':
    case '-':
    case '.':
    case '/':
      return true;
    default:
      return false;
  }
}

static inline bool IsKnownWin32SafeCharacter(char ch) {
  switch (ch) {
    case ' ':
    case '"':
      return false;
    default:
      return true;
  }
}

static inline bool StringNeedsShellEscaping(const string& input) {
  for (size_t i = 0; i < input.size(); ++i) {
    if (!IsKnownShellSafeCharacter(input[i])) return true;
  }
  return false;
}

static inline bool StringNeedsWin32Escaping(const string& input) {
  for (size_t i = 0; i < input.size(); ++i) {
    if (!IsKnownWin32SafeCharacter(input[i])) return true;
  }
  return false;
}

void GetShellEscapedString(const string& input, string* result) {
  assert(result);

  if (!StringNeedsShellEscaping(input)) {
    result->append(input);
    return;
  }

  const char kQuote = '\'';
  const char kEscapeSequence[] = "'\\'";

  result->push_back(kQuote);

  string::const_iterator span_begin = input.begin();
  for (string::const_iterator it = input.begin(), end = input.end(); it != end;
       ++it) {
    if (*it == kQuote) {
      result->append(span_begin, it);
      result->append(kEscapeSequence);
      span_begin = it;
    }
  }
  result->append(span_begin, input.end());
  result->push_back(kQuote);
}


void GetWin32EscapedString(const string& input, string* result) {
  assert(result);
  if (!StringNeedsWin32Escaping(input)) {
    result->append(input);
    return;
  }

  const char kQuote = '"';
  const char kBackslash = '\\';

  result->push_back(kQuote);
  size_t consecutive_backslash_count = 0;
  string::const_iterator span_begin = input.begin();
  for (string::const_iterator it = input.begin(), end = input.end(); it != end;
       ++it) {
    switch (*it) {
      case kBackslash:
        ++consecutive_backslash_count;
        break;
      case kQuote:
        result->append(span_begin, it);
        result->append(consecutive_backslash_count + 1, kBackslash);
        span_begin = it;
        consecutive_backslash_count = 0;
        break;
      default:
        consecutive_backslash_count = 0;
        break;
    }
  }
  result->append(span_begin, input.end());
  result->append(consecutive_backslash_count, kBackslash);
  result->push_back(kQuote);
}

int ReadFile(const string& path, string* contents, string* err) {
#ifdef _WIN32
  // This makes a ninja run on a set of 1500 manifest files about 4% faster
  // than using the generic fopen code below.
  err->clear();
  HANDLE f = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
  if (f == INVALID_HANDLE_VALUE) {
    err->assign(GetLastErrorString());
    return -ENOENT;
  }

  for (;;) {
    DWORD len;
    char buf[64 << 10];
    if (!::ReadFile(f, buf, sizeof(buf), &len, NULL)) {
      err->assign(GetLastErrorString());
      contents->clear();
      ::CloseHandle(f);
      return -EIO;
    }
    if (len == 0)
      break;
    contents->append(buf, len);
  }
  ::CloseHandle(f);
  return 0;
#else
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) {
    err->assign(strerror(errno));
    return -errno;
  }

#ifdef __USE_LARGEFILE64
  struct stat64 st;
  if (fstat64(fileno(f), &st) < 0) {
#else
  struct stat st;
  if (fstat(fileno(f), &st) < 0) {
#endif
    err->assign(strerror(errno));
    fclose(f);
    return -errno;
  }

  // +1 is for the resize in ManifestParser::Load
  contents->reserve(st.st_size + 1);

  char buf[64 << 10];
  size_t len;
  while (!feof(f) && (len = fread(buf, 1, sizeof(buf), f)) > 0) {
    contents->append(buf, len);
  }
  if (ferror(f)) {
    err->assign(strerror(errno));  // XXX errno?
    contents->clear();
    fclose(f);
    return -errno;
  }
  fclose(f);
  return 0;
#endif
}

void SetCloseOnExec(int fd) {
#ifndef _WIN32
  int flags = fcntl(fd, F_GETFD);
  if (flags < 0) {
    perror("fcntl(F_GETFD)");
  } else {
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
      perror("fcntl(F_SETFD)");
  }
#else
  HANDLE hd = (HANDLE) _get_osfhandle(fd);
  if (! SetHandleInformation(hd, HANDLE_FLAG_INHERIT, 0)) {
    fprintf(stderr, "SetHandleInformation(): %s", GetLastErrorString().c_str());
  }
#endif  // ! _WIN32
}


const char* SpellcheckStringV(const string& text,
                              const vector<const char*>& words) {
  const bool kAllowReplacements = true;
  const int kMaxValidEditDistance = 3;

  int min_distance = kMaxValidEditDistance + 1;
  const char* result = NULL;
  for (vector<const char*>::const_iterator i = words.begin();
       i != words.end(); ++i) {
    int distance = EditDistance(*i, text, kAllowReplacements,
                                kMaxValidEditDistance);
    if (distance < min_distance) {
      min_distance = distance;
      result = *i;
    }
  }
  return result;
}

const char* SpellcheckString(const char* text, ...) {
  // Note: This takes a const char* instead of a string& because using
  // va_start() with a reference parameter is undefined behavior.
  va_list ap;
  va_start(ap, text);
  vector<const char*> words;
  const char* word;
  while ((word = va_arg(ap, const char*)))
    words.push_back(word);
  va_end(ap);
  return SpellcheckStringV(text, words);
}

#ifdef _WIN32
string GetLastErrorString() {
  DWORD err = GetLastError();

  char* msg_buf;
  FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
        (char*)&msg_buf,
        0,
        NULL);

  if (msg_buf == nullptr) {
    char fallback_msg[128] = {0};
    snprintf(fallback_msg, sizeof(fallback_msg), "GetLastError() = %lu", err);
    return fallback_msg;
  }

  string msg = msg_buf;
  LocalFree(msg_buf);
  return msg;
}

void Win32Fatal(const char* function, const char* hint) {
  if (hint) {
    Fatal("%s: %s (%s)", function, GetLastErrorString().c_str(), hint);
  } else {
    Fatal("%s: %s", function, GetLastErrorString().c_str());
  }
}
#endif

bool islatinalpha(int c) {
  // isalpha() is locale-dependent.
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

string StripAnsiEscapeCodes(const string& in) {
  string stripped;
  stripped.reserve(in.size());

  for (size_t i = 0; i < in.size(); ++i) {
    if (in[i] != '\33') {
      // Not an escape code.
      stripped.push_back(in[i]);
      continue;
    }

    // Only strip CSIs for now.
    if (i + 1 >= in.size()) break;
    if (in[i + 1] != '[') continue;  // Not a CSI.
    i += 2;

    // Skip everything up to and including the next [a-zA-Z].
    while (i < in.size() && !islatinalpha(in[i]))
      ++i;
  }
  return stripped;
}

#if defined(__linux__) || defined(__GLIBC__)
std::pair<int64_t, bool> readCount(const std::string& path) {
  std::ifstream file(path.c_str());
  if (!file.is_open())
    return std::make_pair(0, false);
  int64_t n = 0;
  file >> n;
  if (file.good())
    return std::make_pair(n, true);
  return std::make_pair(0, false);
}

struct MountPoint {
  int mountId;
  int parentId;
  StringPiece deviceId;
  StringPiece root;
  StringPiece mountPoint;
  vector<StringPiece> options;
  vector<StringPiece> optionalFields;
  StringPiece fsType;
  StringPiece mountSource;
  vector<StringPiece> superOptions;
  bool parse(const string& line) {
    vector<StringPiece> pieces = SplitStringPiece(line, ' ');
    if (pieces.size() < 10)
      return false;
    size_t optionalStart = 0;
    for (size_t i = 6; i < pieces.size(); i++) {
      if (pieces[i] == "-") {
        optionalStart = i + 1;
        break;
      }
    }
    if (optionalStart == 0)
      return false;
    if (optionalStart + 3 != pieces.size())
      return false;
    mountId = atoi(pieces[0].AsString().c_str());
    parentId = atoi(pieces[1].AsString().c_str());
    deviceId = pieces[2];
    root = pieces[3];
    mountPoint = pieces[4];
    options = SplitStringPiece(pieces[5], ',');
    optionalFields =
        vector<StringPiece>(&pieces[6], &pieces[optionalStart - 1]);
    fsType = pieces[optionalStart];
    mountSource = pieces[optionalStart + 1];
    superOptions = SplitStringPiece(pieces[optionalStart + 2], ',');
    return true;
  }
  string translate(string& path) const {
    // path must be sub dir of root
    if (path.compare(0, root.len_, root.str_, root.len_) != 0) {
      return string();
    }
    path.erase(0, root.len_);
    if (path == ".." || (path.length() > 2 && path.compare(0, 3, "../") == 0)) {
      return string();
    }
    return mountPoint.AsString() + "/" + path;
  }
};

struct CGroupSubSys {
  int id;
  string name;
  vector<string> subsystems;
  bool parse(string& line) {
    size_t first = line.find(':');
    if (first == string::npos)
      return false;
    line[first] = '\0';
    size_t second = line.find(':', first + 1);
    if (second == string::npos)
      return false;
    line[second] = '\0';
    id = atoi(line.c_str());
    name = line.substr(second + 1);
    vector<StringPiece> pieces =
        SplitStringPiece(StringPiece(line.c_str() + first + 1), ',');
    for (size_t i = 0; i < pieces.size(); i++) {
      subsystems.push_back(pieces[i].AsString());
    }
    return true;
  }
};

map<string, string> ParseMountInfo(map<string, CGroupSubSys>& subsystems) {
  map<string, string> cgroups;
  ifstream mountinfo("/proc/self/mountinfo");
  if (!mountinfo.is_open())
    return cgroups;
  while (!mountinfo.eof()) {
    string line;
    getline(mountinfo, line);
    MountPoint mp;
    if (!mp.parse(line))
      continue;
    if (mp.fsType != "cgroup")
      continue;
    for (size_t i = 0; i < mp.superOptions.size(); i++) {
      string opt = mp.superOptions[i].AsString();
      map<string, CGroupSubSys>::iterator subsys = subsystems.find(opt);
      if (subsys == subsystems.end())
        continue;
      string newPath = mp.translate(subsys->second.name);
      if (!newPath.empty())
        cgroups.insert(make_pair(opt, newPath));
    }
  }
  return cgroups;
}

map<string, CGroupSubSys> ParseSelfCGroup() {
  map<string, CGroupSubSys> cgroups;
  ifstream cgroup("/proc/self/cgroup");
  if (!cgroup.is_open())
    return cgroups;
  string line;
  while (!cgroup.eof()) {
    getline(cgroup, line);
    CGroupSubSys subsys;
    if (!subsys.parse(line))
      continue;
    for (size_t i = 0; i < subsys.subsystems.size(); i++) {
      cgroups.insert(make_pair(subsys.subsystems[i], subsys));
    }
  }
  return cgroups;
}

int ParseCPUFromCGroup() {
  map<string, CGroupSubSys> subsystems = ParseSelfCGroup();
  map<string, string> cgroups = ParseMountInfo(subsystems);
  map<string, string>::iterator cpu = cgroups.find("cpu");
  if (cpu == cgroups.end())
    return -1;
  std::pair<int64_t, bool> quota = readCount(cpu->second + "/cpu.cfs_quota_us");
  if (!quota.second || quota.first == -1)
    return -1;
  std::pair<int64_t, bool> period =
      readCount(cpu->second + "/cpu.cfs_period_us");
  if (!period.second)
    return -1;
  if (period.first == 0)
    return -1;
  return quota.first / period.first;
}
#endif

int GetProcessorCount() {
#ifdef _WIN32
  DWORD cpuCount = 0;
#ifndef _WIN64
  // Need to use GetLogicalProcessorInformationEx to get real core count on
  // machines with >64 cores. See https://stackoverflow.com/a/31209344/21475
  DWORD len = 0;
  if (!GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len)
        && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
    std::vector<char> buf(len);
    int cores = 0;
    if (GetLogicalProcessorInformationEx(RelationProcessorCore,
          reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
            buf.data()), &len)) {
      for (DWORD i = 0; i < len; ) {
        auto info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
            buf.data() + i);
        if (info->Relationship == RelationProcessorCore &&
            info->Processor.GroupCount == 1) {
          for (KAFFINITY core_mask = info->Processor.GroupMask[0].Mask;
               core_mask; core_mask >>= 1) {
            cores += (core_mask & 1);
          }
        }
        i += info->Size;
      }
      if (cores != 0) {
        cpuCount = cores;
      }
    }
  }
#endif
  if (cpuCount == 0) {
    cpuCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
  }
  JOBOBJECT_CPU_RATE_CONTROL_INFORMATION info;
  // reference:
  // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information
  if (QueryInformationJobObject(NULL, JobObjectCpuRateControlInformation, &info,
                                sizeof(info), NULL)) {
    if (info.ControlFlags & (JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                             JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP)) {
      return cpuCount * info.CpuRate / 10000;
    }
  }
  return cpuCount;
#else
  int cgroupCount = -1;
  int schedCount = -1;
#if defined(__linux__) || defined(__GLIBC__)
  cgroupCount = ParseCPUFromCGroup();
#endif
  // The number of exposed processors might not represent the actual number of
  // processors threads can run on. This happens when a CPU set limitation is
  // active, see https://github.com/ninja-build/ninja/issues/1278
#if defined(__FreeBSD__)
  cpuset_t mask;
  CPU_ZERO(&mask);
  if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(mask),
    &mask) == 0) {
    return CPU_COUNT(&mask);
  }
#elif defined(CPU_COUNT)
  cpu_set_t set;
  if (sched_getaffinity(getpid(), sizeof(set), &set) == 0) {
    schedCount = CPU_COUNT(&set);
  }
#endif
  if (cgroupCount >= 0 && schedCount >= 0) return std::min(cgroupCount, schedCount);
  if (cgroupCount < 0 && schedCount < 0) return sysconf(_SC_NPROCESSORS_ONLN);
  return std::max(cgroupCount, schedCount);
#endif
}

#if defined(_WIN32) || defined(__CYGWIN__)
static double CalculateProcessorLoad(uint64_t idle_ticks, uint64_t total_ticks)
{
  static uint64_t previous_idle_ticks = 0;
  static uint64_t previous_total_ticks = 0;
  static double previous_load = -0.0;

  uint64_t idle_ticks_since_last_time = idle_ticks - previous_idle_ticks;
  uint64_t total_ticks_since_last_time = total_ticks - previous_total_ticks;

  bool first_call = (previous_total_ticks == 0);
  bool ticks_not_updated_since_last_call = (total_ticks_since_last_time == 0);

  double load;
  if (first_call || ticks_not_updated_since_last_call) {
    load = previous_load;
  } else {
    // Calculate load.
    double idle_to_total_ratio =
        ((double)idle_ticks_since_last_time) / total_ticks_since_last_time;
    double load_since_last_call = 1.0 - idle_to_total_ratio;

    // Filter/smooth result when possible.
    if(previous_load > 0) {
      load = 0.9 * previous_load + 0.1 * load_since_last_call;
    } else {
      load = load_since_last_call;
    }
  }

  previous_load = load;
  previous_total_ticks = total_ticks;
  previous_idle_ticks = idle_ticks;

  return load;
}

static uint64_t FileTimeToTickCount(const FILETIME & ft)
{
  uint64_t high = (((uint64_t)(ft.dwHighDateTime)) << 32);
  uint64_t low  = ft.dwLowDateTime;
  return (high | low);
}

double GetLoadAverage() {
  FILETIME idle_time, kernel_time, user_time;
  BOOL get_system_time_succeeded =
      GetSystemTimes(&idle_time, &kernel_time, &user_time);

  double posix_compatible_load;
  if (get_system_time_succeeded) {
    uint64_t idle_ticks = FileTimeToTickCount(idle_time);

    // kernel_time from GetSystemTimes already includes idle_time.
    uint64_t total_ticks =
        FileTimeToTickCount(kernel_time) + FileTimeToTickCount(user_time);

    double processor_load = CalculateProcessorLoad(idle_ticks, total_ticks);
    posix_compatible_load = processor_load * GetProcessorCount();

  } else {
    posix_compatible_load = -0.0;
  }

  return posix_compatible_load;
}
#elif defined(__PASE__)
double GetLoadAverage() {
  return -0.0f;
}
#elif defined(_AIX)
double GetLoadAverage() {
  perfstat_cpu_total_t cpu_stats;
  if (perfstat_cpu_total(NULL, &cpu_stats, sizeof(cpu_stats), 1) < 0) {
    return -0.0f;
  }

  // Calculation taken from comment in libperfstats.h
  return double(cpu_stats.loadavg[0]) / double(1 << SBITS);
}
#elif defined(__UCLIBC__) || (defined(__BIONIC__) && __ANDROID_API__ < 29)
double GetLoadAverage() {
  struct sysinfo si;
  if (sysinfo(&si) != 0)
    return -0.0f;
  return 1.0 / (1 << SI_LOAD_SHIFT) * si.loads[0];
}
#elif defined(__HAIKU__)
double GetLoadAverage() {
    return -0.0f;
}
#else
double GetLoadAverage() {
  double loadavg[3] = { 0.0f, 0.0f, 0.0f };
  if (getloadavg(loadavg, 3) < 0) {
    // Maybe we should return an error here or the availability of
    // getloadavg(3) should be checked when ninja is configured.
    return -0.0f;
  }
  return loadavg[0];
}
#endif // _WIN32

std::string GetWorkingDirectory() {
  std::string ret;
  char* success = NULL;
  do {
    ret.resize(ret.size() + 1024);
    errno = 0;
    success = getcwd(&ret[0], ret.size());
  } while (!success && errno == ERANGE);
  if (!success) {
    Fatal("cannot determine working directory: %s", strerror(errno));
  }
  ret.resize(strlen(&ret[0]));
  return ret;
}

bool Truncate(const string& path, size_t size, string* err) {
#ifdef _WIN32
  int fh = _sopen(path.c_str(), _O_RDWR | _O_CREAT, _SH_DENYNO,
                  _S_IREAD | _S_IWRITE);
  int success = _chsize(fh, size);
  _close(fh);
#else
  int success = truncate(path.c_str(), size);
#endif
  // Both truncate() and _chsize() return 0 on success and set errno and return
  // -1 on failure.
  if (success < 0) {
    *err = strerror(errno);
    return false;
  }
  return true;
}

// Helper function to compute a simple hash
unsigned int simpleHash(const char* str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// Method to check and truncate file names if necessary
int checkFileName(const char* inPath, char* outPath) {
#ifdef _WIN32
  static const unsigned int kPathSeparators = '\\';
#else
  static const unsigned int kPathSeparators = '/';
#endif
  // Extract the base name (file name) from the full path
  const char* baseName = strrchr(inPath, kPathSeparators);
  if (!baseName) {
        baseName = inPath; // No directory separator found, use full string
    } else {
        baseName++; // Skip the separator
    }

  // Check the length of the file name
  size_t baseNameLen = strlen(baseName);
  if (baseNameLen <= MAX_FILENAME_SIZE) {
    strcpy(outPath, inPath); // File name is within limit, copy directly
    return 0;
  }

  // Truncate the file name if it exceeds MAX_FILENAME_SIZE
  size_t dirLen = baseName - inPath; // Length of the directory part
  strncpy(outPath, inPath, dirLen); // Copy the directory part
  outPath[dirLen] = '\0';

  // Compute a simple hash for the base name
  unsigned int hash = simpleHash(baseName);

  // Generate the truncated file name
  snprintf(outPath + dirLen, MAX_FILENAME_SIZE + 1, "%.8x_%s", hash,
           baseName + (baseNameLen - (MAX_FILENAME_SIZE - HASH_SIZE_LEN - 2)));

  return 1; // Indicate that the file name was truncated
}
