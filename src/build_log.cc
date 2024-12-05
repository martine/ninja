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

// On AIX, inttypes.h gets indirectly included by build_log.h.
// It's easiest just to ask for the printf format macros right away.
#ifndef _WIN32
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#endif

#include "build_log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cassert>

#ifndef _WIN32
#include <inttypes.h>
#include <unistd.h>
#endif

#include "build.h"
#include "graph.h"
#include "metrics.h"
#include "util.h"
#if defined(_MSC_VER) && (_MSC_VER < 1800)
#define strtoll _strtoi64
#endif

using namespace std;

// Implementation details:
// Each run's log appends to the log file.
// To load, we run through all log entries in series, throwing away
// older runs.
// Once the number of redundant entries exceeds a threshold, we write
// out a new file and replace the existing one with it.

namespace {

const char kFileSignature[] = "# ninja log v%d\n";
const int kOldestSupportedVersion = 7;
const int kCurrentVersion = 7;

}  // namespace

// static
uint64_t BuildLog::LogEntry::HashCommand(StringPiece command) {
  return rapidhash(command.str_, command.len_);
}

BuildLog::LogEntry::LogEntry(const string& output)
  : output(output) {}

BuildLog::LogEntry::LogEntry(const string& output, uint64_t command_hash,
  int start_time, int end_time, TimeStamp mtime)
  : output(output), command_hash(command_hash),
    start_time(start_time), end_time(end_time), mtime(mtime)
{}

BuildLog::BuildLog(DiskInterface& disk_interface)
    : disk_interface_(&disk_interface) {}

BuildLog::~BuildLog() {
  Close();
}

bool BuildLog::OpenForWrite(const string& path, const BuildLogUser& user,
                            string* err) {
  if (needs_recompaction_) {
    if (!Recompact(path, user, err))
      return false;
  }

  assert(!log_file_);
  log_file_path_ = path;  // we don't actually open the file right now, but will
                          // do so on the first write attempt
  return true;
}

bool BuildLog::RecordCommand(Edge* edge, int start_time, int end_time,
                             TimeStamp mtime) {
  string command = edge->EvaluateCommand(true);
  uint64_t command_hash = LogEntry::HashCommand(command);
  for (vector<Node*>::iterator out = edge->outputs_.begin();
       out != edge->outputs_.end(); ++out) {
    const string& path = (*out)->path();
    Entries::iterator i = entries_.find(path);
    LogEntry* log_entry;
    if (i != entries_.end()) {
      log_entry = i->second;
    } else {
      log_entry = new LogEntry(path);
      entries_.insert(Entries::value_type(log_entry->output, log_entry));
    }
    log_entry->command_hash = command_hash;
    log_entry->start_time = start_time;
    log_entry->end_time = end_time;
    log_entry->mtime = mtime;

    if (!OpenForWriteIfNeeded()) {
      return false;
    }
    if (log_file_) {
      if (!WriteEntry(log_file_, *log_entry))
        return false;
      if (fflush(log_file_) != 0) {
          return false;
      }
    }
  }
  return true;
}

void BuildLog::Close() {
  OpenForWriteIfNeeded();  // create the file even if nothing has been recorded
  if (log_file_)
    fclose(log_file_);
  log_file_ = NULL;
}

bool BuildLog::OpenForWriteIfNeeded() {
  if (log_file_ || log_file_path_.empty()) {
    return true;
  }
  log_file_ = disk_interface_->OpenFile(log_file_path_, "ab");
  if (!log_file_) {
    return false;
  }
  if (setvbuf(log_file_, NULL, _IOLBF, BUFSIZ) != 0) {
    return false;
  }
  SetCloseOnExec(fileno(log_file_));

  // Opening a file in append mode doesn't set the file pointer to the file's
  // end on Windows. Do that explicitly.
  fseek(log_file_, 0, SEEK_END);

  if (ftell(log_file_) == 0) {
    if (fprintf(log_file_, kFileSignature, kCurrentVersion) < 0) {
      return false;
    }
  }
  return true;
}

struct LineReader {
  explicit LineReader(FILE* file)
    : file_(file), buf_end_(buf_), line_start_(buf_), line_end_(NULL) {
      memset(buf_, 0, sizeof(buf_));
  }

  // Reads a \n-terminated line from the file passed to the constructor.
  // On return, *line_start points to the beginning of the next line, and
  // *line_end points to the \n at the end of the line. If no newline is seen
  // in a fixed buffer size, *line_end is set to NULL. Returns false on EOF.
  bool ReadLine(char** line_start, char** line_end) {
    if (line_start_ >= buf_end_ || !line_end_) {
      // Buffer empty, refill.
      size_t size_read = fread(buf_, 1, sizeof(buf_), file_);
      if (!size_read)
        return false;
      line_start_ = buf_;
      buf_end_ = buf_ + size_read;
    } else {
      // Advance to next line in buffer.
      line_start_ = line_end_ + 1;
    }

    line_end_ = static_cast<char*>(memchr(line_start_, '\n', buf_end_ - line_start_));
    if (!line_end_) {
      // No newline. Move rest of data to start of buffer, fill rest.
      size_t already_consumed = line_start_ - buf_;
      size_t size_rest = (buf_end_ - buf_) - already_consumed;
      memmove(buf_, line_start_, size_rest);

      size_t read = fread(buf_ + size_rest, 1, sizeof(buf_) - size_rest, file_);
      buf_end_ = buf_ + size_rest + read;
      line_start_ = buf_;
      line_end_ = static_cast<char*>(memchr(line_start_, '\n', buf_end_ - line_start_));
    }

    *line_start = line_start_;
    *line_end = line_end_;
    return true;
  }

 private:
  FILE* file_;
  char buf_[256 << 10];
  char* buf_end_;  // Points one past the last valid byte in |buf_|.

  char* line_start_;
  // Points at the next \n in buf_ after line_start, or NULL.
  char* line_end_;
};

LoadStatus BuildLog::Load(const string& path, string* err) {
  METRIC_RECORD(".ninja_log load");
  FILE* file = disk_interface_->OpenFile(path, "r");
  if (!file) {
    if (errno == ENOENT)
      return LOAD_NOT_FOUND;
    *err = strerror(errno);
    return LOAD_ERROR;
  }

  int log_version = 0;
  int unique_entry_count = 0;
  int total_entry_count = 0;

  LineReader reader(file);
  char* line_start = 0;
  char* line_end = 0;
  while (reader.ReadLine(&line_start, &line_end)) {
    if (!log_version) {
      sscanf(line_start, kFileSignature, &log_version);

      bool invalid_log_version = false;
      if (log_version < kOldestSupportedVersion) {
        invalid_log_version = true;
        *err = "build log version is too old; starting over";

      } else if (log_version > kCurrentVersion) {
        invalid_log_version = true;
        *err = "build log version is too new; starting over";
      }
      if (invalid_log_version) {
        fclose(file);
        disk_interface_->RemoveFile(path);
        // Don't report this as a failure. A missing build log will cause
        // us to rebuild the outputs anyway.
        return LOAD_NOT_FOUND;
      }
    }

    // If no newline was found in this chunk, read the next.
    if (!line_end)
      continue;

    const char kFieldSeparator = '\t';

    char* start = line_start;
    char* end = static_cast<char*>(memchr(start, kFieldSeparator, line_end - start));
    if (!end)
      continue;
    *end = 0;

    int start_time = 0, end_time = 0;
    TimeStamp mtime = 0;

    start_time = atoi(start);
    start = end + 1;

    end = static_cast<char*>(memchr(start, kFieldSeparator, line_end - start));
    if (!end)
      continue;
    *end = 0;
    end_time = atoi(start);
    start = end + 1;

    end = static_cast<char*>(memchr(start, kFieldSeparator, line_end - start));
    if (!end)
      continue;
    *end = 0;
    mtime = strtoll(start, NULL, 10);
    start = end + 1;

    end = static_cast<char*>(memchr(start, kFieldSeparator, line_end - start));
    if (!end)
      continue;
    string output = string(start, end - start);

    start = end + 1;
    end = line_end;

    LogEntry* entry;
    Entries::iterator i = entries_.find(output);
    if (i != entries_.end()) {
      entry = i->second;
    } else {
      entry = new LogEntry(output);
      entries_.insert(Entries::value_type(entry->output, entry));
      ++unique_entry_count;
    }
    ++total_entry_count;

    entry->start_time = start_time;
    entry->end_time = end_time;
    entry->mtime = mtime;
    char c = *end; *end = '\0';
    entry->command_hash = (uint64_t)strtoull(start, NULL, 16);
    *end = c;
  }
  fclose(file);

  if (!line_start) {
    return LOAD_SUCCESS; // file was empty
  }

  // Decide whether it's time to rebuild the log:
  // - if we're upgrading versions
  // - if it's getting large
  int kMinCompactionEntryCount = 100;
  int kCompactionRatio = 3;
  if (log_version < kCurrentVersion) {
    needs_recompaction_ = true;
  } else if (total_entry_count > kMinCompactionEntryCount &&
             total_entry_count > unique_entry_count * kCompactionRatio) {
    needs_recompaction_ = true;
  }

  return LOAD_SUCCESS;
}

BuildLog::LogEntry* BuildLog::LookupByOutput(const string& path) {
  Entries::iterator i = entries_.find(path);
  if (i != entries_.end())
    return i->second;
  return NULL;
}

bool BuildLog::WriteEntry(FILE* f, const LogEntry& entry) {
  return fprintf(f, "%d\t%d\t%" PRId64 "\t%s\t%" PRIx64 "\n",
          entry.start_time, entry.end_time, entry.mtime,
          entry.output.c_str(), entry.command_hash) > 0;
}

bool BuildLog::Recompact(const string& path, const BuildLogUser& user,
                         string* err) {
  METRIC_RECORD(".ninja_log recompact");

  Close();
  std::string temp_path = path + ".recompact";
  FILE* f = disk_interface_->OpenFile(temp_path, "wb");
  if (!f) {
    *err = strerror(errno);
    return false;
  }

  if (fprintf(f, kFileSignature, kCurrentVersion) < 0) {
    *err = strerror(errno);
    fclose(f);
    return false;
  }

  vector<StringPiece> dead_outputs;
  for (Entries::iterator i = entries_.begin(); i != entries_.end(); ++i) {
    if (user.IsPathDead(i->first)) {
      dead_outputs.push_back(i->first);
      continue;
    }

    if (!WriteEntry(f, *i->second)) {
      *err = strerror(errno);
      fclose(f);
      return false;
    }
  }

  for (size_t i = 0; i < dead_outputs.size(); ++i)
    entries_.erase(dead_outputs[i]);

  fclose(f);
  if (disk_interface_->RemoveFile(path) < 0) {
    *err = strerror(errno);
    return false;
  }

  if (!disk_interface_->RenameFile(temp_path, path)) {
    *err = strerror(errno);
    return false;
  }

  return true;
}

bool BuildLog::Restat(const StringPiece path, const int output_count,
                      char** outputs, std::string* const err) {
  METRIC_RECORD(".ninja_log restat");

  Close();
  std::string temp_path = path.AsString() + ".restat";
  FILE* f = disk_interface_->OpenFile(temp_path, "wb");
  if (!f) {
    *err = strerror(errno);
    return false;
  }

  if (fprintf(f, kFileSignature, kCurrentVersion) < 0) {
    *err = strerror(errno);
    fclose(f);
    return false;
  }
  for (Entries::iterator i = entries_.begin(); i != entries_.end(); ++i) {
    bool skip = output_count > 0;
    for (int j = 0; j < output_count; ++j) {
      if (i->second->output == outputs[j]) {
        skip = false;
        break;
      }
    }
    if (!skip) {
      const TimeStamp mtime = disk_interface_->Stat(i->second->output, err);
      if (mtime == -1) {
        fclose(f);
        return false;
      }
      i->second->mtime = mtime;
    }

    if (!WriteEntry(f, *i->second)) {
      *err = strerror(errno);
      fclose(f);
      return false;
    }
  }

  fclose(f);
  if (disk_interface_->RemoveFile(path.str_) < 0) {
    *err = strerror(errno);
    return false;
  }

  if (!disk_interface_->RenameFile(temp_path, path.AsString())) {
    *err = strerror(errno);
    return false;
  }

  return true;
}
