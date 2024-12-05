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

#include "deps_log.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#elif defined(_MSC_VER) && (_MSC_VER < 1900)
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
#endif

#include "graph.h"
#include "metrics.h"
#include "state.h"
#include "util.h"

using namespace std;

// The version is stored as 4 bytes after the signature and also serves as a
// byte order mark. Signature and version combined are 16 bytes long.
static const char kFileSignature[] = "# ninjadeps\n";
static const size_t kFileSignatureSize = sizeof(kFileSignature) - 1u;

static const int32_t kCurrentVersion = 4;

// Record size is currently limited to less than the full 32 bit, due to
// internal buffers having to have this size.
static constexpr size_t kMaxRecordSize = (1 << 19) - 1;

DepsLog::DepsLog(DiskInterface& disk_interface)
    : disk_interface_(&disk_interface) {}

DepsLog::~DepsLog() {
  Close();
}

bool DepsLog::OpenForWrite(const string& path, string* err) {
  if (needs_recompaction_) {
    if (!Recompact(path, err))
      return false;
  }

  assert(!file_);
  file_path_ = path;  // we don't actually open the file right now, but will do
                      // so on the first write attempt
  return true;
}

bool DepsLog::RecordDeps(Node* node, TimeStamp mtime,
                         const vector<Node*>& nodes) {
  return RecordDeps(node, mtime, nodes.size(), nodes.data());
}

bool DepsLog::RecordDeps(Node* node, TimeStamp mtime, int node_count,
                         Node* const* nodes) {
  // Track whether there's any new data to be recorded.
  bool made_change = false;

  // Assign ids to all nodes that are missing one.
  if (node->id() < 0) {
    if (!RecordId(node))
      return false;
    made_change = true;
  }
  for (int i = 0; i < node_count; ++i) {
    if (nodes[i]->id() < 0) {
      if (!RecordId(nodes[i]))
        return false;
      made_change = true;
    }
  }

  // See if the new data is different than the existing data, if any.
  if (!made_change) {
    Deps* deps = GetDeps(node);
    if (!deps ||
        deps->mtime != mtime ||
        deps->node_count != node_count) {
      made_change = true;
    } else {
      for (int i = 0; i < node_count; ++i) {
        if (deps->nodes[i] != nodes[i]) {
          made_change = true;
          break;
        }
      }
    }
  }

  // Don't write anything if there's no new info.
  if (!made_change)
    return true;

  // Update on-disk representation.
  unsigned size = 4 * (1 + 2 + node_count);
  if (size > kMaxRecordSize) {
    errno = ERANGE;
    return false;
  }

  if (!OpenForWriteIfNeeded()) {
    return false;
  }
  size |= 0x80000000;  // Deps record: set high bit.
  if (fwrite(&size, 4, 1, file_) < 1)
    return false;
  int id = node->id();
  if (fwrite(&id, 4, 1, file_) < 1)
    return false;
  uint32_t mtime_part = static_cast<uint32_t>(mtime & 0xffffffff);
  if (fwrite(&mtime_part, 4, 1, file_) < 1)
    return false;
  mtime_part = static_cast<uint32_t>((mtime >> 32) & 0xffffffff);
  if (fwrite(&mtime_part, 4, 1, file_) < 1)
    return false;
  for (int i = 0; i < node_count; ++i) {
    id = nodes[i]->id();
    if (fwrite(&id, 4, 1, file_) < 1)
      return false;
  }
  if (fflush(file_) != 0)
    return false;

  // Update in-memory representation.
  Deps* deps = new Deps(mtime, node_count);
  for (int i = 0; i < node_count; ++i)
    deps->nodes[i] = nodes[i];
  UpdateDeps(node->id(), deps);

  return true;
}

void DepsLog::Close() {
  OpenForWriteIfNeeded();  // create the file even if nothing has been recorded
  if (file_)
    fclose(file_);
  file_ = NULL;
}

LoadStatus DepsLog::Load(const string& path, State* state, string* err) {
  METRIC_RECORD(".ninja_deps load");
  char buf[kMaxRecordSize + 1];
  FILE* f = disk_interface_->OpenFile(path, "rb");
  if (!f) {
    if (errno == ENOENT)
      return LOAD_NOT_FOUND;
    *err = strerror(errno);
    return LOAD_ERROR;
  }

  bool valid_header = fread(buf, kFileSignatureSize, 1, f) == 1 &&
                      !memcmp(buf, kFileSignature, kFileSignatureSize);

  int32_t version = 0;
  bool valid_version =
      fread(&version, 4, 1, f) == 1 && version == kCurrentVersion;

  // Note: For version differences, this should migrate to the new format.
  // But the v1 format could sometimes (rarely) end up with invalid data, so
  // don't migrate v1 to v3 to force a rebuild. (v2 only existed for a few days,
  // and there was no release with it, so pretend that it never happened.)
  if (!valid_header || !valid_version) {
    if (version == 1)
      *err = "deps log version change; rebuilding";
    else
      *err = "bad deps log signature or version; starting over";
    fclose(f);
    disk_interface_->RemoveFile(path);
    // Don't report this as a failure.  An empty deps log will cause
    // us to rebuild the outputs anyway.
    return LOAD_SUCCESS;
  }

  long offset = ftell(f);
  bool read_failed = false;
  int unique_dep_record_count = 0;
  int total_dep_record_count = 0;
  for (;;) {
    unsigned size;
    if (fread(&size, sizeof(size), 1, f) < 1) {
      if (!feof(f))
        read_failed = true;
      break;
    }
    bool is_deps = (size >> 31) != 0;
    size = size & 0x7FFFFFFF;

    if (size > kMaxRecordSize || fread(buf, size, 1, f) < 1) {
      read_failed = true;
      break;
    }
    offset += size + sizeof(size);

    if (is_deps) {
      if ((size % 4) != 0) {
        read_failed = true;
        break;
      }
      int* deps_data = reinterpret_cast<int*>(buf);
      int out_id = deps_data[0];
      TimeStamp mtime;
      mtime = (TimeStamp)(((uint64_t)(unsigned int)deps_data[2] << 32) |
                          (uint64_t)(unsigned int)deps_data[1]);
      deps_data += 3;
      int deps_count = (size / 4) - 3;

      for (int i = 0; i < deps_count; ++i) {
        int node_id = deps_data[i];
        if (node_id >= (int)nodes_.size() || !nodes_[node_id]) {
          read_failed = true;
          break;
        }
      }
      if (read_failed)
        break;

      Deps* deps = new Deps(mtime, deps_count);
      for (int i = 0; i < deps_count; ++i) {
        deps->nodes[i] = nodes_[deps_data[i]];
      }

      total_dep_record_count++;
      if (!UpdateDeps(out_id, deps))
        ++unique_dep_record_count;
    } else {
      int path_size = size - 4;
      if (path_size <= 0) {
        read_failed = true;
        break;
      }
      // There can be up to 3 bytes of padding.
      if (buf[path_size - 1] == '\0') --path_size;
      if (buf[path_size - 1] == '\0') --path_size;
      if (buf[path_size - 1] == '\0') --path_size;
      StringPiece subpath(buf, path_size);
      // It is not necessary to pass in a correct slash_bits here. It will
      // either be a Node that's in the manifest (in which case it will already
      // have a correct slash_bits that GetNode will look up), or it is an
      // implicit dependency from a .d which does not affect the build command
      // (and so need not have its slashes maintained).
      Node* node = state->GetNode(subpath, 0);

      // Check that the expected index matches the actual index. This can only
      // happen if two ninja processes write to the same deps log concurrently.
      // (This uses unary complement to make the checksum look less like a
      // dependency record entry.)
      unsigned checksum = *reinterpret_cast<unsigned*>(buf + size - 4);
      int expected_id = ~checksum;
      int id = nodes_.size();
      if (id != expected_id || node->id() >= 0) {
        read_failed = true;
        break;
      }
      node->set_id(id);
      nodes_.push_back(node);
    }
  }

  if (read_failed) {
    // An error occurred while loading; try to recover by truncating the
    // file to the last fully-read record.
    if (ferror(f)) {
      *err = strerror(ferror(f));
    } else {
      *err = "premature end of file";
    }
    fclose(f);

    if (!Truncate(path, offset, err))
      return LOAD_ERROR;

    // The truncate succeeded; we'll just report the load error as a
    // warning because the build can proceed.
    *err += "; recovering";
    return LOAD_SUCCESS;
  }

  fclose(f);

  // Rebuild the log if there are too many dead records.
  int kMinCompactionEntryCount = 1000;
  int kCompactionRatio = 3;
  if (total_dep_record_count > kMinCompactionEntryCount &&
      total_dep_record_count > unique_dep_record_count * kCompactionRatio) {
    needs_recompaction_ = true;
  }

  return LOAD_SUCCESS;
}

DepsLog::Deps* DepsLog::GetDeps(Node* node) {
  // Abort if the node has no id (never referenced in the deps) or if
  // there's no deps recorded for the node.
  if (node->id() < 0 || node->id() >= (int)deps_.size())
    return NULL;
  return deps_[node->id()];
}

Node* DepsLog::GetFirstReverseDepsNode(Node* node) {
  for (size_t id = 0; id < deps_.size(); ++id) {
    Deps* deps = deps_[id];
    if (!deps)
      continue;
    for (int i = 0; i < deps->node_count; ++i) {
      if (deps->nodes[i] == node)
        return nodes_[id];
    }
  }
  return NULL;
}

bool DepsLog::Recompact(const string& path, string* err) {
  METRIC_RECORD(".ninja_deps recompact");

  Close();
  std::string temp_path = path + ".recompact";

  // OpenForWrite() opens for append.  Make sure it's not appending to a
  // left-over file from a previous recompaction attempt that crashed somehow.
  disk_interface_->RemoveFile(temp_path);

  DepsLog new_log(*disk_interface_);
  if (!new_log.OpenForWrite(temp_path, err))
    return false;

  // Clear all known ids so that new ones can be reassigned.  The new indices
  // will refer to the ordering in new_log, not in the current log.
  for (vector<Node*>::iterator i = nodes_.begin(); i != nodes_.end(); ++i)
    (*i)->set_id(-1);

  // Write out all deps again.
  for (int old_id = 0; old_id < (int)deps_.size(); ++old_id) {
    Deps* deps = deps_[old_id];
    if (!deps) continue;  // If nodes_[old_id] is a leaf, it has no deps.

    if (!IsDepsEntryLiveFor(nodes_[old_id]))
      continue;

    if (!new_log.RecordDeps(nodes_[old_id], deps->mtime,
                            deps->node_count, deps->nodes)) {
      new_log.Close();
      return false;
    }
  }

  new_log.Close();

  // All nodes now have ids that refer to new_log, so steal its data.
  deps_.swap(new_log.deps_);
  nodes_.swap(new_log.nodes_);

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

bool DepsLog::IsDepsEntryLiveFor(const Node* node) {
  // Skip entries that don't have in-edges or whose edges don't have a
  // "deps" attribute. They were in the deps log from previous builds, but
  // the the files they were for were removed from the build and their deps
  // entries are no longer needed.
  // (Without the check for "deps", a chain of two or more nodes that each
  // had deps wouldn't be collected in a single recompaction.)
  return node->in_edge() && !node->in_edge()->GetBinding("deps").empty();
}

bool DepsLog::UpdateDeps(int out_id, Deps* deps) {
  if (out_id >= (int)deps_.size())
    deps_.resize(out_id + 1);

  bool delete_old = deps_[out_id] != NULL;
  if (delete_old)
    delete deps_[out_id];
  deps_[out_id] = deps;
  return delete_old;
}

bool DepsLog::RecordId(Node* node) {
  int path_size = node->path().size();
  assert(path_size > 0 && "Trying to record empty path Node!");
  int padding = (4 - path_size % 4) % 4;  // Pad path to 4 byte boundary.

  unsigned size = path_size + padding + 4;
  if (size > kMaxRecordSize) {
    errno = ERANGE;
    return false;
  }

  if (!OpenForWriteIfNeeded()) {
    return false;
  }
  if (fwrite(&size, 4, 1, file_) < 1)
    return false;
  if (fwrite(node->path().data(), path_size, 1, file_) < 1) {
    return false;
  }
  if (padding && fwrite("\0\0", padding, 1, file_) < 1)
    return false;
  int id = nodes_.size();
  unsigned checksum = ~(unsigned)id;
  if (fwrite(&checksum, 4, 1, file_) < 1)
    return false;
  if (fflush(file_) != 0)
    return false;

  node->set_id(id);
  nodes_.push_back(node);

  return true;
}

bool DepsLog::OpenForWriteIfNeeded() {
  if (file_path_.empty()) {
    return true;
  }
  file_ = disk_interface_->OpenFile(file_path_, "ab");
  if (!file_) {
    return false;
  }
  // Set the buffer size to this and flush the file buffer after every record
  // to make sure records aren't written partially.
  if (setvbuf(file_, NULL, _IOFBF, kMaxRecordSize + 1) != 0) {
    return false;
  }
  SetCloseOnExec(fileno(file_));

  // Opening a file in append mode doesn't set the file pointer to the file's
  // end on Windows. Do that explicitly.
  fseek(file_, 0, SEEK_END);

  if (ftell(file_) == 0) {
    if (fwrite(kFileSignature, sizeof(kFileSignature) - 1, 1, file_) < 1) {
      return false;
    }
    if (fwrite(&kCurrentVersion, 4, 1, file_) < 1) {
      return false;
    }
  }
  if (fflush(file_) != 0) {
    return false;
  }
  file_path_.clear();
  return true;
}
