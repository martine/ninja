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

#ifdef _WIN32
#include <direct.h>  // Has to be before util.h is included.
#endif

#include "test.h"

#include <algorithm>

#include <errno.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#include "build_log.h"
#include "graph.h"
#include "manifest_parser.h"
#include "util.h"

#ifdef _AIX
extern "C" {
        // GCC "helpfully" strips the definition of mkdtemp out on AIX.
        // The function is still present, so if we define it ourselves
        // it will work perfectly fine.
        extern char* mkdtemp(char* name_template);
}
#endif

using namespace std;

namespace {

#ifdef _MSC_VER
/// MSVC has no mkdtemp.  Implement it in terms of _mktemp_s.
char* mkdtemp(char* name_template) {
  int err = _mktemp_s(name_template, strlen(name_template) + 1);
  if (err < 0) {
    perror("_mktemp_s");
    return NULL;
  }

  err = _mkdir(name_template);
  if (err < 0) {
    perror("mkdir");
    return NULL;
  }

  return name_template;
}
#endif  // _MSC_VER

string GetSystemTempDir() {
#ifdef _WIN32
  char buf[1024];
  if (!GetTempPath(sizeof(buf), buf))
    return "";
  return buf;
#else
  const char* tempdir = getenv("TMPDIR");
  if (tempdir)
    return tempdir;
  return "/tmp";
#endif
}

}  // anonymous namespace

StateTestWithBuiltinRules::StateTestWithBuiltinRules() {
  AddCatRule(&state_);
}

void StateTestWithBuiltinRules::AddCatRule(State* state) {
  AssertParse(state,
"rule cat\n"
"  command = cat $in > $out\n");
}

Node* StateTestWithBuiltinRules::GetNode(const string& path) const {
  EXPECT_FALSE(strpbrk(path.c_str(), "/\\"));
  return state_.GetNode(path);
}

void AssertParse(State* state, const char* input,
                 ManifestParserOptions opts) {
  ManifestParser parser(state, NULL, opts);
  string err;
  EXPECT_TRUE(parser.ParseTest(input, &err));
  ASSERT_EQ("", err);
  VerifyGraph(*state);
}

void AssertHash(const char* expected, uint64_t actual) {
  ASSERT_EQ(BuildLog::LogEntry::HashCommand(expected), actual);
}

void VerifyGraph(const State& state) {
  for (vector<Edge*>::const_iterator e = state.edges_.begin();
       e != state.edges_.end(); ++e) {
    // All edges need at least one output.
    EXPECT_FALSE((*e)->outputs_.empty());
    // Check that the edge's inputs have the edge as out-edge.
    for (vector<Node*>::const_iterator in_node = (*e)->inputs_.begin();
         in_node != (*e)->inputs_.end(); ++in_node) {
      const vector<Edge*>& out_edges = (*in_node)->out_edges();
      EXPECT_NE(find(out_edges.begin(), out_edges.end(), *e),
                out_edges.end());
    }
    // Check that the edge's outputs have the edge as in-edge.
    for (vector<Node*>::const_iterator out_node = (*e)->outputs_.begin();
         out_node != (*e)->outputs_.end(); ++out_node) {
      EXPECT_EQ((*out_node)->in_edge(), *e);
    }
  }

  // The union of all in- and out-edges of each nodes should be exactly edges_.
  set<const Edge*> node_edge_set;
  for (State::Paths::const_iterator p = state.paths_.begin();
       p != state.paths_.end(); ++p) {
    const Node* n = p->second;
    if (n->in_edge())
      node_edge_set.insert(n->in_edge());
    node_edge_set.insert(n->out_edges().begin(), n->out_edges().end());
  }
  set<const Edge*> edge_set(state.edges_.begin(), state.edges_.end());
  EXPECT_EQ(node_edge_set, edge_set);
}

void VirtualFileSystem::Create(const string& path,
                               const string& contents) {
  files_[path].mtime = now_;
  files_[path].contents = contents;
  files_created_.insert(path);
}

TimeStamp VirtualFileSystem::Stat(const string& path, string* err) const {
  FileMap::const_iterator i = files_.find(path);
  if (i != files_.end()) {
    if (!i->second.stat_error.empty()) {
      *err = i->second.stat_error;
      return -1;
    }
    assert(i->second.mtime > 0);
    return i->second.mtime;
  }
  return 0;
}

bool VirtualFileSystem::WriteFile(const string& path, const string& contents,
                                  bool /*crlf_on_windows*/) {
  Create(path, contents);
  return true;
}

bool VirtualFileSystem::MakeDir(const string& path) {
  directories_made_.push_back(path);
  return true;  // success
}

FileReader::Status VirtualFileSystem::ReadFile(const string& path,
                                               string* contents,
                                               string* err) {
  files_read_.push_back(path);
  FileMap::iterator i = files_.find(path);
  if (i != files_.end()) {
    *contents = i->second.contents;
    return Okay;
  }
  *err = strerror(ENOENT);
  return NotFound;
}

int VirtualFileSystem::RemoveFile(const string& path) {
  if (find(directories_made_.begin(), directories_made_.end(), path)
      != directories_made_.end())
    return -1;
  FileMap::iterator i = files_.find(path);
  if (i != files_.end()) {
    files_.erase(i);
    files_removed_.insert(path);
    return 0;
  } else {
    return 1;
  }
}

void ScopedTempDir::CreateAndEnter(const string& name) {
  // First change into the system temp dir and save it for cleanup.
  start_dir_ = GetSystemTempDir();
  if (start_dir_.empty())
    Fatal("couldn't get system temp dir");
  if (chdir(start_dir_.c_str()) < 0)
    Fatal("chdir: %s", strerror(errno));

  // Create a temporary subdirectory of that.
  char name_template[1024];
  strcpy(name_template, name.c_str());
  strcat(name_template, "-XXXXXX");
  char* tempname = mkdtemp(name_template);
  if (!tempname)
    Fatal("mkdtemp: %s", strerror(errno));
  temp_dir_name_ = tempname;

  // chdir into the new temporary directory.
  if (chdir(temp_dir_name_.c_str()) < 0)
    Fatal("chdir: %s", strerror(errno));
}

void ScopedTempDir::Cleanup() {
  if (temp_dir_name_.empty())
    return;  // Something went wrong earlier.

  // Move out of the directory we're about to clobber.
  if (chdir(start_dir_.c_str()) < 0)
    Fatal("chdir: %s", strerror(errno));

#ifdef _WIN32
  string command = "rmdir /s /q " + temp_dir_name_;
#else
  string command = "rm -rf " + temp_dir_name_;
#endif
  if (system(command.c_str()) < 0)
    Fatal("system: %s", strerror(errno));

  temp_dir_name_.clear();
}

ScopedFilePath::ScopedFilePath(ScopedFilePath&& other) noexcept
    : path_(std::move(other.path_)), released_(other.released_) {
  other.released_ = true;
}

/// It would be nice to use '= default' here instead but some old compilers
/// such as GCC from Ubuntu 16.06 will not compile it with "noexcept", so just
/// write it manually.
ScopedFilePath& ScopedFilePath::operator=(ScopedFilePath&& other) noexcept {
  if (this != &other) {
    this->~ScopedFilePath();
    new (this) ScopedFilePath(std::move(other));
  }
  return *this;
}

ScopedFilePath::~ScopedFilePath() {
  if (!released_) {
    platformAwareUnlink(path_.c_str());
  }
}

void ScopedFilePath::Release() {
  released_ = true;
}
