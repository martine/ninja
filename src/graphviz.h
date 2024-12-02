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

#ifndef NINJA_GRAPHVIZ_H_
#define NINJA_GRAPHVIZ_H_

#include <set>

#include "dyndep.h"
#include "graph.h"

struct DiskInterface;
struct Node;
struct Edge;
struct State;

/// Runs the process of creating GraphViz .dot file output.
struct GraphViz {
  GraphViz(State* state, DepsLog* deps_log, DiskInterface* disk_interface, DepfileParserOptions const* depfile_parser_options)
      : dyndep_loader_(state, disk_interface),
        dep_loader_(state, deps_log, disk_interface, depfile_parser_options) {}

  void Start();
  void AddTarget(Node* node);
  void Finish();

  DyndepLoader dyndep_loader_;
  ImplicitDepLoader dep_loader_;
  std::set<Node*> visited_nodes_;
  EdgeSet visited_edges_;
};

#endif  // NINJA_GRAPHVIZ_H_
