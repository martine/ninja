// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "dyndep.h"

#include <assert.h>
#include <stdio.h>

#include "debug_flags.h"
#include "disk_interface.h"
#include "dyndep_parser.h"
#include "explanations.h"
#include "graph.h"
#include "state.h"
#include "util.h"

using namespace std;

bool DyndepLoader::LoadDyndeps(Node* node, std::string* err) const {
  DyndepFile ddf;
  return LoadDyndeps(node, &ddf, err);
}

bool DyndepLoader::LoadDyndeps(Node* node, DyndepFile* ddf,
                               std::string* err) const {
  // We are loading the dyndep file now so it is no longer pending.
  node->set_dyndep_pending(false);

  // Load the dyndep information from the file.
  explanations_.Record(node, "loading dyndep file '%s'", node->path().c_str());

  if (!LoadDyndepFile(node, ddf, err))
    return false;

  if(node->in_edge() != nullptr && node->in_edge()->dyndep_ == node) {
    Edge* const edge = node->in_edge();
    DyndepFile::iterator ddi = ddf->find(edge);
    if (ddi == ddf->end()) {
      *err = ("'" + edge->outputs_[0]->path() + "' "
              "not mentioned in its dyndep file "
              "'" + node->path() + "'");
      return false;
    }

    ddi->second.used_ = true;
    Dyndeps const& dyndeps = ddi->second;
    if (!UpdateEdge(edge, &dyndeps, err)) {
      return false;
    }
  }

  // Update each edge that specified this node as its dyndep binding.
  std::vector<Edge*> const& out_edges = node->out_edges();
  for (Edge* edge : out_edges) {
    if (edge->dyndep_ != node)
      continue;

    DyndepFile::iterator ddi = ddf->find(edge);
    if (ddi == ddf->end()) {
      *err = ("'" + edge->outputs_[0]->path() + "' "
              "not mentioned in its dyndep file "
              "'" + node->path() + "'");
      return false;
    }

    ddi->second.used_ = true;
    Dyndeps const& dyndeps = ddi->second;
    if (!UpdateEdge(edge, &dyndeps, err)) {
      return false;
    }
  }

  // Reject extra outputs in dyndep file.
  for (const auto& dyndep_output : *ddf) {
    if (!dyndep_output.second.used_) {
      Edge* const edge = dyndep_output.first;
      *err = ("dyndep file '" + node->path() + "' mentions output "
              "'" + edge->outputs_[0]->path() + "' whose build statement "
              "does not have a dyndep binding for the file");
      return false;
    }
  }

  return true;
}

bool DyndepLoader::UpdateEdge(Edge* edge, Dyndeps const* dyndeps,
                              std::string* err) const {
  // Add dyndep-discovered bindings to the edge.
  // We know the edge already has its own binding
  // scope because it has a "dyndep" binding.
  if (dyndeps->restat_)
    edge->env_->AddBinding("restat", "1");

  // Add the dyndep-discovered outputs to the edge.
  edge->outputs_.insert(edge->outputs_.end(),
                        dyndeps->implicit_outputs_.begin(),
                        dyndeps->implicit_outputs_.end());
  edge->implicit_outs_ += dyndeps->implicit_outputs_.size();

  // Add this edge as incoming to each new output.
  for (Node* node : dyndeps->implicit_outputs_) {
    if (node->in_edge()) {
      // This node already has an edge producing it.
      *err = "multiple rules generate " + node->path();
      return false;
    }
    node->set_in_edge(edge);
  }

  // Add the dyndep-discovered inputs to the edge.
  edge->inputs_.insert(edge->inputs_.end() - edge->order_only_deps_,
                       dyndeps->implicit_inputs_.begin(),
                       dyndeps->implicit_inputs_.end());
  edge->implicit_deps_ += dyndeps->implicit_inputs_.size();

  // Add this edge as outgoing from each new input.
  for (Node* node : dyndeps->implicit_inputs_)
    node->AddOutEdge(edge);

  return true;
}

bool DyndepLoader::LoadDyndepFile(Node* file, DyndepFile* ddf,
                                  std::string* err) const {
  DyndepParser parser(state_, disk_interface_, ddf);
  return parser.Load(file->path(), err);
}
