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

#include "state.h"

#include <assert.h>
#include <stdio.h>

#include "edit_distance.h"
#include "graph.h"
#include "util.h"

using namespace std;

void Pool::EdgeScheduled(const Edge& edge) {
  if (depth_ != 0)
    current_use_ += edge.weight();
}

void Pool::EdgeFinished(const Edge& edge) {
  if (depth_ != 0)
    current_use_ -= edge.weight();
}

void Pool::DelayEdge(Edge* edge) {
  assert(depth_ != 0);
  delayed_.insert(edge);
}

void Pool::RetrieveReadyEdges(EdgePriorityQueue* ready_queue) {
  DelayedEdges::iterator it = delayed_.begin();
  while (it != delayed_.end()) {
    Edge* edge = *it;
    if (current_use_ + edge->weight() > depth_)
      break;
    ready_queue->push(edge);
    EdgeScheduled(*edge);
    ++it;
  }
  delayed_.erase(delayed_.begin(), it);
}

void Pool::Dump() const {
  printf("%s (%d/%d) ->\n", name_.c_str(), current_use_, depth_);
  for (DelayedEdges::const_iterator it = delayed_.begin();
       it != delayed_.end(); ++it)
  {
    printf("\t");
    (*it)->Dump();
  }
}

Pool State::kDefaultPool("", 0);
Pool State::kConsolePool("console", 1);

State::State() {
  bindings_.AddRule(Rule::Phony());
  AddPool(&kDefaultPool);
  AddPool(&kConsolePool);
}

void State::AddPool(Pool* pool) {
  assert(LookupPool(pool->name()) == NULL);
  pools_[pool->name()] = pool;
}

Pool* State::LookupPool(const string& pool_name) {
  map<string, Pool*>::iterator i = pools_.find(pool_name);
  if (i == pools_.end())
    return NULL;
  return i->second;
}

Edge* State::AddEdge(const Rule* rule) {
  Edge* edge = new Edge();
  edge->rule_ = rule;
  edge->pool_ = &State::kDefaultPool;
  edge->env_ = &bindings_;
  edge->id_ = edges_.size();
  edges_.push_back(edge);
  return edge;
}

Node* State::GetNode(const char* path, uint64_t slash_bits) {
  return GetNode(StringPiece(path), slash_bits);
}

Node* State::GetNode(StringPiece path, uint64_t slash_bits) {
  const std::pair<Paths::iterator, bool> result = paths_.try_emplace(path, nullptr);
  Node*& node = result.first->second;
  const bool is_new = result.second;
  if (is_new) {
    assert(node == nullptr);
    // If `try_emplace` added a new node then we need to actually allocate a `Node`
    // element and replace the existing value in the map.
    node = new Node(path.AsString(), slash_bits);

    // Additionally, as the key is a StringPiece, it needs to refer to a string
    // that has a longer life than the `path` parameter. As we take a deep copy
    // of `path` inside `Node` we can point to this string instead.  Note this does
    // not change the hash result nor the equality behavior of the StringPiece.
    result.first->first = node->path();
  }
  return node;
}

Node* State::GetNode(std::string&& path, uint64_t slash_bits) {
  // See comments on the `GetNode` overload above for more information.
  const std::pair<Paths::iterator, bool> result = paths_.try_emplace(path, nullptr);
  Node*& node = result.first->second;
  const bool is_new = result.second;
  if (is_new) {
    assert(node == nullptr);
    node = new Node(std::move(path), slash_bits);
    result.first->first = node->path();
  }
  return node;
}

Node* State::LookupNode(StringPiece path) const {
  Paths::const_iterator i = paths_.find(path);
  if (i != paths_.end())
    return i->second;
  return NULL;
}

Node* State::SpellcheckNode(const string& path) {
  const bool kAllowReplacements = true;
  const int kMaxValidEditDistance = 3;

  int min_distance = kMaxValidEditDistance + 1;
  Node* result = NULL;
  for (Paths::iterator i = paths_.begin(); i != paths_.end(); ++i) {
    int distance = EditDistance(
        i->first, path, kAllowReplacements, kMaxValidEditDistance);
    if (distance < min_distance && i->second) {
      min_distance = distance;
      result = i->second;
    }
  }
  return result;
}

void State::AddIn(Edge* edge, Node* node) {
  node->set_generated_by_dep_loader(false);
  edge->inputs_.push_back(node);
  node->AddOutEdge(edge);
}

bool State::AddOut(Edge* edge, Node* node, std::string* err) {
  if (Edge* other = node->in_edge()) {
    if (other == edge) {
      *err = node->path() + " is defined as an output multiple times";
    } else {
      *err = "multiple rules generate " + node->path();
    }
    return false;
  }
  edge->outputs_.push_back(node);
  node->set_in_edge(edge);
  node->set_generated_by_dep_loader(false);
  return true;
}

void State::AddValidation(Edge* edge, Node* node) {
  edge->validations_.push_back(node);
  node->AddValidationOutEdge(edge);
  node->set_generated_by_dep_loader(false);
}

bool State::AddDefault(StringPiece path, string* err) {
  Node* node = LookupNode(path);
  if (!node) {
    *err = "unknown target '" + path.AsString() + "'";
    return false;
  }
  defaults_.push_back(node);
  return true;
}

vector<Node*> State::RootNodes(string* err) const {
  vector<Node*> root_nodes;
  // Search for nodes with no output.
  for (vector<Edge*>::const_iterator e = edges_.begin();
       e != edges_.end(); ++e) {
    for (vector<Node*>::const_iterator out = (*e)->outputs_.begin();
         out != (*e)->outputs_.end(); ++out) {
      if ((*out)->out_edges().empty())
        root_nodes.push_back(*out);
    }
  }

  if (!edges_.empty() && root_nodes.empty())
    *err = "could not determine root nodes of build graph";

  return root_nodes;
}

vector<Node*> State::DefaultNodes(string* err) const {
  return defaults_.empty() ? RootNodes(err) : defaults_;
}

void State::Reset() {
  for (Paths::iterator i = paths_.begin(); i != paths_.end(); ++i)
    i->second->ResetState();
  for (vector<Edge*>::iterator e = edges_.begin(); e != edges_.end(); ++e) {
    (*e)->outputs_ready_ = false;
    (*e)->deps_loaded_ = false;
    (*e)->mark_ = Edge::VisitNone;
  }
}

void State::Dump() {
  for (Paths::iterator i = paths_.begin(); i != paths_.end(); ++i) {
    Node* node = i->second;
    printf("%s %s [id:%d]\n",
           node->path().c_str(),
           node->status_known() ? (node->dirty() ? "dirty" : "clean")
                                : "unknown",
           node->id());
  }
  if (!pools_.empty()) {
    printf("resource_pools:\n");
    for (map<string, Pool*>::const_iterator it = pools_.begin();
         it != pools_.end(); ++it)
    {
      if (!it->second->name().empty()) {
        it->second->Dump();
      }
    }
  }
}
