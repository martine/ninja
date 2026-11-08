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

#include "graph.h"

#include <algorithm>
#include <deque>
#include <optional>
#include <assert.h>
#include <stdio.h>

#include "build_log.h"
#include "debug_flags.h"
#include "depfile_parser.h"
#include "deps_log.h"
#include "disk_interface.h"
#include "manifest_parser.h"
#include "metrics.h"
#include "state.h"
#include "util.h"

using namespace std;

namespace {

/// execute hash only once in lifetime of object and only on request
struct LazyEdgeCommandHash {
  LazyEdgeCommandHash(const Edge* edge) : edge_(edge) {}
  std::uint64_t operator()() {
    if (!valid_) {
      valid_ = true;
      return command_ = BuildLog::LogEntry::HashCommand(
                 edge_->EvaluateCommand(/*incl_rsp_file=*/true));
    }
    return command_;
  }

 private:
  const Edge* edge_;
  std::uint64_t command_ = 0;
  bool valid_ = false;
};

/// Performance‑optimized helper class for recomputing the dirty state of
/// outputs.
///
/// Strictly limited to the following usage:
/*
 * {
 *   RecomputeOutputsDirtyCache cache(...);
 *   bool dirty = cache.all(most_recent_input);
 *
 *   // Optional fast follow‑up check after deps have been loaded
 *   if (!dirty && optional)
 *     dirty = cache.depfile(most_recent_input_other);
 * }
 */
class RecomputeOutputsDirtyCache {

  /// Cached wrapper around BuildLog::LookupByOutput.
  ///
  /// This class behaves like an pointer to BuildLog::LogEntry; the pointer may
  /// be nullptr if no entry exists. The lookup result is cached after the first
  /// call to avoid repeated BuildLog lookups.
  class CachedLogEntry {
   public:
    CachedLogEntry(){};

    /// check for nullptr
    bool is_valid() const { return entry_; }
    /// When calling this function repeatedly for the same object,
    /// the `buildLog` and `output` pointers must remain unchanged.
    /// Stable pointer identity is required for correct caching behavior.
    bool LookupByOutput(const BuildLog* buildLog, const Node* output);
    const BuildLog::LogEntry* operator->() const { return entry_; }

   private:
    bool evaluated_ = false;
    BuildLog::LogEntry* entry_ = nullptr;

#ifndef NDEBUG
    const Node* checkOutput_ = nullptr;
#endif
  };

 public:
  RecomputeOutputsDirtyCache(BuildLog* build_log,
                             OptionalExplanations& explanations, Edge* edge)
      : buildLog_(build_log), explanations_(explanations), edge_(edge),
        logEntry_(edge->outputs_.size()) {}

  /// Determines whether at least one output of edge 'edge_' is considered dirty.
  ///
  /// Returns:
  /// - `true`  if at least one output is dirty
  /// - `false` if all outputs are clean
  bool all(const Node* most_recent_input);

  /// Performs the same dirty‑checking logic as `all()`, but relies on cached
  /// state produced during the preceding call to `all()`.
  ///
  /// Preconditions:
  /// - `all(most_recent_input)` must have been called first and must have
  ///   returned a false.
  /// - The set and order of outputs in `edge_` must be unchanged.
  ///
  /// This function is intended as a fast follow‑up check once deps has been
  /// loaded.
  bool depfile(const Node* most_recent_input);

 private:
  /// Checks whether `output` of `edge_` is dirty.
  /// @param FIRSTRUN  Indicates whether this is called from `all()` (true)
  ///                  or from `depfile()` (false), enabling or disabling
  ///                  certain checks accordingly.
  /// Returns true if dirty.
  template <bool FIRSTRUN>
  bool RecomputeOutputDirty(const Node* output, const Node* most_recent_input,
                            CachedLogEntry& entry);

  /// Dirty check for phony edges.
  /// Returns true if dirty.
  bool Phony(Node* output, const Node* most_recent_input) const;

  const BuildLog* const buildLog_;
  OptionalExplanations& explanations_;
  const Edge* const edge_;

  const bool isRestat_ = edge_->GetBindingBool("restat");
  bool generator_ = false;
  bool generatorValid_ = false;
  std::vector<CachedLogEntry> logEntry_;
  LazyEdgeCommandHash commandHash_ = LazyEdgeCommandHash(edge_);

#ifndef NDEBUG
  std::vector<const Node*> checkOutputs_;
#endif
};

bool RecomputeOutputsDirtyCache::CachedLogEntry::LookupByOutput(
    const BuildLog* buildLog, const Node* output) {
  if (evaluated_) {
    assert(output == checkOutput_);
    return entry_;
  }
  evaluated_ = true;
  assert((checkOutput_ = output, true));
  return (entry_ = buildLog->LookupByOutput(output->path()));
}

bool RecomputeOutputsDirtyCache::all(const Node* most_recent_input) {
  assert((checkOutputs_.assign(edge_->outputs_.begin(), edge_->outputs_.end()),
          true));

  for (std::size_t i = 0; i != edge_->outputs_.size(); ++i) {
    const bool outputDirty =
        edge_->is_phony()
            ? Phony(edge_->outputs_[i], most_recent_input)
            : RecomputeOutputDirty<true>(edge_->outputs_[i], most_recent_input,
                                         logEntry_[i]);
    if (outputDirty)
      return true;
  }
  return false;
}

bool RecomputeOutputsDirtyCache::depfile(const Node* most_recent_input) {
  // Precondition: RecomputeOutputsDirtyCache::all() was previously called
  // with the same edge_->outputs_ as used here.
  assert(std::equal(checkOutputs_.begin(), checkOutputs_.end(),
                    edge_->outputs_.begin()));

  for (std::size_t i = 0; i != edge_->outputs_.size(); ++i) {
    assert(!edge_->is_phony());
    if (RecomputeOutputDirty<false>(edge_->outputs_[i], most_recent_input,
                                    logEntry_[i]))
      return true;
  }
  return false;
}

bool RecomputeOutputsDirtyCache::Phony(Node* output,
                                       const Node* most_recent_input) const {
  // Phony edges don't write any output.  Outputs are only dirty if
  // there are no inputs or validations and we're missing the output.
  // If a phony target has inputs or validations, or the output exists,
  // they are used for dirty calculation instead of this fallback.
  if (edge_->inputs_.empty() && edge_->validations_.empty() &&
      !output->exists()) {
    explanations_.Record(output,
                         "output %s of phony edge with no inputs doesn't exist",
                         output->path().c_str());
    return true;
  }

  // Update the mtime with the newest input. Dependents can thus call mtime()
  // on the fake node and get the latest mtime of the dependencies
  if (most_recent_input) {
    output->UpdatePhonyMtime(most_recent_input->mtime());
  }

  // Phony edges are clean, nothing to do
  return false;
}

#define IF_FIRSTRUN(cond)                                     \
  if constexpr (!FIRSTRUN) assert(!(cond));      /* NOLINT */ \
  if constexpr (FIRSTRUN) if (cond)              /* NOLINT */

template <bool FIRSTRUN>
bool RecomputeOutputsDirtyCache::RecomputeOutputDirty(
    const Node* output, const Node* most_recent_input, CachedLogEntry& entry) {
  // Dirty if we're missing the output.
  IF_FIRSTRUN (!output->exists()) {
    explanations_.Record(output, "output %s doesn't exist",
                         output->path().c_str());
    return true;
  }

  // If this is a restat rule, we may have cleaned the output in a
  // previous run and stored the command start time in the build log.
  // We don't want to consider a restat rule's outputs as dirty unless
  // an input changed since the last run, so we'll skip checking the
  // output file's actual mtime and simply check the recorded mtime from
  // the log against the most recent input's mtime (see below)
  bool used_restat = false;
  if (isRestat_ && buildLog_ && entry.LookupByOutput(buildLog_, output)) {
    used_restat = true;
  }

  // Dirty if the output is older than the input.
  if (!used_restat && most_recent_input &&
      output->mtime() < most_recent_input->mtime()) {
    explanations_.Record(output,
                         "output %s older than most recent input %s "
                         "(%" PRId64 " vs %" PRId64 ")",
                         output->path().c_str(),
                         most_recent_input->path().c_str(), output->mtime(),
                         most_recent_input->mtime());
    return true;
  }

  if (buildLog_) {
    IF_FIRSTRUN (!generatorValid_) {
      generator_ = edge_->GetBindingBool("generator");
      generatorValid_ = true;
    }
    if (entry.LookupByOutput(buildLog_, output)) {
      IF_FIRSTRUN (!generator_ && commandHash_() != entry->command_hash) {
        // May also be dirty due to the command changing since the last build.
        // But if this is a generator rule, the command changing does not make
        // us dirty.
        explanations_.Record(output, "command line changed for %s",
                             output->path().c_str());
        return true;
      }
      if (most_recent_input && entry->mtime < most_recent_input->mtime()) {
        // May also be dirty due to the mtime in the log being older than the
        // mtime of the most recent input.  This can occur even when the mtime
        // on disk is newer if a previous run wrote to the output file but
        // exited with an error or was interrupted. If this was a restat rule,
        // then we only check the recorded mtime against the most recent input
        // mtime and ignore the actual output's mtime above.
        explanations_.Record(
            output,
            "recorded mtime of %s older than most recent input %s (%" PRId64
            " vs %" PRId64 ")",
            output->path().c_str(), most_recent_input->path().c_str(),
            entry->mtime, most_recent_input->mtime());
        return true;
      }
    }
    IF_FIRSTRUN (!entry.is_valid() && !generator_) {
      explanations_.Record(output, "command line not found in log for %s",
                           output->path().c_str());
      return true;
    }
  }

  return false;
}
}  // namespace

bool Node::Stat(DiskInterface* disk_interface, string* err) {
  mtime_ = disk_interface->Stat(path_, err);
  if (mtime_ == -1) {
    return false;
  }
  exists_ = (mtime_ != 0) ? ExistenceStatusExists : ExistenceStatusMissing;
  return true;
}

void Node::UpdatePhonyMtime(TimeStamp mtime) {
  if (!exists()) {
    mtime_ = std::max(mtime_, mtime);
  }
}

bool DependencyScan::RecomputeDirty(Node* initial_node,
                                    std::vector<Node*>* validation_nodes,
                                    string* err) {
  std::vector<Node*> stack;
  std::vector<Node*> new_validation_nodes;

  std::deque<Node*> nodes(1, initial_node);

  // RecomputeNodeDirty might return new validation nodes that need to be
  // checked for dirty state, keep a queue of nodes to visit.
  while (!nodes.empty()) {
    Node* node = nodes.front();
    nodes.pop_front();

    stack.clear();
    new_validation_nodes.clear();

    if (!RecomputeNodeDirty(node, &stack, &new_validation_nodes, err))
      return false;
    nodes.insert(nodes.end(), new_validation_nodes.begin(),
                              new_validation_nodes.end());
    if (!new_validation_nodes.empty()) {
      assert(validation_nodes &&
          "validations require RecomputeDirty to be called with validation_nodes");
      validation_nodes->insert(validation_nodes->end(),
                           new_validation_nodes.begin(),
                           new_validation_nodes.end());
    }
  }

  return true;
}

/// Recomputes the dirtiness state of the specified input range of the node's
/// incoming edge. For each input in the given range, the function updates its
/// dirtiness state and propagates any effects to the node.
///
/// Additionally, the node’s overall dirtiness is recalculated based on these
/// inputs. The `most_recent_input` pointer is updated if a newer input (based
/// on mtime) is found.
///
/// @param input_range  Defines the subset of inputs to process. The first
///                     element is the offset from the beginning, the second
///                     the offset from the end of the input list.
/// @param most_recent_input  Will be updated to the newest non-dirty regular
///                           input, if applicable.
/// @param dirty        Set to true if any regular input is dirty or missing.
/// @return true on success, false if an error occurred during recomputation.
bool DependencyScan::RecomputeEdgesInputsDirty(
    const Node* node, EdgeInputsRange input_range, Node*& most_recent_input,
    bool& dirty, std::vector<Node*>* stack,
    std::vector<Node*>* validation_nodes, std::string* err) {
  const auto& edge = input_range.edge_;

  // Visit all specified inputs before checking if any of them is ready.
  // Newly encountered edges may load dyndep files and gain
  // outputs that correspond to some of our inputs.
  for (auto i : input_range) {
    if (!RecomputeNodeDirty(i, stack, validation_nodes, err))
      return false;
  }

  for (auto i = input_range.begin(); i != input_range.end(); ++i) {
    // If an input is not ready, neither are our outputs.
    if (Edge* in_edge = (*i)->in_edge()) {
      if (!in_edge->outputs_ready_)
        edge->outputs_ready_ = false;
    }

    if (!edge->is_order_only(i - edge->inputs_.cbegin())) {
      // If a regular input is dirty (or missing), we're dirty.
      // Otherwise consider mtime.
      if ((*i)->dirty()) {
        explanations_.Record(node, "%s is dirty", (*i)->path().c_str());
        dirty = true;
      } else {
        if (!most_recent_input || (*i)->mtime() > most_recent_input->mtime()) {
          most_recent_input = *i;
        }
      }
    }
  }

  return true;
}

bool DependencyScan::RecomputeNodeDirty(Node* node, std::vector<Node*>* stack,
                                        std::vector<Node*>* validation_nodes,
                                        string* err) {
  Edge* edge = node->in_edge();
  if (!edge) {
    // If we already visited this leaf node then we are done.
    if (node->status_known())
      return true;
    // This node has no in-edge; it is dirty if it is missing.
    if (!node->StatIfNecessary(disk_interface_, err))
      return false;
    if (!node->exists())
      explanations_.Record(node, "%s has no in-edge and is missing",
                           node->path().c_str());
    node->set_dirty(!node->exists());
    return true;
  }

  // If we already finished this edge then we are done.
  if (edge->mark_ == Edge::VisitDone)
    return true;

  // If we encountered this edge earlier in the call stack we have a cycle.
  if (!VerifyDAG(node, stack, err))
    return false;

  // Store any validation nodes from the edge for adding to the initial
  // nodes.  Don't recurse into them, that would trigger the dependency
  // cycle detector if the validation node depends on this node.
  // RecomputeDirty will add the validation nodes to the initial nodes
  // and recurse into them.
  validation_nodes->insert(validation_nodes->end(),
      edge->validations_.begin(), edge->validations_.end());

  // Mark the edge temporarily while in the call stack.
  edge->mark_ = Edge::VisitInStack;
  stack->push_back(node);

  bool dirty = false;
  edge->outputs_ready_ = true;
  edge->deps_missing_ = false;

  const bool edge_deps_loaded = edge->deps_loaded_;
  if (!edge->deps_loaded_) {
    // This is our first encounter with this edge.
    edge->deps_loaded_ = true;

    // If there is a pending dyndep file, visit it now:
    // * If the dyndep file is ready then load it now to get any
    //   additional inputs and outputs for this and other edges.
    //   Once the dyndep file is loaded it will no longer be pending
    //   if any other edges encounter it, but they will already have
    //   been updated.
    // * If the dyndep file is not ready then since is known to be an
    //   input to this edge, the edge will not be considered ready below.
    //   Later during the build the dyndep file will become ready and be
    //   loaded to update this edge before it can possibly be scheduled.
    if (edge->dyndep_ && edge->dyndep_->dyndep_pending()) {
      if (!RecomputeNodeDirty(edge->dyndep_, stack, validation_nodes, err))
        return false;

      if (!edge->dyndep_->in_edge() ||
          edge->dyndep_->in_edge()->outputs_ready()) {
        // The dyndep file is ready, so load it now.
        if (!LoadDyndeps(edge->dyndep_, err))
          return false;
      }
    }
  }

  // Load output mtimes so we can compare them to the most recent input below.
  for (Node* o : edge->outputs_) {
    if (err) {
      *err = "";
    }
    if (!o->StatIfNecessary(disk_interface_, err)) {
      return false;
    }
  }

  Node* most_recent_input = nullptr;
  if (!RecomputeEdgesInputsDirty(node, EdgeInputsRange(node->in_edge()),
                                 most_recent_input, dirty, stack,
                                 validation_nodes, err))
    return false;

  // We may also be dirty due to output state: missing outputs, out of
  // date outputs, etc.  Visit all outputs and determine whether they're dirty.
  RecomputeOutputsDirtyCache recomputeOutputsDirty(build_log(), explanations_,
                                                edge);
  if (!dirty)
    dirty = recomputeOutputsDirty.all(most_recent_input);

  if (!edge_deps_loaded) {
    // only try to load the deps log if no rebuild is necessary
    // if an rebuild is necessary the deps log is outdated for this target
    if (!dirty) {
      // Load discovered deps.
      std::optional<EdgeInputsRange> new_deps = dep_loader_.LoadDeps(edge, err);
      if (!new_deps) {
        if (!err->empty())
          return false;
        // Failed to load dependency info: rebuild to regenerate it.
        // LoadDeps() did explanations_->Record() already, no need to do it
        // here.
        dirty = edge->deps_missing_ = true;
      } else {
        // depfile load succeeded
        // check the recently added inputs from depfile
        const Node* most_recent_input_previous = most_recent_input;
        if (!RecomputeEdgesInputsDirty(node, new_deps.value(), most_recent_input, dirty,
                                       stack, validation_nodes, err))
          return false;

        // only applicable if most_recent_input did change, any other criteria
        // has already been checked.
        if (!dirty && most_recent_input_previous != most_recent_input)
          dirty = recomputeOutputsDirty.depfile(most_recent_input);
      }
    } else if (!dep_loader_.LoadDepsTry(edge, err)) {
      if (!err->empty())
        return false;
      else
        dirty = edge->deps_missing_ = true;
    }
  }

  // Finally, visit each output and update their dirty state if necessary.
  if (dirty) {
    for (auto o : edge->outputs_)
      o->MarkDirty();
  }

  // If an edge is dirty, its outputs are normally not ready.  (It's
  // possible to be clean but still not be ready in the presence of
  // order-only inputs.)
  // But phony edges with no inputs have nothing to do, so are always
  // ready.
  if (dirty && !(edge->is_phony() && edge->inputs_.empty()))
    edge->outputs_ready_ = false;

  // Mark the edge as finished during this walk now that it will no longer
  // be in the call stack.
  edge->mark_ = Edge::VisitDone;
  assert(stack->back() == node);
  stack->pop_back();

  return true;
}

bool DependencyScan::VerifyDAG(Node* node, vector<Node*>* stack, string* err) {
  Edge* edge = node->in_edge();
  assert(edge != NULL);

  // If we have no temporary mark on the edge then we do not yet have a cycle.
  if (edge->mark_ != Edge::VisitInStack)
    return true;

  // We have this edge earlier in the call stack.  Find it.
  vector<Node*>::iterator start = stack->begin();
  while (start != stack->end() && (*start)->in_edge() != edge)
    ++start;
  assert(start != stack->end());

  // Make the cycle clear by reporting its start as the node at its end
  // instead of some other output of the starting edge.  For example,
  // running 'ninja b' on
  //   build a b: cat c
  //   build c: cat a
  // should report a -> c -> a instead of b -> c -> a.
  *start = node;

  // Construct the error message rejecting the cycle.
  *err = "dependency cycle: ";
  for (vector<Node*>::const_iterator i = start; i != stack->end(); ++i) {
    err->append((*i)->path());
    err->append(" -> ");
  }
  err->append((*start)->path());

  if ((start + 1) == stack->end() && edge->maybe_phonycycle_diagnostic()) {
    // The manifest parser would have filtered out the self-referencing
    // input if it were not configured to allow the error.
    err->append(" [-w phonycycle=err]");
  }

  return false;
}

bool DependencyScan::RecomputeOutputsDirty(Edge* edge, Node* most_recent_input,
                                           bool* outputs_dirty, string* err) {
  *outputs_dirty = RecomputeOutputsDirtyCache(build_log(), explanations_, edge)
                       .all(most_recent_input);
  return true;
}

bool DependencyScan::LoadDyndeps(Node* node, string* err) const {
  return dyndep_loader_.LoadDyndeps(node, err);
}

bool DependencyScan::LoadDyndeps(Node* node, DyndepFile* ddf,
                                 string* err) const {
  return dyndep_loader_.LoadDyndeps(node, ddf, err);
}

bool Edge::AllInputsReady() const {
  for (vector<Node*>::const_iterator i = inputs_.begin();
       i != inputs_.end(); ++i) {
    if ((*i)->in_edge() && !(*i)->in_edge()->outputs_ready())
      return false;
  }
  return true;
}

/// An Env for an Edge, providing $in and $out.
struct EdgeEnv : public Env {
  enum EscapeKind { kShellEscape, kDoNotEscape };

  EdgeEnv(const Edge* const edge, const EscapeKind escape)
      : edge_(edge), escape_in_out_(escape), recursive_(false) {}
  virtual std::string LookupVariable(StringPiece var);

  /// Given a span of Nodes, construct a list of paths suitable for a command
  /// line.
  std::string MakePathList(const Node* const* span, size_t size, char sep) const;

 private:
  std::vector<std::string> lookups_;
  const Edge* const edge_;
  EscapeKind escape_in_out_;
  bool recursive_;
};

std::string EdgeEnv::LookupVariable(StringPiece var) {
  if (var == "in" || var == "in_newline") {
    int explicit_deps_count =
        static_cast<int>(edge_->inputs_.size() - edge_->implicit_deps_ -
                         edge_->order_only_deps_);
    return MakePathList(edge_->inputs_.data(), explicit_deps_count,
                        var == "in" ? ' ' : '\n');
  } else if (var == "out") {
    int explicit_outs_count =
        static_cast<int>(edge_->outputs_.size() - edge_->implicit_outs_);
    return MakePathList(&edge_->outputs_[0], explicit_outs_count, ' ');
  }

  // Technical note about the lookups_ vector.
  //
  // This is used to detect cycles during recursive variable expansion
  // which can be seen as a graph traversal problem. Consider the following
  // example:
  //
  //    rule something
  //      command = $foo $foo $var1
  //      var1 = $var2
  //      var2 = $var3
  //      var3 = $var1
  //      foo = FOO
  //
  // Each variable definition can be seen as a node in a graph that looks
  // like the following:
  //
  //   command --> foo
  //      |
  //      v
  //    var1 <-----.
  //      |        |
  //      v        |
  //    var2 ---> var3
  //
  // The lookups_ vector is used as a stack of visited nodes/variables
  // during recursive expansion. Entering a node adds an item to the
  // stack, leaving the node removes it.
  //
  // The recursive_ flag is used as a small performance optimization
  // to never record the starting node in the stack when beginning a new
  // expansion, since in most cases, expansions are not recursive
  // at all.
  //
  if (recursive_) {
    auto it = std::find_if(lookups_.begin(),
                           lookups_.end(),
                           [var](const std::string& lookup){
      return var == lookup;
    });
    if (it != lookups_.end()) {
      std::string cycle;
      for (; it != lookups_.end(); ++it)
        cycle.append(*it + " -> ");
      cycle.append(var.str_, var.len_);
      Fatal(("cycle in rule variables: " + cycle).c_str());
    }
  }

  // See notes on BindingEnv::LookupWithFallback.
  const EvalString* eval = edge_->rule_->GetBinding(var);
  bool record_varname = recursive_ && eval;
  if (record_varname)
    lookups_.push_back(var.AsString());

  // In practice, variables defined on rules never use another rule variable.
  // For performance, only start checking for cycles after the first lookup.
  recursive_ = true;
  std::string result = edge_->env_->LookupWithFallback(var, eval, this);
  if (record_varname)
    lookups_.pop_back();
  return result;
}

std::string EdgeEnv::MakePathList(const Node* const* const span,
                                  const size_t size, const char sep) const {
  string result;
  std::string temp_path;
  for (const Node* const* i = span; i != span + size; ++i) {
    if (!result.empty())
      result.push_back(sep);
    if (escape_in_out_ == kShellEscape) {
      temp_path.clear();
      (*i)->AppendPathDecanonicalized(&temp_path);
#ifdef _WIN32
      GetWin32EscapedString(temp_path, &result);
#else
      GetShellEscapedString(temp_path, &result);
#endif
    } else {
      (*i)->AppendPathDecanonicalized(&result);
    }
  }
  return result;
}

std::string Edge::EvaluateCommand(const bool incl_rsp_file) const {
  string command = GetBinding("command");
  if (incl_rsp_file) {
    string rspfile_content = GetBinding("rspfile_content");
    if (!rspfile_content.empty())
      command += ";rspfile=" + rspfile_content;
  }
  return command;
}

std::string Edge::GetBinding(StringPiece key) const {
  EdgeEnv env(this, EdgeEnv::kShellEscape);
  return env.LookupVariable(key);
}

bool Edge::GetBindingBool(StringPiece key) const {
  return !GetBinding(key).empty();
}

string Edge::GetUnescapedDepfile() const {
  EdgeEnv env(this, EdgeEnv::kDoNotEscape);
  return env.LookupVariable("depfile");
}

string Edge::GetUnescapedDyndep() const {
  EdgeEnv env(this, EdgeEnv::kDoNotEscape);
  return env.LookupVariable("dyndep");
}

std::string Edge::GetUnescapedRspfile() const {
  EdgeEnv env(this, EdgeEnv::kDoNotEscape);
  return env.LookupVariable("rspfile");
}

void Edge::Dump(const char* prefix) const {
  printf("%s[ ", prefix);
  for (vector<Node*>::const_iterator i = inputs_.begin();
       i != inputs_.end() && *i != NULL; ++i) {
    printf("%s ", (*i)->path().c_str());
  }
  printf("--%s-> ", rule_->name().c_str());
  for (vector<Node*>::const_iterator i = outputs_.begin();
       i != outputs_.end() && *i != NULL; ++i) {
    printf("%s ", (*i)->path().c_str());
  }
  if (!validations_.empty()) {
    printf(" validations ");
    for (std::vector<Node*>::const_iterator i = validations_.begin();
         i != validations_.end() && *i != NULL; ++i) {
      printf("%s ", (*i)->path().c_str());
    }
  }
  if (pool_) {
    if (!pool_->name().empty()) {
      printf("(in pool '%s')", pool_->name().c_str());
    }
  } else {
    printf("(null pool?)");
  }
  printf("] 0x%p\n", this);
}

bool Edge::is_phony() const {
  return rule_->IsPhony();
}

bool Edge::use_console() const {
  return pool() == &State::kConsolePool;
}

bool Edge::maybe_phonycycle_diagnostic() const {
  // CMake 2.8.12.x and 3.0.x produced self-referencing phony rules
  // of the form "build a: phony ... a ...".   Restrict our
  // "phonycycle" diagnostic option to the form it used.
  return is_phony() && outputs_.size() == 1 && implicit_outs_ == 0 &&
      implicit_deps_ == 0 && order_only_deps_ == 0;
}

// static
void Node::AppendPathDecanonicalized(std::string* output, StringPiece path,
                                     uint64_t slash_bits) {
  if (path.empty()) {
    return;
  }
  output->append(path.begin(), path.end());
#ifdef _WIN32
  char* data = &(*output)[0];
  char* end = data + output->size();
  char* c = end - path.size();
  while (slash_bits != 0) {
    c = static_cast<char*>(memchr(c, '/', end - c));

    // If `memchr` returns null then there are too many bits in `slash_bits`,
    // which happens when we pass `~0u` in `build.cc` instead of calculating it.
    if (!c)
      return;
    if (slash_bits & 1)
      *c = '\\';
    ++c;
    slash_bits >>= 1;
  }
#endif
}

void Node::Dump(const char* prefix) const {
  printf("%s <%s 0x%p> mtime: %" PRId64 "%s, (:%s), ",
         prefix, path().c_str(), this,
         mtime(), exists() ? "" : " (:missing)",
         dirty() ? " dirty" : " clean");
  if (in_edge()) {
    in_edge()->Dump("in-edge: ");
  } else {
    printf("no in-edge\n");
  }
  printf(" out edges:\n");
  for (vector<Edge*>::const_iterator e = out_edges().begin();
       e != out_edges().end() && *e != NULL; ++e) {
    (*e)->Dump(" +- ");
  }
  if (!validation_out_edges().empty()) {
    printf(" validation out edges:\n");
    for (std::vector<Edge*>::const_iterator e = validation_out_edges().begin();
         e != validation_out_edges().end() && *e != NULL; ++e) {
      (*e)->Dump(" +- ");
    }
  }
}

std::optional<EdgeInputsRange> ImplicitDepLoader::LoadDeps(Edge* edge,
                                                           string* err) {
  string deps_type = edge->GetBinding("deps");
  if (!deps_type.empty())
    return LoadDepsFromLog(edge, err);

  string depfile = edge->GetUnescapedDepfile();
  if (!depfile.empty())
    return LoadDepFile(edge, depfile, err);

  // No deps to load.
  return EdgeInputsRange::Empty(edge);
}

bool ImplicitDepLoader::LoadDepsTry(const Edge* edge, string* err) const {
  string deps_type = edge->GetBinding("deps");
  if (!deps_type.empty())
    return LoadDepsFromLogTry(edge, err);

  string depfile = edge->GetUnescapedDepfile();
  if (!depfile.empty())
    return LoadDepFileTry(edge, depfile, err);

  // No deps to load.
  return true;
}

struct matches {
  explicit matches(std::vector<StringPiece>::iterator i) : i_(i) {}

  bool operator()(const Node* node) const {
    StringPiece opath = StringPiece(node->path());
    return *i_ == opath;
  }

  std::vector<StringPiece>::iterator i_;
};

std::optional<EdgeInputsRange> ImplicitDepLoader::LoadDepFile(
    Edge* edge, const string& path, string* err) {
  METRIC_RECORD("depfile load");
  // Read depfile content.  Treat a missing depfile as empty.
  string content;
  switch (disk_interface_->ReadFile(path, &content, err)) {
  case DiskInterface::Okay:
    break;
  case DiskInterface::NotFound:
    err->clear();
    break;
  case DiskInterface::OtherError:
    *err = "loading '" + path + "': " + *err;
    return std::nullopt;
  }
  // On a missing depfile: return false and empty *err.
  Node* first_output = edge->outputs_[0];
  if (content.empty()) {
    explanations_.Record(first_output, "depfile '%s' is missing", path.c_str());
    return std::nullopt;
  }

  DepfileParser depfile(depfile_parser_options_
                        ? *depfile_parser_options_
                        : DepfileParserOptions());
  string depfile_err;
  if (!depfile.Parse(&content, &depfile_err)) {
    *err = path + ": " + depfile_err;
    return std::nullopt;
  }

  if (depfile.outs_.empty()) {
    *err = path + ": no outputs declared";
    return std::nullopt;
  }

  uint64_t unused;
  std::vector<StringPiece>::iterator primary_out = depfile.outs_.begin();
  CanonicalizePath(const_cast<char*>(primary_out->str_), &primary_out->len_,
                   &unused);

  // Check that this depfile matches the edge's output, if not return false to
  // mark the edge as dirty.
  StringPiece opath = StringPiece(first_output->path());
  if (opath != *primary_out) {
    explanations_.Record(first_output,
                         "expected depfile '%s' to mention '%s', got '%s'",
                         path.c_str(), first_output->path().c_str(),
                         primary_out->AsString().c_str());
    return std::nullopt;
  }

  // Ensure that all mentioned outputs are outputs of the edge.
  for (std::vector<StringPiece>::iterator o = depfile.outs_.begin();
       o != depfile.outs_.end(); ++o) {
    matches m(o);
    if (std::find_if(edge->outputs_.begin(), edge->outputs_.end(), m) == edge->outputs_.end()) {
      *err = path + ": depfile mentions '" + o->AsString() + "' as an output, but no such output was declared";
      return std::nullopt;
    }
  }

  return ProcessDepfileDeps(edge, &depfile.ins_, err);
}

bool ImplicitDepLoader::LoadDepFileTry(const Edge* edge, const string& path,
                                       string* err) const {
  TimeStamp time_stamp = disk_interface_->Stat(path, err);

  if (time_stamp > 0)
    return true;
  else if (time_stamp == 0) {
    *err = "";
    return false;
  } else {
    *err = "loading '" + path + "': " + *err;
    return false;
  }
}

std::optional<EdgeInputsRange> ImplicitDepLoader::ProcessDepfileDeps(
    Edge* edge, std::vector<StringPiece>* depfile_ins,
    std::string* err) {
  // Preallocate space in edge->inputs_ to be filled in below.
  vector<Node*>::iterator implicit_dep =
      PreallocateSpace(edge, static_cast<int>(depfile_ins->size()));
  const auto beg = implicit_dep;

  // Add all its in-edges.
  for (std::vector<StringPiece>::iterator i = depfile_ins->begin();
       i != depfile_ins->end(); ++i, ++implicit_dep) {
    uint64_t slash_bits;
    CanonicalizePath(const_cast<char*>(i->str_), &i->len_, &slash_bits);
    Node* node = state_->GetNode(*i, slash_bits);
    *implicit_dep = node;
    node->AddOutEdge(edge);
  }

  const auto end = implicit_dep;
  return EdgeInputsRange(edge, beg, end);
}

std::optional<EdgeInputsRange> ImplicitDepLoader::LoadDepsFromLog(Edge* edge,
                                                                  string* err) {
  // NOTE: deps are only supported for single-target edges.
  Node* output = edge->outputs_[0];
  DepsLog::Deps* deps = deps_log_ ? deps_log_->GetDeps(output) : NULL;
  if (!deps) {
    explanations_.Record(output, "deps for '%s' are missing",
                         output->path().c_str());
    return std::nullopt;
  }

  // Load the output's mtime if we haven't already.
  if (!output->StatIfNecessary(disk_interface_, err)) {
    return std::nullopt;
  }

  // Deps are invalid if the output is newer than the deps.
  if (output->mtime() > deps->mtime) {
    explanations_.Record(output,
                         "stored deps info out of date for '%s' (%" PRId64
                         " vs %" PRId64 ")",
                         output->path().c_str(), deps->mtime, output->mtime());
    return std::nullopt;
  }

  Node** nodes = deps->nodes;
  const size_t node_count = deps->node_count;
  const auto implicit_dep = edge->inputs_.end() - edge->order_only_deps_;

  edge->implicit_deps_ += static_cast<int>(node_count);
  for (size_t i = 0; i < node_count; ++i) {
    nodes[i]->AddOutEdge(edge);
  }

  const auto begin = edge->inputs_.insert(implicit_dep, nodes, nodes + node_count);
  return EdgeInputsRange(edge, begin, begin + node_count);
}

bool ImplicitDepLoader::LoadDepsFromLogTry(const Edge* edge,
                                           string* err) const {
  // NOTE: deps are only supported for single-target edges.
  Node* output = edge->outputs_[0];
  DepsLog::Deps* deps = deps_log_ ? deps_log_->GetDeps(output) : NULL;
  if (!deps) {
    err->clear();
    explanations_.Record(output, "deps for '%s' are missing",
                         output->path().c_str());
    return false;
  }

  // Load the output's mtime if we haven't already.
  if (!output->StatIfNecessary(disk_interface_, err)) {
    return false;
  }

  // Deps are invalid if the output is newer than the deps.
  if (output->mtime() > deps->mtime) {
    explanations_.Record(output,
                         "stored deps info out of date for '%s' (%" PRId64
                         " vs %" PRId64 ")",
                         output->path().c_str(), deps->mtime, output->mtime());
    return false;
  }

  return true;
}

vector<Node*>::iterator ImplicitDepLoader::PreallocateSpace(Edge* edge,
                                                            int count) {
  edge->inputs_.insert(edge->inputs_.end() - edge->order_only_deps_,
                       (size_t)count, 0);
  edge->implicit_deps_ += count;
  return edge->inputs_.end() - edge->order_only_deps_ - count;
}

void InputsCollector::VisitNode(const Node* node) {
  const Edge* edge = node->in_edge();

  if (!edge)  // A source file.
    return;

  // Add inputs of the producing edge to the result,
  // except if they are themselves produced by a phony
  // edge.
  for (const Node* input : edge->inputs_) {
    if (!visited_nodes_.insert(input).second)
      continue;

    VisitNode(input);

    const Edge* input_edge = input->in_edge();
    if (!(input_edge && input_edge->is_phony())) {
      inputs_.push_back(input);
    }
  }
}

std::vector<std::string> InputsCollector::GetInputsAsStrings(
    bool shell_escape) const {
  std::vector<std::string> result(inputs_.size());
  auto out = result.begin();

  std::string temp_path;
  for (const Node* input : inputs_) {
    if (shell_escape) {
      temp_path.clear();
      input->AppendPathDecanonicalized(&temp_path);
#ifdef _WIN32
      GetWin32EscapedString(temp_path, &*out);
#else
      GetShellEscapedString(temp_path, &*out);
#endif
    } else {
      input->AppendPathDecanonicalized(&*out);
    }
    ++out;
  }
  return result;
}
