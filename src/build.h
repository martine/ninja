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

#ifndef NINJA_BUILD_H_
#define NINJA_BUILD_H_

#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "depfile_parser.h"
#include "exit_status.h"
#include "graph.h"
#include "util.h"  // int64_t

struct BuildLog;
struct Builder;
struct DiskInterface;
struct Edge;
struct Explanations;
struct Node;
struct State;
struct Status;

/// Plan stores the state of a build plan: what we intend to build,
/// which steps we're ready to execute.
struct Plan {
  Plan(Builder* builder = NULL);

  /// Add a target to our plan (including all its dependencies).
  /// Returns false if we don't need to build this target; may
  /// fill in |err| with an error message if there's a problem.
  bool AddTarget(const Node* target, std::string* err);

  // Pop a ready edge off the queue of edges to build.
  // Returns NULL if there's no work to do.
  Edge* FindWork();

  /// Returns true if there's more work to be done.
  bool more_to_do() const { return wanted_edges_ > 0 && command_edges_ > 0; }

  /// Dumps the current state of the plan.
  void Dump() const;

  enum EdgeResult {
    kEdgeFailed,
    kEdgeSucceeded
  };

  /// Mark an edge as done building (whether it succeeded or failed).
  /// If any of the edge's outputs are dyndep bindings of their dependents,
  /// this loads dynamic dependencies from the nodes' paths.
  /// Returns 'false' if loading dyndep info fails and 'true' otherwise.
  bool EdgeFinished(Edge* edge, EdgeResult result, std::string* err);

  /// Clean the given node during the build.
  /// Return false on error.
  bool CleanNode(DependencyScan* scan, Node* node, std::string* err);

  /// Number of edges with commands to run.
  int command_edge_count() const { return command_edges_; }

  /// Reset state.  Clears want and ready sets.
  void Reset();

  // After all targets have been added, prepares the ready queue for find work.
  void PrepareQueue();

  /// Update the build plan to account for modifications made to the graph
  /// by information loaded from a dyndep file.
  bool DyndepsLoaded(DependencyScan* scan, const Node* node,
                     const DyndepFile& ddf, std::string* err);

  /// Enumerate possible steps we want for an edge.
  enum Want
  {
    /// We do not want to build the edge, but we might want to build one of
    /// its dependents.
    kWantNothing,
    /// We want to build the edge, but have not yet scheduled it.
    kWantToStart,
    /// We want to build the edge, have scheduled it, and are waiting
    /// for it to complete.
    kWantToFinish
  };

private:
  void ComputeCriticalPath();
  bool RefreshDyndepDependents(DependencyScan* scan, const Node* node, std::string* err);
  void UnmarkDependents(const Node* node, std::set<Node*>* dependents);
  bool AddSubTarget(const Node* node, const Node* dependent, std::string* err,
                    std::set<Edge*>* dyndep_walk);

  // Add edges that kWantToStart into the ready queue
  // Must be called after ComputeCriticalPath and before FindWork
  void ScheduleInitialEdges();

  /// Update plan with knowledge that the given node is up to date.
  /// If the node is a dyndep binding on any of its dependents, this
  /// loads dynamic dependencies from the node's path.
  /// Returns 'false' if loading dyndep info fails and 'true' otherwise.
  bool NodeFinished(Node* node, std::string* err);

  void EdgeWanted(const Edge* edge);
  bool EdgeMaybeReady(std::map<Edge*, Want>::iterator want_e, std::string* err);

  /// Submits a ready edge as a candidate for execution.
  /// The edge may be delayed from running, for example if it's a member of a
  /// currently-full pool.
  void ScheduleWork(std::map<Edge*, Want>::iterator want_e);

  /// Keep track of which edges we want to build in this plan.  If this map does
  /// not contain an entry for an edge, we do not want to build the entry or its
  /// dependents.  If it does contain an entry, the enumeration indicates what
  /// we want for the edge.
  std::map<Edge*, Want> want_;

  EdgePriorityQueue ready_;

  Builder* builder_;
  /// user provided targets in build order, earlier one have higher priority
  std::vector<const Node*> targets_;

  /// Total number of edges that have commands (not phony).
  int command_edges_;

  /// Total remaining number of wanted edges.
  int wanted_edges_;
};

struct BuildConfig;

/// CommandRunner is an interface that wraps running the build
/// subcommands.  This allows tests to abstract out running commands.
/// RealCommandRunner is an implementation that actually runs commands.
struct CommandRunner {
  virtual ~CommandRunner() {}
  virtual size_t CanRunMore() const = 0;
  virtual bool StartCommand(Edge* edge) = 0;

  /// The result of waiting for a command.
  struct Result {
    Result() : edge(NULL) {}
    Edge* edge;
    ExitStatus status;
    std::string output;
    bool success() const { return status == ExitSuccess; }
  };
  /// Wait for a command to complete, or return false if interrupted.
  virtual bool WaitForCommand(Result* result) = 0;

  virtual std::vector<Edge*> GetActiveEdges() { return std::vector<Edge*>(); }
  virtual void Abort() {}

  /// Creates the RealCommandRunner
  static CommandRunner* factory(const BuildConfig& config);
};

/// Options (e.g. verbosity, parallelism) passed to a build.
struct BuildConfig {
  BuildConfig() : verbosity(NORMAL), dry_run(false), parallelism(1),
                  failures_allowed(1), max_load_average(-0.0f) {}

  enum Verbosity {
    QUIET,  // No output -- used when testing.
    NO_STATUS_UPDATE,  // just regular output but suppress status update
    NORMAL,  // regular output and status update
    VERBOSE
  };
  Verbosity verbosity;
  bool dry_run;
  int parallelism;
  int failures_allowed;
  /// The maximum load average we must not exceed. A negative value
  /// means that we do not have any limit.
  double max_load_average;
  DepfileParserOptions depfile_parser_options;
};

/// Builder wraps the build process: starting commands, updating status.
struct Builder {
  Builder(State* state, const BuildConfig& config, BuildLog* build_log,
          DepsLog* deps_log, DiskInterface* disk_interface, Status* status,
          int64_t start_time_millis);
  ~Builder();

  /// Clean up after interrupted commands by deleting output files.
  void Cleanup();

  Node* AddTarget(const std::string& name, std::string* err);

  /// Add a target to the build, scanning dependencies.
  /// @return false on error.
  bool AddTarget(Node* target, std::string* err);

  /// Returns true if the build targets are already up to date.
  bool AlreadyUpToDate() const;

  /// Run the build.  Returns ExitStatus or the exit code of the last failed job.
  /// It is an error to call this function when AlreadyUpToDate() is true.
  ExitStatus Build(std::string* err);

  bool StartEdge(Edge* edge, std::string* err);

  /// Update status ninja logs following a command termination.
  /// @return false if the build can not proceed further due to a fatal error.
  bool FinishCommand(CommandRunner::Result* result, std::string* err);

  /// Used for tests.
  void SetBuildLog(BuildLog* log) {
    scan_.set_build_log(log);
  }

  /// Load the dyndep information provided by the given node.
  bool LoadDyndeps(Node* node, std::string* err);

  State* state_;
  const BuildConfig& config_;
  Plan plan_;
  std::unique_ptr<CommandRunner> command_runner_;
  Status* status_;

  /// Returns ExitStatus or the exit code of the last failed job
  /// (doesn't need to be an enum value of ExitStatus)
  ExitStatus GetExitCode() const { return exit_code_; }

 private:
  bool ExtractDeps(CommandRunner::Result* result, const std::string& deps_type,
                   const std::string& deps_prefix,
                   std::vector<Node*>* deps_nodes, std::string* err);

  /// Map of running edge to time the edge started running.
  typedef std::map<const Edge*, int> RunningEdgeMap;
  RunningEdgeMap running_edges_;

  /// Time the build started.
  int64_t start_time_millis_;

  std::string lock_file_path_;
  DiskInterface* disk_interface_;

  // Only create an Explanations class if '-d explain' is used.
  std::unique_ptr<Explanations> explanations_;

  DependencyScan scan_;

  /// Keep the global exit code for the build
  ExitStatus exit_code_ = ExitSuccess;
  void SetFailureCode(ExitStatus code);

  // Unimplemented copy ctor and operator= ensure we don't copy the auto_ptr.
  Builder(const Builder &other);        // DO NOT IMPLEMENT
  void operator=(const Builder &other); // DO NOT IMPLEMENT
};

#endif  // NINJA_BUILD_H_
