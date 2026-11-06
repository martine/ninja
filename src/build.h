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
#include <unordered_map>
#include <vector>

#include "build_result.h"
#include "depfile_parser.h"
#include "exit_status.h"
#include "graph.h"
#include "jobserver.h"
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

  /// Returns true if there's more work ready to be done.
  bool work_ready() const { return !ready_.empty(); }

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
  /// by information loaded from a set of dyndep files.
  bool DyndepsLoaded(DependencyScan* scan,
                     const std::vector<Node*>& dyndep_nodes,
                     const std::unordered_map<Edge*, Dyndeps>& dyndep_edges,
                     std::string* err);

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
  bool RefreshDyndepDependents(DependencyScan* scan,
                               const std::vector<Node*>& dyndep_nodes,
                               std::string* err);
  void UnmarkDependents(const Node* node, std::set<Node*>* dependents);
  bool AddSubTarget(const Node* node, const Node* dependent, std::string* err,
                    std::set<Edge*>* added_edges);

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

  /// Clean the given node during the build.
  /// Return false on error.
  bool CleanNode(DependencyScan* scan, Node* node,
                 std::vector<Node*>* validation_nodes,
                 std::vector<EdgeInputsRange>* cycle_detection_nodes,
                 std::string* err);

  /// Add any validation nodes as new top level targets.
  /// Returns false on error
  bool AddValidationNodes(std::vector<Node*>& validation_nodes,
                          std::string* err);

  /// Add newly added input dependency to build plan. The inputs had recently
  /// been added to the dependency graph.
  ///
  /// Returns false on error.
  bool AddInputTargets(const EdgeInputsRange& new_inputs, std::string* err);

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

  /// Wait for a command to complete, or return false if interrupted.
  virtual BuildResult WaitForCommand() = 0;

  /// Wait for a command to complete or a jobserver token to become available, or
  /// return false if interrupted. Default implementation waits for a command to complete.
  /// Overridden by RealCommandRunner to also wait for jobserver tokens.
  virtual BuildResult WaitForCommandOrJobserverToken(bool watch_jobserver) {
    (void)watch_jobserver;
    return WaitForCommand();
  }

  virtual std::vector<Edge*> GetActiveEdges() { return std::vector<Edge*>(); }
  virtual void Abort() {}

  /// Creates the RealCommandRunner. \arg jobserver can be nullptr if there
  /// is no jobserver pool to use.
  static CommandRunner* factory(const BuildConfig& config,
                                Jobserver::Client* jobserver);
};

/// Options (e.g. verbosity, parallelism) passed to a build.
struct BuildConfig {
  BuildConfig() = default;

  enum Verbosity {
    QUIET,  // No output -- used when testing.
    NO_STATUS_UPDATE,  // just regular output but suppress status update
    NORMAL,  // regular output and status update
    VERBOSE
  };
  Verbosity verbosity = NORMAL;
  bool dry_run = false;
  /// Number of concurrent jobs, auto-detected or specified explicitly.
  int parallelism = 1;
  /// True if -j<count> was used on the command line.
  bool explicit_parallelism = false;
  /// True if --jobserver-pool was used on the command line.
  bool jobserver_pool = false;
  int failures_allowed = 1;
  /// The maximum load average we must not exceed. A negative value
  /// means that we do not have any limit.
  double max_load_average = -0.0f;
  /// Progress status format, as set by --status. Overrides $NINJA_STATUS
  /// when non-null.
  const char* progress_status_format = nullptr;
  DepfileParserOptions depfile_parser_options;
};

/// Builder wraps the build process: starting commands, updating status.
struct Builder {
  Builder(State* state, const BuildConfig& config, BuildLog* build_log,
          DepsLog* deps_log, DiskInterface* disk_interface, Status* status,
          int64_t start_time_millis);
  ~Builder();

  /// Set Jobserver client instance for this builder.
  void SetJobserverClient(std::unique_ptr<Jobserver::Client> jobserver_client) {
    jobserver_ = std::move(jobserver_client);
  }

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
  bool FinishCommand(BuildResult::CommandCompleted& result, std::string* err);

  /// Used for tests.
  void SetBuildLog(BuildLog* log) {
    scan_.set_build_log(log);
  }

  /// Load the dyndep information provided by the given edge's outputs.
  bool LoadDyndeps(Edge* edge, std::string* err);

  State* state_;
  const BuildConfig& config_;
  Plan plan_;
  std::unique_ptr<Jobserver::Client> jobserver_;
  std::unique_ptr<CommandRunner> command_runner_;
  Status* status_;

  /// Returns ExitStatus or the exit code of the last failed job
  /// (doesn't need to be an enum value of ExitStatus)
  ExitStatus GetExitCode() const { return exit_code_; }

  /// only for unittests
  const Explanations* getExplanations() const;
  void ClearExplanations();

private:
  /// Parses the CommandCompleted result to extract dependencies.
  /// May modify result.output to extract dependency messages out of it
  /// (such as MSVC /showIncludes).
  /// @return true if successful, false otherwise.
  bool ExtractDeps(BuildResult::CommandCompleted& result,
                   const std::string& deps_type, const std::string& deps_prefix,
                   std::vector<Node*>* deps_nodes, std::string* err);

  /// Map of running edge to time the edge started running.
  typedef std::map<const Edge*, int64_t> RunningEdgeMap;
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
