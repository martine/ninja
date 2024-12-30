// Copyright 2016 Google Inc. All Rights Reserved.
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

#ifndef NINJA_STATUS_H_
#define NINJA_STATUS_H_

#include <string>
#include "exit_status.h"

struct BuildConfig;
struct Edge;
struct Explanations;

/// Abstract interface to object that tracks the status of a build:
/// completion fraction, printing updates.
struct Status {
  virtual void EdgeAddedToPlan(const Edge* edge) = 0;
  virtual void EdgeRemovedFromPlan(const Edge* edge) = 0;
  virtual void BuildEdgeStarted(const Edge* edge,
                                int64_t start_time_millis) = 0;
  virtual void BuildEdgeFinished(Edge* edge, int64_t start_time_millis,
                                 int64_t end_time_millis, ExitStatus exit_code,
                                 const std::string& output) = 0;
  virtual void BuildStarted() = 0;
  virtual void BuildFinished() = 0;

  /// Set the Explanations instance to use to report explanations,
  /// argument can be nullptr if no explanations need to be printed
  /// (which is the default).
  virtual void SetExplanations(Explanations*) = 0;

  virtual void Info(const char* msg, ...) = 0;
  virtual void Warning(const char* msg, ...) = 0;
  virtual void Error(const char* msg, ...) = 0;

  virtual ~Status() { }

  /// creates the actual implementation
  static Status* factory(const BuildConfig&);
};

#endif // NINJA_STATUS_H_
