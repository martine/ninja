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

#include "build.h"
#include "jobserver.h"
#include "subprocess.h"

struct RealCommandRunner : public CommandRunner {
  explicit RealCommandRunner(const BuildConfig& config,
                             Jobserver::Client* jobserver)
      : config_(config), jobserver_(jobserver) {}
  size_t CanRunMore() const override;
  bool StartCommand(Edge* edge) override;
  bool WaitForCommand(Result* result) override;
  std::vector<Edge*> GetActiveEdges() override;
  void Abort() override;

  void ClearJobTokens() {
    if (jobserver_) {
      for (Edge* edge : GetActiveEdges()) {
        jobserver_->Release(std::move(edge->job_slot_));
      }
    }
  }

  const BuildConfig& config_;
  SubprocessSet subprocs_;
  Jobserver::Client* jobserver_ = nullptr;
  std::map<const Subprocess*, Edge*> subproc_to_edge_;
};

std::vector<Edge*> RealCommandRunner::GetActiveEdges() {
  std::vector<Edge*> edges;
  for (std::map<const Subprocess*, Edge*>::iterator e =
           subproc_to_edge_.begin();
       e != subproc_to_edge_.end(); ++e)
    edges.push_back(e->second);
  return edges;
}

void RealCommandRunner::Abort() {
  ClearJobTokens();
  subprocs_.Clear();
}

size_t RealCommandRunner::CanRunMore() const {
  size_t subproc_number =
      subprocs_.running_.size() + subprocs_.finished_.size();

  int64_t capacity = config_.parallelism - subproc_number;

  if (config_.max_load_average > 0.0f) {
    int load_capacity = config_.max_load_average - GetLoadAverage();
    if (load_capacity < capacity)
      capacity = load_capacity;
  }

  if (capacity < 0)
    capacity = 0;

  if (capacity == 0 && subprocs_.running_.empty())
    // Ensure that we make progress.
    capacity = 1;

  return capacity;
}

bool RealCommandRunner::StartCommand(Edge* edge) {
  std::string command = edge->EvaluateCommand();
  Subprocess* subproc = subprocs_.Add(command, edge->use_console());
  if (!subproc)
    return false;
  subproc_to_edge_.insert(std::make_pair(subproc, edge));

  return true;
}

bool RealCommandRunner::WaitForCommand(Result* result) {
  Subprocess* subproc;
  while ((subproc = subprocs_.NextFinished()) == NULL) {
    bool interrupted = subprocs_.DoWork();
    if (interrupted)
      return false;
  }

  result->status = subproc->Finish();
  result->output = subproc->GetOutput();

  std::map<const Subprocess*, Edge*>::iterator e =
      subproc_to_edge_.find(subproc);
  result->edge = e->second;
  subproc_to_edge_.erase(e);

  delete subproc;
  return true;
}

CommandRunner* CommandRunner::factory(const BuildConfig& config,
                                      Jobserver::Client* jobserver) {
  return new RealCommandRunner(config, jobserver);
}
