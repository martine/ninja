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
#pragma once

#include <cstdint>
#include <queue>

#include "exit_status.h"
#include "explanations.h"
#include "line_printer.h"
#include "status.h"

/// Implementation of the Status interface that prints the status as
/// human-readable strings to stdout
struct StatusPrinter : Status {
  explicit StatusPrinter(const BuildConfig& config);

  /// Callbacks for the Plan to notify us about adding/removing Edge's.
  void EdgeAddedToPlan(const Edge* edge) override;
  void EdgeRemovedFromPlan(const Edge* edge) override;

  void BuildEdgeStarted(const Edge* edge, int64_t start_time_millis) override;
  void BuildEdgeFinished(Edge* edge, int64_t start_time_millis,
                                 int64_t end_time_millis, ExitStatus exit_code,
                                 const std::string& output) override;
  void BuildStarted() override;
  void BuildFinished() override;

  void Info(const char* msg, ...) override;
  void Warning(const char* msg, ...) override;
  void Error(const char* msg, ...) override;

  /// Format the progress status string by replacing the placeholders.
  /// See the user manual for more information about the available
  /// placeholders.
  /// @param progress_status_format The format of the progress status.
  /// @param status The status of the edge.
  std::string FormatProgressStatus(const char* progress_status_format,
                                   int64_t time_millis) const;

  /// Set the |explanations_| pointer. Used to implement `-d explain`.
  void SetExplanations(Explanations* explanations) override {
    explanations_ = explanations;
  }

 private:
  void PrintStatus(const Edge* edge, int64_t time_millis);

  const BuildConfig& config_;

  int started_edges_, finished_edges_, total_edges_, running_edges_;

  /// How much wall clock elapsed so far?
  int64_t time_millis_ = 0;

  /// How much cpu clock elapsed so far?
  int64_t cpu_time_millis_ = 0;

  /// What percentage of predicted total time have elapsed already?
  double time_predicted_percentage_ = 0.0;

  /// Out of all the edges, for how many do we know previous time?
  int eta_predictable_edges_total_ = 0;
  /// And how much time did they all take?
  int64_t eta_predictable_cpu_time_total_millis_ = 0;

  /// Out of all the non-finished edges, for how many do we know previous time?
  int eta_predictable_edges_remaining_ = 0;
  /// And how much time will they all take?
  int64_t eta_predictable_cpu_time_remaining_millis_ = 0;

  /// For how many edges we don't know the previous run time?
  int eta_unpredictable_edges_remaining_ = 0;

  void RecalculateProgressPrediction();

  /// Prints progress output.
  LinePrinter printer_;

  /// An optional Explanations pointer, used to implement `-d explain`.
  Explanations* explanations_ = nullptr;

  /// The custom progress status format to use.
  const char* progress_status_format_;

  template <size_t S>
  void SnprintfRate(double rate, char (&buf)[S], const char* format) const {
    if (rate == -1)
      snprintf(buf, S, "?");
    else
      snprintf(buf, S, format, rate);
  }

  struct SlidingRateInfo {
    SlidingRateInfo(int n) : rate_(-1), N(n), last_update_(-1) {}

    double rate() { return rate_; }

    void UpdateRate(int update_hint, int64_t time_millis) {
      if (update_hint == last_update_)
        return;
      last_update_ = update_hint;

      if (times_.size() == N)
        times_.pop();
      times_.push(time_millis);
      if (times_.back() != times_.front())
        rate_ = times_.size() / ((times_.back() - times_.front()) / 1e3);
    }

   private:
    double rate_;
    const size_t N;
    std::queue<double> times_;
    int last_update_;
  };

  mutable SlidingRateInfo current_rate_;
};
