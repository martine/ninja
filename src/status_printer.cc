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

#include "status_printer.h"

#ifdef _WIN32
#include "win32port.h"
#else
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <cinttypes>
#endif

#include <stdarg.h>
#include <stdlib.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include "build.h"
#include "debug_flags.h"
#include "exit_status.h"

using namespace std;

Status* Status::factory(const BuildConfig& config) {
  return new StatusPrinter(config);
}

StatusPrinter::StatusPrinter(const BuildConfig& config)
    : config_(config), started_edges_(0), finished_edges_(0), total_edges_(0),
      running_edges_(0), progress_status_format_(NULL),
      current_rate_(config.parallelism) {
  // Don't do anything fancy in verbose mode.
  if (config_.verbosity != BuildConfig::NORMAL)
    printer_.set_smart_terminal(false);

  progress_status_format_ = getenv("NINJA_STATUS");
  if (!progress_status_format_)
    progress_status_format_ = "[%f/%t] ";
}

void StatusPrinter::EdgeAddedToPlan(const Edge* edge) {
  ++total_edges_;

  // Do we know how long did this edge take last time?
  if (edge->prev_elapsed_time_millis != -1) {
    ++eta_predictable_edges_total_;
    ++eta_predictable_edges_remaining_;
    eta_predictable_cpu_time_total_millis_ += edge->prev_elapsed_time_millis;
    eta_predictable_cpu_time_remaining_millis_ +=
        edge->prev_elapsed_time_millis;
  } else
    ++eta_unpredictable_edges_remaining_;
}

void StatusPrinter::EdgeRemovedFromPlan(const Edge* edge) {
  --total_edges_;

  // Do we know how long did this edge take last time?
  if (edge->prev_elapsed_time_millis != -1) {
    --eta_predictable_edges_total_;
    --eta_predictable_edges_remaining_;
    eta_predictable_cpu_time_total_millis_ -= edge->prev_elapsed_time_millis;
    eta_predictable_cpu_time_remaining_millis_ -=
        edge->prev_elapsed_time_millis;
  } else
    --eta_unpredictable_edges_remaining_;
}

void StatusPrinter::BuildEdgeStarted(const Edge* edge,
                                     int64_t start_time_millis) {
  ++started_edges_;
  ++running_edges_;
  time_millis_ = start_time_millis;

  if (edge->use_console() || printer_.is_smart_terminal())
    PrintStatus(edge, start_time_millis);

  if (edge->use_console())
    printer_.SetConsoleLocked(true);
}

void StatusPrinter::RecalculateProgressPrediction() {
  time_predicted_percentage_ = 0.0;

  // Sometimes, the previous and actual times may be wildly different.
  // For example, the previous build may have been fully recovered from ccache,
  // so it was blazing fast, while the new build no longer gets hits from ccache
  // for whatever reason, so it actually compiles code, which takes much longer.
  // We should detect such cases, and avoid using "wrong" previous times.

  // Note that we will only use the previous times if there are edges with
  // previous time knowledge remaining.
  bool use_previous_times = eta_predictable_edges_remaining_ &&
                            eta_predictable_cpu_time_remaining_millis_;

  // Iff we have sufficient statistical information for the current run,
  // that is, if we have took at least 15 sec AND finished at least 5% of edges,
  // we can check whether our performance so far matches the previous one.
  if (use_previous_times && total_edges_ && finished_edges_ &&
      (time_millis_ >= 15 * 1e3) &&
      (((double)finished_edges_ / total_edges_) >= 0.05)) {
    // Over the edges we've just run, how long did they take on average?
    double actual_average_cpu_time_millis =
        (double)cpu_time_millis_ / finished_edges_;
    // What is the previous average, for the edges with such knowledge?
    double previous_average_cpu_time_millis =
        (double)eta_predictable_cpu_time_total_millis_ /
        eta_predictable_edges_total_;

    double ratio = std::max(previous_average_cpu_time_millis,
                            actual_average_cpu_time_millis) /
                   std::min(previous_average_cpu_time_millis,
                            actual_average_cpu_time_millis);

    // Let's say that the average times should differ by less than 10x
    use_previous_times = ratio < 10;
  }

  int edges_with_known_runtime = finished_edges_;
  if (use_previous_times)
    edges_with_known_runtime += eta_predictable_edges_remaining_;
  if (edges_with_known_runtime == 0)
    return;

  int edges_with_unknown_runtime = use_previous_times
                                       ? eta_unpredictable_edges_remaining_
                                       : (total_edges_ - finished_edges_);

  // Given the time elapsed on the edges we've just run,
  // and the runtime of the edges for which we know previous runtime,
  // what's the edge's average runtime?
  int64_t edges_known_runtime_total_millis = cpu_time_millis_;
  if (use_previous_times)
    edges_known_runtime_total_millis +=
        eta_predictable_cpu_time_remaining_millis_;

  double average_cpu_time_millis =
      (double)edges_known_runtime_total_millis / edges_with_known_runtime;

  // For the edges for which we do not have the previous runtime,
  // let's assume that their average runtime is the same as for the other edges,
  // and we therefore can predict their remaining runtime.
  double unpredictable_cpu_time_remaining_millis =
      average_cpu_time_millis * edges_with_unknown_runtime;

  // And therefore we can predict the remaining and total runtimes.
  double total_cpu_time_remaining_millis =
      unpredictable_cpu_time_remaining_millis;
  if (use_previous_times)
    total_cpu_time_remaining_millis +=
        eta_predictable_cpu_time_remaining_millis_;
  double total_cpu_time_millis =
      cpu_time_millis_ + total_cpu_time_remaining_millis;
  if (total_cpu_time_millis == 0.0)
    return;

  // After that we can tell how much work we've completed, in time units.
  time_predicted_percentage_ = cpu_time_millis_ / total_cpu_time_millis;
}

void StatusPrinter::BuildEdgeFinished(Edge* edge, int64_t start_time_millis,
                                      int64_t end_time_millis, ExitStatus exit_code,
                                      const string& output) {
  time_millis_ = end_time_millis;
  ++finished_edges_;

  int64_t elapsed = end_time_millis - start_time_millis;
  cpu_time_millis_ += elapsed;

  // Do we know how long did this edge take last time?
  if (edge->prev_elapsed_time_millis != -1) {
    --eta_predictable_edges_remaining_;
    eta_predictable_cpu_time_remaining_millis_ -=
        edge->prev_elapsed_time_millis;
  } else
    --eta_unpredictable_edges_remaining_;

  if (edge->use_console())
    printer_.SetConsoleLocked(false);

  if (config_.verbosity == BuildConfig::QUIET)
    return;

  if (!edge->use_console())
    PrintStatus(edge, end_time_millis);

  --running_edges_;

  // Print the command that is spewing before printing its output.
  if (exit_code != ExitSuccess) {
    string outputs;
    for (vector<Node*>::const_iterator o = edge->outputs_.begin();
         o != edge->outputs_.end(); ++o)
      outputs += (*o)->path() + " ";

    string failed = "FAILED: [code=" + std::to_string(exit_code) + "] ";
    if (printer_.supports_color()) {
        printer_.PrintOnNewLine("\x1B[31m" + failed + "\x1B[0m" + outputs + "\n");
    } else {
        printer_.PrintOnNewLine(failed + outputs + "\n");
    }
    printer_.PrintOnNewLine(edge->EvaluateCommand() + "\n");
  }

  if (!output.empty()) {
#ifdef _WIN32
    // Fix extra CR being added on Windows, writing out CR CR LF (#773)
    fflush(stdout);  // Begin Windows extra CR fix
    _setmode(_fileno(stdout), _O_BINARY);
#endif

    // ninja sets stdout and stderr of subprocesses to a pipe, to be able to
    // check if the output is empty. Some compilers, e.g. clang, check
    // isatty(stderr) to decide if they should print colored output.
    // To make it possible to use colored output with ninja, subprocesses should
    // be run with a flag that forces them to always print color escape codes.
    // To make sure these escape codes don't show up in a file if ninja's output
    // is piped to a file, ninja strips ansi escape codes again if it's not
    // writing to a |smart_terminal_|.
    // (Launching subprocesses in pseudo ttys doesn't work because there are
    // only a few hundred available on some systems, and ninja can launch
    // thousands of parallel compile commands.)
    if (printer_.supports_color() || output.find('\x1b') == std::string::npos) {
      printer_.PrintOnNewLine(output);
    } else {
      std::string final_output = StripAnsiEscapeCodes(output);
      printer_.PrintOnNewLine(final_output);
    }

#ifdef _WIN32
    fflush(stdout);
    _setmode(_fileno(stdout), _O_TEXT);  // End Windows extra CR fix
#endif
  }
}

void StatusPrinter::BuildStarted() {
  started_edges_ = 0;
  finished_edges_ = 0;
  running_edges_ = 0;
}

void StatusPrinter::BuildFinished() {
  printer_.SetConsoleLocked(false);
  printer_.PrintOnNewLine("");
}

string StatusPrinter::FormatProgressStatus(const char* progress_status_format,
                                           int64_t time_millis) const {
  string out;
  char buf[32];
  for (const char* s = progress_status_format; *s != '\0'; ++s) {
    if (*s == '%') {
      ++s;
      switch (*s) {
      case '%':
        out.push_back('%');
        break;

        // Started edges.
      case 's':
        snprintf(buf, sizeof(buf), "%d", started_edges_);
        out += buf;
        break;

        // Total edges.
      case 't':
        snprintf(buf, sizeof(buf), "%d", total_edges_);
        out += buf;
        break;

        // Running edges.
      case 'r': {
        snprintf(buf, sizeof(buf), "%d", running_edges_);
        out += buf;
        break;
      }

        // Unstarted edges.
      case 'u':
        snprintf(buf, sizeof(buf), "%d", total_edges_ - started_edges_);
        out += buf;
        break;

        // Finished edges.
      case 'f':
        snprintf(buf, sizeof(buf), "%d", finished_edges_);
        out += buf;
        break;

        // Overall finished edges per second.
      case 'o':
        SnprintfRate(finished_edges_ / (time_millis_ / 1e3), buf, "%.1f");
        out += buf;
        break;

        // Current rate, average over the last '-j' jobs.
      case 'c':
        current_rate_.UpdateRate(finished_edges_, time_millis_);
        SnprintfRate(current_rate_.rate(), buf, "%.1f");
        out += buf;
        break;

        // Percentage of edges completed
      case 'p': {
        int percent = 0;
        if (finished_edges_ != 0 && total_edges_ != 0)
          percent = (100 * finished_edges_) / total_edges_;
        snprintf(buf, sizeof(buf), "%3i%%", percent);
        out += buf;
        break;
      }

#define FORMAT_TIME_HMMSS(t)                                                \
  "%" PRId64 ":%02" PRId64 ":%02" PRId64 "", (t) / 3600, ((t) % 3600) / 60, \
      (t) % 60
#define FORMAT_TIME_MMSS(t) "%02" PRId64 ":%02" PRId64 "", (t) / 60, (t) % 60

        // Wall time
      case 'e':  // elapsed, seconds
      case 'w':  // elapsed, human-readable
      case 'E':  // ETA, seconds
      case 'W':  // ETA, human-readable
      {
        double elapsed_sec = time_millis_ / 1e3;
        double eta_sec = -1;  // To be printed as "?".
        if (time_predicted_percentage_ != 0.0) {
          // So, we know that we've spent time_millis_ wall clock,
          // and that is time_predicted_percentage_ percent.
          // How much time will we need to complete 100%?
          double total_wall_time = time_millis_ / time_predicted_percentage_;
          // Naturally, that gives us the time remaining.
          eta_sec = (total_wall_time - time_millis_) / 1e3;
        }

        const bool print_with_hours =
            elapsed_sec >= 60 * 60 || eta_sec >= 60 * 60;

        double sec = -1;
        switch (*s) {
        case 'e':  // elapsed, seconds
        case 'w':  // elapsed, human-readable
          sec = elapsed_sec;
          break;
        case 'E':  // ETA, seconds
        case 'W':  // ETA, human-readable
          sec = eta_sec;
          break;
        }

        if (sec < 0)
          snprintf(buf, sizeof(buf), "?");
        else {
          switch (*s) {
          case 'e':  // elapsed, seconds
          case 'E':  // ETA, seconds
            snprintf(buf, sizeof(buf), "%.3f", sec);
            break;
          case 'w':  // elapsed, human-readable
          case 'W':  // ETA, human-readable
            if (print_with_hours)
              snprintf(buf, sizeof(buf), FORMAT_TIME_HMMSS((int64_t)sec));
            else
              snprintf(buf, sizeof(buf), FORMAT_TIME_MMSS((int64_t)sec));
            break;
          }
        }
        out += buf;
        break;
      }

      // Percentage of time spent out of the predicted time total
      case 'P': {
        snprintf(buf, sizeof(buf), "%3i%%",
                 (int)(100. * time_predicted_percentage_));
        out += buf;
        break;
      }

      default:
        Fatal("unknown placeholder '%%%c' in $NINJA_STATUS", *s);
        return "";
      }
    } else {
      out.push_back(*s);
    }
  }

  return out;
}

void StatusPrinter::PrintStatus(const Edge* edge, int64_t time_millis) {
  if (explanations_) {
    // Collect all explanations for the current edge's outputs.
    std::vector<std::string> explanations;
    for (Node* output : edge->outputs_) {
      explanations_->LookupAndAppend(output, &explanations);
    }
    if (!explanations.empty()) {
      // Start a new line so that the first explanation does not append to the
      // status line.
      printer_.PrintOnNewLine("");
      for (const auto& exp : explanations) {
        fprintf(stderr, "ninja explain: %s\n", exp.c_str());
      }
    }
  }

  if (config_.verbosity == BuildConfig::QUIET
      || config_.verbosity == BuildConfig::NO_STATUS_UPDATE)
    return;

  RecalculateProgressPrediction();

  bool force_full_command = config_.verbosity == BuildConfig::VERBOSE;

  string to_print = edge->GetBinding("description");
  if (to_print.empty() || force_full_command)
    to_print = edge->GetBinding("command");

  to_print = FormatProgressStatus(progress_status_format_, time_millis)
      + to_print;

  printer_.Print(to_print,
                 force_full_command ? LinePrinter::FULL : LinePrinter::ELIDE);
}

void StatusPrinter::Warning(const char* msg, ...) {
  va_list ap;
  va_start(ap, msg);
  ::Warning(msg, ap);
  va_end(ap);
}

void StatusPrinter::Error(const char* msg, ...) {
  va_list ap;
  va_start(ap, msg);
  ::Error(msg, ap);
  va_end(ap);
}

void StatusPrinter::Info(const char* msg, ...) {
  va_list ap;
  va_start(ap, msg);
  ::Info(msg, ap);
  va_end(ap);
}
