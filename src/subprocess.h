// Copyright 2012 Google Inc. All Rights Reserved.
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

#ifndef NINJA_SUBPROCESS_H_
#define NINJA_SUBPROCESS_H_

#include <stdint.h>

#include <queue>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

// ppoll() exists on FreeBSD, but only on newer versions.
#ifdef __FreeBSD__
#  include <sys/param.h>
#  if defined USE_PPOLL && __FreeBSD_version < 1002000
#    undef USE_PPOLL
#  endif
#endif

#include "exit_status.h"

/// Subprocess wraps a single async subprocess.  It is entirely
/// passive: it expects the caller to notify it when its fds are ready
/// for reading, as well as call Finish() to reap the child once done()
/// is true.
struct Subprocess {
  ~Subprocess();

  /// Returns ExitSuccess on successful process exit, ExitInterrupted if
  /// the process was interrupted, ExitFailure if it otherwise failed.
  ExitStatus Finish();

  bool Done() const;

  const std::string& GetOutput() const;

 private:
  Subprocess(bool use_console);
  bool Start(struct SubprocessSet* set, const std::string& command);
  void OnPipeReady();

  std::string buf_;

#ifdef _WIN32
  /// Set up pipe_ as the parent-side pipe of the subprocess; return the
  /// other end of the pipe, usable in the child process.
  HANDLE SetupPipe(HANDLE ioport);

  HANDLE child_;
  HANDLE pipe_;
  OVERLAPPED overlapped_;
  char overlapped_buf_[4 << 10];
  bool is_reading_;
#else
  int fd_;
  pid_t pid_;
#endif
  bool use_console_;

  friend struct SubprocessSet;
};

/// SubprocessSet runs a ppoll/pselect() loop around a set of Subprocesses.
/// DoWork() waits for any state change in subprocesses; finished_
/// is a queue of subprocesses as they finish.
struct SubprocessSet {
  SubprocessSet();
  ~SubprocessSet();

  // Value returned by DoWork() method,
  // - COMPLETION means that a process has completed.
  // - INTERRUPTION means that user interruption happened. On Posix this means
  //   a SIGINT, SIGHUP or SIGTERM signal. On Win32, this means Ctrl-C was
  //   pressed.
  // - TIMEOUT means that the called timed out.
  enum class WorkResult {
    COMPLETION = 0,
    INTERRUPTION = 1,
    TIMEOUT = 3,
  };

  // Start a new subprocess running |command|. Set |use_console| to true
  // if the process will inherit the current console handles (terminal
  // input and outputs on Posix). If false, the subprocess' output
  // will be buffered instead, and available after completion.
  Subprocess* Add(const std::string& command, bool use_console = false);

  // Equivalent to DoWork(-1), which returns true in case of interruption
  // and false otherwise.
  bool DoWork();

  // Wait for at most |timeout_millis| milli-seconds for either a process
  // completion or a user-initiated interruption. If |timeout_millis| is
  // negative, waits indefinitely, and never return WorkStatus::TIMEOUT.
  //
  // IMPORTANT: On Posix, spurious wakeups are possible, and will return
  // WorkResult::COMPLETION even though no process has really
  // completed. The caller should call NextFinished() and compare the
  // its result to nullptr to check for this rare condition.
  WorkResult DoWork(int64_t timeout_millis);

  // Return the next Subprocess after a WorkResult::COMPLETION result.
  // The result can be nullptr on Posix in case of spurious wakeups.
  // NOTE: This transfers ownership of the Subprocess instance to the caller.
  Subprocess* NextFinished();

  void Clear();

  std::vector<Subprocess*> running_;
  std::queue<Subprocess*> finished_;

#ifdef _WIN32
  static BOOL WINAPI NotifyInterrupted(DWORD dwCtrlType);
  static HANDLE ioport_;
#else
  static void SetInterruptedFlag(int signum);
  static void HandlePendingInterruption();
  /// Store the signal number that causes the interruption.
  /// 0 if not interruption.
  static int interrupted_;

  static bool IsInterrupted() { return interrupted_ != 0; }

  struct sigaction old_int_act_;
  struct sigaction old_term_act_;
  struct sigaction old_hup_act_;
  sigset_t old_mask_;
#endif
};

#endif // NINJA_SUBPROCESS_H_
