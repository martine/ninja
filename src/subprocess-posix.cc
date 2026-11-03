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

#include "exit_status.h"
#include "subprocess.h"

#include <sys/select.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <spawn.h>

#if defined(USE_PPOLL)
#include <poll.h>
#else
#include <sys/select.h>
#endif

extern char** environ;

#include "util.h"

using namespace std;

namespace {
  ExitStatus ParseExitStatus(int status);
}

Subprocess::Subprocess(bool use_console) : fd_(-1), pid_(-1),
                                           use_console_(use_console) {
}

Subprocess::~Subprocess() {
  if (fd_ >= 0)
    close(fd_);
  // Reap child if forgotten.
  if (pid_ != -1)
    Finish();
}

bool Subprocess::Start(SubprocessSet* set, const string& command) {
  int subproc_stdout_fd = -1;
  if (use_console_) {
    fd_ = -1;
  } else {
    int output_pipe[2];
    if (pipe(output_pipe) < 0)
      Fatal("pipe: %s", strerror(errno));
    fd_ = output_pipe[0];
    subproc_stdout_fd = output_pipe[1];
#if !defined(USE_PPOLL)
    // If available, we use ppoll in DoWork(); otherwise we use pselect
    // and so must avoid overly-large FDs.
    if (fd_ >= static_cast<int>(FD_SETSIZE))
      Fatal("pipe: %s", strerror(EMFILE));
#endif  // !USE_PPOLL
    SetCloseOnExec(fd_);
  }

  posix_spawn_file_actions_t action;
  int err = posix_spawn_file_actions_init(&action);
  if (err != 0)
    Fatal("posix_spawn_file_actions_init: %s", strerror(err));

  if (!use_console_) {
    err = posix_spawn_file_actions_addclose(&action, fd_);
    if (err != 0)
      Fatal("posix_spawn_file_actions_addclose: %s", strerror(err));
  }

  posix_spawnattr_t attr;
  err = posix_spawnattr_init(&attr);
  if (err != 0)
    Fatal("posix_spawnattr_init: %s", strerror(err));

  short flags = 0;

  flags |= POSIX_SPAWN_SETSIGMASK;
  err = posix_spawnattr_setsigmask(&attr, &set->old_mask_);
  if (err != 0)
    Fatal("posix_spawnattr_setsigmask: %s", strerror(err));
  // Signals which are set to be caught in the calling process image are set to
  // default action in the new process image, so no explicit
  // POSIX_SPAWN_SETSIGDEF parameter is needed.

  if (!use_console_) {
    // Put the child in its own process group, so ctrl-c won't reach it.
    flags |= POSIX_SPAWN_SETPGROUP;
    // No need to posix_spawnattr_setpgroup(&attr, 0), it's the default.

    // Open /dev/null over stdin.
    err = posix_spawn_file_actions_addopen(&action, 0, "/dev/null", O_RDONLY,
          0);
    if (err != 0) {
      Fatal("posix_spawn_file_actions_addopen: %s", strerror(err));
    }

    err = posix_spawn_file_actions_adddup2(&action, subproc_stdout_fd, 1);
    if (err != 0)
      Fatal("posix_spawn_file_actions_adddup2: %s", strerror(err));
    err = posix_spawn_file_actions_adddup2(&action, subproc_stdout_fd, 2);
    if (err != 0)
      Fatal("posix_spawn_file_actions_adddup2: %s", strerror(err));
    err = posix_spawn_file_actions_addclose(&action, subproc_stdout_fd);
    if (err != 0)
      Fatal("posix_spawn_file_actions_addclose: %s", strerror(err));
  }

#ifdef POSIX_SPAWN_USEVFORK
  flags |= POSIX_SPAWN_USEVFORK;
#endif

  err = posix_spawnattr_setflags(&attr, flags);
  if (err != 0)
    Fatal("posix_spawnattr_setflags: %s", strerror(err));

  const char* spawned_args[] = { "/bin/sh", "-c", command.c_str(), NULL };
  err = posix_spawn(&pid_, "/bin/sh", &action, &attr,
        const_cast<char**>(spawned_args), environ);
  if (err != 0)
    Fatal("posix_spawn: %s", strerror(err));

  err = posix_spawnattr_destroy(&attr);
  if (err != 0)
    Fatal("posix_spawnattr_destroy: %s", strerror(err));
  err = posix_spawn_file_actions_destroy(&action);
  if (err != 0)
    Fatal("posix_spawn_file_actions_destroy: %s", strerror(err));

  if (!use_console_)
    close(subproc_stdout_fd);
  return true;
}

void Subprocess::OnPipeReady() {
  char buf[4 << 10];
  ssize_t len = read(fd_, buf, sizeof(buf));
  if (len > 0) {
    buf_.append(buf, len);
  } else {
    if (len < 0)
      Fatal("read: %s", strerror(errno));
    close(fd_);
    fd_ = -1;
  }
}


bool Subprocess::TryFinish(int waitpid_options) {
  assert(pid_ != -1);
  int status, ret;
  while ((ret = waitpid(pid_, &status, waitpid_options)) < 0) {
    if (errno != EINTR)
      Fatal("waitpid(%d): %s", pid_, strerror(errno));
  }
  if (ret == 0)
    return false; // Subprocess is alive (WNOHANG-only).
  pid_ = -1;
  exit_status_ = ParseExitStatus(status);
  return true; // Subprocess has terminated.
}

ExitStatus Subprocess::Finish() {
  if (pid_ != -1) {
    TryFinish(0);
    assert(pid_ == -1);
  }
  return exit_status_;
}

namespace {

ExitStatus ParseExitStatus(int status) {
#ifdef _AIX
  if (WIFEXITED(status) && WEXITSTATUS(status) & 0x80) {
    // Map the shell's exit code used for signal failure (128 + signal) to the
    // status code expected by AIX WIFSIGNALED and WTERMSIG macros which, unlike
    // other systems, uses a different bit layout.
    int signal = WEXITSTATUS(status) & 0x7f;
    status = (signal << 16) | signal;
  }
#endif

  if (WIFEXITED(status)) {
    // propagate the status transparently
    return static_cast<ExitStatus>(WEXITSTATUS(status));
  }
  if (WIFSIGNALED(status)) {
    if (WTERMSIG(status) == SIGINT || WTERMSIG(status) == SIGTERM
        || WTERMSIG(status) == SIGHUP)
      return ExitInterrupted;
  }
  // At this point, we exit with any other signal+128
  return static_cast<ExitStatus>(status + 128);
}

} // anonymous namespace

bool Subprocess::Done() const {
  // Console subprocesses share console with ninja, and we consider them done
  // when they exit.
  // For other processes, we consider them done when we have consumed all their
  // output and closed their associated pipe.
  return (use_console_ && pid_ == -1) || (!use_console_ && fd_ == -1);
}

const string& Subprocess::GetOutput() const {
  return buf_;
}

volatile sig_atomic_t SubprocessSet::interrupted_;
volatile sig_atomic_t SubprocessSet::s_sigchld_received;

void SubprocessSet::SetInterruptedFlag(int signum) {
  interrupted_ = signum;
}

void SubprocessSet::SigChldHandler(int signo, siginfo_t* info, void* context) {
  s_sigchld_received = 1;
}

void SubprocessSet::HandlePendingInterruption() {
  sigset_t pending;
  sigemptyset(&pending);
  if (sigpending(&pending) == -1) {
    perror("ninja: sigpending");
    return;
  }
  if (sigismember(&pending, SIGINT))
    interrupted_ = SIGINT;
  else if (sigismember(&pending, SIGTERM))
    interrupted_ = SIGTERM;
  else if (sigismember(&pending, SIGHUP))
    interrupted_ = SIGHUP;
}

SubprocessSet::SubprocessSet() {
  // Block all these signals.
  // Their handlers will only be enabled during ppoll/pselect().
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &set, &old_mask_) < 0)
    Fatal("sigprocmask: %s", strerror(errno));

  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = SetInterruptedFlag;

  // Check if SIGHUP is ignored, e.g. using nohup.
  if (sigaction(SIGHUP, nullptr, &old_hup_act_) < 0)
    Fatal("sigaction: %s", strerror(errno));

  // Change the child handler of SIGHUP if not ignored.
  if (old_hup_act_.sa_handler != SIG_IGN) {
    if (sigaction(SIGHUP, &act, nullptr) < 0)
      Fatal("sigaction: %s", strerror(errno));
  }

  if (sigaction(SIGINT, &act, &old_int_act_) < 0)
    Fatal("sigaction: %s", strerror(errno));
  if (sigaction(SIGTERM, &act, &old_term_act_) < 0)
    Fatal("sigaction: %s", strerror(errno));

  memset(&act, 0, sizeof(act));
  act.sa_flags = SA_SIGINFO | SA_NOCLDSTOP;
  act.sa_sigaction = SigChldHandler;
  if (sigaction(SIGCHLD, &act, &old_chld_act_) < 0)
    Fatal("sigaction: %s", strerror(errno));
}

// Reaps console processes that have exited and moves them from the running set
// to the finished set.
void SubprocessSet::CheckConsoleProcessTerminated(SubprocessSet::WorkResult* work_result) {
  if (!s_sigchld_received)
    return;
  for (auto i = running_.begin(); i != running_.end(); ) {
    if ((*i)->use_console_ && (*i)->TryFinish(WNOHANG)) {
      finished_.push(*i);
      i = running_.erase(i);
      *work_result = WorkResult::SubprocFinished;
    } else {
      ++i;
    }
  }
}

SubprocessSet::~SubprocessSet() {
  Clear();

  if (sigaction(SIGINT, &old_int_act_, 0) < 0)
    Fatal("sigaction: %s", strerror(errno));
  if (sigaction(SIGTERM, &old_term_act_, 0) < 0)
    Fatal("sigaction: %s", strerror(errno));
  if (sigaction(SIGHUP, &old_hup_act_, 0) < 0)
    Fatal("sigaction: %s", strerror(errno));
  if (sigaction(SIGCHLD, &old_chld_act_, 0) < 0)
    Fatal("sigaction: %s", strerror(errno));
  if (sigprocmask(SIG_SETMASK, &old_mask_, 0) < 0)
    Fatal("sigprocmask: %s", strerror(errno));
}

Subprocess *SubprocessSet::Add(const string& command, bool use_console) {
  Subprocess *subprocess = new Subprocess(use_console);
  if (!subprocess->Start(this, command)) {
    delete subprocess;
    return 0;
  }
  running_.push_back(subprocess);
  return subprocess;
}

#ifdef USE_PPOLL
SubprocessSet::WorkResult SubprocessSet::DoWork() {
  vector<pollfd> fds;
  nfds_t nfds = 0;
  WorkResult work_result = WorkResult::NoWork;

  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i) {
    int fd = (*i)->fd_;
    if (fd < 0)
      continue;
    pollfd pfd = { fd, POLLIN | POLLPRI, 0 };
    fds.push_back(pfd);
    ++nfds;
  }

  nfds_t jobserver_idx = nfds;
  if (jobserver_fd_ >= 0) {
    pollfd pfd = { jobserver_fd_, POLLIN | POLLPRI, 0 };
    fds.push_back(pfd);
    ++nfds;
  }

  if (nfds == 0) {
    // Add a dummy entry to prevent using an empty pollfd vector.
    // ppoll() allows to do this by setting fd < 0.
    pollfd pfd = { -1, 0, 0 };
    fds.push_back(pfd);
    ++nfds;
  }

  interrupted_ = 0;
  s_sigchld_received = 0;
  int ret = ppoll(&fds.front(), nfds, NULL, &old_mask_);
  // Note: This can remove console processes from the running set, but that is
  // not a problem for the pollfd set, as console processes are not part of the
  // pollfd set (they don't have a fd).
  CheckConsoleProcessTerminated(&work_result);
  if (ret == -1) {
    if (errno != EINTR) {
      perror("ninja: ppoll");
      return work_result;
    }
    return IsInterrupted() ? WorkResult::Interrupted : work_result;
  }

  // ppoll/pselect prioritizes file descriptor events over a signal delivery.
  // However, if the user is trying to quit ninja, we should react as fast as
  // possible.
  HandlePendingInterruption();
  if (IsInterrupted())
    return WorkResult::Interrupted;

  // Iterate through both the pollfd set and the running set.
  // All valid fds in the running set are in the pollfd, in the same order.
  nfds_t cur_nfd = 0;
  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ) {
    int fd = (*i)->fd_;
    if (fd < 0) {
      ++i;
      continue;
    }
    assert(fd == fds[cur_nfd].fd);
    if (fds[cur_nfd++].revents) {
      (*i)->OnPipeReady();
      if ((*i)->Done()) {
        finished_.push(*i);
        i = running_.erase(i);
        work_result = WorkResult::SubprocFinished;
        continue;
      }
    }
    ++i;
  }

  // Jobserver token is available. Make sure that we only react
  // to jobserver tokens if no other work was done
  const bool no_work = work_result == WorkResult::NoWork;
  if (jobserver_fd_ >= 0 && fds[jobserver_idx].revents && no_work) {
    work_result = WorkResult::JobserverTokenAvailable;
  }

  return IsInterrupted() ? WorkResult::Interrupted : work_result;
}

#else  // !defined(USE_PPOLL)
SubprocessSet::WorkResult SubprocessSet::DoWork() {
  fd_set set;
  int nfds = 0;
  FD_ZERO(&set);
  WorkResult work_result = WorkResult::NoWork;

  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i) {
    int fd = (*i)->fd_;
    if (fd >= 0) {
      FD_SET(fd, &set);
      if (nfds < fd+1)
        nfds = fd+1;
    }
  }

  if (jobserver_fd_ >= 0) {
    FD_SET(jobserver_fd_, &set);
    if (nfds < jobserver_fd_+1)
      nfds = jobserver_fd_+1;
  }

  interrupted_ = 0;
  s_sigchld_received = 0;
  int ret = pselect(nfds, (nfds > 0 ? &set : nullptr), 0, 0, 0, &old_mask_);
  CheckConsoleProcessTerminated(&work_result);
  if (ret == -1) {
    if (errno != EINTR) {
      perror("ninja: pselect");
      return work_result;
    }
    return IsInterrupted() ? WorkResult::Interrupted : work_result;
  }

  // ppoll/pselect prioritizes file descriptor events over a signal delivery.
  // However, if the user is trying to quit ninja, we should react as fast as
  // possible.
  HandlePendingInterruption();
  if (IsInterrupted())
    return WorkResult::Interrupted;

  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ) {
    int fd = (*i)->fd_;
    if (fd >= 0 && FD_ISSET(fd, &set)) {
      (*i)->OnPipeReady();
      if ((*i)->Done()) {
        finished_.push(*i);
        i = running_.erase(i);
        work_result = WorkResult::SubprocFinished;
        continue;
      }
    }
    ++i;
  }

  // Jobserver token is available. Make sure that we only react
  // to jobserver tokens if no other work was done
  const bool no_work = work_result == WorkResult::NoWork;
  if (jobserver_fd_ >= 0 && FD_ISSET(jobserver_fd_, &set) && no_work) {
    work_result = WorkResult::JobserverTokenAvailable;
  }

  return IsInterrupted() ? WorkResult::Interrupted : work_result;
}
#endif  // !defined(USE_PPOLL)

Subprocess* SubprocessSet::NextFinished() {
  if (finished_.empty())
    return NULL;
  Subprocess* subproc = finished_.front();
  finished_.pop();
  return subproc;
}

void SubprocessSet::Clear() {
  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i)
    // Since the foreground process is in our process group, it will receive
    // the interruption signal (i.e. SIGINT or SIGTERM) at the same time as us.
    if (!(*i)->use_console_)
      kill(-(*i)->pid_, interrupted_);
  for (vector<Subprocess*>::iterator i = running_.begin();
       i != running_.end(); ++i)
    delete *i;
  running_.clear();
}
