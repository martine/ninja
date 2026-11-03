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

#include "subprocess.h"

#include "exit_status.h"
#include "test.h"

#ifndef _WIN32
// SetWithLots need setrlimit.
#include <signal.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

using namespace std;

namespace {

#ifdef _WIN32
const char* kSimpleCommand = "cmd /c dir \\";
#else
const char* kSimpleCommand = "ls /";
#endif

struct SubprocessTest : public testing::Test {
  SubprocessSet subprocs_;
};

#ifndef _WIN32
struct ScopedPipe {
    int read_fd_ = -1;
    int write_fd_ = -1;

    ScopedPipe() {
        int fds[2];
        if (::pipe(fds) == -1) {
            return;
        }
        read_fd_ = fds[0];
        write_fd_ = fds[1];
    }

    ~ScopedPipe() {
        if (read_fd_ >= 0) {
            ::close(read_fd_);
        }
        if (write_fd_ >= 0) {
            ::close(write_fd_);
        }
    }

    // Check if both ends are valid
    bool IsValid() const {
        return read_fd_ >= 0 && write_fd_ >= 0;
    }
};
#endif

}  // anonymous namespace

// Run a command that fails and emits to stderr.
TEST_F(SubprocessTest, BadCommandStderr) {
  Subprocess* subproc = subprocs_.Add("cmd /c ninja_no_such_command");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    // Pretend we discovered that stderr was ready for writing.
    subprocs_.DoWork();
  }

  ExitStatus exit = subproc->Finish();
  EXPECT_NE(ExitSuccess, exit);
  EXPECT_NE("", subproc->GetOutput());
}

// Run a command that does not exist
TEST_F(SubprocessTest, NoSuchCommand) {
  Subprocess* subproc = subprocs_.Add("ninja_no_such_command");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    // Pretend we discovered that stderr was ready for writing.
    subprocs_.DoWork();
  }

  ExitStatus exit = subproc->Finish();
  EXPECT_NE(ExitSuccess, exit);
  EXPECT_NE("", subproc->GetOutput());
#ifdef _WIN32
  ASSERT_EQ("CreateProcess failed: The system cannot find the file "
            "specified.\n", subproc->GetOutput());
#endif
}

#ifndef _WIN32

TEST_F(SubprocessTest, InterruptChild) {
  Subprocess* subproc = subprocs_.Add("kill -INT $$");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    subprocs_.DoWork();
  }

  EXPECT_EQ(ExitInterrupted, subproc->Finish());
}

TEST_F(SubprocessTest, InterruptParent) {
  Subprocess* subproc = subprocs_.Add("kill -INT $PPID ; sleep 1");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    SubprocessSet::WorkResult status = subprocs_.DoWork();
    if (status == SubprocessSet::WorkResult::Interrupted)
      return;
  }

  ASSERT_FALSE("We should have been interrupted");
}

TEST_F(SubprocessTest, InterruptChildWithSigTerm) {
  Subprocess* subproc = subprocs_.Add("kill -TERM $$");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    subprocs_.DoWork();
  }

  EXPECT_EQ(ExitInterrupted, subproc->Finish());
}

TEST_F(SubprocessTest, InterruptParentWithSigTerm) {
  Subprocess* subproc = subprocs_.Add("kill -TERM $PPID ; sleep 1");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    SubprocessSet::WorkResult status = subprocs_.DoWork();
    if (status == SubprocessSet::WorkResult::Interrupted)
      return;
  }

  ASSERT_FALSE("We should have been interrupted");
}

TEST_F(SubprocessTest, InterruptChildWithSigHup) {
  Subprocess* subproc = subprocs_.Add("kill -HUP $$");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    subprocs_.DoWork();
  }

  EXPECT_EQ(ExitInterrupted, subproc->Finish());
}

TEST_F(SubprocessTest, NotInterruptChildWithNoHup) {
  struct sigaction nohup, hup;

  memset(&nohup, 0, sizeof(struct sigaction));
  nohup.sa_handler = SIG_IGN;
  sigaction(SIGHUP, &nohup, &hup);

  Subprocess* subproc = subprocs_.Add("kill -HUP $$");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    subprocs_.DoWork();
  }

  EXPECT_EQ(ExitSuccess, subproc->Finish());
  sigaction(SIGHUP, &hup, nullptr);
}

TEST_F(SubprocessTest, InterruptParentWithSigHup) {
  Subprocess* subproc = subprocs_.Add("kill -HUP $PPID ; sleep 1");
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    SubprocessSet::WorkResult status = subprocs_.DoWork();
    if (status == SubprocessSet::WorkResult::Interrupted)
      return;
  }

  ASSERT_FALSE("We should have been interrupted");
}

TEST_F(SubprocessTest, Console) {
  // Skip test if we don't have the console ourselves.
  if (isatty(0) && isatty(1) && isatty(2)) {
    Subprocess* subproc =
        subprocs_.Add("test -t 0 -a -t 1 -a -t 2", /*use_console=*/true);
    ASSERT_NE((Subprocess*)0, subproc);

    while (!subproc->Done()) {
      subprocs_.DoWork();
    }

    EXPECT_EQ(ExitSuccess, subproc->Finish());
  }
}

#endif

TEST_F(SubprocessTest, SetWithSingle) {
  Subprocess* subproc = subprocs_.Add(kSimpleCommand);
  ASSERT_NE((Subprocess *) 0, subproc);

  while (!subproc->Done()) {
    subprocs_.DoWork();
  }
  ASSERT_EQ(ExitSuccess, subproc->Finish());
  ASSERT_NE("", subproc->GetOutput());

  ASSERT_EQ(1u, subprocs_.finished_.size());
}

TEST_F(SubprocessTest, SetWithMulti) {
  Subprocess* processes[3];
  const char* kCommands[3] = {
    kSimpleCommand,
#ifdef _WIN32
    "cmd /c echo hi",
    "cmd /c time /t",
#else
    "id -u",
    "pwd",
#endif
  };

  for (int i = 0; i < 3; ++i) {
    processes[i] = subprocs_.Add(kCommands[i]);
    ASSERT_NE((Subprocess *) 0, processes[i]);
  }

  ASSERT_EQ(3u, subprocs_.running_.size());
  for (int i = 0; i < 3; ++i) {
    ASSERT_FALSE(processes[i]->Done());
    ASSERT_EQ("", processes[i]->GetOutput());
  }

  while (!processes[0]->Done() || !processes[1]->Done() ||
         !processes[2]->Done()) {
    ASSERT_GT(subprocs_.running_.size(), 0u);
    subprocs_.DoWork();
  }

  ASSERT_EQ(0u, subprocs_.running_.size());
  ASSERT_EQ(3u, subprocs_.finished_.size());

  for (int i = 0; i < 3; ++i) {
    ASSERT_EQ(ExitSuccess, processes[i]->Finish());
    ASSERT_NE("", processes[i]->GetOutput());
    delete processes[i];
  }
}

#if defined(USE_PPOLL)
TEST_F(SubprocessTest, SetWithLots) {
  // Arbitrary big number; needs to be over 1024 to confirm we're no longer
  // hostage to pselect.
  const unsigned kNumProcs = 1025;

  // Make sure [ulimit -n] isn't going to stop us from working.
  rlimit rlim;
  ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &rlim));
  if (rlim.rlim_cur < kNumProcs) {
    printf("Raise [ulimit -n] above %u (currently %lu) to make this test go\n",
           kNumProcs, static_cast<unsigned long>(rlim.rlim_cur));
    return;
  }

  vector<Subprocess*> procs;
  for (size_t i = 0; i < kNumProcs; ++i) {
    Subprocess* subproc = subprocs_.Add("/bin/echo");
    ASSERT_NE((Subprocess *) 0, subproc);
    procs.push_back(subproc);
  }
  while (!subprocs_.running_.empty())
    subprocs_.DoWork();
  for (size_t i = 0; i < procs.size(); ++i) {
    ASSERT_EQ(ExitSuccess, procs[i]->Finish());
    ASSERT_NE("", procs[i]->GetOutput());
  }
  ASSERT_EQ(kNumProcs, subprocs_.finished_.size());
}
#endif  // !__APPLE__ && !_WIN32

// TODO: this test could work on Windows, just not sure how to simply
// read stdin.
#ifndef _WIN32
// Verify that a command that attempts to read stdin correctly thinks
// that stdin is closed.
TEST_F(SubprocessTest, ReadStdin) {
  Subprocess* subproc = subprocs_.Add("cat -");
  while (!subproc->Done()) {
    subprocs_.DoWork();
  }
  ASSERT_EQ(ExitSuccess, subproc->Finish());
  ASSERT_EQ(1u, subprocs_.finished_.size());
}
#endif  // _WIN32

#ifndef _WIN32
TEST_F(SubprocessTest, JobserverTokenAvailable) {
  // Setup a mock jobserver by using a pipe.
  // Give the read end of the pipe to SubprocessSet.
  ScopedPipe mock_jobserver;
  ASSERT_TRUE(mock_jobserver.IsValid());

  int read_fd = mock_jobserver.read_fd_;
  int write_fd = mock_jobserver.write_fd_;
  subprocs_.SetJobserverFD(mock_jobserver.read_fd_);

  // Trigger mock jobserver token availability by
  // writing a byte to the write end of the pipe.
  uint8_t token = 0;
  ssize_t ret = ::write(write_fd, &token, 1);
  ASSERT_EQ(1, ret);

  // Assert we detected the jobserver token availability.
  Subprocess* subproc = subprocs_.Add("sleep 1");
  SubprocessSet::WorkResult result = subprocs_.DoWork();
  ASSERT_EQ(SubprocessSet::WorkResult::JobserverTokenAvailable, result);

  // To avoid busy waiting, set the jobserver fd to -1
  subprocs_.SetJobserverFD(-1);

  // Finish the subprocess to avoid leaks.
  while (!subproc->Done()) {
    subprocs_.DoWork();
  }

  ASSERT_EQ(ExitSuccess, subproc->Finish());
  ASSERT_EQ(1u, subprocs_.finished_.size());
}
#endif
