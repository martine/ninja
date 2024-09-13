// Copyright 2024 Google Inc. All Rights Reserved.
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

#include "jobserver.h"

#include "test.h"

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {

#ifndef _WIN32
struct ScopedTestFd {
  explicit ScopedTestFd(int fd) : fd_(fd) {}

  ~ScopedTestFd() {
    if (IsValid())
      ::close(fd_);
  }

  bool IsValid() const { return fd_ >= 0; }

  int fd_ = -1;
};
#endif  // !_WIN32

}  // namespace

TEST(Jobserver, SlotTest) {
  // Default construction.
  Jobserver::Slot slot;
  EXPECT_FALSE(slot.IsValid());

  // Construct implicit slot
  Jobserver::Slot slot0 = Jobserver::Slot::CreateImplicit();
  EXPECT_TRUE(slot0.IsValid());
  EXPECT_TRUE(slot0.IsImplicit());
  EXPECT_FALSE(slot0.IsExplicit());

  // Construct explicit slots
  auto slot1 = Jobserver::Slot::CreateExplicit(10u);
  EXPECT_TRUE(slot1.IsValid());
  EXPECT_FALSE(slot1.IsImplicit());
  EXPECT_TRUE(slot1.IsExplicit());
  EXPECT_EQ(10u, slot1.GetExplicitValue());

  auto slot2 = Jobserver::Slot::CreateExplicit(42u);
  EXPECT_TRUE(slot2.IsValid());
  EXPECT_FALSE(slot2.IsImplicit());
  EXPECT_TRUE(slot2.IsExplicit());
  EXPECT_EQ(42u, slot2.GetExplicitValue());

  // Move operation.
  slot2 = std::move(slot1);
  EXPECT_FALSE(slot1.IsValid());
  EXPECT_TRUE(slot2.IsValid());
  EXPECT_TRUE(slot2.IsExplicit());
  ASSERT_EQ(10u, slot2.GetExplicitValue());

  slot1 = std::move(slot0);
  EXPECT_FALSE(slot0.IsValid());
  EXPECT_TRUE(slot1.IsValid());
  EXPECT_TRUE(slot1.IsImplicit());
  EXPECT_FALSE(slot1.IsExplicit());
}

TEST(Jobserver, ParseMakeFlagsValue) {
  Jobserver::Config config;
  std::string error;

  // Passing nullptr does not crash.
  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue(nullptr, &config, &error));
  EXPECT_EQ(Jobserver::Config::kModeNone, config.mode);

  // Passing an empty string does not crash.
  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("", &config, &error));
  EXPECT_EQ(Jobserver::Config::kModeNone, config.mode);

  // Passing a string that only contains whitespace does not crash.
  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("  \t", &config, &error));
  EXPECT_EQ(Jobserver::Config::kModeNone, config.mode);

  // Passing an `n` in the first word reports no mode.
  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("kns --jobserver-auth=fifo:foo",
                                             &config, &error));
  EXPECT_EQ(Jobserver::Config::kModeNone, config.mode);

  // Passing "--jobserver-auth=fifo:<path>" works.
  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("--jobserver-auth=fifo:foo",
                                             &config, &error));
  EXPECT_EQ(Jobserver::Config::kModePosixFifo, config.mode);
  EXPECT_EQ("foo", config.path);

  // Passing an `n` in the first word _after_ a dash works though, i.e.
  // It is not interpreted as GNU Make dry-run flag.
  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue(
      "-one-flag --jobserver-auth=fifo:foo", &config, &error));
  EXPECT_EQ(Jobserver::Config::kModePosixFifo, config.mode);

  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("--jobserver-auth=semaphore_name",
                                             &config, &error));
  EXPECT_EQ(Jobserver::Config::kModeWin32Semaphore, config.mode);
  EXPECT_EQ("semaphore_name", config.path);

  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("--jobserver-auth=10,42", &config,
                                             &error));
  EXPECT_EQ(Jobserver::Config::kModePipe, config.mode);
  EXPECT_EQ(10, config.read_fd);
  EXPECT_EQ(42, config.write_fd);

  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("--jobserver-auth=-1,42", &config,
                                             &error));
  EXPECT_EQ(Jobserver::Config::kModeNone, config.mode);

  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue("--jobserver-auth=10,-42", &config,
                                             &error));
  EXPECT_EQ(Jobserver::Config::kModeNone, config.mode);

  config = {};
  error.clear();
  ASSERT_TRUE(Jobserver::ParseMakeFlagsValue(
      "--jobserver-auth=10,42 --jobserver-fds=12,44 "
      "--jobserver-auth=fifo:/tmp/fifo",
      &config, &error));
  EXPECT_EQ(Jobserver::Config::kModePosixFifo, config.mode);
  EXPECT_EQ("/tmp/fifo", config.path);

  config = {};
  error.clear();
  ASSERT_FALSE(
      Jobserver::ParseMakeFlagsValue("--jobserver-fds=10,", &config, &error));
  EXPECT_EQ("Invalid file descriptor pair [10,]", error);
}
