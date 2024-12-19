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

#include "status_printer.h"

#include "build.h"
#include "test.h"

struct StatusPrinterTest : public testing::Test {
  StatusPrinterTest() : config_(MakeConfig()), status_(config_) {}

  virtual void SetUp() { status_.BuildStarted(); }

  static BuildConfig MakeConfig() {
    BuildConfig config;
    config.verbosity = BuildConfig::QUIET;
    return config;
  }

  BuildConfig config_;
  StatusPrinter status_;
};

TEST_F(StatusPrinterTest, StatusFormatElapsed_e) {
  // Before any task is done, the elapsed time must be zero.
  EXPECT_EQ("[%/e0.000]", status_.FormatProgressStatus("[%%/e%e]", 0));
}

TEST_F(StatusPrinterTest, StatusFormatElapsed_w) {
  // Before any task is done, the elapsed time must be zero.
  EXPECT_EQ("[%/e00:00]", status_.FormatProgressStatus("[%%/e%w]", 0));
}

TEST_F(StatusPrinterTest, StatusFormatETA) {
  // Before any task is done, the ETA time must be unknown.
  EXPECT_EQ("[%/E?]", status_.FormatProgressStatus("[%%/E%E]", 0));
}

TEST_F(StatusPrinterTest, StatusFormatTimeProgress) {
  // Before any task is done, the percentage of elapsed time must be zero.
  EXPECT_EQ("[%/p  0%]", status_.FormatProgressStatus("[%%/p%p]", 0));
}

TEST_F(StatusPrinterTest, StatusFormatReplacePlaceholder) {
  EXPECT_EQ("[%/s0/t0/r0/u0/f0]",
            status_.FormatProgressStatus("[%%/s%s/t%t/r%r/u%u/f%f]", 0));
}

TEST_F(StatusPrinterTest, StatusFormatValidator) {
  EXPECT_TRUE(StatusPrinter::IsValidProgressStatus("[%f/%t] "));
  {
    std::string error_output;
    EXPECT_FALSE(
        StatusPrinter::IsValidProgressStatus("[%f/%X] ", &error_output));
    EXPECT_EQ("unknown placeholder '%X' in $NINJA_STATUS", error_output);
  }

  EXPECT_EQ("", status_.FormatProgressStatus("[%f/%X] ", 0));
}
