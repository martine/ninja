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

#include <assert.h>
#include <stdio.h>

#include <vector>

#include "string_piece.h"

namespace {

// If |input| starts with |prefix|, return true and sets |*value| to the rest
// of the input. Otherwise return false.
bool GetPrefixedValue(StringPiece input, StringPiece prefix,
                      StringPiece* value) {
  assert(prefix.len_ > 0);
  if (input.len_ < prefix.len_ || memcmp(prefix.str_, input.str_, prefix.len_))
    return false;

  *value = StringPiece(input.str_ + prefix.len_, input.len_ - prefix.len_);
  return true;
}

// Try to read a comma-separated pair of file descriptors from |input|.
// On success return true and set |*config| accordingly. Otherwise return
// false if the input doesn't follow the appropriate format.
bool GetFileDescriptorPair(StringPiece input, Jobserver::Config* config) {
  std::string pair = input.AsString();
  if (sscanf(pair.c_str(), "%d,%d", &config->read_fd, &config->write_fd) != 2)
    return false;

  // From
  // https://www.gnu.org/software/make/manual/html_node/POSIX-Jobserver.html Any
  // negative descriptor means the feature is disabled.
  if (config->read_fd < 0 || config->write_fd < 0)
    config->mode = Jobserver::Config::kModeNone;
  else
    config->mode = Jobserver::Config::kModePipe;

  return true;
}

}  // namespace

// static
const int16_t Jobserver::Slot::kImplicitValue;

uint8_t Jobserver::Slot::GetExplicitValue() const {
  assert(IsExplicit());
  return static_cast<uint8_t>(value_);
}

bool Jobserver::ParseMakeFlagsValue(const char* makeflags_env,
                                    Jobserver::Config* config,
                                    std::string* error) {
  *config = Config();

  if (!makeflags_env || !makeflags_env[0]) {
    /// Return default Config instance with kModeNone if input is null or empty.
    return true;
  }

  // Decompose input into vector of space or tab separated string pieces.
  std::vector<StringPiece> args;
  const char* p = makeflags_env;
  while (*p) {
    const char* next_space = strpbrk(p, " \t");
    if (!next_space) {
      args.emplace_back(p);
      break;
    }

    if (next_space > p)
      args.emplace_back(p, next_space - p);

    p = next_space + 1;
  }

  // clang-format off
  //
  // From:
  // https://www.gnu.org/software/make/manual/html_node/POSIX-Jobserver.html
  //
  // """
  // Your tool may also examine the first word of the MAKEFLAGS variable and
  // look for the character n. If this character is present then make was
  // invoked with the ‘-n’ option and your tool may want to stop without
  // performing any operations.
  // """
  //
  // Where according to
  // https://www.gnu.org/software/make/manual/html_node/Options_002fRecursion.html
  // MAKEFLAGS begins with all "flag letters" passed to make.
  //
  // Experimentation shows that GNU Make 4.3, at least, will set MAKEFLAGS with
  // an initial space if no letter flag are passed to its invocation (except -j),
  // i.e.:
  //
  //    make -ks --> MAKEFLAGS="ks"
  //    make -j  --> MAKEFLAGS=" -j"
  //    make -ksj --> MAKEFLAGS="ks -j"
  //    make -ks -j3  --> MAKEFLAGS="ks -j3 --jobserver-auth=3,4"
  //    make -j3      --> MAKEFLAGS=" -j3 --jobserver-auth=3,4"
  //
  // However, other jobserver implementation will not, for example the one
  // at https://github.com/rust-lang/jobserver-rs will set MAKEFLAGS to just
  // "--jobserver-fds=R,W --jobserver-auth=R,W" instead, without an initial
  // space.
  //
  // Another implementation is from Rust's Cargo itself which will set it to
  // "-j --jobserver-fds=R,W --jobserver-auth=R,W".
  //
  // For the record --jobserver-fds=R,W is an old undocumented and deprecated
  // version of --jobserver-auth=R,W that was implemented by GNU Make before 4.2
  // was released, and some tooling may depend on it. Hence it makes sense to
  // define both --jobserver-fds and --jobserver-auth at the same time, since
  // the last recognized one should win in client code.
  //
  // The initial space will have been stripped by the loop above, but we can
  // still support the requirement by ignoring the first arg if it begins with a
  // dash (-).
  //
  // clang-format on
  if (!args.empty() && args[0][0] != '-' &&
      !!memchr(args[0].str_, 'n', args[0].len_)) {
    return true;
  }

  // Loop over all arguments, the last one wins, except in case of errors.
  for (const auto& arg : args) {
    StringPiece value;

    // Handle --jobserver-auth=... here.
    if (GetPrefixedValue(arg, "--jobserver-auth=", &value)) {
      if (GetFileDescriptorPair(value, config)) {
        continue;
      }
      StringPiece fifo_path;
      if (GetPrefixedValue(value, "fifo:", &fifo_path)) {
        config->mode = Jobserver::Config::kModePosixFifo;
        config->path = fifo_path.AsString();
      } else {
        config->mode = Jobserver::Config::kModeWin32Semaphore;
        config->path = value.AsString();
      }
      continue;
    }

    // Handle --jobserver-fds which is an old undocumented variant of
    // --jobserver-auth that only accepts a pair of file descriptor.
    // This was replaced by --jobserver-auth=R,W in GNU Make 4.2.
    if (GetPrefixedValue(arg, "--jobserver-fds=", &value)) {
      if (!GetFileDescriptorPair(value, config)) {
        *error = "Invalid file descriptor pair [" + value.AsString() + "]";
        return false;
      }
      config->mode = Jobserver::Config::kModePipe;
      continue;
    }

    // Ignore this argument. This assumes that MAKEFLAGS does not
    // use spaces to separate the option from its argument, e.g.
    // `--jobserver-auth <something>`, which has been confirmed with
    // Make 4.3, even if it receives such a value in its own env.
  }

  return true;
}

bool Jobserver::ParseNativeMakeFlagsValue(const char* makeflags_env,
                                          Jobserver::Config* config,
                                          std::string* error) {
  if (!ParseMakeFlagsValue(makeflags_env, config, error))
    return false;

#ifdef _WIN32
  if (config->mode == Jobserver::Config::kModePosixFifo) {
    *error = "FIFO mode is not available on Windows!";
    return false;
  }
  if (config->mode == Jobserver::Config::kModePipe) {
    *error =
        "File-descriptor based authentication is not available on Windows!";
    return false;
  }
#else   // !_WIN32
  if (config->mode == Jobserver::Config::kModeWin32Semaphore) {
    *error = "Semaphore mode is only available on Windows!";
    return false;
  }
#endif  // !_WIN32
  return true;
}
