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

#pragma once

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

/// Jobserver provides types related to managing a pool of "job slots"
/// using the GNU Make jobserver ptocol described at:
///
/// https://www.gnu.org/software/make/manual/html_node/Job-Slots.html
///
struct Jobserver {
  /// A Jobserver::Slot models a single job slot that can be acquired from.
  /// or released to a jobserver pool. This class is move-only, and can
  /// wrap three types of values:
  ///
  /// - An "invalid" value (the default), used to indicate errors, e.g.
  ///   that no slot could be acquired from the pool.
  ///
  /// - The "implicit" value, used to model the job slot that is implicitly
  ///   assigned to a jobserver client by the parent process that spawned
  ///   it.
  ///
  /// - The "explicit" values, which correspond to an actual byte read from
  ///   the slot pool's pipe (for Posix), or a semaphore decrement operation
  ///   (for Windows).
  ///
  /// Use IsValid(), IsImplicit(), HasValue() to test for categories.
  ///
  /// TECHNICAL NOTE: This design complies with the requirements laid out
  /// on https://www.gnu.org/software/make/manual/html_node/POSIX-Jobserver.html
  /// which requires clients to write back the exact token values they
  /// received from a Posix pipe.
  ///
  /// Note that *currently* all pool implementations write the same token
  /// values to the pipe ('+' for GNU Make, and '|' for the Rust jobserver),
  /// and do not care about the values written back by clients.
  ///
  struct Slot {
    /// Default constructor creates invalid instance.
    Slot() = default;

    /// Move operations are allowed.
    Slot(Slot&& o) noexcept : value_(o.value_) { o.value_ = -1; }

    Slot& operator=(Slot&& o) noexcept {
      if (this != &o) {
        this->value_ = o.value_;
        o.value_ = -1;
      }
      return *this;
    }

    /// Copy operations are disallowed.
    Slot(const Slot&) = delete;
    Slot& operator=(const Slot&) = delete;

    /// Return true if this instance is valid, i.e. that it is either
    /// implicit or explicit job slot.
    bool IsValid() const { return value_ >= 0; }

    /// Return true if this instance represents an implicit job slot.
    bool IsImplicit() const { return value_ == kImplicitValue; }

    /// Return true if this instance represents an explicit job slot
    bool IsExplicit() const { return IsValid() && !IsImplicit(); }

    /// Return value of an explicit slot. It is a runtime error to call
    /// this from an invalid instance.
    uint8_t GetExplicitValue() const;

    /// Create instance for explicit byte value.
    static Slot CreateExplicit(uint8_t value) {
      return Slot(static_cast<int16_t>(value));
    }

    /// Create instance for the implicit value.
    static Slot CreateImplicit() { return Slot(kImplicitValue); }

   private:
    Slot(int16_t value) : value_(value) {}

    static constexpr int16_t kImplicitValue = 256;

    int16_t value_ = -1;
  };

  /// A Jobserver::Config models how to access or implement a GNU jobserver
  /// implementation.
  struct Config {
    /// Different implementation modes for the slot pool.
    ///
    /// kModeNone means there is no pool.
    ///
    /// kModePipe means that `--jobserver-auth=R,W` is used to
    ///    pass a pair of file descriptors to client processes. This also
    ///    matches `--jobserver-fds=R,W` which is an old undocumented
    ///    variant of the same scheme.
    ///
    /// kModePosixFifo means that `--jobserver-auth=fifo:PATH` is used to
    ///    pass the path of a Posix FIFO to client processes. This is not
    ///    supported on Windows. Implemented by GNU Make 4.4 and above
    ///    when `--jobserver-style=fifo` is used.
    ///
    /// kModeWin32Semaphore means that `--jobserver-auth=SEMAPHORE_NAME` is
    ///    used to pass the name of a Win32 semaphore to client processes.
    ///    This is not supported on Posix.
    ///
    /// kModeDefault is the default mode to enable on the current platform.
    ///    This is an alias for kModeWin32Semaphore on Windows ,and
    ///    kModePipe on Posix, since FIFO mode was only introduced in
    ///    GNU Make 4.4, and older clients may not support it.
    enum Mode {
      kModeNone = 0,
      kModePipe,
      kModePosixFifo,
      kModeWin32Semaphore,
#ifdef _WIN32
      kModeDefault = kModeWin32Semaphore,
#else   // _WIN32
      kModeDefault = kModePipe,
#endif  // _WIN32
    };

    /// Implementation mode for the pool.
    Mode mode = kModeNone;

    /// For kModeFifo, this is the path to the Unix FIFO to use.
    /// For kModeSemaphore, this is the name of the Win32 semaphore to use.
    std::string path;

    /// For kModePipe, these are the file descriptor values
    /// extracted from MAKEFLAGS.
    int read_fd = -1;
    int write_fd = -1;

    /// Return true if this instance matches an active implementation mode.
    /// This does not try to validate configuration parameters though.
    bool HasMode() { return mode != kModeNone; }
  };

  /// Parse the value of a MAKEFLAGS environment variable. On success return
  /// true and set |*config|. On failure, return false and set |*error| to
  /// explain what's wrong. If |makeflags_env| is nullptr or an empty string,
  /// this returns success and sets |config->mode| to Config::kModeNone.
  static bool ParseMakeFlagsValue(const char* makeflags_env, Config* config,
                                  std::string* error);

  /// A variant of ParseMakeFlagsValue() that will return an error if the parsed
  /// result is not compatible with the native system. For example
  /// --jobserver-auth=R,W or --jobserver-auth=fifo:PATH only work on Posix,
  /// while --jobserver-auth=NAME only work on Windows.
  static bool ParseNativeMakeFlagsValue(const char* makeflags_env,
                                        Config* config, std::string* error);

  /// A Jobserver::Client instance models a client of an external GNU jobserver
  /// pool, which can be implemented as a Unix FIFO, or a Windows named semaphore.
  /// Usage is the following:
  ///
  ///  - Call Jobserver::Client::Create(), passing a Config value as argument,
  ///    (e.g. one initialized with ParseNativeMakeFlagsValue()) to create
  ///    a new instance.
  ///
  ///  - Call TryAcquire() to try to acquire a job slot from the pool.
  ///    If the result is not an invalid slot, store it until the
  ///    corresponding command completes, then call Release() to send it
  ///    back to the pool.
  ///
  ///  - It is important that all acquired slots are released to the pool,
  ///    even if Ninja terminates early (e.g. due to a build command failing).
  ///
  class Client {
   public:
    /// Destructor.
    virtual ~Client() {}

    /// Try to acquire a slot from the pool. On failure, i.e. if no slot
    /// can be acquired, this returns an invalid Token instance.
    ///
    /// Note that this will always return the implicit slot value the first
    /// time this is called, without reading anything from the pool, as
    /// specified by the protocol. This implicit value *must* be released
    /// just like any other one. In general, users of this class should not
    /// care about this detail, except unit-tests.
    virtual Slot TryAcquire() { return Slot(); }

    /// Release a slot to the pool. Does nothing if slot is invalid,
    /// or if writing to the pool fails (and if this is not the implicit slot).
    /// If the pool is destroyed before Ninja, then only the implicit slot
    /// can be acquired in the next calls (if it was released). This simply
    /// enforces serialization of all commands, instead of blocking.
    virtual void Release(Slot slot) {}

    /// Create a new Client instance from a given configuration. On failure,
    /// this returns null after setting |*error|. Note that it is an error to
    /// call this function with |config.HasMode() == false|.
    static std::unique_ptr<Client> Create(const Config&, std::string* error);

   protected:
    Client() = default;
  };
};
