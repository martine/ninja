// Copyright 2025 Google Inc. All Rights Reserved.
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

#include "jobserver_pool.h"

#include <assert.h>
#include <stdlib.h>

#include "util.h"

#ifdef _WIN32

#include <windows.h>

class Win32JobserverPool : public JobserverPool {
 public:
  static std::unique_ptr<Win32JobserverPool> Create(size_t slot_count,
                                                    std::string* error) {
    assert(slot_count > 1 && "slot_count must be 2 or higher");
    auto pool = std::unique_ptr<Win32JobserverPool>(new Win32JobserverPool());
    if (!pool->InitWithSemaphore(slot_count, error))
      pool.reset();
    return pool;
  }

  std::string GetEnvMakeFlagsValue() const override {
    std::string result;
    result.resize(sem_name_.size() + 32);
    int ret =
        snprintf(const_cast<char*>(result.data()), result.size(),
                 " -j%zd --jobserver-auth=%s", job_count_, sem_name_.c_str());
    if (ret < 0 || ret > static_cast<int>(result.size()))
      Fatal("Could not format Win32JobserverPool MAKEFLAGS!");

    return result;
  }

  virtual ~Win32JobserverPool() {
    if (IsValid())
      ::CloseHandle(handle_);
  }

 private:
  Win32JobserverPool() = default;

  // CreateSemaphore returns NULL on failure.
  bool IsValid() const {
    // CreateSemaphoreA() returns NULL on failure, not INVALID_HANDLE_VALUE.
    return handle_ != NULL;
  }

  // Compute semaphore name for new instance.
  static std::string GetSemaphoreName() {
    // Use a per-process global counter to allow multiple instances of this
    // class to run in the same process. Useful for unit-tests.
    static int counter = 0;
    counter += 1;
    char name[64];
    snprintf(name, sizeof(name), "ninja_jobserver_pool_%d_%d",
             GetCurrentProcessId(), counter);
    return std::string(name);
  }

  bool InitWithSemaphore(size_t slot_count, std::string* error) {
    job_count_ = slot_count;
    sem_name_ = GetSemaphoreName();
    LONG count = static_cast<LONG>(slot_count - 1);
    handle_ = ::CreateSemaphoreA(NULL, count, count, sem_name_.c_str());
    if (!IsValid()) {
      *error = "Could not create semaphore: " + GetLastErrorString();
      return false;
    }
    return true;
  }

  // Semaphore handle.
  HANDLE handle_ = NULL;

  // Saved slot count.
  size_t job_count_ = 0;

  // Semaphore name.
  std::string sem_name_;
};

#else  // !_WIN32

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

class PosixJobserverPool : public JobserverPool {
 public:
  static std::unique_ptr<PosixJobserverPool> Create(size_t slot_count,
                                                    std::string* error) {
    assert(slot_count > 1 && "slot_count must be 2 or higher");
    auto pool = std::unique_ptr<PosixJobserverPool>(new PosixJobserverPool());
    if (!pool->InitWithFifo(slot_count, error)) {
      pool.reset();
    }
    return pool;
  }

  std::string GetEnvMakeFlagsValue() const override {
    std::string result;
    if (!fifo_.empty()) {
      result.resize(fifo_.size() + 32);
      int ret = snprintf(const_cast<char*>(result.data()), result.size(),
                         " -j%zd --jobserver-auth=fifo:%s", job_count_,
                         fifo_.c_str());
      if (ret < 0 || ret > static_cast<int>(result.size()))
        Fatal("Could not format PosixJobserverPool MAKEFLAGS!");
      result.resize(static_cast<size_t>(ret));
    }
    return result;
  }

  virtual ~PosixJobserverPool() {
    if (write_fd_ >= 0)
      ::close(write_fd_);
    if (!fifo_.empty())
      ::unlink(fifo_.c_str());
  }

 private:
  PosixJobserverPool() = default;

  // Fill the pool to satisfy |slot_count| job slots. This
  // writes |slot_count - 1| bytes to the pipe to satisfy the
  // implicit job slot requirement.
  bool FillSlots(size_t slot_count, std::string* error) {
    job_count_ = slot_count;
    while (slot_count > 1) {
      // Write '+' into the pipe, just like GNU Make. Note that some
      // implementations write '|' instead, but so far no client or pool
      // implementation cares about the exact value, though the official spec
      // says this might change in the future.
      const char slot_char = '+';
      ssize_t ret = ::write(write_fd_, &slot_char, 1);
      if (ret == 1) {
        slot_count--;
        continue;
      }
      if (ret < 0 && errno == EINTR)
        continue;

      *error = std::string("Could not fill job slots pool: ") + strerror(errno);
      return false;
    }
    return true;
  }

  bool InitWithFifo(size_t slot_count, std::string* error) {
    const char* tmp_dir = getenv("TMPDIR");
    if (!tmp_dir)
      tmp_dir = "/tmp";

    fifo_.resize(strlen(tmp_dir) + 32);
    int len = snprintf(const_cast<char*>(fifo_.data()), fifo_.size(),
                       "%s/NinjaFIFO%d", tmp_dir, getpid());
    if (len < 0) {
      *error = "Cannot create fifo path!";
      return false;
    }
    fifo_.resize(static_cast<size_t>(len));

    // Only the owner may open the fifo, as with GNU Make: any process that
    // can open it is able to take job slots out of the pool or add new ones.
    int ret = mknod(fifo_.c_str(), S_IFIFO | 0600, 0);
    if (ret < 0) {
      *error = std::string("Cannot create fifo: ") + strerror(errno);
      return false;
    }

    do {
      write_fd_ = ::open(fifo_.c_str(), O_RDWR | O_CLOEXEC);
    } while (write_fd_ < 0 && errno == EINTR);
    if (write_fd_ < 0) {
      *error = std::string("Could not open fifo: ") + strerror(errno);
      // Let destructor remove the fifo.
      return false;
    }
    return FillSlots(slot_count, error);
  }

  // Number of parallel job slots (including implicit one).
  size_t job_count_ = 0;

  // A non-inheritable file descriptor to keep the pool alive.
  int write_fd_ = -1;

  // Path to fifo, this will be empty when using an anonymous pipe.
  std::string fifo_;
};
#endif  // !_WIN32

// static
std::unique_ptr<JobserverPool> JobserverPool::Create(size_t num_job_slots,
                                                     std::string* error) {
  if (num_job_slots < 2) {
    *error = "At least 2 job slots needed";
    return nullptr;
  }

#ifdef _WIN32
  return Win32JobserverPool::Create(num_job_slots, error);
#else   // !_WIN32
  return PosixJobserverPool::Create(num_job_slots, error);
#endif  // !_WIN32
}
