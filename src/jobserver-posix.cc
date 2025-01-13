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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "jobserver.h"
#include "util.h"

namespace {

// Return true if |fd| is a fifo or pipe descriptor.
bool IsFifoDescriptor(int fd) {
  struct stat info;
  int ret = ::fstat(fd, &info);
  return (ret == 0) && ((info.st_mode & S_IFMT) == S_IFIFO);
}

bool SetNonBlockingFd(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (!(flags & O_NONBLOCK)) {
    int ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (ret < 0)
      return false;
  }
  return true;
}

bool SetCloseOnExecFd(int fd) {
  int flags = fcntl(fd, F_GETFD, 0);
  if (!(flags & FD_CLOEXEC)) {
    int ret = fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    if (ret < 0)
      return false;
  }
  return true;
}

// Duplicate the descriptor and make the result non-blocking and
// close-on-exec.
bool DuplicateDescriptor(int from_fd, int* to_fd) {
  int new_fd = dup(from_fd);
  if (new_fd < 0) {
    return false;
  }
  if (!SetNonBlockingFd(new_fd) || !SetCloseOnExecFd(new_fd)) {
    ::close(new_fd);
    return false;
  }
  *to_fd = new_fd;
  return true;
}

// Implementation of Jobserver::Client for Posix systems
class PosixJobserverClient : public Jobserver::Client {
 public:
  virtual ~PosixJobserverClient() {
    if (write_fd_ >= 0)
      ::close(write_fd_);
    if (read_fd_ >= 0)
      ::close(read_fd_);
  }

  Jobserver::Slot TryAcquire() override {
    if (has_implicit_slot_) {
      has_implicit_slot_ = false;
      return Jobserver::Slot::CreateImplicit();
    }
    uint8_t slot_char = '\0';
    int ret;
    do {
      ret = ::read(read_fd_, &slot_char, 1);
    } while (ret < 0 && errno == EINTR);
    if (ret == 1) {
      return Jobserver::Slot::CreateExplicit(slot_char);
    }
    return Jobserver::Slot();
  }

  void Release(Jobserver::Slot slot) override {
    if (!slot.IsValid())
      return;

    if (slot.IsImplicit()) {
      assert(!has_implicit_slot_ && "Implicit slot cannot be released twice!");
      has_implicit_slot_ = true;
      return;
    }

    uint8_t slot_char = slot.GetExplicitValue();
    int ret;
    do {
      ret = ::write(write_fd_, &slot_char, 1);
    } while (ret < 0 && errno == EINTR);
    (void)ret;  // Nothing can be done in case of error here.
  }

  // Initialize instance with two explicit pipe file descriptors.
  bool InitWithPipeFds(int read_fd, int write_fd, std::string* error) {
    // Verify that the file descriptors belong to FIFOs.
    if (!IsFifoDescriptor(read_fd) || !IsFifoDescriptor(write_fd)) {
      *error = "Invalid file descriptors";
      return false;
    }
    // Duplicate the file descriptors to make then non-blocking, and
    // close-on-exec. This is important because the original descriptors
    // might be inherited by sub-processes of this client.
    if (!DuplicateDescriptor(read_fd, &read_fd_)) {
      *error = "Could not duplicate read descriptor";
      return false;
    }
    if (!DuplicateDescriptor(write_fd, &write_fd_)) {
      *error = "Could not duplicate write descriptor";
      // Let destructor close read_fd_.
      return false;
    }
    return true;
  }

  // Initialize with FIFO file path.
  bool InitWithFifo(const std::string& fifo_path, std::string* error) {
    if (fifo_path.empty()) {
      *error = "Empty fifo path";
      return false;
    }
    read_fd_ = ::open(fifo_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (read_fd_ < 0) {
      *error =
          std::string("Error opening fifo for reading: ") + strerror(errno);
      return false;
    }
    if (!IsFifoDescriptor(read_fd_)) {
      *error = "Not a fifo path: " + fifo_path;
      // Let destructor close read_fd_.
      return false;
    }
    write_fd_ = ::open(fifo_path.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (write_fd_ < 0) {
      *error =
          std::string("Error opening fifo for writing: ") + strerror(errno);
      // Let destructor close read_fd_
      return false;
    }
    return true;
  }

 private:
  // Set to true if the implicit slot has not been acquired yet.
  bool has_implicit_slot_ = true;

  // read and write descriptors.
  int read_fd_ = -1;
  int write_fd_ = -1;
};

}  // namespace

// static
std::unique_ptr<Jobserver::Client> Jobserver::Client::Create(
    const Jobserver::Config& config, std::string* error) {
  bool success = false;
  auto client = std::unique_ptr<PosixJobserverClient>(new PosixJobserverClient);
  if (config.mode == Jobserver::Config::kModePipe) {
    success = client->InitWithPipeFds(config.read_fd, config.write_fd, error);
  } else if (config.mode == Jobserver::Config::kModePosixFifo) {
    success = client->InitWithFifo(config.path, error);
  } else {
    *error = "Unsupported jobserver mode";
  }
  if (!success)
    client.reset();
  return client;
}
