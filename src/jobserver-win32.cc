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
#include <windows.h>

#include "jobserver.h"
#include "util.h"

namespace {

// Implementation of Jobserver::Client for Win32 systems.
// At the moment, only the semaphore scheme is supported,
// even when running under Cygwin which could support the
// pipe version, in theory.
class Win32JobserverClient : public Jobserver::Client {
 public:
  virtual ~Win32JobserverClient() {
    // NOTE: OpenSemaphore() returns NULL on failure.
    if (IsValid()) {
      ::CloseHandle(handle_);
    }
  }

  Jobserver::Slot TryAcquire() override {
    if (IsValid()) {
      if (has_implicit_slot_) {
        has_implicit_slot_ = false;
        return Jobserver::Slot::CreateImplicit();
      }

      DWORD ret = ::WaitForSingleObject(handle_, 0);
      if (ret == WAIT_OBJECT_0) {
        // Hard-code value 1 for the explicit slot value.
        return Jobserver::Slot::CreateExplicit(1);
      }
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

    // Nothing can be done in case of error here.
    (void)::ReleaseSemaphore(handle_, 1, NULL);
  }

  bool InitWithSemaphore(const std::string& name, std::string* error) {
    handle_ = ::OpenSemaphoreA(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE,
                               name.c_str());
    if (handle_ == NULL) {
      *error = "Error opening semaphore: " + GetLastErrorString();
      return false;
    }
    return true;
  }

 protected:
  bool IsValid() const {
    // NOTE: OpenSemaphore() returns NULL on failure, not INVALID_HANDLE_VALUE.
    return handle_ != NULL;
  }

  // Set to true if the implicit slot has not been acquired yet.
  bool has_implicit_slot_ = true;

  // Semaphore handle. NULL means not in use.
  HANDLE handle_ = NULL;
};

}  // namespace

// static
std::unique_ptr<Jobserver::Client> Jobserver::Client::Create(
    const Jobserver::Config& config, std::string* error) {
  bool success = false;
  auto client =
      std::unique_ptr<Win32JobserverClient>(new Win32JobserverClient());
  if (config.mode == Jobserver::Config::kModeWin32Semaphore) {
    success = client->InitWithSemaphore(config.path, error);
  } else {
    *error = "Unsupported jobserver mode";
  }
  if (!success)
    client.reset();
  return client;
}
