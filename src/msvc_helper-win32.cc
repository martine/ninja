// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "msvc_helper.h"

#include <windows.h>

#include "util.h"

using namespace std;

namespace {

string Replace(const string& input, const string& find, const string& replace) {
  string result = input;
  size_t start_pos = 0;
  while ((start_pos = result.find(find, start_pos)) != string::npos) {
    result.replace(start_pos, find.length(), replace);
    start_pos += replace.length();
  }
  return result;
}

}  // anonymous namespace

string EscapeForDepfile(const string& path) {
  // Depfiles don't escape single \.
  return Replace(path, " ", "\\ ");
}

int CLWrapper::Run(const string& command, string* output) {
  SECURITY_ATTRIBUTES security_attributes = {};
  security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
  security_attributes.bInheritHandle = TRUE;

  // Must be inheritable so subprocesses can dup to children.
  HANDLE nul =
      CreateFileW(L"NUL", GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  &security_attributes, OPEN_EXISTING, 0, NULL);
  if (nul == INVALID_HANDLE_VALUE)
    Fatal("couldn't open nul");

  HANDLE stdout_read, stdout_write;
  if (!CreatePipe(&stdout_read, &stdout_write, &security_attributes, 0))
    Win32Fatal("CreatePipe");

  if (!SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0))
    Win32Fatal("SetHandleInformation");

  PROCESS_INFORMATION process_info = {};
  STARTUPINFOW startup_info = {};
  startup_info.cb = sizeof(STARTUPINFOW);
  startup_info.hStdInput = nul;
  startup_info.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
  startup_info.hStdOutput = stdout_write;
  startup_info.dwFlags |= STARTF_USESTDHANDLES;

  // NOTE: CreateProcessW() modifies the input command string.
  // env_block_ contains an ANSI environment block, so
  // CREATE_UNICODE_ENVIRONMENT is _not_ used here in dwCreationFlags.
  std::wstring command_wide = UTF8ToWin32Unicode(command);
  if (!CreateProcessW(NULL, const_cast<wchar_t*>(command_wide.data()), NULL,
                      NULL,
                      /* inherit handles */ TRUE, 0, env_block_, NULL,
                      &startup_info, &process_info)) {
    Win32Fatal("CreateProcess");
  }

  if (!CloseHandle(nul) ||
      !CloseHandle(stdout_write)) {
    Win32Fatal("CloseHandle");
  }

  // Read all output of the subprocess.
  DWORD read_len = 1;
  while (read_len) {
    char buf[64 << 10];
    read_len = 0;
    if (!::ReadFile(stdout_read, buf, sizeof(buf), &read_len, NULL) &&
        GetLastError() != ERROR_BROKEN_PIPE) {
      Win32Fatal("ReadFile");
    }
    output->append(buf, read_len);
  }

  // Wait for it to exit and grab its exit code.
  if (WaitForSingleObject(process_info.hProcess, INFINITE) == WAIT_FAILED)
    Win32Fatal("WaitForSingleObject");
  DWORD exit_code = 0;
  if (!GetExitCodeProcess(process_info.hProcess, &exit_code))
    Win32Fatal("GetExitCodeProcess");

  if (!CloseHandle(stdout_read) ||
      !CloseHandle(process_info.hProcess) ||
      !CloseHandle(process_info.hThread)) {
    Win32Fatal("CloseHandle");
  }

  return exit_code;
}
