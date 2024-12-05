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

#ifdef _WIN32

#include <windows.h>

// Must appear after <windows.h>
#include <dbghelp.h>

#include "util.h"

using namespace std;

typedef BOOL (WINAPI *MiniDumpWriteDumpFunc) (
    IN HANDLE,
    IN DWORD,
    IN HANDLE,
    IN MINIDUMP_TYPE,
    IN CONST PMINIDUMP_EXCEPTION_INFORMATION, OPTIONAL
    IN CONST PMINIDUMP_USER_STREAM_INFORMATION, OPTIONAL
    IN CONST PMINIDUMP_CALLBACK_INFORMATION OPTIONAL
    );

/// Creates a windows minidump in temp folder.
void CreateWin32MiniDump(_EXCEPTION_POINTERS* pep) {
  wchar_t temp_path[MAX_PATH];
  GetTempPathW(sizeof(temp_path) / sizeof(temp_path[0]), temp_path);
  wchar_t temp_file[MAX_PATH];
  _snwprintf(temp_file, MAX_PATH, L"%s\\ninja_crash_dump_%lu.dmp", temp_path,
             GetCurrentProcessId());

  // Delete any previous minidump of the same name.
  DeleteFileW(temp_file);

  // Load DbgHelp.dll dynamically, as library is not present on all
  // Windows versions.
  HMODULE dbghelp = LoadLibraryW(L"dbghelp.dll");
  if (dbghelp == NULL) {
    Error("failed to create minidump: LoadLibrary('dbghelp.dll'): %s",
          GetLastErrorString().c_str());
    return;
  }

  MiniDumpWriteDumpFunc mini_dump_write_dump =
      (MiniDumpWriteDumpFunc)GetProcAddress(dbghelp, "MiniDumpWriteDump");
  if (mini_dump_write_dump == NULL) {
    Error("failed to create minidump: GetProcAddress('MiniDumpWriteDump'): %s",
          GetLastErrorString().c_str());
    return;
  }

  HANDLE hFile = CreateFileW(temp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == NULL) {
    Error("failed to create minidump: CreateFileW(%s): %s",
          Win32UnicodeToUTF8(temp_file).c_str(), GetLastErrorString().c_str());
    return;
  }

  MINIDUMP_EXCEPTION_INFORMATION mdei;
  mdei.ThreadId           = GetCurrentThreadId();
  mdei.ExceptionPointers  = pep;
  mdei.ClientPointers     = FALSE;
  MINIDUMP_TYPE mdt       = (MINIDUMP_TYPE) (MiniDumpWithDataSegs |
                                             MiniDumpWithHandleData);

  BOOL rv = mini_dump_write_dump(GetCurrentProcess(), GetCurrentProcessId(),
                                 hFile, mdt, (pep != 0) ? &mdei : 0, 0, 0);
  CloseHandle(hFile);

  if (!rv) {
    Error("MiniDumpWriteDump failed: %s", GetLastErrorString().c_str());
    return;
  }

  Warning("minidump created: %s", temp_file);
}

#endif  // _WIN32
