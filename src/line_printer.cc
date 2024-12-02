// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "line_printer.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x4
#endif
#else
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/time.h>
#endif

#include "elide_middle.h"
#include "util.h"

using namespace std;

LinePrinter::LinePrinter() : have_blank_line_(true), console_locked_(false) {
  const char* term = getenv("TERM");
#ifndef _WIN32
  smart_terminal_ = isatty(1) && term && string(term) != "dumb";
#else
  if (term) {
    // Assume we are in a terminal emulator.
    smart_terminal_ = string(term) != "dumb";
    console_ = INVALID_HANDLE_VALUE;
  } else {
    console_ = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    smart_terminal_ = GetConsoleScreenBufferInfo(console_, &csbi);
  }
#endif
  supports_color_ = smart_terminal_;
#ifdef _WIN32
  // On Windows it is not possible to distinguish a terminal emulator
  // from a pipe and ANSI escape sequences break applications that
  // parse ninja's output (cmake, for instance):
  supports_color_ = supports_color_ && console_ != INVALID_HANDLE_VALUE;
  // Try enabling ANSI escape sequence support on Windows 10 terminals.
  if (supports_color_) {
    DWORD mode;
    if (GetConsoleMode(console_, &mode)) {
      if (!SetConsoleMode(console_, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        supports_color_ = false;
      }
    }
  }
#endif
  if (!supports_color_) {
    const char* clicolor_force = getenv("CLICOLOR_FORCE");
    supports_color_ = clicolor_force && std::string(clicolor_force) != "0";
  }
}

void LinePrinter::Print(string to_print, LineType type) {
  if (console_locked_) {
    line_buffer_ = to_print;
    line_type_ = type;
    return;
  }

  if (smart_terminal_) {
    printf("\r");  // Print over previous line, if any.
    // On Windows, calling a C library function writing to stdout also handles
    // pausing the executable when the "Pause" key or Ctrl-S is pressed.
  }

  if (smart_terminal_ && type == ELIDE) {
#ifdef _WIN32
    if (console_ == INVALID_HANDLE_VALUE) {
      // Assume we are in a terminal emulator.
      to_print = ElideMiddle(to_print, 80);
      printf("%s", to_print.c_str());
      fflush(stdout);
      return;
    }

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console_, &csbi);

    ElideMiddleInPlace(to_print, static_cast<size_t>(csbi.dwSize.X));
    if (supports_color_) {  // this means ENABLE_VIRTUAL_TERMINAL_PROCESSING
                            // succeeded
      printf("%s\x1B[K", to_print.c_str());  // Clear to end of line.
      fflush(stdout);
    } else {
      // We don't want to have the cursor spamming back and forth, so instead of
      // printf use WriteConsoleOutput which updates the contents of the buffer,
      // but doesn't move the cursor position.
      COORD buf_size = { csbi.dwSize.X, 1 };
      COORD zero_zero = { 0, 0 };
      SMALL_RECT target = { csbi.dwCursorPosition.X, csbi.dwCursorPosition.Y,
                            static_cast<SHORT>(csbi.dwCursorPosition.X +
                                               csbi.dwSize.X - 1),
                            csbi.dwCursorPosition.Y };
      vector<CHAR_INFO> char_data(csbi.dwSize.X);
      for (size_t i = 0; i < static_cast<size_t>(csbi.dwSize.X); ++i) {
        char_data[i].Char.AsciiChar = i < to_print.size() ? to_print[i] : ' ';
        char_data[i].Attributes = csbi.wAttributes;
      }
      WriteConsoleOutput(console_, &char_data[0], buf_size, zero_zero, &target);
    }
#else
    // Limit output to width of the terminal if provided so we don't cause
    // line-wrapping.
    winsize size;
    if ((ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0) && size.ws_col) {
      ElideMiddleInPlace(to_print, size.ws_col);
    }
    printf("%s", to_print.c_str());
    printf("\x1B[K");  // Clear to end of line.
    fflush(stdout);
#endif

    have_blank_line_ = false;
  } else {
    printf("%s\n", to_print.c_str());
    fflush(stdout);
  }
}

void LinePrinter::PrintOrBuffer(const char* data, size_t size) {
  if (console_locked_) {
    output_buffer_.append(data, size);
  } else {
    // Avoid printf and C strings, since the actual output might contain null
    // bytes like UTF-16 does (yuck).
    fwrite(data, 1, size, stdout);
  }
}

void LinePrinter::PrintOnNewLine(const string& to_print) {
  if (console_locked_ && !line_buffer_.empty()) {
    output_buffer_.append(line_buffer_);
    output_buffer_.append(1, '\n');
    line_buffer_.clear();
  }
  if (!have_blank_line_) {
    PrintOrBuffer("\n", 1);
  }
  if (!to_print.empty()) {
    PrintOrBuffer(&to_print[0], to_print.size());
  }
  have_blank_line_ = to_print.empty() || *to_print.rbegin() == '\n';
}

void LinePrinter::SetConsoleLocked(bool locked) {
  if (locked == console_locked_)
    return;

  if (locked)
    PrintOnNewLine("");

  console_locked_ = locked;

  if (!locked) {
    PrintOnNewLine(output_buffer_);
    if (!line_buffer_.empty()) {
      Print(line_buffer_, line_type_);
    }
    output_buffer_.clear();
    line_buffer_.clear();
  }
}
