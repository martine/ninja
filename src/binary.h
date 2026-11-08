// Copyright 2026 Google Inc. All Rights Reserved.
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

#ifndef NINJA_BINARY_H_
#define NINJA_BINARY_H_

#include <stdio.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

struct State;
struct BindingEnv;

class ReadBinary {
 public:
  virtual bool read(char* data, std::size_t size) = 0;
  virtual std::size_t tellg() = 0;
  virtual std::size_t GetFileSize() const = 0;
  virtual ~ReadBinary() {}
};

class ReadBinaryTest final : public ReadBinary {
 public:
  ReadBinaryTest(std::string&& content);
  static ReadBinaryTest file(std::string filename);

  bool read(char* data, std::size_t size) override final;
  virtual std::size_t tellg() override final;
  std::size_t GetFileSize() const override final;

 private:
  const std::string data_;
  std::size_t position_ = 0;
};

class WriteBinary {
 public:
  virtual ~WriteBinary() {}
  virtual bool Write(const char* data, std::size_t size) = 0;
  virtual std::size_t Tellp()const  = 0;
  virtual void Seekp(std::size_t offset) = 0;
};

/// Buffered binary reader for disk files using 64 KB chunks to reduce system
/// calls and limit memory allocations.
class WriteBinaryDisk final : public WriteBinary {
 public:
  WriteBinaryDisk(std::string fileName);
  ~WriteBinaryDisk();
  bool Write(const char* data, std::size_t size) override final;
  std::size_t Tellp() const override final;
  void Seekp(std::size_t offset) override final;

 private:
  bool Flush();

  FILE* file_;

  static constexpr std::size_t BUFFER_SIZE = 64 * 1024;
  /// buffer data from disk
  char buffer_[BUFFER_SIZE];

  std::size_t buffer_pos_ = 0;
};

class WriteBinaryTest final : public WriteBinary {
 public:
  WriteBinaryTest(std::string& data) : data_(data), pos_(data.size()) {}
  bool Write(const char* data, std::size_t size) override final;
  virtual std::size_t Tellp() const override final;
  void Seekp(std::size_t offset) override final;

  std::string& GetData() { return data_; }

 private:
  std::string& data_;
  std::size_t pos_;  // current write cursor
};

void WriteManifestCache(WriteBinary& os, const State* state,
                        const std::vector<std::string>& includeFiles,
                        const std::vector<BindingEnv*>& bindingEnv);
std::string ReadManifestCache(ReadBinary& is, State* state);

/// @return returns names of all included files, on success
std::optional<std::vector<std::string>> ReadIncludeFiles(ReadBinary& is);

#endif
