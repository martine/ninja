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

#include "edge_bindings.h"

#include "file_scope.h"
#include "string_piece_util.h"

#include <cassert>
#include <map>

struct EdgeBindings::Impl {
  explicit Impl(FileScope* parent) : parent(parent) {}
  FileScope* parent;
  std::map<std::string, std::string, StringPieceLess> bindings;
};

EdgeBindings::EdgeBindings(FileScope* parent) : data_(parent) {
  assert(parent != nullptr && "an edge needs the scope of its file");
}

EdgeBindings::~EdgeBindings() {
  delete get_if<Impl*>(&data_);
}

FileScope& EdgeBindings::parent() const {
  return holds_alternative<FileScope*>(data_)
             ? *get<FileScope*>(data_)
             : *get<Impl*>(data_)->parent;
}

std::optional<StringPiece> EdgeBindings::FindBinding(StringPiece var) const {
  const Impl* impl = get_if<Impl*>(&data_);
  if (!impl)
    return std::nullopt;
  const auto i = impl->bindings.find(var);
  if (i == impl->bindings.end())
    return std::nullopt;
  return StringPiece(i->second);
}

void EdgeBindings::AddBinding(const std::string& key, StringPiece val) {
  Impl* impl = get_if<Impl*>(&data_);
  if (!impl) {
    impl = new Impl(get<FileScope*>(data_));
    data_ = impl;
  }
  impl->bindings[key].assign(val.begin(), val.end());
}
