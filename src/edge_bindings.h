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

#ifndef NINJA_EDGE_BINDINGS_H_
#define NINJA_EDGE_BINDINGS_H_

#include "pointer_variant.h"
#include "string_piece.h"

#include <optional>
#include <string>

struct FileScope;

/// The variables declared in an edge's build block (indented under its
/// `build` line), with a pointer to the scope of the file the block is in.
/// This is only data: EdgeScope and the parser's EdgePathScope define how
/// variables are looked up.
struct EdgeBindings {
  /// Create the bindings of an edge declared in the file whose scope is
  /// `parent`.
  /// @pre parent != nullptr
  explicit EdgeBindings(FileScope* parent);
  ~EdgeBindings();

  EdgeBindings(const EdgeBindings&) = delete;
  EdgeBindings& operator=(const EdgeBindings&) = delete;

  /// Add a binding, replacing any earlier binding of the same key.
  void AddBinding(const std::string& key, StringPiece val);

  /// Return this build block's value for `var`, or nothing if it doesn't set
  /// one.  This doesn't look in the parent.  The value stays valid until the
  /// bindings are next changed.
  std::optional<StringPiece> FindBinding(StringPiece var) const;

  /// Return the scope of the file containing this build block.
  FileScope& parent() const;

private:
  /// The parent and bindings of a build block with at least one binding.
  struct Impl;

  /// There is one EdgeBindings per edge and most edges have no bindings, so
  /// this holds only the parent until there is a binding, and then an owned
  /// Impl holding the parent and the bindings.  Either way it is one pointer.
  PointerVariant<FileScope*, Impl*> data_;
};

#endif  // NINJA_EDGE_BINDINGS_H_
