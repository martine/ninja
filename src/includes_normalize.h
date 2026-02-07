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

#ifndef INCLUDES_NORMALIZE_H_
#define INCLUDES_NORMALIZE_H_

#include <string>
#include <vector>

struct StringPiece;

/// Utility functions for normalizing include paths on Windows.
struct IncludesNormalize {
  /// Normalize path relative to |relative_to|.
  IncludesNormalize(StringPiece relative_to);

  /// Make |path| absolute and return whether it was successful. On failure,
  /// load an error message to |err| and return false.
  /// @pre |path| must be in the canonical form, see CanonicalizePath.
  /// @pre |err| is empty.
  static bool MakePathAbsolute(std::string* path, std::string* err);

  /// Make the |abs_path| variable relative to the path components in
  /// |start_list|.
  /// @pre |abs_path| and |start_list| must both be absolute paths on the same
  /// drive, and in the canonical form, see CanonicalizePath.
  static void Relativize(std::string* abs_path,
                         const std::vector<StringPiece>& start_list);

  /// Normalize by fixing slashes style, fixing redundant .. and . and makes the
  /// path |input| relative to |this->relative_to_| and store to |result|. On
  /// failure, load an error message to |err| and return false.
  /// @pre |err| is empty.
  bool Normalize(StringPiece input, std::string* result,
                 std::string* err) const;

 private:
  std::string relative_to_;
  std::vector<StringPiece> split_relative_to_;
};

#endif  // INCLUDES_NORMALIZE_H_
