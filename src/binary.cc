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

#include "binary.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>
#include <unordered_map>
#include "third_party/ankerl/unordered_dense.h"

#include "eval_env.h"
#include "graph.h"
#include "hash_map.h"
#include "metrics.h"
#include "state.h"
#include "string_piece.h"
#include "util.h"

namespace {

/// Increment this whenever the binary format changes incompatibly.
constexpr uint16_t kBinaryFormatVersion = 1;
constexpr uint64_t kDyndepSentinel = uint64_t(-1);

// IntBin stores by value so typed helpers can safely cast from a temporary.
template <class T>
struct IntBin {
  explicit IntBin(T value) : value_(value) {}
  T value_;
};

struct IntBin40 {
  explicit IntBin40(uint64_t value) : value_(value) {}
  uint64_t value_;
};

template <class T>
WriteBinary& operator<<(WriteBinary& os, const IntBin<T>& myInt) {
  os.Write(reinterpret_cast<const char*>(&myInt.value_), sizeof(myInt.value_));
  return os;
}

WriteBinary& operator<<(WriteBinary& os, const IntBin40& myInt) {
  assert(myInt.value_ < (uint64_t{1} << 40));
  os.Write(reinterpret_cast<const char*>(&myInt.value_), 5);
  return os;
}

template <class U> IntBin<uint8_t>  Int8  (U myInt) { return IntBin<uint8_t> (static_cast<uint8_t> (myInt)); }
template <class U> IntBin<uint16_t> Int16(U myInt)  { return IntBin<uint16_t>(static_cast<uint16_t>(myInt)); }
template <class U> IntBin<uint32_t> Int32 (U myInt) { return IntBin<uint32_t>(static_cast<uint32_t>(myInt)); }
template <class U> IntBin<uint64_t> Int64(U myInt)  { return IntBin<uint64_t>(static_cast<uint64_t>(myInt)); }

// Writes a string with a length prefix.
// Strings up to 254 bytes use a single-byte length prefix.
// Longer strings are prefixed with 255 followed by a 32-bit length.
WriteBinary& operator<<(WriteBinary& os, std::string_view s) {
  if (s.size() > 254) {
    os << Int8(255) << Int32(s.size());  // WriteID #00034, WriteID #00035
    os.Write(s.data(), s.size());  // WriteID #00026
  } else {
    os << Int8(static_cast<std::uint8_t>(s.size()));  // WriteID #00034
    os.Write(s.data(), s.size());  // WriteID #00026
  }
  return os;
}

WriteBinary& operator<<(WriteBinary& os, const std::string& s) {
  return os << std::string_view(s);
}

WriteBinary& operator<<(WriteBinary& os, StringPiece s) {
  return os << std::string_view(s.str_, s.len_);
}

// Writes an EvalString token list: uint32_t count, then for each token a
// length-prefixed string followed by a type byte ('R' = raw, 'S' = special).
WriteBinary& operator<<(WriteBinary& os, const EvalString::TokenList& tokens) {
  os << Int32(tokens.size());  // WriteID #00021
  for (const auto& token : tokens)
    os << Int8(token.second == EvalString::RAW ? 'R' : 'S') << token.first;  // WriteID #00027
  return os;
}

// Writes Rule::Bindings: uint32_t count, then for each entry: key (string),
// flag byte (0 = single string, 1 = token list), value.
WriteBinary& operator<<(WriteBinary& os, const Rule::Bindings& bindings) {
  os << Int32(bindings.size());  // WriteID #00022
  for (const auto& entry : bindings) {
    os << entry.first;  // WriteID #00028
    if (entry.second.IsSingle()) {
      os << Int8(0) << entry.second.Single();  // WriteID #00029
    } else {
      os << Int8(1) << entry.second.SingleToken();  // WriteID #00029
    }
  }
  return os;
}

WriteBinary& operator<<(WriteBinary& os, const Rule& rules) {
  return os << rules.name() << rules.GetBindings();  // WriteID #00019
}

WriteBinary& operator<<(WriteBinary& os, const Pool& pools) {
  return os << pools.name() << Int32(pools.depth());  // WriteID #00020
}

/// unordered_dense::map wrapper whose try_emplace asserts that the key is new.
template <class K, class V>
struct UniqueMap : ankerl::unordered_dense::map<K, V> {
  template <class Key2, class... Args>
  void try_emplace(Key2&& key, Args&&... args) {
    [[maybe_unused]] const auto [_, ok] = ankerl::unordered_dense::map<K, V>::try_emplace(
        std::forward<Key2>(key), std::forward<Args>(args)...);
    assert(ok);
  }
};

/// Serializes a build State to a binary stream.
class Dump {
 public:
  static void File(WriteBinary& os, const State* state,
                   const std::vector<std::string>& includeFiles,
                   const std::vector<BindingEnv*>& bindingEnv);

 private:
  Dump(WriteBinary& os, const State* state,
       const std::vector<std::string> includeFiles,
       const std::vector<BindingEnv*>& bindingEnv)
      : os_(os), state_(state), include_files_(includeFiles),
        file_Enbinding_(bindingEnv) {}

  void DumpToFile();
  void DumpToFileEdge(const BindingEnv& env);
  void DumpToFileRoot(const BindingEnv& env);
  void DumpToFileFile(const BindingEnv& env);
  void DumpToFilebody(const BindingEnv& env);

  void DumpEnv();
  void DumpEdges();
  void DumpPaths();
  void DumpDefaults();
  void DumpPools();

  WriteBinary& os_;
  const State* state_;
  const std::vector<std::string> include_files_;
  const std::vector<BindingEnv*> file_Enbinding_;

  // Maps from object pointer to its byte offset in the output stream.
  // Used to emit back-references instead of duplicating shared objects.
  // Exception: node_offsets_ stores the node's sequential index in the
  // path table (see Dump::DumpPaths()), not a byte offset.
  UniqueMap<const Rule*, uint64_t> rule_offsets_;
  UniqueMap<const Pool*, uint64_t> pool_offsets_;
  UniqueMap<const Node*, uint64_t> node_offsets_;
  UniqueMap<const BindingEnv*, uint64_t> env_offsets_;
};

// Writes user-defined pools into pool_offsets_ (built-ins are pre-seeded as
// sentinels and skipped here). Offsets 0 and 1 are reserved for
// kDefaultPool/kConsolePool.
void Dump::DumpPools() {
  const auto& pools = state_->pools_;
  // Count user-defined pools; built-ins are already in pool_offsets_ as
  // sentinels (added by the caller before DumpPools), so they are excluded.
  uint32_t count = 0;
  for (const auto& entry : pools)
    if (pool_offsets_.find(entry.second) == pool_offsets_.end())
      ++count;

  os_ << Int32(count);  // WriteID #00008
  for (const auto& entry : pools) {
    if (pool_offsets_.find(entry.second) != pool_offsets_.end())
      continue;
    pool_offsets_.try_emplace(entry.second, static_cast<uint64_t>(os_.Tellp()));
    os_ << (*entry.second);
  }
}

// Writes objects of class 'Paths' and records each node's index so edges can
// later reference by that index.
void Dump::DumpPaths() {
  const auto& paths = state_->paths_;
  os_ << Int32(paths.size()); // WriteID #00001
  std::size_t i = 0;
  for (const auto& entry : paths) {
    node_offsets_.try_emplace(entry.second, static_cast<uint64_t>(i++));
    os_ << entry.first << Int64(entry.second->slash_bits());  // WriteID #00036, WriteID #00037
  }
}

void Dump::DumpEdges() {
  const auto& edges = state_->edges_;
  os_ << Int32(edges.size());  // WriteID #00009

  for (const Edge* edge : edges) {
    // dyndep node offset (kDyndepSentinel if none)  // WriteID #00010
    if (edge->dyndep_) {
      auto it = node_offsets_.find(edge->dyndep_);
      assert(it != node_offsets_.end());
      os_ << Int64(it->second);
    } else {
      os_ << Int64(kDyndepSentinel);
    }

    // env: 'd' = defined inline here, 'r' = back-reference by offset  // WriteID #00011
    auto env_it = env_offsets_.find(edge->env_);
    if (env_it != env_offsets_.end()) {
      os_ << Int8('r') << Int64(env_it->second);
    } else {
      os_ << Int8('d');
      DumpToFileEdge(*edge->env_);  // WriteID #00018
    }

    // rule offset (0 reserved for phony)  // WriteID #00012
    if (edge->rule_->IsPhony()) {
      os_ << IntBin40(0);
    } else {
      auto rule_it = rule_offsets_.find(edge->rule_);
      assert(rule_it != rule_offsets_.end());
      os_ << IntBin40(rule_it->second);
    }

    // pool offset  // WriteID #00013
    {
      const auto pool_it = pool_offsets_.find(edge->pool_);
      assert(pool_it != pool_offsets_.end());
      os_ << IntBin40(pool_it->second);
    }

    // outputs  // WriteID #00014
    os_ << Int32(edge->implicit_outs_) << Int32(edge->outputs_.size());
    for (const Node* out : edge->outputs_) {
      auto it = node_offsets_.find(out);
      assert(it != node_offsets_.end());
      os_ << Int32(it->second);
    }

    // inputs  // WriteID #00015
    os_ << Int32(edge->implicit_deps_) << Int32(edge->order_only_deps_)
        << Int32(edge->inputs_.size());
    for (const Node* in : edge->inputs_) {
      auto it = node_offsets_.find(in);
      assert(it != node_offsets_.end());
      os_ << Int32(it->second);
    }

    // validations  // WriteID #00016
    os_ << Int32(edge->validations_.size());
    for (const Node* v : edge->validations_) {
      auto it = node_offsets_.find(v);
      assert(it != node_offsets_.end());
      os_ << Int32(it->second);
    }
  }
}

void Dump::File(WriteBinary& os, const State* state,
                const std::vector<std::string>& includeFiles,
                const std::vector<BindingEnv*>& bindingEnv) {
  Dump dump(os, state, includeFiles, bindingEnv);
  dump.DumpToFile();
}

void Dump::DumpDefaults() {
  const auto& defaults = state_->defaults_;
  os_ << Int32(defaults.size());  // WriteID #00017
  for (const Node* node : defaults) {
    const auto it = node_offsets_.find(node);
    assert(it != node_offsets_.end());
    os_ << Int32(it->second);
  }
}

void Dump::DumpToFileEdge(const BindingEnv& env) {
  const BindingEnv* parent = env.GetParent();
  assert(parent);
  auto it = env_offsets_.find(parent);
  assert(it != env_offsets_.end());
  os_ << Int64(it->second);  // WriteID #00030
  assert(env.GetRules().empty());

  // bindings
  const auto& bindings = env.GetBindings();
  os_ << Int32(bindings.size());  // WriteID #00025
  for (const auto& b : bindings)
    os_ << b.first << b.second;  // WriteID #00031
}

void Dump::DumpToFileRoot(const BindingEnv& env) {
  assert(!env.GetParent());
  env_offsets_.try_emplace(&env, static_cast<uint64_t>(os_.Tellp()));
  DumpToFilebody(env);
}

void Dump::DumpToFileFile(const BindingEnv& env) {
  const BindingEnv* parent = env.GetParent();
  assert(parent);
  auto it = env_offsets_.find(parent);
  assert(it != env_offsets_.end());
  os_ << Int64(it->second);
  env_offsets_.try_emplace(&env, static_cast<uint64_t>(os_.Tellp()));
  DumpToFilebody(env);
}

void Dump::DumpToFilebody(const BindingEnv& env) {
  const auto& bindings = env.GetBindings();
  const auto& rules = env.GetRules();
  // bindings
  os_ << Int32(bindings.size());  // WriteID #00023
  for (const auto& b : bindings)
    os_ << b.first << b.second;  // WriteID #00032

  // rules (phony excluded — State::State() always re-adds it on load)
  uint32_t non_phony_count = 0;
  for (const auto& r : rules)
    if (!r.second->IsPhony())
      ++non_phony_count;

  os_ << Int32(non_phony_count);  // WriteID #00024
  for (const auto& r : rules) {
    if (r.second->IsPhony())
      continue;
    rule_offsets_.try_emplace(r.second.get(),
                              static_cast<uint64_t>(os_.Tellp()));
    os_ << (*r.second);
  }
}

void Dump::DumpEnv() {
  DumpToFileRoot(state_->bindings_); // root env, WriteID #00006

  os_ << Int32(file_Enbinding_.size());  // WriteID #00007
  for (auto& i : file_Enbinding_) {  // any other file level env
    DumpToFileFile(*i);
  }
}

void Dump::DumpToFile() {
  METRIC_RECORD("write binary manifest");
  os_ << Int16(kBinaryFormatVersion);  // WriteID #00002

  // integrity check
  os_ << Int64(
      rapidhash(reinterpret_cast<const void*>(&kBinaryFormatVersion), 2));  // WriteID #00003

  // Write the integrity check with dummy values; the real file length and
  // its hash are patched in at the end via Seekp(10).
  os_ << Int64(0) << Int64(0);  // WriteID #00004

  // Include files of manifest
  os_ << Int16(include_files_.size());  // WriteID #00005
  for (auto file : include_files_)
    os_ << file;  // WriteID #00033

  // Sentinel offsets for built-in pools (never written to file, like phony).
  pool_offsets_.try_emplace(&state_->kDefaultPool, uint64_t(0));
  pool_offsets_.try_emplace(&state_->kConsolePool, uint64_t(1));
  DumpEnv();
  DumpPools();
  DumpPaths();
  DumpEdges();
  DumpDefaults();

  // Rewrite the integrity check at the start of the file. Its presence
  // indicates the file was written successfully, will be checked on read.
  const auto fileSize = os_.Tellp();
  os_.Seekp(10);
  os_ << Int64(fileSize)
      << Int64(rapidhash(reinterpret_cast<const void*>(&fileSize), 8));  // WriteID #00004
}

template <class T>
T ReadBin(ReadBinary& is) {
  T value{};
  is.read(reinterpret_cast<char*>(&value), sizeof(value));
  return value;
}

inline uint8_t  ReadU8 (ReadBinary& is) { return ReadBin<uint8_t>(is);  }
inline uint16_t ReadU16(ReadBinary& is) { return ReadBin<uint16_t>(is); }
inline uint32_t ReadU32(ReadBinary& is) { return ReadBin<uint32_t>(is); }
inline uint64_t ReadU64(ReadBinary& is) { return ReadBin<uint64_t>(is); }
inline int8_t   ReadI8 (ReadBinary& is) { return ReadBin<int8_t>(is);   }
inline int32_t  ReadI32(ReadBinary& is) { return ReadBin<int32_t>(is);  }

inline uint64_t ReadU40(ReadBinary& is) {
  uint64_t value = 0;
  is.read(reinterpret_cast<char*>(&value), 5);
  return value;
}

std::string ReadString(ReadBinary& is) {
  const uint8_t pre = ReadU8(is);  // ReadID #00034
  if (pre != 255) {
    std::string s(pre, '\0');
    is.read(s.data(), pre);  // ReadID #00026
    return s;
  } else {
    const uint32_t len = ReadU32(is);  // ReadID #00035
    std::string s(len, '\0');
    is.read(s.data(), len);  // ReadID #00026
    return s;
  }
}

// Reads a binding value: flag byte selects single-string (0) or token-list (1)
// encoding.
EvalString ReadEvalString(ReadBinary& is) {
  const uint8_t flag = ReadU8(is);  // ReadID #00029
  EvalString eval;
  if (flag == 0) {
    eval.AddText(ReadString(is));
  } else {
    const uint32_t count = ReadU32(is);  // ReadID #00021
    for (uint32_t i = 0; i < count; ++i) {
      const uint8_t type = ReadU8(is);  // ReadID #00027
      if (type == 'R')
        eval.AddText(ReadString(is));
      else
        eval.AddSpecial(ReadString(is));
    }
  }
  return eval;
}

struct NodePtr {
 public:
  void assign(Node* ptr) {
    ptr_ = ptr;
}

  Node* operator[](const std::size_t i) const {
    assert(i < size_);
    return ptr_ + i;
  }

  void reserve(std::size_t n) { size_ = n; }

  std::size_t size() const { return size_; }

 private:
  Node* ptr_ = nullptr;
  // size_ only for debug, optimized away in release build
  std::size_t size_ = 0;
};

/// Deserializes a build State from a binary stream written by Dump::DumpToFile.
class Read {
 public:
  /// Returns value of variable 'enableJobserverPool'
  /// Returns empty string if variable is not defined in manifest
  static std::string File(ReadBinary& is, State* state);

  // Parses the header (version, integrity hashes, include-file list).
  // Returns std::nullopt if the format version is unrecognised or the
  // file's integrity check fails.
  static std::optional<std::vector<std::string>> IncludeFile(ReadBinary& is);
  std::string enableJobserverPool() const;

 private:
  Read(ReadBinary& is, State* state);

  BindingEnv* ReadBindingEnv();
  std::unique_ptr<Rule> ReadRule();
  void ReadPool();
  void ReadNode();
  void ReadEdge();
  void ReadDefaults();

  void ReadBindingEnvBody(BindingEnv* env);
  void ReadBindingEnvFile();

  ReadBinary& is_;
  State* state_;

  // Maps from byte offset in the stream to the deserialized object.
  // Used to resolve back-references.
  NodePtr nodes_;
  UniqueMap<uint64_t, const Rule*> rules_by_offset_;
  UniqueMap<uint64_t, Pool*> pools_by_offset_;
  UniqueMap<uint64_t, BindingEnv*> envs_by_offset_;

#ifndef NDEBUG
  bool bindingEnv_root = false;
#endif
};

std::optional<std::vector<std::string>> Read::IncludeFile(ReadBinary& is) {
 const uint16_t version = ReadU16(is);  // ReadID #00002
  const uint64_t integrity = ReadU64(is);  // ReadID #00003
  if (version != kBinaryFormatVersion ||
      integrity !=
          rapidhash(reinterpret_cast<const void*>(&kBinaryFormatVersion), 2))
    return std::nullopt;

  const std::size_t file_size = is.GetFileSize();
  if (file_size == static_cast<std::size_t>(-1))
    return std::nullopt;

  // check if the file has been written correctly
  const auto file_size_in_file = ReadU64(is);  // ReadID #00004
  const auto hash_of_size = ReadU64(is);  // ReadID #00004
  if (file_size_in_file != file_size || hash_of_size != rapidhash(reinterpret_cast<const void*>(&file_size_in_file), 8))
    return std::nullopt;

  // parse the include files, to propagate file position
  std::vector<std::string> ret;
  const std::size_t nr = ReadU16(is);  // ReadID #00005
  ret.reserve(nr);
  for (std::size_t i = 0; i < nr; i++)
    ret.push_back(ReadString(is));  // ReadID #00033

  return ret;
}

std::string Read::File(ReadBinary& is, State* state) {
  Read myRead(is, state);

  return myRead.enableJobserverPool();
}

void Read::ReadPool() {
  const uint32_t count = ReadU32(is_);  // ReadID #00008

  for (uint32_t i = 0; i < count; ++i) {
    const auto offset = is_.tellg();
    const std::string name = ReadString(is_);  // ReadID #00020
    const int32_t depth = ReadI32(is_);  // ReadID #00020
    Pool* pool = new Pool(name, depth);
    state_->AddPool(pool);
    pools_by_offset_.try_emplace(static_cast<uint64_t>(offset), pool);
  }
}

std::unique_ptr<Rule> Read::ReadRule() {
  const auto offset = is_.tellg();
  std::string name = ReadString(is_);  // ReadID #00019
  auto rule = std::make_unique<Rule>(std::move(name));
  rules_by_offset_.try_emplace(offset, rule.get());

  const uint32_t count = ReadU32(is_);  // ReadID #00022
  for (uint32_t i = 0; i < count; ++i) {
    const std::string key = ReadString(is_);  // ReadID #00028
    const EvalString val = ReadEvalString(is_);  // ReadID #00029
    rule->AddBinding(key, val);
  }
  return rule;
}

void Read::ReadBindingEnvBody(BindingEnv* env) {
  const uint32_t binding_count = ReadU32(is_);  // ReadID #00023
  for (uint32_t i = 0; i < binding_count; ++i) {
    const std::string key = ReadString(is_);  // ReadID #00032
    const std::string val = ReadString(is_);  // ReadID #00032
    env->AddBinding(key, val);
  }

  const uint32_t rule_count = ReadU32(is_);  // ReadID #00024
  for (uint32_t i = 0; i < rule_count; ++i) {
    env->AddRule(ReadRule());
  }
}

void Read::ReadBindingEnvFile() {
  // root binding
  BindingEnv* env = &state_->bindings_;
  envs_by_offset_.try_emplace(static_cast<uint64_t>(is_.tellg()), env);
  ReadBindingEnvBody(env);  // ReadID #00006

  // any other file level Env
  const uint32_t count = ReadU32(is_);  // ReadID #00007
  for (std::size_t i = 0; i < count; ++i) {
    const uint64_t ref = ReadU64(is_);
    const auto it = envs_by_offset_.find(ref);
    assert(it != envs_by_offset_.end());
    env = new BindingEnv(it->second);
    envs_by_offset_.try_emplace(static_cast<uint64_t>(is_.tellg()), env);
    ReadBindingEnvBody(env);
  }
}

BindingEnv* Read::ReadBindingEnv() {
  const uint64_t ref = ReadU64(is_);  // ReadID #00030
  const auto it = envs_by_offset_.find(ref);
  assert(it != envs_by_offset_.end());

  BindingEnv* env = new BindingEnv(it->second);
  const uint32_t binding_count = ReadU32(is_);  // ReadID #00025
  for (uint32_t i = 0; i < binding_count; ++i) {
    const std::string key = ReadString(is_);  // ReadID #00031
    const std::string val = ReadString(is_);  // ReadID #00031
    env->AddBinding(key, val);
  }

  // BindingEnv of edges never have rules
  return env;
}

void Read::ReadNode() {
  const uint32_t count = ReadU32(is_); // ReadID #00001
  // exact number of nodes in the manifest. Guarantees no reallocation.
  nodes_.reserve(count);
  state_->paths_.reserve(count, true);

  // Intentional leak: node storage must outlive this function for the
  // lifetime of the process, so it is never explicitly freed here, the
  // OS reclaims it on exit. Contiguous storage also makes later
  // iteration over all nodes cache-friendly.
  auto nodes = new std::vector<Node>();
  nodes->reserve(count);
  nodes_.assign(nodes->data());

  for (uint32_t i = 0; i < count; ++i) {
    std::string path = ReadString(is_);  // ReadID #00036
    const uint64_t slash_bits = ReadU64(is_);  // ReadID #00037
    Node& insert = nodes->emplace_back(std::move(path), slash_bits, false);

    // add node 'insert' to state_
    assert(state_->LookupNode(insert.path()) == nullptr);
    state_->paths_[insert.path()] = &insert;
  }
}

void Read::ReadEdge() {
  const uint32_t count = ReadU32(is_);  // ReadID #00009

  // Intentional leak: edge storage must outlive this function for the
  // lifetime of the process, so it is never explicitly freed here, the
  // OS reclaims it on exit. Contiguous storage also makes later
  // iteration over all nodes cache-friendly.
  auto all_edges = new std::vector<Edge>;
  all_edges->reserve(count);

  envs_by_offset_.reserve(count);
  state_->edges_.reserve(count);

  for (uint32_t i = 0; i < count; ++i) {
    const uint64_t dyndep_offset = ReadU64(is_);  // ReadID #00010

    // env: 'd' = defined inline, 'r' = back-reference by offset  // ReadID #00011
    const int8_t env_tag = ReadI8(is_);
    BindingEnv* env;
    if (env_tag == 'd') {
      env = ReadBindingEnv();  // ReadID #00018
    } else {
      assert(env_tag == 'r');
      const uint64_t ref = ReadU64(is_);
      const auto it = envs_by_offset_.find(ref);
      assert(it != envs_by_offset_.end());
      env = it->second;
    }

    // rule (offset 0 is reserved for phony)  // ReadID #00012
    const uint64_t rule_offset = ReadU40(is_);
    const auto rule_it = rules_by_offset_.find(rule_offset);
    assert(rule_it != rules_by_offset_.end());

    // pool  // ReadID #00013
    const uint64_t pool_offset = ReadU40(is_);
    const auto pool_it = pools_by_offset_.find(pool_offset);
    assert(pool_it != pools_by_offset_.end());

    Edge* const edge = &all_edges->emplace_back();
    state_->AddEdge(rule_it->second, edge);
    edge->env_ = env;
    edge->pool_ = pool_it->second;

    if (dyndep_offset != kDyndepSentinel) {
      assert(dyndep_offset < nodes_.size());
      Node* node = nodes_[dyndep_offset];
      edge->dyndep_ = node;
    }

    // outputs  // ReadID #00014
    const int32_t implicit_outs = ReadI32(is_);
    const uint32_t out_count = ReadU32(is_);
    edge->implicit_outs_ = implicit_outs;
    edge->outputs_.reserve(out_count);
    for (uint32_t j = 0; j < out_count; ++j) {
      const uint64_t offset = ReadU32(is_);
      assert(offset < nodes_.size());
      Node* node = nodes_[offset];
      assert(!node->in_edge());
      edge->outputs_.push_back(node);
      node->set_in_edge(edge);
    }

    // inputs  // ReadID #00015
    edge->implicit_deps_ = ReadI32(is_);
    edge->order_only_deps_ = ReadI32(is_);
    const uint32_t in_count = ReadU32(is_);
    edge->inputs_.reserve(in_count);
    for (uint32_t j = 0; j < in_count; ++j) {
      const uint64_t offset = ReadU32(is_);
      assert(offset < nodes_.size());
      Node* node = nodes_[offset];
      edge->inputs_.push_back(node);
      node->AddOutEdge(edge);
    }

    // validations  // ReadID #00016
    const uint32_t val_count = ReadU32(is_);
    for (uint32_t j = 0; j < val_count; ++j) {
      const uint64_t offset = ReadU32(is_);
      assert(offset < nodes_.size());
      Node* node = nodes_[offset];
      edge->validations_.push_back(node);
      node->AddValidationOutEdge(edge);
    }
  }
}

void Read::ReadDefaults() {
  const uint32_t count = ReadU32(is_);  // ReadID #00017
  for (uint32_t i = 0; i < count; ++i) {
    const uint64_t offset = ReadU32(is_);
    assert(offset < nodes_.size());
    Node* node = nodes_[offset];
    state_->defaults_.push_back(node);
  }
}

Read::Read(ReadBinary& is, State* state) : is_(is), state_(state) {
  // Sentinel offsets for built-ins — never in the file, seeded like phony.
  rules_by_offset_[0] = state_->bindings_.LookupRule("phony");
  assert(rules_by_offset_[0]);
  pools_by_offset_[0] = &state_->kDefaultPool;
  pools_by_offset_[1] = &state_->kConsolePool;

  ReadBindingEnvFile();
  ReadPool();
  ReadNode();
  ReadEdge();
  ReadDefaults();
}

std::string Read::enableJobserverPool() const {
  return state_->bindings_.LookupVariable("enable_jobserver_pool");
}

}  // namespace

ReadBinaryTest::ReadBinaryTest(std::string&& content)
    : data_(std::move(content)) {}

ReadBinaryTest ReadBinaryTest::file(std::string filename) {
  std::string contents;
  std::string err;
  ReadFile(filename, &contents, &err);
  return ReadBinaryTest(std::move(contents));
}

bool ReadBinaryTest::read(char* data, std::size_t size) {
  assert(position_ <= data_.size());
  const std::size_t available = data_.size() - position_;
  if (size > available)
    return false;

  std::memcpy(data, data_.data() + position_, size);
  position_ += size;
  return true;
}

std::size_t ReadBinaryTest::tellg() {
  return position_;
}

std::size_t ReadBinaryTest::GetFileSize() const {
  return data_.size();
}

bool WriteBinaryTest::Write(const char* data, std::size_t size) {
  if (pos_ + size > data_.size()) {
    data_.resize(pos_ + size);
  }
  std::memcpy(&data_[pos_], data, size);
  pos_ += size;
  return true;
}

std::size_t WriteBinaryTest::Tellp() const {
  return pos_;
}

void WriteBinaryTest::Seekp(std::size_t offset) {
  pos_ = offset;
  if (pos_ > data_.size()) {
    data_.resize(pos_, '\0');  // pad gap with zero bytes, like a real file
  }
}

WriteBinaryDisk::WriteBinaryDisk(std::string fileName) {
  file_ = std::fopen(fileName.c_str(), "wb");
}

WriteBinaryDisk::~WriteBinaryDisk() {
  if (file_) {
    Flush();
    std::fclose(file_);
  }
}

std::size_t WriteBinaryDisk::Tellp() const {
  long filePos = std::ftell(file_);
  if (filePos < 0)
    return static_cast<std::size_t>(-1);

  return static_cast<std::size_t>(filePos) + buffer_pos_;
}

void WriteBinaryDisk::Seekp(std::size_t offset) {
  Flush();
  std::fseek(file_, static_cast<long>(offset), SEEK_SET);
}

bool WriteBinaryDisk::Flush() {
  if (buffer_pos_ == 0) {
    return true;
  }

  std::size_t toWrite = buffer_pos_;
  std::size_t written = std::fwrite(buffer_, 1, toWrite, file_);
  buffer_pos_ = 0;

  return written == toWrite;
}

bool WriteBinaryDisk::Write(const char* data, std::size_t size) {
  std::size_t totalWritten = 0;

  while (totalWritten < size) {
    std::size_t available = BUFFER_SIZE - buffer_pos_;

    // if buffer full, write to disk
    if (available == 0) {
      std::fwrite(buffer_, 1, BUFFER_SIZE, file_);
      buffer_pos_ = 0;
      available = BUFFER_SIZE;
    }

    // fill the buffer
    std::size_t toCopy = std::min(size - totalWritten, available);
    std::memcpy(buffer_ + buffer_pos_, data + totalWritten, toCopy);

    buffer_pos_ += toCopy;
    totalWritten += toCopy;
  }

  return true;
}

void WriteManifestCache(WriteBinary& os, const State* state,
                        const std::vector<std::string>& includeFiles,
                        const std::vector<BindingEnv*>& bindingEnv) {
  Dump::File(os, state, includeFiles, bindingEnv);
}

std::string ReadManifestCache(ReadBinary& is, State* state) {
  return Read::File(is, state);
}

std::optional<std::vector<std::string>> ReadIncludeFiles(ReadBinary& is){
  return Read::IncludeFile(is);
}
