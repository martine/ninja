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

#include <algorithm>
#include <sstream>

#include "graph.h"
#include "manifest_parser.h"
#include "state.h"
#include "test.h"

namespace {

void ExpectRuleEqual(const Rule& rule_a, const Rule& rule_b,
                     const std::string& tag = "") {
  const auto& binding_a = rule_a.GetBindings();
  const auto& binding_b = rule_b.GetBindings();
  ASSERT_EQ(binding_a.size(), binding_b.size()) << tag << " bindings count";
  for (const auto& [k, v] : binding_a) {
    auto it = binding_b.find(k);
    ASSERT_NE(it, binding_b.end()) << tag << " missing binding: " << k;
    EXPECT_EQ(v.Serialize(), it->second.Serialize())
        << tag << " binding[" << k << "]";
  }
}

void ExpectBindingEnvsEqual(const BindingEnv* a, const BindingEnv* b,
                            const std::string& tag = "") {
  if (a == nullptr && b == nullptr)
    return;
  ASSERT_NE(a, nullptr) << tag;
  ASSERT_NE(b, nullptr) << tag;

  EXPECT_EQ(a->GetBindings(), b->GetBindings()) << tag;

  const auto& rules_a = a->GetRules();
  const auto& rules_b = b->GetRules();
  ASSERT_EQ(rules_a.size(), rules_b.size()) << tag << " (rules count)";
  for (const auto& [name, rule_a] : rules_a) {
    auto it = rules_b.find(name);
    ASSERT_NE(it, rules_b.end()) << tag << " missing rule: " << name;
    ExpectRuleEqual(*rule_a, *it->second, tag + " rule '" + name + "'");
  }

  ExpectBindingEnvsEqual(a->GetParent(), b->GetParent(), tag + ".parent");
}

// Compares two States for equivalence: same edges (by output path), same
// inputs/outputs/validations/pool/rule/env-bindings per edge, same defaults,
// same node set, and same root env bindings.
void ExpectStatesEqual(const State& a, const State& b) {
  // Node set — compare all paths, not just the count.
  auto NodePaths = [](const State& s) {
    std::vector<std::string> paths;
    paths.reserve(s.paths_.size());
    for (const auto& entry : s.paths_)
      paths.emplace_back(entry.first.str_, entry.first.len_);
    std::sort(paths.begin(), paths.end());
    return paths;
  };
  EXPECT_EQ(NodePaths(a), NodePaths(b));

  // Root env: bindings, rules, and parent chain.
  ExpectBindingEnvsEqual(&a.bindings_, &b.bindings_);

  // Default targets (order matters — Ninja uses the declared order).
  ASSERT_EQ(a.defaults_.size(), b.defaults_.size());
  for (size_t i = 0; i < a.defaults_.size(); ++i)
    EXPECT_EQ(a.defaults_[i]->path(), b.defaults_[i]->path())
        << "defaults[" << i << "]";

  // Edges — sort by first output path so the comparison is order-independent.
  auto sorted = [](std::vector<Edge*> edges) {
    std::sort(edges.begin(), edges.end(), [](const Edge* x, const Edge* y) {
      const std::string kx = x->outputs_.empty() ? "" : x->outputs_[0]->path();
      const std::string ky = y->outputs_.empty() ? "" : y->outputs_[0]->path();
      return kx < ky;
    });
    return edges;
  };
  const auto edges_a = sorted(a.edges_);
  const auto edges_b = sorted(b.edges_);

  ASSERT_EQ(edges_a.size(), edges_b.size());
  for (size_t i = 0; i < edges_a.size(); ++i) {
    const Edge* edge_a = edges_a[i];
    const Edge* edge_b = edges_b[i];
    const std::string tag =
        " (edge with first output '" +
        (edge_a->outputs_.empty() ? "<none>" : edge_a->outputs_[0]->path()) +
        "')";

    // Rule bindings are already verified via ExpectBindingEnvsEqual on the
    // edge's env.
    EXPECT_EQ(edge_a->rule_->name(), edge_b->rule_->name()) << tag;
    EXPECT_EQ(edge_a->pool_->name(), edge_b->pool_->name()) << tag;
    EXPECT_EQ(edge_a->implicit_outs_, edge_b->implicit_outs_) << tag;
    EXPECT_EQ(edge_a->implicit_deps_, edge_b->implicit_deps_) << tag;
    EXPECT_EQ(edge_a->order_only_deps_, edge_b->order_only_deps_) << tag;

    const std::string dyndep_a = edge_a->dyndep_ ? edge_a->dyndep_->path() : "";
    const std::string dyndep_b = edge_b->dyndep_ ? edge_b->dyndep_->path() : "";
    EXPECT_EQ(dyndep_a, dyndep_b) << tag << " dyndep";

    // Outputs (order matters: explicit first, then implicit).
    ASSERT_EQ(edge_a->outputs_.size(), edge_b->outputs_.size()) << tag;
    for (size_t j = 0; j < edge_a->outputs_.size(); ++j)
      EXPECT_EQ(edge_a->outputs_[j]->path(), edge_b->outputs_[j]->path())
          << tag << " output[" << j << "]";

    // Inputs (order matters: explicit, implicit, order-only).
    ASSERT_EQ(edge_a->inputs_.size(), edge_b->inputs_.size()) << tag;
    for (size_t j = 0; j < edge_a->inputs_.size(); ++j)
      EXPECT_EQ(edge_a->inputs_[j]->path(), edge_b->inputs_[j]->path())
          << tag << " input[" << j << "]";

    // Validations.
    ASSERT_EQ(edge_a->validations_.size(), edge_b->validations_.size()) << tag;
    for (size_t j = 0; j < edge_a->validations_.size(); ++j)
      EXPECT_EQ(edge_a->validations_[j]->path(),
                edge_b->validations_[j]->path())
          << tag << " validation[" << j << "]";

    // Per-edge env: bindings, rules, and parent chain.
    ExpectBindingEnvsEqual(edge_a->env_, edge_b->env_, tag);
  }
}

// SCOPED_TRACE records the call site
#define CHECK_BINARY_PARSER()      \
  {                                 \
    SCOPED_TRACE("");               \
    State out;                      \
    RoundTrip(&out);                \
    ExpectStatesEqual(state_, out); \
  }

// ============================================================
// Basic round-trip tests
// ============================================================

struct BinaryTest : public StateTestWithBuiltinRules {
  void AssertParse(State* state, const char* input,
                   ManifestParserOptions opts = ManifestParserOptions()) {
    ManifestParser parser(state, NULL, opts);
    std::string err;
    EXPECT_TRUE(parser.ParseTest(input, &err));
    ASSERT_EQ("", err);
    includePaths_ = parser.getIncludes();
    fileEnv_ = parser.getFileEnv_();
    VerifyGraph(*state);
  }

  void RoundTrip(State* out) {
    std::string data;
    WriteBinaryTest ss(data);
    WriteManifestCache(ss, &state_, includePaths_, fileEnv_);
    ReadBinaryTest in(std::move(data));
    EXPECT_NE(ReadIncludeFiles(in), std::nullopt);
    EXPECT_EQ(ReadManifestCache(in, out),"");
  }

 protected:
  // collects all include paths of the top level manifest
  std::vector<std::string> includePaths_;
  // all file level bindings except root
  std::vector<BindingEnv*> fileEnv_;
};

TEST_F(BinaryTest, EmptyManifest) {
  AssertParse(&state_, "");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, SimpleEdge) {
  AssertParse(&state_, "build out: cat in\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, ConsolePool) {
  AssertParse(&state_,
              "build out: cat in\n"
              "  pool = console\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, UserDefinedPool) {
  AssertParse(&state_,
              "pool mypool\n"
              "  depth = 4\n"
              "build out: cat in\n"
              "  pool = mypool\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, DefaultTargets) {
  AssertParse(&state_,
              "build a: cat in\n"
              "build b: cat in\n"
              "default a\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, PerEdgeBindings) {
  AssertParse(&state_,
              "build out: cat in\n"
              "  description = hello\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, SharedEnvBackReference) {
  // Two edges with no per-edge bindings share the root env.
  // Verifies the '2' (back-reference) path fires without triggering the
  // UniqueMap duplicate-key assert.
  AssertParse(&state_,
              "build out1: cat in\n"
              "build out2: cat in\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, PhonyEdge) {
  AssertParse(&state_,
              "build out: cat in\n"
              "build all: phony out\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, ImplicitOutput) {
  AssertParse(&state_, "build out | imp: cat in\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, ImplicitDep) {
  AssertParse(&state_, "build out: cat in | imp\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, OrderOnlyDep) {
  AssertParse(&state_, "build out: cat in || ord\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, Rspfile) {
  AssertParse(&state_,
              "rule link\n"
              "  command = link @$rspfile -o $out\n"
              "  rspfile = $out.rsp\n"
              "  rspfile_content = $in\n"
              "build out: link in\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, Restat) {
  AssertParse(&state_,
              "rule gen\n"
              "  command = gen $in -o $out\n"
              "  restat = 1\n"
              "build out: gen in\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, Generator) {
  AssertParse(&state_,
              "rule regen\n"
              "  command = regen\n"
              "  generator = 1\n"
              "build build.ninja: regen\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, Depfile) {
  AssertParse(&state_,
              "rule cc\n"
              "  command = cc $in -o $out\n"
              "  depfile = $out.d\n"
              "build out.o: cc in.c\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, Deps) {
  AssertParse(&state_,
              "rule cc\n"
              "  command = cc $in -o $out\n"
              "  deps = gcc\n"
              "  depfile = $out.d\n"
              "build out.o: cc in.c\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, Validation) {
  AssertParse(&state_, "build out: cat in |@ val\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, VersionMismatch) {
  std::stringstream ss;
  const uint16_t bad_version = 0;
  ss.write(reinterpret_cast<const char*>(&bad_version), sizeof(bad_version));
  ReadBinaryTest in(ss.str());
  State out;
  EXPECT_EQ(ReadIncludeFiles(in), std::nullopt);
}

TEST_F(BinaryTest, MultipleEdgesAndNodes) {
  AssertParse(&state_,
              "build b: cat a\n"
              "build c: cat b\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, DyndepEdge) {
  AssertParse(&state_,
              "build out: cat in dd\n"
              "  dyndep = dd\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryTest, AsciiVsBinary) {
  AssertParse(&state_,
              "pool mypool\n"
              "  depth = 3\n"
              "rule cc\n"
              "  command = cc $in -o $out\n"
              "rule link\n"
              "  command = link $in -o $out\n"
              "build foo.o: cc foo.c\n"
              "build bar.o: cc bar.c\n"
              "  description = compiling bar\n"
              "build app: link foo.o bar.o\n"
              "  pool = mypool\n"
              "build all: phony app\n"
              "default all\n");
  CHECK_BINARY_PARSER();
}

// ============================================================
// Multi-scope tests (subninja / include)
// ============================================================

struct BinaryMultiScopeTest : public BinaryTest {
  void ParseWithFsold(const char* input) {
    ManifestParser parser(&state_, &fs_);
    std::string err;
    ASSERT_TRUE(parser.ParseTest(input, &err)) << err;
    VerifyGraph(state_);
  }

   void ParseWithFs(const char* input) {
    ManifestParser parser(&state_, &fs_);
    std::string err;
    EXPECT_TRUE(parser.ParseTest(input, &err));
    ASSERT_EQ("", err);
    includePaths_ = parser.getIncludes();
    fileEnv_ = parser.getFileEnv_();
    VerifyGraph(state_);
  }

  VirtualFileSystem fs_;
};

TEST_F(BinaryMultiScopeTest, SubninjaEdgeHasChildEnv) {
  fs_.Create("sub.ninja",
             "rule mycat\n"
             "  command = mycat $in > $out\n"
             "build out: mycat in\n");
  ParseWithFs("subninja sub.ninja\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryMultiScopeTest, SubninjaRuleScoped) {
  fs_.Create("sub.ninja",
             "rule inner\n"
             "  command = inner $in > $out\n"
             "build out: inner in\n");
  ParseWithFs("subninja sub.ninja\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryMultiScopeTest, SubninjaVariableInheritance) {
  fs_.Create("sub.ninja",
             "rule mycat\n"
             "  command = mycat $in > $out\n"
             "build out: mycat in\n");
  ParseWithFs(
      "myvar = hello\n"
      "subninja sub.ninja\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryMultiScopeTest, IncludeSameScope) {
  fs_.Create("inc.ninja", "incvar = frominclude\n");
  ParseWithFs(
      "include inc.ninja\n"
      "build out: cat in\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryMultiScopeTest, FourScopeChain) {
  // Four nested scopes via chained subninja directives.
  // Each scope defines its own variable; the deepest edge's env must be able
  // to look up all four after a binary round-trip.
  fs_.Create("sub3.ninja",
             "var3 = level3\n"
             "rule mycat\n"
             "  command = mycat $in > $out\n"
             "build out: mycat in\n");
  fs_.Create("sub2.ninja",
             "var2 = level2\n"
             "subninja sub3.ninja\n");
  fs_.Create("sub1.ninja",
             "var1 = level1\n"
             "subninja sub2.ninja\n");
  ParseWithFs(
      "var0 = root\n"
      "subninja sub1.ninja\n");
  CHECK_BINARY_PARSER();
}

TEST_F(BinaryMultiScopeTest, FourScopeChainIncludes) {
  fs_.Create("sub3.ninja",
             "var3 = level3\n"
             "rule mycat\n"
             "  command = mycat $in > $out\n"
             "build out: mycat in\n");
  fs_.Create("sub2.ninja",
             "var2 = level2\n"
             "subninja sub3.ninja\n");
  fs_.Create("sub1.ninja",
             "var1 = level1\n"
             "subninja sub2.ninja\n");

  ManifestParser parser(&state_, &fs_);
  std::string err;
  ASSERT_TRUE(parser.ParseTest("subninja sub1.ninja\n", &err)) << err;
  VerifyGraph(state_);
  auto includes = parser.getIncludes();
  ASSERT_EQ(includes.size(), 3);
  EXPECT_EQ(includes,
            std::vector<std::string>(
                { { "sub1.ninja" }, { "sub2.ninja" }, { "sub3.ninja" } }));

  const std::vector<BindingEnv*>& includesEnv = parser.getFileEnv_();
  EXPECT_EQ(includesEnv[0]->LookupVariable("var1"), "level1");
  EXPECT_EQ(includesEnv[1]->LookupVariable("var2"), "level2");
  EXPECT_EQ(includesEnv[2]->LookupVariable("var3"), "level3");
}

}  // namespace
