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

#include "indexed_range.h"

#include <iterator>
#include <numeric>
#include <vector>

#include "test.h"

TEST(IndexedRange, Basic) {
  std::vector<int> range{ 0, 1 };
  IndexedRange indexed_range(range);

  auto iter_range = range.begin();
  auto iter_range_index = indexed_range.begin();

  EXPECT_EQ(&*iter_range_index, &*iter_range);
  EXPECT_EQ(&*++iter_range_index, &*++iter_range);
  EXPECT_TRUE(++iter_range_index == indexed_range.end());
}

TEST(IndexedRange, ForLoop) {
  std::vector<int> range{ 0, 1, 2, 3, 4, 5 };

  int plain_sum = 0;
  int indexed_sum = 0;

  for (auto i : range) {
    plain_sum += i;
  }

  for (auto i : IndexedRange(range)) {
    indexed_sum += i;
  }

  EXPECT_EQ(plain_sum, indexed_sum);
}

TEST(IndexedRange, Const) {
  const std::vector<int> range{ 0, 1, 2 };

  int sum = 0;
  for (const auto& i : IndexedRange(range)) {
    sum += i;
  }

  EXPECT_EQ(3, sum);
}

TEST(IndexedRange, StlCompliance) {
  std::vector<int> range{ 0, 1, 2 };

  IndexedRange indexed_range(range);

  EXPECT_EQ(3, std::accumulate(indexed_range.begin(), indexed_range.end(), 0));
  EXPECT_EQ(3, std::distance(indexed_range.begin(), indexed_range.end()));
}

TEST(IndexedRange, Reallocate) {
  std::vector<int> range(10000);
  std::iota(range.begin(), range.end(), 0);

  int plain_sum = 0;
  int indexed_sum = 0;

  for (auto i : range) {
    plain_sum += i;
  }

  // Usually triggers a reallocation
  for (auto i : IndexedRange(range)) {
    indexed_sum += i;
    range.push_back(1);
  }

  EXPECT_EQ(plain_sum, indexed_sum);
  EXPECT_EQ(20000u, range.size());
}
