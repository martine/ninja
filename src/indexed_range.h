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

#ifndef NINJA_INDEXED_RANGE_H_
#define NINJA_INDEXED_RANGE_H_

#include <cstddef>
#include <iterator>
#include <type_traits>

/// A range over a container that is addressed by index instead of by
/// iterator.
///
/// Use IndexedRange when the loop body may modify the container in a way
/// that would invalidate iterators (e.g. appending to Edge::inputs_ via
/// dyndep). It makes such loops safe and also marks them for the reader.
/// If no invalidation can occur, prefer a plain range-based for loop.
///
/// Modifications of the container during traversal must only happen at or
/// behind the end of the range, i.e. elements may only be appended. The new
/// elements are not visited. Inserting or erasing elements before the end
/// of the range is not supported and leads to skipped or invalid elements.
///
/// The range covers the indices [0, size) where size is the container's
/// size at the time the IndexedRange is constructed. Elements are always
/// accessed through container[index], never through a stored iterator or
/// pointer, so the range stays valid even if the container reallocates
/// while it is being traversed (e.g. when dyndep loading appends to
/// Edge::outputs_).
///
/// The container must outlive the range and must not be moved. It must
/// provide operator[], size() and the usual container typedefs, as
/// std::vector does.
///
/// Example:
///
///   // Undefined behavior if foo() appends to edge->outputs_ and the vector
///   // reallocates. The range-for holds iterators into the old storage.
///   for (Node* i : edge->outputs_) foo(i);
///
///   // Safe: the element is looked up by index on every iteration.
///   const size_t size = edge->outputs_.size();
///   for (size_t i = 0; i < size; ++i) foo(edge->outputs_[i]);
///
///   // Equally safe, with the convenience of a range-based for loop.
///   for (Node* i : IndexedRange(edge->outputs_)) foo(i);
///
///   // Safe example for inputs.
///   // Sub-range of an edge's inputs without the order-only inputs. Dyndep
///   // inserts new implicit inputs behind the implicit inputs and in front
///   // of the order-only inputs, i.e. at the end of this range, so
///   // nothing inside the range is modified.
///   EdgeInputsRange inputs_range(...);
///   for (Node* i : IndexedRange(inputs_range)) foo(i);
template <typename Container>
class IndexedRange {
  using size_type = typename Container::size_type;

  /// Iterator that holds the container and an index and resolves the element
  /// via container[index] on each dereference, so it survives reallocation of
  /// the container. Only comparable with iterators of the same range.
  class iterator {
   public:
    using difference_type = std::ptrdiff_t;
    using value_type = typename Container::value_type;
    using pointer =
        typename std::conditional<std::is_const<Container>::value,
                                  typename Container::const_pointer,
                                  typename Container::pointer>::type;
    using reference =
        typename std::conditional<std::is_const<Container>::value,
                                  typename Container::const_reference,
                                  typename Container::reference>::type;
    using iterator_category = std::input_iterator_tag;

    iterator(Container& container, size_type index)
        : container_(container), index_(index) {}

    /// Looks up the element via operator[], so it is unaffected by any
    /// reallocation of the container since the iterator was created.
    reference operator*() const { return container_[index_]; }

    iterator& operator++() {
      ++index_;
      return *this;
    }

    bool operator!=(const iterator& other) const {
      return index_ != other.index_;
    }

    bool operator==(const iterator& other) const {
      return index_ == other.index_;
    }

   private:
    Container& container_;
    size_type index_;
  };

 public:
  /// Captures the container's current size as the end of the range.
  explicit IndexedRange(Container& container)
      : container_(container), size_(container.size()) {}

  IndexedRange(Container&&) = delete;

  iterator begin() const { return iterator(container_, 0); }
  iterator end() const { return iterator(container_, size_); }

 private:
  Container& container_;
  const size_type size_;
};

#endif  // NINJA_INDEXED_RANGE_H_
