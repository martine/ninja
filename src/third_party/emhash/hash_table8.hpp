// emhash8::HashMap for C++14/17/20
// version 1.7.0
// https://github.com/ktprime/emhash/blob/master/hash_table8.hpp
//
// Licensed under the MIT License <http://opensource.org/licenses/MIT>.
// SPDX-License-Identifier: MIT
// Copyright (c) 2021-2025 Huang Yuanbing & bailuzhou AT 163.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE

#pragma once

#include <cstring>
#include <string>
#include <cstdlib>
#include <type_traits>
#include <cassert>
#include <utility>
#include <cstdint>
#include <functional>
#include <iterator>
#include <algorithm>
#include <memory>

#undef  EMH_NEW
#undef  EMH_EMPTY
#undef  EMH_EQHASH 

// likely/unlikely
#if defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
#    define EMH_LIKELY(condition)   __builtin_expect(condition, 1)
#    define EMH_UNLIKELY(condition) __builtin_expect(condition, 0)
#else
#    define EMH_LIKELY(condition)   condition
#    define EMH_UNLIKELY(condition) condition
#endif

#define EMH_EMPTY(n) (0 > (int)(_index[n].next))
#define EMH_EQHASH(n, key_hash) (((size_type)(key_hash) & ~_mask) == (_index[n].slot & ~_mask))
//#define EMH_EQHASH(n, key_hash) ((size_type)(key_hash - _index[n].slot) & ~_mask) == 0
#define EMH_NEW(key, val, bucket, key_hash) \
    new(_pairs + _num_filled) value_type(key, val); \
    _etail = bucket; \
    _index[bucket] = {bucket, _num_filled++ | ((size_type)(key_hash) & ~_mask)}

    #if _WIN32 && defined(_M_IX86)
    #include <xmmintrin.h>
    #endif

    namespace emhash8 {

struct DefaultPolicy {
    static constexpr float load_factor = 0.80f;
    static constexpr float min_load_factor = 0.20f;
    static constexpr size_t cacheline_size = 64U;
};

template<typename KeyT, typename ValueT,
         typename HashT = std::hash<KeyT>,
         typename EqT = std::equal_to<KeyT>,
         typename Allocator = std::allocator<std::pair<KeyT, ValueT>>, //never used
         typename Policy = DefaultPolicy> //never used
class HashMap
{
#ifndef EMH_DEFAULT_LOAD_FACTOR
    constexpr static float EMH_DEFAULT_LOAD_FACTOR = 0.80f;
#endif
    constexpr static float EMH_MIN_LOAD_FACTOR     = 0.25f; //< 0.5
    constexpr static uint32_t EMH_CACHE_LINE_SIZE  = 64; //debug only

public:
    using htype = HashMap<KeyT, ValueT, HashT, EqT>;
    using value_type = std::pair<KeyT, ValueT>;
    using key_type = KeyT;
    using mapped_type = ValueT;
    //using dPolicy = Policy;

#ifdef EMH_SMALL_TYPE
    using size_type = uint16_t;
#elif EMH_SIZE_TYPE == 0
    using size_type = uint32_t;
#else
    using size_type = size_t;
#endif

    using hasher = HashT;
    using key_equal = EqT;

    constexpr static size_type INACTIVE = 0-1u;
    constexpr static size_type EAD      = 2;

    struct Index
    {
        size_type next;
        size_type slot;
    };

    class const_iterator; // Forward declaration

    class iterator
    {
    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using iterator_concept = std::bidirectional_iterator_tag; // added for C++20 Ranges
        using difference_type = std::ptrdiff_t;
        using value_type = typename htype::value_type;
        using pointer = value_type*;
        using reference = value_type&;
        using const_pointer = const value_type*;
        using const_reference = const value_type&;

        // Maak constructoren constexpr
        constexpr iterator() : kv_(nullptr) {}
        constexpr iterator(const const_iterator& cit) : kv_(cit.kv_) {}
        constexpr iterator(const htype* hash_map, size_type bucket) : kv_(hash_map->_pairs + static_cast<int>(bucket)) {}

        // Maak operatoren constexpr
        constexpr iterator& operator++()
        {
            kv_++;
            return *this;
        }

        constexpr iterator operator++(int)
        {
            iterator cur = *this;
            kv_++;
            return cur;
        }

        constexpr iterator& operator--()
        {
            kv_--;
            return *this;
        }

        constexpr iterator operator--(int)
        {
            iterator cur = *this;
            kv_--;
            return cur;
        }

        constexpr reference operator*() const { return *kv_; }
        constexpr pointer operator->() const { return kv_; }

        // Maak vergelijking operatoren constexpr
        constexpr bool operator==(const iterator& rhs) const { return kv_ == rhs.kv_; }
        constexpr bool operator!=(const iterator& rhs) const { return kv_ != rhs.kv_; }
        constexpr bool operator==(const const_iterator& rhs) const { return kv_ == rhs.kv_; }
        constexpr bool operator!=(const const_iterator& rhs) const { return kv_ != rhs.kv_; }

    public:
        value_type* kv_;
    private:

        // Vriend klasse om toegang te geven aan const_iterator
        friend class const_iterator;
    };

   

    class const_iterator
    {
    public:
        using iterator_category = std::bidirectional_iterator_tag;
        using iterator_concept = std::bidirectional_iterator_tag; // Toegevoegd voor C++20 Ranges
        using value_type = typename htype::value_type;
        using difference_type = std::ptrdiff_t;
        using pointer = const value_type*;
        using const_pointer = const value_type*;
        using reference = const value_type&;
        using const_reference = const value_type&;

        // Maak constructoren constexpr
        constexpr const_iterator() : kv_(nullptr) {}
        constexpr const_iterator(const iterator& it) : kv_(it.kv_) {}
        constexpr const_iterator(const htype* hash_map, size_type bucket) : kv_(hash_map->_pairs + static_cast<int>(bucket)) {}

        // Maak operatoren constexpr
        constexpr const_iterator& operator++()
        {
            kv_++;
            return *this;
        }

        constexpr const_iterator operator++(int)
        {
            const_iterator cur = *this;
            kv_++;
            return cur;
        }

        constexpr const_iterator& operator--()
        {
            kv_--;
            return *this;
        }

        constexpr const_iterator operator--(int)
        {
            const_iterator cur = *this;
            kv_--;
            return cur;
        }

        constexpr const_reference operator*() const { return *kv_; }
        constexpr const_pointer operator->() const { return kv_; }

        // Maak vergelijking operatoren constexpr
        constexpr bool operator==(const const_iterator& rhs) const { return kv_ == rhs.kv_; }
        constexpr bool operator!=(const const_iterator& rhs) const { return kv_ != rhs.kv_; }
        constexpr bool operator==(const iterator& rhs) const { return kv_ == rhs.kv_; }
        constexpr bool operator!=(const iterator& rhs) const { return kv_ != rhs.kv_; }

    public:
        const value_type* kv_;
    };

    void init(size_type bucket, float mlf = EMH_DEFAULT_LOAD_FACTOR)
    {
        _pairs = nullptr;
        _index = nullptr;
        _mask  = _num_buckets = 0;
        _num_filled = 0;
        _mlf = (uint32_t)((1 << 27) / EMH_DEFAULT_LOAD_FACTOR);
        max_load_factor(mlf);
        rehash(bucket);
    }

    HashMap(size_type bucket = 2, float mlf = EMH_DEFAULT_LOAD_FACTOR)
    {
        init(bucket, mlf);
    }

    HashMap(const HashMap& rhs)
    {
        if (rhs.load_factor() > EMH_MIN_LOAD_FACTOR) {
            _pairs = alloc_bucket((size_type)((float)rhs._num_buckets * rhs.max_load_factor()) + 4);
            _index = alloc_index(rhs._num_buckets);
            clone(rhs);
        } else {
            init(rhs._num_filled + 2, rhs.max_load_factor());
            for (auto it = rhs.begin(); it != rhs.end(); ++it)
                insert_unique(it->first, it->second);
        }
    }

    HashMap(HashMap&& rhs) noexcept
    {
        init(0);
        *this = std::move(rhs);
    }

    HashMap(std::initializer_list<value_type> ilist)
    {
        init((size_type)ilist.size());
        for (auto it = ilist.begin(); it != ilist.end(); ++it)
            do_insert(*it);
    }

    template<class InputIt>
    HashMap(InputIt first, InputIt last, size_type bucket_count=4)
    {
        init((size_type)std::distance(first, last) + bucket_count);
        for (; first != last; ++first)
            emplace(*first);
    }

    HashMap& operator=(const HashMap& rhs)
    {
        if (this == &rhs)
            return *this;

        if (rhs.load_factor() < EMH_MIN_LOAD_FACTOR) {
            clear(); free(_pairs); _pairs = nullptr;
            rehash(rhs._num_filled + 2);
            for (auto it = rhs.begin(); it != rhs.end(); ++it)
                insert_unique(it->first, it->second);
            return *this;
        }

        clearkv();

        if (_num_buckets != rhs._num_buckets) {
            free(_pairs); free(_index);
            _index = alloc_index(rhs._num_buckets);
            _pairs = alloc_bucket((size_type)((float)rhs._num_buckets * rhs.max_load_factor()) + 4);
        }

        clone(rhs);
        return *this;
    }

    HashMap& operator=(HashMap&& rhs) noexcept
    {
        if (this != &rhs) {
            swap(rhs);
            rhs.clear();
        }
        return *this;
    }

    template<typename Con>
    bool operator == (const Con& rhs) const
    {
        if (size() != rhs.size())
            return false;

        for (auto it = begin(), last = end(); it != last; ++it) {
            auto oi = rhs.find(it->first);
            if (oi == rhs.end() || it->second != oi->second)
                return false;
        }
        return true;
    }

    template<typename Con>
    bool operator != (const Con& rhs) const { return !(*this == rhs); }

    ~HashMap() noexcept
    {
        clearkv();
        free(_pairs);
        free(_index);
        _index = nullptr;
        _pairs = nullptr;
    }

    void clone(const HashMap& rhs)
    {
        _hasher      = rhs._hasher;
//        _eq          = rhs._eq;
        _num_buckets = rhs._num_buckets;
        _num_filled  = rhs._num_filled;
        _mlf         = rhs._mlf;
        _last        = rhs._last;
        _mask        = rhs._mask;
#if EMH_HIGH_LOAD
        _ehead       = rhs._ehead;
#endif
        _etail       = rhs._etail;

        auto opairs  = rhs._pairs;
        memcpy((char*)_index, (char*)rhs._index, (_num_buckets + EAD) * sizeof(Index));

        if (is_copy_trivially()) {
            memcpy((char*)_pairs, (char*)opairs, _num_filled * sizeof(value_type));
        } else {
            for (size_type slot = 0; slot < _num_filled; slot++)
                new(_pairs + slot) value_type(opairs[slot]);
        }
    }

    void swap(HashMap& rhs)
    {
        //      std::swap(_eq, rhs._eq);
        std::swap(_hasher, rhs._hasher);
        std::swap(_pairs, rhs._pairs);
        std::swap(_index, rhs._index);
        std::swap(_num_buckets, rhs._num_buckets);
        std::swap(_num_filled, rhs._num_filled);
        std::swap(_mask, rhs._mask);
        std::swap(_mlf, rhs._mlf);
        std::swap(_last, rhs._last);
#if EMH_HIGH_LOAD
        std::swap(_ehead, rhs._ehead);
#endif
        std::swap(_etail, rhs._etail);
    }

    // -------------------------------------------------------------
    iterator first() const { return {this, 0}; }
    iterator last() const { return {this, _num_filled - 1}; }

    value_type& front() { return _pairs[0]; }
    const value_type& front() const { return _pairs[0]; }
    value_type& back() { return _pairs[_num_filled - 1]; }
    const value_type& back() const { return _pairs[_num_filled - 1]; }

    void pop_front() { erase(begin()); } //TODO. only erase first without move last
    void pop_back() { erase(last()); }

    constexpr iterator begin() { return first(); }
    constexpr const_iterator cbegin() const { return first(); }
    constexpr const_iterator begin() const { return first(); }

    constexpr iterator end() { return { this, _num_filled }; }
    constexpr const_iterator cend() const { return { this, _num_filled }; }
    constexpr const_iterator end() const { return cend(); }

    const value_type* values() const { return _pairs; }
    const Index* index() const { return _index; }

    size_type size() const { return _num_filled; }
    bool empty() const { return _num_filled == 0; }
    size_type bucket_count() const { return _num_buckets; }

    /// Returns average number of elements per bucket.
    float load_factor() const { return static_cast<float>(_num_filled) / ((float)_mask + 1.0f); }

    HashT& hash_function() const { return _hasher; }
    EqT& key_eq() const { return _eq; }

    void max_load_factor(float mlf)
    {
        if (mlf < 0.992 && mlf > EMH_MIN_LOAD_FACTOR) {
            _mlf = (uint32_t)((1 << 27) / mlf);
            if (_num_buckets > 0) rehash(_num_buckets);
        }
    }

    constexpr float max_load_factor() const { return (1 << 27) / (float)_mlf; }
    constexpr size_type max_size() const { return (1ull << (sizeof(size_type) * 8 - 1)); }
    constexpr size_type max_bucket_count() const { return max_size(); }

#if EMH_STATIS
    //Returns the bucket number where the element with key k is located.
    size_type bucket(const KeyT& key) const
    {
        const auto bucket = hash_bucket(key);
        const auto next_bucket = _index[bucket].next;
        if ((int)next_bucket < 0)
            return 0;
        else if (bucket == next_bucket)
            return bucket + 1;

        return hash_main(bucket) + 1;
    }

    //Returns the number of elements in bucket n.
    size_type bucket_size(const size_type bucket) const
    {
        auto next_bucket = _index[bucket].next;
        if ((int)next_bucket < 0)
            return 0;

        next_bucket = hash_main(bucket);
        size_type ibucket_size = 1;

        //iterator each item in current main bucket
        while (true) {
            const auto nbucket = _index[next_bucket].next;
            if (nbucket == next_bucket) {
                break;
            }
            ibucket_size ++;
            next_bucket = nbucket;
        }
        return ibucket_size;
    }

    size_type get_main_bucket(const size_type bucket) const
    {
        auto next_bucket = _index[bucket].next;
        if ((int)next_bucket < 0)
            return INACTIVE;

        return hash_main(bucket);
    }

    size_type get_diss(size_type bucket, size_type next_bucket, const size_type slots) const
    {
        auto pbucket = reinterpret_cast<uint64_t>(&_pairs[bucket]);
        auto pnext   = reinterpret_cast<uint64_t>(&_pairs[next_bucket]);
        if (pbucket / EMH_CACHE_LINE_SIZE == pnext / EMH_CACHE_LINE_SIZE)
            return 0;
        size_type diff = pbucket > pnext ? (pbucket - pnext) : (pnext - pbucket);
        if (diff / EMH_CACHE_LINE_SIZE < slots - 1)
            return diff / EMH_CACHE_LINE_SIZE + 1;
        return slots - 1;
    }

    int get_bucket_info(const size_type bucket, size_type steps[], const size_type slots) const
    {
        auto next_bucket = _index[bucket].next;
        if ((int)next_bucket < 0)
            return -1;

        const auto main_bucket = hash_main(bucket);
        if (next_bucket == main_bucket)
            return 1;
        else if (main_bucket != bucket)
            return 0;

        steps[get_diss(bucket, next_bucket, slots)] ++;
        size_type ibucket_size = 2;
        //find a empty and linked it to tail
        while (true) {
            const auto nbucket = _index[next_bucket].next;
            if (nbucket == next_bucket)
                break;

            steps[get_diss(nbucket, next_bucket, slots)] ++;
            ibucket_size ++;
            next_bucket = nbucket;
        }
        return (int)ibucket_size;
    }

    void dump_statics() const
    {
        const size_type slots = 128;
        size_type buckets[slots + 1] = {0};
        size_type steps[slots + 1]   = {0};
        for (size_type bucket = 0; bucket < _num_buckets; ++bucket) {
            auto bsize = get_bucket_info(bucket, steps, slots);
            if (bsize > 0)
                buckets[bsize] ++;
        }

        size_type sumb = 0, collision = 0, sumc = 0, finds = 0, sumn = 0;
        puts("============== buckets size ration =========");
        for (size_type i = 0; i < sizeof(buckets) / sizeof(buckets[0]); i++) {
            const auto bucketsi = buckets[i];
            if (bucketsi == 0)
                continue;
            sumb += bucketsi;
            sumn += bucketsi * i;
            collision += bucketsi * (i - 1);
            finds += bucketsi * i * (i + 1) / 2;
            printf("  %2u  %8u  %2.2lf|  %.2lf\n", i, bucketsi, bucketsi * 100.0 * i / _num_filled, sumn * 100.0 / _num_filled);
        }

        puts("========== collision miss ration ===========");
        for (size_type i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
            sumc += steps[i];
            if (steps[i] <= 2)
                continue;
            printf("  %2u  %8u  %.2lf  %.2lf\n", i, steps[i], steps[i] * 100.0 / collision, sumc * 100.0 / collision);
        }

        if (sumb == 0)  return;
        printf("    _num_filled/bucket_size/packed collision/cache_miss/hit_find = %u/%.2lf/%zd/ %.2lf%%/%.2lf%%/%.2lf\n",
                _num_filled, _num_filled * 1.0 / sumb, sizeof(value_type), (collision * 100.0 / _num_filled), (collision - steps[0]) * 100.0 / _num_filled, finds * 1.0 / _num_filled);
        assert(sumn == _num_filled);
        assert(sumc == collision);
        puts("============== buckets size end =============");
    }
#endif

    void pack_zero(ValueT zero)
    {
        _pairs[_num_filled] = {KeyT(), zero};
    }

    // ------------------------------------------------------------
    template<typename K=KeyT>
    iterator find(const K& key) noexcept
    {
        return {this, find_filled_slot(key)};
    }

    template<typename K=KeyT>
    const_iterator find(const K& key) const noexcept
    {
        return {this, find_filled_slot(key)};
    }

    template<typename K=KeyT>
    ValueT& at(const K& key)
    {
        const auto slot = find_filled_slot(key);
        //throw
        return _pairs[slot].second;
    }

    template<typename K=KeyT>
    const ValueT& at(const K& key) const
    {
        const auto slot = find_filled_slot(key);
        //throw
        return _pairs[slot].second;
    }

    const ValueT& index(const uint32_t index) const
    {
        return _pairs[index].second;
    }

    ValueT& index(const uint32_t index)
    {
        return _pairs[index].second;
    }

    template<typename K=KeyT>
    bool contains(const K& key) const noexcept
    {
        return find_filled_slot(key) != _num_filled;
    }

    template<typename K=KeyT>
    size_type count(const K& key) const noexcept
    {
        return find_filled_slot(key) == _num_filled ? 0 : 1;
        //return find_sorted_bucket(key) == END ? 0 : 1;
        //return find_hash_bucket(key) == END ? 0 : 1;
    }

    template<typename K=KeyT>
    std::pair<iterator, iterator> equal_range(const K& key)
    {
        const auto found = find(key);
        if (found.second == _num_filled)
            return { found, found };
        else
            return { found, std::next(found) };
    }

    void merge(HashMap& rhs)
    {
        if (empty()) {
            *this = std::move(rhs);
            return;
        }

        for (auto rit = rhs.begin(); rit != rhs.end(); ) {
            auto fit = find(rit->first);
            if (fit == end()) {
                insert_unique(rit->first, std::move(rit->second));
                rit = rhs.erase(rit);
            } else {
                ++rit;
            }
        }
    }

    /// Returns the matching ValueT or nullptr if k isn't found.
    bool try_get(const KeyT& key, ValueT& val) const noexcept
    {
        const auto slot = find_filled_slot(key);
        const auto found = slot != _num_filled;
        if (found) {
            val = _pairs[slot].second;
        }
        return found;
    }

    /// Returns the matching ValueT or nullptr if k isn't found.
    ValueT* try_get(const KeyT& key) noexcept
    {
        const auto slot = find_filled_slot(key);
        return slot != _num_filled ? &_pairs[slot].second : nullptr;
    }

    /// Const version of the above
    ValueT* try_get(const KeyT& key) const noexcept
    {
        const auto slot = find_filled_slot(key);
        return slot != _num_filled ? &_pairs[slot].second : nullptr;
    }

    /// set value if key exist
    bool try_set(const KeyT& key, const ValueT& val) noexcept
    {
        const auto slot = find_filled_slot(key);
        if (slot == _num_filled)
            return false;

        _pairs[slot].second = val;
        return true;
    }

    /// set value if key exist
    bool try_set(const KeyT& key, ValueT&& val) noexcept
    {
        const auto slot = find_filled_slot(key);
        if (slot == _num_filled)
            return false;

        _pairs[slot].second = std::move(val);
        return true;
    }

    /// Convenience function.
    ValueT get_or_return_default(const KeyT& key) const noexcept
    {
        const auto slot = find_filled_slot(key);
        return slot == _num_filled ? ValueT() : _pairs[slot].second;
    }

    // -----------------------------------------------------
    std::pair<iterator, bool> do_insert(const value_type& value) noexcept
    {
        const auto key_hash = hash_key(value.first);
        const auto bucket = find_or_allocate(value.first, key_hash);
        const auto bempty = EMH_EMPTY(bucket);
        if (bempty) {
            EMH_NEW(value.first, value.second, bucket, key_hash);
        }

        const auto slot = _index[bucket].slot & _mask;
        return { {this, slot}, bempty };
    }

    std::pair<iterator, bool> do_insert(value_type&& value) noexcept
    {
        const auto key_hash = hash_key(value.first);
        const auto bucket = find_or_allocate(value.first, key_hash);
        const auto bempty = EMH_EMPTY(bucket);
        if (bempty) {
            EMH_NEW(std::move(value.first), std::move(value.second), bucket, key_hash);
        }

        const auto slot = _index[bucket].slot & _mask;
        return { {this, slot}, bempty };
    }

    template<typename K, typename V>
    std::pair<iterator, bool> do_insert(K&& key, V&& val) noexcept
    {
        const auto key_hash = hash_key(key);
        const auto bucket = find_or_allocate(key, key_hash);
        const auto bempty = EMH_EMPTY(bucket);
        if (bempty) {
            EMH_NEW(std::forward<K>(key), std::forward<V>(val), bucket, key_hash);
        }

        const auto slot = _index[bucket].slot & _mask;
        return { {this, slot}, bempty };
    }

    template<typename K, typename V>
    std::pair<iterator, bool> do_assign(K&& key, V&& val) noexcept
    {
        check_expand_need();
        const auto key_hash = hash_key(key);
        const auto bucket = find_or_allocate(key, key_hash);
        const auto bempty = EMH_EMPTY(bucket);
        if (bempty) {
            EMH_NEW(std::forward<K>(key), std::forward<V>(val), bucket, key_hash);
        } else {
            _pairs[_index[bucket].slot & _mask].second = std::move(val);
        }

        const auto slot = _index[bucket].slot & _mask;
        return { {this, slot}, bempty };
    }

    std::pair<iterator, bool> insert(const value_type& p)
    {
        check_expand_need();
        return do_insert(p);
    }

    std::pair<iterator, bool> insert(value_type && p)
    {
        check_expand_need();
        return do_insert(std::move(p));
    }

    void insert(std::initializer_list<value_type> ilist)
    {
        reserve(ilist.size() + _num_filled, false);
        for (auto it = ilist.begin(); it != ilist.end(); ++it)
            do_insert(*it);
    }

    template <typename Iter>
    void insert(Iter first, Iter last)
    {
        reserve(std::distance(first, last) + _num_filled, false);
        for (; first != last; ++first)
            do_insert(first->first, first->second);
    }

#if 0
    template <typename Iter>
    void insert_unique(Iter begin, Iter end)
    {
        reserve(std::distance(begin, end) + _num_filled, false);
        for (; begin != end; ++begin) {
            insert_unique(*begin);
        }
    }
#endif

    template<typename K, typename V>
    size_type insert_unique(K&& key, V&& val)
    {
        check_expand_need();
        const auto key_hash = hash_key(key);
        auto bucket = find_unique_bucket(key_hash);
        EMH_NEW(std::forward<K>(key), std::forward<V>(val), bucket, key_hash);
        return bucket;
    }

    size_type insert_unique(value_type&& value)
    {
        return insert_unique(std::move(value.first), std::move(value.second));
    }

    size_type insert_unique(const value_type& value)
    {
        return insert_unique(value.first, value.second);
    }

    template <class... Args>
    std::pair<iterator, bool> emplace(Args&&... args) noexcept
    {
        check_expand_need();
        return do_insert(std::forward<Args>(args)...);
    }

    //no any optimize for position
    template <class... Args>
    iterator emplace_hint(const_iterator hint, Args&&... args)
    {
        (void)hint;
        check_expand_need();
        return do_insert(std::forward<Args>(args)...).first;
    }

    template<class... Args>
    std::pair<iterator, bool> try_emplace(const KeyT& k, Args&&... args)
    {
        check_expand_need();
        return do_insert(k, std::forward<Args>(args)...);
    }

    template<class... Args>
    std::pair<iterator, bool> try_emplace(KeyT&& k, Args&&... args)
    {
        check_expand_need();
        return do_insert(std::move(k), std::forward<Args>(args)...);
    }

    template <class... Args>
    size_type emplace_unique(Args&&... args)
    {
        return insert_unique(std::forward<Args>(args)...);
    }

    std::pair<iterator, bool> insert_or_assign(const KeyT& key, ValueT&& val) { return do_assign(key, std::forward<ValueT>(val)); }
    std::pair<iterator, bool> insert_or_assign(KeyT&& key, ValueT&& val) { return do_assign(std::move(key), std::forward<ValueT>(val)); }

    /// Return the old value or ValueT() if it didn't exist.
    ValueT set_get(const KeyT& key, const ValueT& val)
    {
        check_expand_need();
        const auto key_hash = hash_key(key);
        const auto bucket = find_or_allocate(key, key_hash);
        if (EMH_EMPTY(bucket)) {
            EMH_NEW(key, val, bucket, key_hash);
            return ValueT();
        } else {
            const auto slot = _index[bucket].slot & _mask;
            ValueT old_value(val);
            std::swap(_pairs[slot].second, old_value);
            return old_value;
        }
    }

    /// Like std::map<KeyT, ValueT>::operator[].
    ValueT& operator[](const KeyT& key) noexcept
    {
        check_expand_need();
        const auto key_hash = hash_key(key);
        const auto bucket = find_or_allocate(key, key_hash);
        if (EMH_EMPTY(bucket)) {
            /* Check if inserting a value rather than overwriting an old entry */
            EMH_NEW(key, std::move(ValueT()), bucket, key_hash);
        }

        const auto slot = _index[bucket].slot & _mask;
        return _pairs[slot].second;
    }

    ValueT& operator[](KeyT&& key) noexcept
    {
        check_expand_need();
        const auto key_hash = hash_key(key);
        const auto bucket = find_or_allocate(key, key_hash);
        if (EMH_EMPTY(bucket)) {
            EMH_NEW(std::move(key), std::move(ValueT()), bucket, key_hash);
        }

        const auto slot = _index[bucket].slot & _mask;
        return _pairs[slot].second;
    }

    /// Erase an element from the hash table.
    /// return 0 if element was not found
    size_type erase(const KeyT& key) noexcept
    {
        const auto key_hash = hash_key(key);
        const auto sbucket = find_filled_bucket(key, key_hash);
        if (sbucket == INACTIVE)
            return 0;

        const auto main_bucket = key_hash & _mask;
        erase_slot(sbucket, (size_type)main_bucket);
        return 1;
    }

    //iterator erase(const_iterator begin_it, const_iterator end_it)
    iterator erase(const const_iterator& cit) noexcept
    {
        const auto slot = (size_type)(cit.kv_ - _pairs);
        size_type main_bucket;
        const auto sbucket = find_slot_bucket(slot, main_bucket); //TODO
        erase_slot(sbucket, main_bucket);
        return {this, slot};
    }

    //only last >= first
    iterator erase(const_iterator first, const_iterator last) noexcept
    {
        auto esize = long(last.kv_ - first.kv_);
        auto tsize = long((_pairs + _num_filled) - last.kv_); //last to tail size
        auto next = first;
        while (tsize -- > 0) {
            if (esize-- <= 0)
                break;
            next = ++erase(next);
        }

        //fast erase from last
        next = this->last();
        while (esize -- > 0)
            next = --erase(next);

        return {this, size_type(next.kv_ - _pairs)};
    }

    template<typename Pred>
    size_type erase_if(Pred pred)
    {
        auto old_size = size();
        for (auto it = begin(); it != end();) {
            if (pred(*it))
                it = erase(it);
            else
                ++it;
        }
        return old_size - size();
    }

    static constexpr bool is_triviall_destructable()
    {
#if __cplusplus >= 201402L || _MSC_VER > 1600
        return !(std::is_trivially_destructible<KeyT>::value && std::is_trivially_destructible<ValueT>::value);
#else
        return !(std::is_pod<KeyT>::value && std::is_pod<ValueT>::value);
#endif
    }

    static constexpr bool is_copy_trivially()
    {
#if __cplusplus >= 201103L || _MSC_VER > 1600
        return (std::is_trivially_copyable<KeyT>::value && std::is_trivially_copyable<ValueT>::value);
#else
        return (std::is_pod<KeyT>::value && std::is_pod<ValueT>::value);
#endif
    }

    void clearkv()
    {
        if (is_triviall_destructable()) {
            while (_num_filled --)
                _pairs[_num_filled].~value_type();
        }
    }

    /// Remove all elements, keeping full capacity.
    void clear() noexcept
    {
        clearkv();

        if (_num_filled > 0)
            memset((char*)_index, (int)INACTIVE, sizeof(_index[0]) * _num_buckets);

        _last = _num_filled = 0;
        _etail = INACTIVE;

#if EMH_HIGH_LOAD
        _ehead = 0;
#endif
    }

    void shrink_to_fit(const float min_factor = EMH_DEFAULT_LOAD_FACTOR / 4)
    {
        if (load_factor() < min_factor && bucket_count() > 10) //safe guard
            rehash(_num_filled + 1);
    }

#if EMH_HIGH_LOAD
    #define EMH_PREVET(i, n) i[n].slot
    void set_empty()
    {
        auto prev = 0;
        for (int32_t bucket = 1; bucket < _num_buckets; ++bucket) {
            if (EMH_EMPTY(bucket)) {
                if (prev != 0) {
                    EMH_PREVET(_index, bucket) = prev;
                    _index[_prev].next = -bucket;
                }
                else
                    _ehead = bucket;
                prev = bucket;
            }
        }

        EMH_PREVET(_index, _ehead) = prev;
        _index[_prev].next = 0-_ehead;
        _ehead = 0-_index[_ehead].next;
    }

    void clear_empty()
    {
        auto prev = EMH_PREVET(_index, _ehead);
        while (prev != _ehead) {
            _index[_prev].next = INACTIVE;
            prev = EMH_PREVET(_index, prev);
        }
        _index[_ehead].next = INACTIVE;
        _ehead = 0;
    }

    //prev-ehead->next
    size_type pop_empty(const size_type bucket)
    {
        const auto prev_bucket = EMH_PREVET(_index, bucket);
        const int next_bucket = 0-_index[bucket].next;

        EMH_PREVET(_index, next_bucket) = prev_bucket;
        _index[prev_bucket].next = -next_bucket;

        _ehead = next_bucket;
        return bucket;
    }

    //ehead->bucket->next
    void push_empty(const int32_t bucket)
    {
        const int next_bucket = 0-_index[_ehead].next;
        assert(next_bucket > 0);

        EMH_PREVET(_index, bucket) = _ehead;
        _index[bucket].next = -next_bucket;

        EMH_PREVET(_index, next_bucket) = bucket;
        _index[_ehead].next = -bucket;
        //        _ehead = bucket;
    }
#endif

    /// Make room for this many elements
    bool reserve(uint64_t num_elems, bool force)
    {
        (void)force;
#if EMH_HIGH_LOAD == 0
        const auto required_buckets = num_elems * _mlf >> 27;
        if (EMH_LIKELY(required_buckets < _mask)) // && !force
            return false;

#elif EMH_HIGH_LOAD
        const auto required_buckets = num_elems + num_elems * 1 / 9;
        if (EMH_LIKELY(required_buckets < _mask))
            return false;

        else if (_num_buckets < 16 && _num_filled < _num_buckets)
            return false;

        else if (_num_buckets > EMH_HIGH_LOAD) {
            if (_ehead == 0) {
                set_empty();
                return false;
            } else if (/*_num_filled + 100 < _num_buckets && */_index[_ehead].next != 0-_ehead) {
                return false;
            }
        }
#endif
#if EMH_STATIS
        if (_num_filled > EMH_STATIS) dump_statics();
#endif

        //assert(required_buckets < max_size());
        rehash(required_buckets + 2);
        return true;
    }

    static value_type* alloc_bucket(size_type num_buckets)
    {
#ifdef EMH_ALLOC
        auto new_pairs = aligned_alloc(32, (uint64_t)num_buckets * sizeof(value_type));
#else
        auto new_pairs = malloc((uint64_t)num_buckets * sizeof(value_type));
#endif
        return (value_type *)(new_pairs);
    }

    static Index* alloc_index(size_type num_buckets)
    {
        auto new_index = (char*)malloc((uint64_t)(EAD + num_buckets) * sizeof(Index));
        return (Index *)(new_index);
    }

    bool reserve(size_type required_buckets) noexcept
    {
        if (_num_filled != required_buckets)
            return reserve(required_buckets, true);

        _last = 0;
#if EMH_HIGH_LOAD
        _ehead = 0;
#endif

#if EMH_SORT
        std::sort(_pairs, _pairs + _num_filled, [this](const value_type & l, const value_type & r) {
            const auto hashl = (size_type)hash_key(l.first) & _mask, hashr = (size_type)hash_key(r.first) & _mask;
            return hashl < hashr;
            //return l.first < r.first;
        });
#endif

        memset((char*)_index, (int)INACTIVE, sizeof(_index[0]) * _num_buckets);
        for (size_type slot = 0; slot < _num_filled; slot++) {
            const auto& key = _pairs[slot].first;
            const auto key_hash = hash_key(key);
            const auto bucket = size_type(key_hash & _mask);
            auto& next_bucket = _index[bucket].next;
            if ((int)next_bucket < 0)
                _index[bucket] = {1, slot | ((size_type)(key_hash) & ~_mask)};
            else {
                _index[bucket].slot |= (size_type)(key_hash) & ~_mask;
                next_bucket ++;
            }
        }
        return true;
    }

    void rebuild(size_type num_buckets) noexcept
    {
        free(_index);
        auto new_pairs = (value_type*)alloc_bucket((size_type)((double)num_buckets * max_load_factor()) + 4);
        if (is_copy_trivially()) {
            if (_pairs)
            memcpy((char*)new_pairs, (char*)_pairs, _num_filled * sizeof(value_type));
        } else {
            for (size_type slot = 0; slot < _num_filled; slot++) {
                new(new_pairs + slot) value_type(std::move(_pairs[slot]));
                if (is_triviall_destructable())
                    _pairs[slot].~value_type();
            }
        }
        free(_pairs);
        _pairs = new_pairs;
        _index = (Index*)alloc_index (num_buckets);

        memset((char*)_index, (int)INACTIVE, sizeof(_index[0]) * num_buckets);
        memset((char*)(_index + num_buckets), 0, sizeof(_index[0]) * EAD);
    }

    void rehash(uint64_t required_buckets)
    {
        if (required_buckets < _num_filled)
            return;

        assert(required_buckets < max_size());
        auto num_buckets = _num_filled > (1u << 16) ? (1u << 16) : 4u;
        while (num_buckets < required_buckets) { num_buckets *= 2; }
#if EMH_SAVE_MEM
        if (sizeof(KeyT) < sizeof(size_type) && num_buckets >= (1ul << (2 * 8)))
            num_buckets = 2ul << (sizeof(KeyT) * 8);
#endif

#if EMH_REHASH_LOG
        auto last = _last;
        size_type collision = 0;
#endif

#if EMH_HIGH_LOAD
        _ehead = 0;
#endif
        _last = 0;

        _mask        = num_buckets - 1;
#if EMH_PACK_TAIL > 1
        _last = _mask;
        num_buckets += num_buckets * EMH_PACK_TAIL / 100; //add more 5-10%
#endif
        _num_buckets = num_buckets;

        rebuild(num_buckets);

#ifdef EMH_SORT
        std::sort(_pairs, _pairs + _num_filled, [this](const value_type & l, const value_type & r) {
            const auto hashl = hash_key(l.first), hashr = hash_key(r.first);
            auto diff = int64_t((hashl & _mask) - (hashr & _mask));
            if (diff != 0)
                return diff < 0;
            return hashl < hashr;
//          return l.first < r.first;
        });
#endif

        _etail = INACTIVE;
        for (size_type slot = 0; slot < _num_filled; ++slot) {
            const auto& key = _pairs[slot].first;
            const auto key_hash = hash_key(key);
            const auto bucket = find_unique_bucket(key_hash);
            _index[bucket] = { bucket, slot | ((size_type)(key_hash) & ~_mask) };

#if EMH_REHASH_LOG
            if (bucket != hash_main(bucket))
                collision ++;
#endif
        }

#if EMH_REHASH_LOG
        if (_num_filled > EMH_REHASH_LOG) {
            auto mbucket = _num_filled - collision;
            char buff[255] = {0};
            sprintf(buff, "    _num_filled/aver_size/K.V/pack/collision|last = %u/%.2lf/%s.%s/%zd|%.2lf%%,%.2lf%%",
                    _num_filled, double (_num_filled) / mbucket, typeid(KeyT).name(), typeid(ValueT).name(), sizeof(_pairs[0]), collision * 100.0 / _num_filled, last * 100.0 / _num_buckets);
#ifdef EMH_LOG
            static uint32_t ihashs = 0; EMH_LOG() << "hash_nums = " << ihashs ++ << "|" <<__FUNCTION__ << "|" << buff << endl;
#else
            puts(buff);
#endif
        }
#endif
    }

private:
    // Can we fit another element?
    bool check_expand_need()
    {
        return reserve(_num_filled, false);
    }

    static void prefetch_heap_block(char* ctrl)
    {
        // Prefetch the heap-allocated memory region to resolve potential TLB
        // misses.  This is intended to overlap with execution of calculating the hash for a key.
#if __linux__
        __builtin_prefetch(static_cast<const void*>(ctrl));
#elif _WIN32 && defined(_M_IX86)
        _mm_prefetch((const char*)ctrl, _MM_HINT_T0);
#endif
    }

    size_type slot_to_bucket(const size_type slot) const noexcept
    {
        size_type main_bucket;
        return find_slot_bucket(slot, main_bucket); //TODO
    }

    //very slow
    void erase_slot(const size_type sbucket, const size_type main_bucket) noexcept
    {
        const auto slot = _index[sbucket].slot & _mask;
        const auto ebucket = erase_bucket(sbucket, main_bucket);
        const auto last_slot = --_num_filled;
        if (EMH_LIKELY(slot != last_slot)) {
            const auto last_bucket = (_etail == INACTIVE || ebucket == _etail)
                ? slot_to_bucket(last_slot) : _etail;

            _pairs[slot] = std::move(_pairs[last_slot]);
            _index[last_bucket].slot = slot | (_index[last_bucket].slot & ~_mask);
        }

        if (is_triviall_destructable())
            _pairs[last_slot].~value_type();

        _etail = INACTIVE;
        _index[ebucket] = {INACTIVE, 0};
#if EMH_HIGH_LOAD
        if (_ehead) {
            if (10 * _num_filled < 8 * _num_buckets)
                clear_empty();
            else if (ebucket)
                push_empty(ebucket);
        }
#endif
    }

    size_type erase_bucket(const size_type bucket, const size_type main_bucket) noexcept
    {
        const auto next_bucket = _index[bucket].next;
        if (bucket == main_bucket) {
            if (main_bucket != next_bucket) {
                const auto nbucket = _index[next_bucket].next;
                _index[main_bucket] = {
                    (nbucket == next_bucket) ? main_bucket : nbucket,
                    _index[next_bucket].slot
                };
            }
            return next_bucket;
        }

        const auto prev_bucket = find_prev_bucket(main_bucket, bucket);
        _index[prev_bucket].next = (bucket == next_bucket) ? prev_bucket : next_bucket;
        return bucket;
    }

    // Find the slot with this key, or return bucket size
    size_type find_slot_bucket(const size_type slot, size_type& main_bucket) const
    {
        const auto key_hash = hash_key(_pairs[slot].first);
        const auto bucket = main_bucket = size_type(key_hash & _mask);
        if (slot == (_index[bucket].slot & _mask))
            return bucket;

        auto next_bucket = _index[bucket].next;
        while (true) {
            if (EMH_LIKELY(slot == (_index[next_bucket].slot & _mask)))
                return next_bucket;
            next_bucket = _index[next_bucket].next;
        }

        return INACTIVE;
    }

    // Find the slot with this key, or return bucket size
    size_type find_filled_bucket(const KeyT& key, uint64_t key_hash) const noexcept
    {
        const auto bucket = size_type(key_hash & _mask);
        auto next_bucket  = _index[bucket].next;
        if (EMH_UNLIKELY((int)next_bucket < 0))
            return INACTIVE;

        const auto slot = _index[bucket].slot & _mask;
        //prefetch_heap_block((char*)&_pairs[slot]);
        if (EMH_EQHASH(bucket, key_hash)) {
            if (EMH_LIKELY(_eq(key, _pairs[slot].first)))
                return bucket;
        }
        if (next_bucket == bucket)
            return INACTIVE;

        while (true) {
            if (EMH_EQHASH(next_bucket, key_hash)) {
                const auto eslot = _index[next_bucket].slot & _mask;
                if (EMH_LIKELY(_eq(key, _pairs[eslot].first)))
                    return next_bucket;
            }

            const auto nbucket = _index[next_bucket].next;
            if (nbucket == next_bucket)
                return INACTIVE;
            next_bucket = nbucket;
        }

        return INACTIVE;
    }

    // Find the slot with this key, or return bucket size
    template<typename K=KeyT>
    size_type find_filled_slot(const K& key) const noexcept
    {
        const auto key_hash = hash_key(key);
        const auto bucket = size_type(key_hash & _mask);
        auto next_bucket = _index[bucket].next;
        if ((int)next_bucket < 0)
            return _num_filled;

        const auto slot = _index[bucket].slot & _mask;
        //prefetch_heap_block((char*)&_pairs[slot]);
        if (EMH_EQHASH(bucket, key_hash)) {
            if (EMH_LIKELY(_eq(key, _pairs[slot].first)))
                return slot;
        }
        if (next_bucket == bucket)
            return _num_filled;

        while (true) {
            if (EMH_EQHASH(next_bucket, key_hash)) {
                const auto eslot = _index[next_bucket].slot & _mask;
                if (EMH_LIKELY(_eq(key, _pairs[eslot].first)))
                    return eslot;
            }

            const auto nbucket = _index[next_bucket].next;
            if (nbucket == next_bucket)
                return _num_filled;
            next_bucket = nbucket;
        }

        return _num_filled;
    }

#if EMH_SORT
    size_type find_hash_bucket(const KeyT& key) const noexcept
    {
        const auto key_hash = hash_key(key);
        const auto bucket = size_type(key_hash & _mask);
        const auto next_bucket = _index[bucket].next;
        if ((int)next_bucket < 0)
            return END;

        auto slot = _index[bucket].slot & _mask;
        if (_eq(key, _pairs[slot++].first))
            return slot;
        else if (next_bucket == bucket)
            return END;

        while (true) {
            const auto& okey = _pairs[slot++].first;
            if (_eq(key, okey))
                return slot;

            const auto hasho = hash_key(okey);
            if ((hasho & _mask) != bucket)
                break;
            else if (hasho > key_hash)
                break;
            else if (EMH_UNLIKELY(slot >= _num_filled))
                break;
        }

        return END;
    }

    //only for find/can not insert
    size_type find_sorted_bucket(const KeyT& key) const noexcept
    {
        const auto key_hash = hash_key(key);
        const auto bucket = size_type(key_hash & _mask);
        const auto slots = (int)(_index[bucket].next); //TODO
        if (slots < 0 /**|| key < _pairs[slot].first*/)
            return END;

        const auto slot = _index[bucket].slot & _mask;
        auto ormask = _index[bucket].slot & ~_mask;
        auto hmask  = (size_type)(key_hash) & ~_mask;
        if ((hmask | ormask) != ormask)
            return END;

        if (_eq(key, _pairs[slot].first))
            return slot;
        else if (slots == 1 || key < _pairs[slot].first)
            return END;

#if EMH_SORT
        if (key < _pairs[slot].first || key > _pairs[slots + slot - 1].first)
            return END;
#endif

        for (size_type i = 1; i < slots; ++i) {
            const auto& okey = _pairs[slot + i].first;
            if (_eq(key, okey))
                return slot + i;
            //            else if (okey > key)
            //                return END;
        }

        return END;
    }
#endif

    //kick out bucket and find empty to occpuy
    //it will break the origin link and relink again.
    //before: main_bucket-->prev_bucket --> bucket   --> next_bucket
    //atfer : main_bucket-->prev_bucket --> (removed)--> new_bucket--> next_bucket
    size_type kickout_bucket(const size_type kmain, const size_type bucket) noexcept
    {
        const auto next_bucket = _index[bucket].next;
        const auto new_bucket  = find_empty_bucket(next_bucket, 2);
        const auto prev_bucket = find_prev_bucket(kmain, bucket);

        const auto last = next_bucket == bucket ? new_bucket : next_bucket;
        _index[new_bucket] = {last, _index[bucket].slot};

        _index[prev_bucket].next = new_bucket;
        _index[bucket].next = INACTIVE;

        return bucket;
    }

    /*
     ** inserts a new key into a hash table; first, check whether key's main
     ** bucket/position is free. If not, check whether colliding node/bucket is in its main
     ** position or not: if it is not, move colliding bucket to an empty place and
     ** put new key in its main position; otherwise (colliding bucket is in its main
     ** position), new key goes to an empty position.
     */
    template<typename K=KeyT>
    size_type find_or_allocate(const K& key, uint64_t key_hash) noexcept
    {
        const auto bucket = size_type(key_hash & _mask);
        auto next_bucket = _index[bucket].next;
        prefetch_heap_block((char*)&_pairs[bucket]);
        if ((int)next_bucket < 0) {
#if EMH_HIGH_LOAD
            if (next_bucket != INACTIVE)
                pop_empty(bucket);
#endif
            return bucket;
        }

        const auto slot = _index[bucket].slot & _mask;
        if (EMH_EQHASH(bucket, key_hash))
            if (EMH_LIKELY(_eq(key, _pairs[slot].first)))
                return bucket;

        //check current bucket_key is in main bucket or not
        const auto kmain = hash_bucket(_pairs[slot].first);
        if (kmain != bucket)
            return kickout_bucket(kmain, bucket);
        else if (next_bucket == bucket)
            return _index[next_bucket].next = find_empty_bucket(next_bucket, 1);

        uint32_t csize = 1;
        //find next linked bucket and check key
        while (true) {
            const auto eslot = _index[next_bucket].slot & _mask;
            if (EMH_EQHASH(next_bucket, key_hash)) {
                if (EMH_LIKELY(_eq(key, _pairs[eslot].first)))
                    return next_bucket;
            }

            csize += 1;
            const auto nbucket = _index[next_bucket].next;
            if (nbucket == next_bucket)
                break;
            next_bucket = nbucket;
        }

        //find a empty and link it to tail
        const auto new_bucket = find_empty_bucket(next_bucket, csize);
        prefetch_heap_block((char*)&_pairs[new_bucket]);
        return _index[next_bucket].next = new_bucket;
    }

    size_type find_unique_bucket(uint64_t key_hash) noexcept
    {
        const auto bucket = size_type(key_hash & _mask);
        auto next_bucket = _index[bucket].next;
        if ((int)next_bucket < 0) {
#if EMH_HIGH_LOAD
            if (next_bucket != INACTIVE)
                pop_empty(bucket);
#endif
            return bucket;
        }

        //check current bucket_key is in main bucket or not
        const auto kmain = hash_main(bucket);
        if (EMH_UNLIKELY(kmain != bucket))
            return kickout_bucket(kmain, bucket);
        else if (EMH_UNLIKELY(next_bucket != bucket))
            next_bucket = find_last_bucket(next_bucket);

        return _index[next_bucket].next = find_empty_bucket(next_bucket, 2);
    }

    /***
      Different probing techniques usually provide a trade-off between memory locality and avoidance of clustering.
      Since Robin Hood hashing is relatively resilient to clustering (both primary and secondary), linear probing is the most cache friendly alternativeis typically used.

      It's the core algorithm of this hash map with highly optimization/benchmark.
      normally linear probing is inefficient with high load factor, it use a new 3-way linear
      probing strategy to search empty slot. from benchmark even the load factor > 0.9, it's more 2-3 timer fast than
      one-way search strategy.

      1. linear or quadratic probing a few cache line for less cache miss from input slot "bucket_from".
      2. the first  search  slot from member variant "_last", init with 0
      3. the second search slot from calculated pos "(_num_filled + _last) & _mask", it's like a rand value
      */
    // key is not in this mavalue. Find a place to put it.
    size_type find_empty_bucket(const size_type bucket_from, uint32_t csize) noexcept
    {
        (void)csize;
#if EMH_HIGH_LOAD
        if (_ehead)
            return pop_empty(_ehead);
#endif

        auto bucket = bucket_from;
        if (EMH_EMPTY(++bucket) || EMH_EMPTY(++bucket))
            return bucket;

#ifdef EMH_QUADRATIC
        constexpr size_type linear_probe_length = 2 * EMH_CACHE_LINE_SIZE / sizeof(Index);//16
        for (size_type offset = csize + 2, step = 4; offset <= linear_probe_length; ) {
            bucket = (bucket_from + offset) & _mask;
            if (EMH_EMPTY(bucket) || EMH_EMPTY(++bucket))
                return bucket;
            offset += step; //7/8. 12. 16
        }
#else
        constexpr size_type quadratic_probe_length = 6u;
        for (size_type offset = 4u, step = 3u; step < quadratic_probe_length; ) {
            bucket = (bucket_from + offset) & _mask;
            if (EMH_EMPTY(bucket) || EMH_EMPTY(++bucket))
                return bucket;
            offset += step++;
        }
#endif

#if EMH_PREFETCH
        __builtin_prefetch(static_cast<const void*>(_index + _last + 1), 0, EMH_PREFETCH);
#endif

        for (;;) {
#if EMH_PACK_TAIL
            //find empty bucket and skip next
            if (EMH_EMPTY(_last++))// || EMH_EMPTY(_last++))
                return _last++ - 1;

            if (EMH_UNLIKELY(_last >= _num_buckets))
                _last = 0;

            auto medium = (_mask / 4 + _last++) & _mask;
            if (EMH_EMPTY(medium))
                return medium;
#else
            _last &= _mask;
            if (EMH_EMPTY(++_last))// || EMH_EMPTY(++_last))
                return _last;

            auto medium = (_num_buckets / 2 + _last) & _mask;
            if (EMH_EMPTY(medium))// || EMH_EMPTY(++medium))
                return medium;
#endif
        }

    }

    size_type find_last_bucket(size_type main_bucket) const
    {
        auto next_bucket = _index[main_bucket].next;
        if (next_bucket == main_bucket)
            return main_bucket;

        while (true) {
            const auto nbucket = _index[next_bucket].next;
            if (nbucket == next_bucket)
                return next_bucket;
            next_bucket = nbucket;
        }
    }

    size_type find_prev_bucket(const size_type main_bucket, const size_type bucket) const
    {
        auto next_bucket = _index[main_bucket].next;
        if (next_bucket == bucket)
            return main_bucket;

        while (true) {
            const auto nbucket = _index[next_bucket].next;
            if (nbucket == bucket)
                return next_bucket;
            next_bucket = nbucket;
        }
    }

    size_type hash_bucket(const KeyT& key) const noexcept
    {
        return (size_type)hash_key(key) & _mask;
    }

    size_type hash_main(const size_type bucket) const noexcept
    {
        const auto slot = _index[bucket].slot & _mask;
        return (size_type)hash_key(_pairs[slot].first) & _mask;
    }

#if EMH_INT_HASH
    static constexpr uint64_t KC = UINT64_C(11400714819323198485);
    static uint64_t hash64(uint64_t key)
    {
#if __SIZEOF_INT128__ && EMH_INT_HASH == 1
        __uint128_t r = key; r *= KC;
        return (uint64_t)(r >> 64) + (uint64_t)r;
#elif EMH_INT_HASH == 2
        //MurmurHash3Mixer
        uint64_t h = key;
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccd;
        h ^= h >> 33;
        h *= 0xc4ceb9fe1a85ec53;
        h ^= h >> 33;
        return h;
#elif _WIN64 && EMH_INT_HASH == 1
        uint64_t high;
        return _umul128(key, KC, &high) + high;
#elif EMH_INT_HASH == 3
        auto ror  = (key >> 32) | (key << 32);
        auto low  = key * 0xA24BAED4963EE407ull;
        auto high = ror * 0x9FB21C651E98DF25ull;
        auto mix  = low + high;
        return mix;
#elif EMH_INT_HASH == 1
        uint64_t r = key * UINT64_C(0xca4bcaa75ec3f625);
        return (r >> 32) + r;
#elif EMH_WYHASH64
        return wyhash64(key, KC);
#else
        uint64_t x = key;
        x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
        x = x ^ (x >> 31);
        return x;
#endif
    }
#endif

#if EMH_WYHASH_HASH
    //#define WYHASH_CONDOM 1
    static uint64_t wymix(uint64_t A, uint64_t B)
    {
#if defined(__SIZEOF_INT128__)
        __uint128_t r = A; r *= B;
#if WYHASH_CONDOM2
        A ^= (uint64_t)r; B ^= (uint64_t)(r >> 64);
#else
        A = (uint64_t)r; B = (uint64_t)(r >> 64);
#endif

#elif defined(_MSC_VER) && defined(_M_X64)
#if WYHASH_CONDOM2
        uint64_t a, b;
        a = _umul128(A, B, &b);
        A ^= a; B ^= b;
#else
        A = _umul128(A, B, &B);
#endif
#else
        uint64_t ha = A >> 32, hb = B >> 32, la = (uint32_t)A, lb = (uint32_t)B, hi, lo;
        uint64_t rh = ha * hb, rm0 = ha * lb, rm1 = hb * la, rl = la * lb, t = rl + (rm0 << 32), c = t < rl;
        lo = t + (rm1 << 32); c += lo < t; hi = rh + (rm0 >> 32) + (rm1 >> 32) + c;
#if WYHASH_CONDOM2
        A ^= lo; B ^= hi;
#else
        A = lo; B = hi;
#endif
#endif
        return A ^ B;
    }

    //multiply and xor mix function, aka MUM
    static inline uint64_t wyr8(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
    static inline uint64_t wyr4(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
    static inline uint64_t wyr3(const uint8_t *p, size_t k) {
        return (((uint64_t)p[0]) << 16) | (((uint64_t)p[k >> 1]) << 8) | p[k - 1];
    }

    inline static const uint64_t secret[4] = {
        0x2d358dccaa6c78a5ull, 0x8bb84b93962eacc9ull,
        0x4b33a62ed433d4a3ull, 0x4d5a2da51de1aa47ull};
public:
    //wyhash main function https://github.com/wangyi-fudan/wyhash
    static uint64_t wyhashstr(const char *key, const size_t len)
    {
        uint64_t a = 0, b = 0, seed = secret[0];
        const uint8_t *p = (const uint8_t*)key;
        if (EMH_LIKELY(len <= 16)) {
            if (EMH_LIKELY(len >= 4)) {
                const auto half = (len >> 3) << 2;
                a = (wyr4(p) << 32U) | wyr4(p + half); p += len - 4;
                b = (wyr4(p) << 32U) | wyr4(p - half);
            } else if (len) {
                a = wyr3(p, len);
            }
        } else {
            size_t i = len;
            if (EMH_UNLIKELY(i > 48)) {
                uint64_t see1 = seed, see2 = seed;
                do {
                    seed = wymix(wyr8(p +  0) ^ secret[1], wyr8(p +  8) ^ seed);
                    see1 = wymix(wyr8(p + 16) ^ secret[2], wyr8(p + 24) ^ see1);
                    see2 = wymix(wyr8(p + 32) ^ secret[3], wyr8(p + 40) ^ see2);
                    p += 48; i -= 48;
                } while (EMH_LIKELY(i > 48));
                seed ^= see1 ^ see2;
            }
            while (i > 16) {
                seed = wymix(wyr8(p) ^ secret[1], wyr8(p + 8) ^ seed);
                i -= 16; p += 16;
            }
            a = wyr8(p + i - 16);
            b = wyr8(p + i - 8);
        }

        return wymix(secret[1] ^ len, wymix(a ^ secret[1], b ^ seed));
    }
#endif

private:
    template<typename UType, typename std::enable_if<std::is_integral<UType>::value, uint32_t>::type = 0>
        inline uint64_t hash_key(const UType key) const
        {
#if EMH_INT_HASH
            return hash64(key);
#elif EMH_IDENTITY_HASH
            return key + (key >> 24);
#else
            return _hasher(key);
#endif
        }

    template<typename UType, typename std::enable_if<std::is_same<UType, std::string>::value, uint32_t>::type = 0>
        inline uint64_t hash_key(const UType& key) const
        {
#if EMH_WYHASH_HASH
            return wyhashstr(key.data(), key.size());
#else
            return _hasher(key);
#endif
        }

    template<typename UType, typename std::enable_if<!std::is_integral<UType>::value && !std::is_same<UType, std::string>::value, uint32_t>::type = 0>
        inline uint64_t hash_key(const UType& key) const
        {
            return _hasher(key);
        }

private:
    Index*    _index;
    value_type*_pairs;

    HashT     _hasher;
    EqT       _eq;
    uint32_t  _mlf;
    size_type _mask;
    size_type _num_buckets;
    size_type _num_filled;
    size_type _last;
#if EMH_HIGH_LOAD
    size_type _ehead;
#endif
    size_type _etail;
};
} // namespace emhash