// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This library defines the concepts "fuzzing feature" and "feature domain".
// It is used by Centipede, and it can be used by fuzz runners to
// define their features in a way most friendly to Centipede.
// Fuzz runners do not have to use this file nor to obey the rules defined here.
// But using this file and following its rules is the simplest way if you want
// Centipede to understand the details about the features generated by the
// runner.
//
// This library must not depend on anything other than libc so that fuzz targets
// using it doesn't gain redundant coverage. For the same reason this library
// uses raw __builtin_trap instead of CHECKs.
// We make an exception for <algorithm> for std::sort/std::unique,
// since <algorithm> is very lightweight.
// This library is also header-only, with all functions defined as inline.

#ifndef THIRD_PARTY_CENTIPEDE_CONCURRENT_BITSET_H_
#define THIRD_PARTY_CENTIPEDE_CONCURRENT_BITSET_H_

#include <stddef.h>
#include <string.h>

// WARNING!!!: Be very careful with what STL headers or other dependencies you
// add here. This header needs to remain mostly bare-bones so that we can
// include it into runner.
#include <cstdint>
#include <limits>
#include <memory>

namespace centipede {

// A fixed-size bitset with a lossy concurrent set() function.
// kSize must be a multiple of 512 - this allows the implementation
// to use any word size up to 64 bytes.
template <size_t kSizeInBits>
class ConcurrentBitSet {
 public:
  static_assert((kSizeInBits % 512) == 0);

  // Constructs an empty bit set.
  ConcurrentBitSet() = default;

  // Clears the bit set.
  void clear() { memset(words_, 0, sizeof(words_)); }

  // Sets the bit `idx % kSizeInBits`.
  // set() can be called concurrently with another set().
  // If several threads race to update adjacent bits,
  // the update may be lost (i.e. set() is lossy).
  // We could use atomic set-bit instructions to make it non-lossy,
  // but it is going to be too expensive.
  void set(size_t idx) {
    idx %= kSizeInBits;
    size_t word_idx = idx / kBitsInWord;
    size_t bit_idx = idx % kBitsInWord;
    word_t mask = 1ULL << bit_idx;
    word_t word = __atomic_load_n(&words_[word_idx], __ATOMIC_RELAXED);
    if (!(word & mask)) {
      word |= mask;
      __atomic_store_n(&words_[word_idx], word, __ATOMIC_RELAXED);
    }
  }

  // Calls `action(index)` for every index of a non-zero bit in the set.
  template <typename Action>
  __attribute__((noinline)) void ForEachNonZeroBit(Action action) {
    for (size_t word_idx = 0; word_idx < kSizeInWords; word_idx++) {
      if (word_t word = words_[word_idx]) {
        do {
          size_t bit_idx = __builtin_ctzll(word);
          action(word_idx * kBitsInWord + bit_idx);
          word_t mask = 1ULL << bit_idx;
          word &= ~mask;
        } while (word);
      }
    }
  }

 private:
  using word_t = uintptr_t;
  static const size_t kBitsInWord = 8 * sizeof(word_t);
  static const size_t kSizeInWords = kSizeInBits / kBitsInWord;
  word_t words_[kSizeInWords] = {};
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_CONCURRENT_BITSET_H_
