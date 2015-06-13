// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/string_number_conversions.h"

#include <stdlib.h>

#include <limits>

namespace base {

// Utility to convert a character to a digit in a given base
template<typename CHAR, int BASE, bool BASE_LTE_10> class BaseCharToDigit {
};

// Faster specialization for bases <= 10
template<typename CHAR, int BASE> class BaseCharToDigit<CHAR, BASE, true> {
 public:
  static bool Convert(CHAR c, uint8_t* digit) {
    if (c >= '0' && c < '0' + BASE) {
      *digit = static_cast<uint8_t>(c - '0');
      return true;
    }
    return false;
  }
};

// Specialization for bases where 10 < base <= 36
template<typename CHAR, int BASE> class BaseCharToDigit<CHAR, BASE, false> {
 public:
  static bool Convert(CHAR c, uint8_t* digit) {
    if (c >= '0' && c <= '9') {
      *digit = c - '0';
    } else if (c >= 'a' && c < 'a' + BASE - 10) {
      *digit = c - 'a' + 10;
    } else if (c >= 'A' && c < 'A' + BASE - 10) {
      *digit = c - 'A' + 10;
    } else {
      return false;
    }
    return true;
  }
};

template<int BASE, typename CHAR> bool CharToDigit(CHAR c, uint8_t* digit) {
  return BaseCharToDigit<CHAR, BASE, BASE <= 10>::Convert(c, digit);
}

template<typename STR>
bool HexStringToBytesT(const STR& input, std::vector<uint8_t>* output) {
  output->clear();
  size_t count = input.size();
  if (count == 0 || (count % 2) != 0)
    return false;
  for (uintptr_t i = 0; i < count / 2; ++i) {
    uint8_t msb = 0;  // most significant 4 bits
    uint8_t lsb = 0;  // least significant 4 bits
    if (!CharToDigit<16>(input[i * 2], &msb) ||
        !CharToDigit<16>(input[i * 2 + 1], &lsb))
      return false;
    output->push_back((msb << 4) | lsb);
  }
  return true;
}


std::string HexEncode(const void* bytes, size_t size) {
  static const char kHexChars[] = "0123456789ABCDEF";

  // Each input byte creates two output hex characters.
  std::string ret(size * 2, '\0');

  for (size_t i = 0; i < size; ++i) {
    char b = reinterpret_cast<const char*>(bytes)[i];
    ret[(i * 2)] = kHexChars[(b >> 4) & 0xf];
    ret[(i * 2) + 1] = kHexChars[b & 0xf];
  }
  return ret;
}


bool HexStringToBytes(const std::string& input, std::vector<uint8_t>* output) {
  return HexStringToBytesT(input, output);
}

}  // namespace base
