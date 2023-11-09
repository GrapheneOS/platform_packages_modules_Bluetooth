/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

#include "hci/octets.h"

namespace bluetooth {
namespace crypto_toolbox {

hci::Octet16 c1(
    const hci::Octet16& k,
    const hci::Octet16& r,
    const uint8_t* pres,
    const uint8_t* preq,
    const uint8_t iat,
    const uint8_t* ia,
    const uint8_t rat,
    const uint8_t* ra);
hci::Octet16 s1(const hci::Octet16& k, const hci::Octet16& r1, const hci::Octet16& r2);

hci::Octet16 aes_128(const hci::Octet16& key, const hci::Octet16& message);
hci::Octet16 aes_cmac(const hci::Octet16& key, const uint8_t* message, uint16_t length);
hci::Octet16 f4(uint8_t* u, uint8_t* v, const hci::Octet16& x, uint8_t z);
void f5(
    uint8_t* w,
    const hci::Octet16& n1,
    const hci::Octet16& n2,
    uint8_t* a1,
    uint8_t* a2,
    hci::Octet16* mac_key,
    hci::Octet16* ltk);
hci::Octet16 f6(
    const hci::Octet16& w,
    const hci::Octet16& n1,
    const hci::Octet16& n2,
    const hci::Octet16& r,
    uint8_t* iocap,
    uint8_t* a1,
    uint8_t* a2);
hci::Octet16 h6(const hci::Octet16& w, std::array<uint8_t, 4> keyid);
hci::Octet16 h7(const hci::Octet16& salt, const hci::Octet16& w);
uint32_t g2(uint8_t* u, uint8_t* v, const hci::Octet16& x, const hci::Octet16& y);
hci::Octet16 ltk_to_link_key(const hci::Octet16& ltk, bool use_h7);
hci::Octet16 link_key_to_ltk(const hci::Octet16& link_key, bool use_h7);

/* This function computes AES_128(key, message). |key| must be 128bit.
 * |message| can be at most 16 bytes long, it's length in bytes is given in
 * |length| */
inline hci::Octet16 aes_128(const hci::Octet16& key, const uint8_t* message, const uint8_t length) {
  // CHECK(length <= OCTET16_LEN) << "you tried aes_128 more than 16 bytes!";
  hci::Octet16 msg{0};
  std::copy(message, message + length, msg.begin());
  return aes_128(key, msg);
}

// |tlen| - lenth of mac desired
// |p_signature| - data pointer to where signed data to be stored, tlen long.
inline void aes_cmac(
    const hci::Octet16& key,
    const uint8_t* message,
    uint16_t length,
    uint16_t tlen,
    uint8_t* p_signature) {
  hci::Octet16 signature = aes_cmac(key, message, length);

  uint8_t* p_mac = signature.data() + (hci::kOctet16Length - tlen);
  memcpy(p_signature, p_mac, tlen);
}

inline hci::Octet16 aes_cmac(const hci::Octet16& key, const hci::Octet16& message) {
  return aes_cmac(key, message.data(), message.size());
}

}  // namespace crypto_toolbox
}  // namespace bluetooth
