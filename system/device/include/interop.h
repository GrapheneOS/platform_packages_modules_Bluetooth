/******************************************************************************
 *
 *  Copyright (C) 2015 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#pragma once

#include <stdbool.h>

#include "btcore/include/bdaddr.h"

typedef enum {
  // Disable secure connections
  // This is for pre BT 4.1/2 devices that do not handle secure mode
  // very well.
  INTEROP_DISABLE_LE_SECURE_CONNECTIONS,

  // Some devices have proven problematic during the pairing process, often
  // requiring multiple retries to complete pairing. To avoid degrading the user
  // experience for those devices, automatically re-try pairing if page
  // timeouts are received during pairing.
  INTEROP_AUTO_RETRY_PAIRING,

  // Some headsets have audio jitter issues because of increased re-transmissions as the
  // 3 Mbps packets have a lower link margin, and are more prone to interference. We can
  // disable 3DH packets (use only 2DH packets) for the ACL link to improve sensitivity
  // when streaming A2DP audio to the headset. Air sniffer logs show reduced
  // re-transmissions after switching to 2DH packets.
  //
  // Disable 3Mbps packets and use only 2Mbps packets for ACL links when streaming audio.
  INTEROP_2MBPS_LINK_ONLY
} interop_feature_t;

// Check if a given |addr| matches a known interoperability workaround as identified
// by the |interop_feature_t| enum. This API is used for simple address based lookups
// where more information is not available. No look-ups or random address resolution
// is performed on |addr|.
bool interop_match(const interop_feature_t feature, const bt_bdaddr_t *addr);
