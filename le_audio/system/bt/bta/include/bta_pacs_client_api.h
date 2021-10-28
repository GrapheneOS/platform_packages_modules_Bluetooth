/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2018 The Android Open Source Project
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

#include <string>
#include <hardware/bt_pacs_client.h>

namespace bluetooth {
namespace bap {
namespace pacs {

class PacsClient {
  public:
    virtual ~PacsClient() = default;

    static void Initialize(bluetooth::bap::pacs::PacsClientCallbacks* callbacks);
    static void CleanUp(uint16_t client_id);
    static PacsClient* Get();
    virtual void Connect(uint16_t client_id, const RawAddress& address,
                         bool is_direct) = 0;
    virtual void Disconnect(uint16_t client_id,
                            const RawAddress& address) = 0;
    virtual void StartDiscovery(uint16_t client_id,
                                  const RawAddress& address) = 0;
    virtual void GetAudioAvailability(uint16_t client_id,
                                    const RawAddress& address) = 0;
};

}  // namespace pacs
}  // namespace bap
}  // namespace bluetooth
