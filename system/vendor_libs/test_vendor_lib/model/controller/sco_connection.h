/*
 * Copyright 2021 The Android Open Source Project
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

#include <cstdint>
#include <optional>

#include "hci/address.h"

namespace test_vendor_lib {

using ::bluetooth::hci::Address;

/*
 * Notes about SCO / eSCO connection establishment:
 *
 * - Connections will always be established as eSCO connections. The LMP
 * parameter negotiation is skipped, instead the required parameters
 * are directly sent to the peer.
 *
 * - If the parameters are compatible with the values returned from
 * HCI Accept Synchronous Connection Request on the peer,
 * the peer selects a valid link configuration which it returns
 * in response.
 */

struct ScoLinkParameters {
  uint8_t transmission_interval;
  uint8_t retransmission_window;
  uint16_t rx_packet_length;
  uint16_t tx_packet_length;
  uint8_t air_mode;
};

struct ScoConnectionParameters {
  uint32_t transmit_bandwidth;
  uint32_t receive_bandwidth;
  uint16_t max_latency; // 0-3 reserved, 0xFFFF = don't care
  uint16_t voice_setting;
  uint8_t retransmission_effort;
  uint16_t packet_type;

  // Return the link parameters for these connection parameters, if the
  // parameters are coherent, none otherwise.
  std::optional<ScoLinkParameters> GetLinkParameters();
};

class ScoConnection {
 public:
  ScoConnection(Address address, ScoConnectionParameters const &parameters)
    : address_(address), parameters_(parameters), link_parameters_() {}

  virtual ~ScoConnection() = default;

  Address GetAddress() const { return address_; }

  ScoConnectionParameters GetConnectionParameters() const {
    return parameters_;
  }
  ScoLinkParameters GetLinkParameters() const {
    return link_parameters_;
  }
  void SetLinkParameters(ScoLinkParameters const &parameters) {
    link_parameters_ = parameters;
  }

  // Negotiate the connection parameters.
  // Update the local connection parameters with negotiated values.
  // Return true if the negotiation was successful, false otherwise.
  bool NegotiateLinkParameters(ScoConnectionParameters const &peer);

 private:
  Address address_;
  ScoConnectionParameters parameters_;
  ScoLinkParameters link_parameters_;
};

}  // namespace test_vendor_lib
