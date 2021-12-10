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

#include <vector>

#include <hci/hci_packets.h>
#include <os/log.h>

#include "sco_connection.h"

using namespace test_vendor_lib;
using namespace bluetooth::hci;

std::optional<ScoLinkParameters> ScoConnectionParameters::GetLinkParameters() {
  // Packets HV1, HV2, HV3 are not considered since we are establishing
  // an eSCO connection.
  struct Packet {
    unsigned length;
    unsigned slots;

    Packet(unsigned length, unsigned slots) : length(length), slots(slots) {}
  };

  std::vector<Packet> accepted_packets;
  accepted_packets.push_back(Packet(0, 1)); // POLL/NULL

  if (packet_type & (uint16_t)SynchronousPacketTypeBits::EV3_ALLOWED)
    accepted_packets.push_back(Packet(30, 1));
  if (packet_type & (uint16_t)SynchronousPacketTypeBits::EV4_ALLOWED)
    accepted_packets.push_back(Packet(120, 3));
  if (packet_type & (uint16_t)SynchronousPacketTypeBits::EV5_ALLOWED)
    accepted_packets.push_back(Packet(180, 3));
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_2_EV3_ALLOWED) == 0)
    accepted_packets.push_back(Packet(60, 1));
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_3_EV3_ALLOWED) == 0)
    accepted_packets.push_back(Packet(360, 3));
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_2_EV5_ALLOWED) == 0)
    accepted_packets.push_back(Packet(90, 1));
  if ((packet_type & (uint16_t)SynchronousPacketTypeBits::NO_3_EV5_ALLOWED) == 0)
    accepted_packets.push_back(Packet(540, 3));

  // Ignore empty bandwidths for now.
  if (transmit_bandwidth == 0 || receive_bandwidth == 0) {
    LOG_WARN("eSCO transmissions with null bandwidths are not supported");
    return {};
  }

  // Bandwidth usage of the optimal selection.
  double best_bandwidth_usage = 1.0;
  std::optional<ScoLinkParameters> best_parameters = {};

  // Explore all packet combinations, select the valid one
  // with smallest actual bandwidth usage.
  for (auto tx : accepted_packets) {
    if (tx.length == 0)
      continue;

    unsigned tx_count = (transmit_bandwidth + tx.length - 1) / tx.length;
    unsigned tx_max_interval = 1600 / tx_count;

    for (auto rx : accepted_packets) {
      if (rx.length == 0)
        continue;

      unsigned rx_count = (receive_bandwidth + rx.length - 1) / rx.length;
      unsigned rx_max_interval = 1600 / rx_count;

      // Choose the best interval satisfying both.
      unsigned transmission_interval = std::min(tx_max_interval, rx_max_interval);
      transmission_interval -= transmission_interval % 2;
      transmission_interval = std::min(transmission_interval, 254u);

      // Compute retransmission window.
      unsigned retransmission_window =
        retransmission_effort == (uint8_t)RetransmissionEffort::NO_RETRANSMISSION ? 0 :
        retransmission_effort == (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_POWER ?
            rx.slots + tx.slots :
        retransmission_effort == (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_LINK_QUALITY ?
            rx.slots + tx.slots : 0;

      // Compute transmission window and validate latency.
      unsigned transmission_window = tx.slots + rx.slots +
        retransmission_window;

      // Validate window.
      if (transmission_window > transmission_interval)
        // Oops
        continue;

      // Compute and validate latency.
      unsigned latency = (transmission_window * 1250) / 2;
      if (latency > max_latency)
        // Oops
        continue;

      // We got a valid configuration.
      // Evaluate the actual bandwidth usage.
      double bandwidth_usage =
        (double)transmission_window / (double)transmission_interval;

      if (bandwidth_usage < best_bandwidth_usage) {
        uint16_t tx_packet_length =
            (transmit_bandwidth * transmission_interval + 1600 - 1) / 1600;
        uint16_t rx_packet_length =
            (receive_bandwidth * transmission_interval + 1600 - 1) / 1600;
        uint8_t air_mode = voice_setting & 0x3;

        best_bandwidth_usage = bandwidth_usage;
        best_parameters = {
            (uint8_t)transmission_interval,
            (uint8_t)retransmission_window,
            rx_packet_length, tx_packet_length, air_mode };
      }
    }
  }

  return best_parameters;
}

bool ScoConnection::NegotiateLinkParameters(ScoConnectionParameters const &peer) {

  if (peer.transmit_bandwidth != 0xffff &&
      peer.transmit_bandwidth != parameters_.receive_bandwidth) {
    LOG_WARN("transmit bandwidth requirements cannot be met");
    return false;
  }

  if (peer.receive_bandwidth != 0xffff &&
      peer.receive_bandwidth != parameters_.transmit_bandwidth) {
    LOG_WARN("receive bandwidth requirements cannot be met");
    return false;
  }

  if (peer.voice_setting != parameters_.voice_setting) {
    LOG_WARN("voice setting requirements cannot be met");
    return false;
  }

  uint16_t packet_type = peer.packet_type & parameters_.packet_type & 0x3f;
  packet_type |= ~peer.packet_type & ~parameters_.packet_type & 0x3c0;

  if (packet_type == 0) {
    LOG_WARN("packet type requirements cannot be met");
    return false;
  }

  uint16_t max_latency =
    peer.max_latency == 0xffff ? parameters_.max_latency :
    parameters_.max_latency == 0xffff ? peer.max_latency :
    std::min(peer.max_latency, parameters_.max_latency);

  uint8_t retransmission_effort;
  if (peer.retransmission_effort == parameters_.retransmission_effort ||
      peer.retransmission_effort == (uint8_t)RetransmissionEffort::DO_NOT_CARE)
    retransmission_effort = parameters_.retransmission_effort;
  else if (parameters_.retransmission_effort == (uint8_t)RetransmissionEffort::DO_NOT_CARE)
    retransmission_effort = peer.retransmission_effort;
  else if (peer.retransmission_effort == (uint8_t)RetransmissionEffort::NO_RETRANSMISSION ||
           parameters_.retransmission_effort == (uint8_t)RetransmissionEffort::NO_RETRANSMISSION) {
    LOG_WARN("retransmission effort requirements cannot be met");
    return false;
  } else {
    retransmission_effort = (uint8_t)RetransmissionEffort::OPTIMIZED_FOR_POWER;
  }

  ScoConnectionParameters negotiated_parameters = {
    parameters_.transmit_bandwidth, parameters_.receive_bandwidth,
    max_latency, parameters_.voice_setting, retransmission_effort, packet_type
  };

  auto link_parameters = negotiated_parameters.GetLinkParameters();
  if (link_parameters.has_value())
    link_parameters_ = link_parameters.value();
  return link_parameters.has_value();
}
