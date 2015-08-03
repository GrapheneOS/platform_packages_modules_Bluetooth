//
// Copyright 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#define LOG_TAG "packet_stream"

#include "vendor_libs/test_vendor_lib/include/packet_stream.h"

extern "C" {
#include "osi/include/log.h"

#include <errno.h>
#include <unistd.h>
}  // extern "C"

namespace test_vendor_lib {

PacketStream::PacketStream() : fd_(-1) {}

PacketStream::~PacketStream() {
  close(fd_);
}

std::unique_ptr<CommandPacket> PacketStream::ReceiveCommand() {
  std::vector<uint8_t> header;
  if (!ReceiveData(header, CommandPacket::kCommandHeaderSize)) {
    LOG_ERROR(LOG_TAG, "Error: receiving command header.");
    return std::unique_ptr<CommandPacket>(nullptr);
  }
  std::vector<uint8_t> payload;
  if (!ReceiveData(payload, header.back())) {
    LOG_ERROR(LOG_TAG, "Error: receiving command payload.");
    return std::unique_ptr<CommandPacket>(nullptr);
  }
  std::unique_ptr<CommandPacket> command(new CommandPacket());
  if (!command->Encode(header, payload)) {
    LOG_ERROR(LOG_TAG, "Error: encoding command packet.");
    return std::unique_ptr<CommandPacket>(nullptr);
  }
  return command;
}

serial_data_type_t PacketStream::ReceivePacketType() {
  LOG_INFO(LOG_TAG, "Receiving packet type.");

  std::vector<uint8_t> raw_type_octet;
  if (!ReceiveData(raw_type_octet, 1)) {
    // TODO(dennischeng): Proper error handling.
    LOG_ERROR(LOG_TAG, "Error: Could not receive packet type.");
  }

  // Check that the type octet received is in the valid range, i.e. the packet
  // must be a command or data.
  serial_data_type_t type = static_cast<serial_data_type_t>(raw_type_octet[0]);
  if (!ValidateTypeOctet(type)) {
    // TODO(dennischeng): Proper error handling.
    LOG_ERROR(LOG_TAG, "Error: Received invalid packet type.");
  }

  return type;
}

void PacketStream::SendEvent(const EventPacket& event) {
  LOG_INFO(LOG_TAG, "Sending event with event code: 0x%04X",
           event.GetEventCode());
  LOG_INFO(LOG_TAG, "Sending event with size: %zu octets",
           event.GetPacketSize());

  // TODO(dennischeng): Decide if three separate writes is necessary here.
  if (!SendData({event.GetType()}, 1)) {
    // TODO(dennischeng): Proper error handling.
    LOG_ERROR(LOG_TAG, "Error: Could not send event type.");
    return;
  }
  if (!SendData(event.GetHeader(), event.GetHeaderSize())) {
    // TODO(dennischeng): Proper error handling.
    LOG_ERROR(LOG_TAG, "Error: Could not send event header.");
    return;
  }
  if (!SendData(event.GetPayload(), event.GetPayloadSize())) {
    // TODO(dennischeng): Proper error handling.
    LOG_ERROR(LOG_TAG, "Error: Could not send event payload.");
    return;
  }
  LOG_INFO(LOG_TAG, "Event sent.");
}

void PacketStream::SetFd(int fd) {
  if (fd >= 0) {
    fd_ = fd;
  }
}

bool PacketStream::ValidateTypeOctet(serial_data_type_t type) const {
  LOG_INFO(LOG_TAG, "Signal octet is 0x%02X.", type);
  // The only types of packets that should be received from the HCI are command
  // packets and data packets.
  return (type >= DATA_TYPE_COMMAND) && (type <= DATA_TYPE_SCO);
}

bool PacketStream::ReceiveData(std::vector<uint8_t>& buffer,
                              size_t num_octets_to_receive) {
  buffer.resize(num_octets_to_receive);
  size_t octets_remaining = num_octets_to_receive;
  do {
    int num_octets_received = read(
        fd_,
        &buffer[num_octets_to_receive - octets_remaining],
        octets_remaining);
    if (num_octets_received < 0) {
      return false;
    }
    octets_remaining -= num_octets_received;
  } while (octets_remaining > 0);
  return true;
}

bool PacketStream::SendData(const std::vector<uint8_t>& source,
                           size_t num_octets_to_send) {
  // TODO(dennischeng): use CHECK and DCHECK when libbase is imported.
  assert(source.size() >= num_octets_to_send);
  size_t octets_remaining = num_octets_to_send;
  do {
    int num_octets_sent = write(
        fd_, &source[num_octets_to_send - octets_remaining], octets_remaining);
    if (num_octets_sent < 0) {
      return false;
    }
    octets_remaining -= num_octets_sent;
  } while (octets_remaining > 0);
  return true;
}

}  // namespace test_vendor_lib
