/*
 * Copyright 2022 The Android Open Source Project
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

#include "acl_scheduler.h"

#include <queue>
#include <unordered_set>

namespace bluetooth {
namespace hci {

namespace acl_manager {

struct AclCreateConnectionQueueEntry {
  Address address;
  common::ContextualOnceCallback<void()> callback;
};

struct AclScheduler::impl {
  void EnqueueOutgoingAclConnection(Address address, common::ContextualOnceCallback<void()> start_connection) {
    pending_outgoing_connections_.push({address, std::move(start_connection)});
    try_dequeue_next_connection();
  }

  void RegisterPendingIncomingConnection(Address address) {
    incoming_connecting_address_set_.insert(address);
  }

  void ReportAclConnectionCompletion(
      Address address,
      common::ContextualOnceCallback<void()> handle_outgoing_connection,
      common::ContextualOnceCallback<void()> handle_incoming_connection,
      common::ContextualOnceCallback<void(std::string)> handle_unknown_connection) {
    if (outgoing_connecting_address_ == address) {
      outgoing_connecting_address_ = Address::kEmpty;
      handle_outgoing_connection.InvokeIfNotEmpty();
    } else if (incoming_connecting_address_set_.find(address) != incoming_connecting_address_set_.end()) {
      incoming_connecting_address_set_.erase(address);
      handle_incoming_connection.InvokeIfNotEmpty();
    } else {
      handle_unknown_connection.InvokeIfNotEmpty(set_of_incoming_connecting_addresses());
    }
    try_dequeue_next_connection();
  }

  void ReportOutgoingAclConnectionFailure() {
    if (outgoing_connecting_address_ == Address::kEmpty) {
      LOG_ERROR("Outgoing connection failure reported, but none present!");
      return;
    }
    outgoing_connecting_address_ = Address::kEmpty;
    try_dequeue_next_connection();
  }

  void CancelAclConnection(
      Address address,
      common::ContextualOnceCallback<void()> cancel_connection,
      common::ContextualOnceCallback<void()> cancel_connection_completed) {
    cancel_connection.Invoke();
  }

  void Stop() {
    stopped_ = true;
  }

 private:
  void try_dequeue_next_connection() {
    if (stopped_) {
      return;
    }
    if (incoming_connecting_address_set_.empty() && outgoing_connecting_address_.IsEmpty() &&
        !pending_outgoing_connections_.empty()) {
      LOG_INFO("Pending connections is not empty; so sending next connection");
      auto entry = std::move(pending_outgoing_connections_.front());
      pending_outgoing_connections_.pop();
      outgoing_connecting_address_ = entry.address;
      entry.callback.Invoke();
    }
  }

  const std::string set_of_incoming_connecting_addresses() const {
    std::stringstream buffer;
    for (const auto& c : incoming_connecting_address_set_) buffer << " " << c;
    return buffer.str();
  }

  Address outgoing_connecting_address_;
  std::queue<AclCreateConnectionQueueEntry> pending_outgoing_connections_;
  std::unordered_set<Address> incoming_connecting_address_set_;
  bool stopped_ = false;
};

AclScheduler::AclScheduler() : pimpl_(std::make_unique<impl>()){};
AclScheduler::~AclScheduler() = default;

void AclScheduler::EnqueueOutgoingAclConnection(
    Address address, common::ContextualOnceCallback<void()> start_connection) {
  pimpl_->EnqueueOutgoingAclConnection(address, std::move(start_connection));
}

void AclScheduler::RegisterPendingIncomingConnection(Address address) {
  pimpl_->RegisterPendingIncomingConnection(address);
}

void AclScheduler::ReportAclConnectionCompletion(
    Address address,
    common::ContextualOnceCallback<void()> handle_outgoing_connection,
    common::ContextualOnceCallback<void()> handle_incoming_connection,
    common::ContextualOnceCallback<void(std::string)> handle_unknown_connection) {
  pimpl_->ReportAclConnectionCompletion(
      address,
      std::move(handle_outgoing_connection),
      std::move(handle_incoming_connection),
      std::move(handle_unknown_connection));
}

void AclScheduler::ReportOutgoingAclConnectionFailure() {
  pimpl_->ReportOutgoingAclConnectionFailure();
}

void AclScheduler::CancelAclConnection(
    Address address,
    common::ContextualOnceCallback<void()> cancel_connection,
    common::ContextualOnceCallback<void()> cancel_connection_completed) {
  pimpl_->CancelAclConnection(address, std::move(cancel_connection), std::move(cancel_connection_completed));
}

void AclScheduler::Stop() {
  pimpl_->Stop();
}

}  // namespace acl_manager
}  // namespace hci
}  // namespace bluetooth