//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#pragma once

#include <base/macros.h>
#include <binder/IBinder.h>
#include <binder/IInterface.h>

namespace ipc {
namespace binder {

// This class defines the Binder IPC interface for receiving callbacks related
// to Bluetooth GATT server-role operations.
// TODO(armansito): This class was written based on a new design doc proposal.
// We need to add an AIDL for this to the framework code.
//
// NOTE: KEEP THIS FILE UP-TO-DATE with the corresponding AIDL, otherwise this
// won't be compatible with the Android framework.
/* oneway */ class IBluetoothGattServerCallback : public android::IInterface {
 public:
  DECLARE_META_INTERFACE(BluetoothGattServerCallback);

  static const char kServiceName[];

  // Transaction codes for interface methods.
  enum {
    ON_SERVER_REGISTERED_TRANSACTION = android::IBinder::FIRST_CALL_TRANSACTION,
    ON_SERVICE_ADDED_TRANSACTION,
    ON_CHARACTERISTIC_READ_REQUEST_TRANSACTION,
    ON_DESCRIPTOR_READ_REQUEST_TRANSACTION,
    ON_CHARACTERISTIC_WRITE_REQUEST_TRANSACTION,
    ON_DESCRIPTOR_WRITE_REQUEST_TRANSACTION,
    ON_EXECUTE_WRITE_TRANSACTION,
    ON_NOTIFICATION_SENT_TRANSACTION,
  };

  virtual void OnServerRegistered(int status, int server_if) = 0;

  // TODO(armansito): Complete the API definition.

 private:
  DISALLOW_COPY_AND_ASSIGN(IBluetoothGattServerCallback);
};

// The Binder server interface to IBluetoothGattServerCallback. A class that
// implements IBluetoothGattServerCallback must inherit from this class.
class BnBluetoothGattServerCallback
    : public android::BnInterface<IBluetoothGattServerCallback> {
 public:
  BnBluetoothGattServerCallback() = default;
  virtual ~BnBluetoothGattServerCallback() = default;

 private:
  virtual android::status_t onTransact(
      uint32_t code,
      const android::Parcel& data,
      android::Parcel* reply,
      uint32_t flags = 0);

  DISALLOW_COPY_AND_ASSIGN(BnBluetoothGattServerCallback);
};

// The Binder client interface to IBluetoothGattServerCallback.
class BpBluetoothGattServerCallback
    : public android::BpInterface<IBluetoothGattServerCallback> {
 public:
  explicit BpBluetoothGattServerCallback(
      const android::sp<android::IBinder>& impl);
  virtual ~BpBluetoothGattServerCallback() = default;

  // IBluetoothGattServerCallback overrides:
  void OnServerRegistered(int status, int server_if) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(BpBluetoothGattServerCallback);
};

}  // namespace binder
}  // namespace ipc
