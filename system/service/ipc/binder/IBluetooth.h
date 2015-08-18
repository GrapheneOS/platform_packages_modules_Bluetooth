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

// This class defines the Binder IPC interface for accessing the Bluetooth
// service. This class was written based on the corresponding AIDL file at
// /frameworks/base/core/java/android/bluetooth/IBluetooth.aidl.
class IBluetooth : public android::IInterface {
 public:
  DECLARE_META_INTERFACE(Bluetooth);

  static const char kBluetoothServiceName[];

  // Transaction codes for interface methods.
  enum {
    IS_ENABLED_TRANSACTION = android::IBinder::FIRST_CALL_TRANSACTION,
    GET_STATE_TRANSACTION,
    ENABLE_TRANSACTION,
    ENABLE_NO_AUTO_CONNECT_TRANSACTION,
    DISABLE_TRANSACTION,
  };

  // Returns a handle to the IBluetooth Binder from the Android ServiceManager.
  // Binder client code can use this to make calls to the service.
  static android::sp<IBluetooth> getClientInterface();

  virtual bool IsEnabled() = 0;
  virtual int GetState() = 0;
  virtual bool Enable() = 0;
  virtual bool EnableNoAutoConnect() = 0;
  virtual bool Disable() = 0;

  // TODO(armansito): Complete the API definition.
 private:
  DISALLOW_COPY_AND_ASSIGN(IBluetooth);
};

// TODO(armansito): Implement notification for when the process dies.

// The Binder server interface to IBluetooth. A class that implements IBluetooth
// must inherit from this class.
class BnBluetooth : public android::BnInterface<IBluetooth> {
 public:
  BnBluetooth() = default;
  virtual ~BnBluetooth() = default;

 private:
  virtual android::status_t onTransact(
      uint32_t code,
      const android::Parcel& data,
      android::Parcel* reply,
      uint32_t flags = 0);
};

// The Binder client interface to IBluetooth.
class BpBluetooth : public android::BpInterface<IBluetooth> {
 public:
  BpBluetooth(const android::sp<android::IBinder>& impl);
  virtual ~BpBluetooth() = default;

  // IBluetooth overrides:
  bool IsEnabled() override;
  int GetState() override;
  bool Enable() override;
  bool EnableNoAutoConnect() override;
  bool Disable() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(BpBluetooth);
};

}  // namespace binder
}  // namespace ipc
