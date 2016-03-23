/*
 * Copyright (C) 2016 The Android Open Source Project
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

package android.bluetooth;

import android.bluetooth.IBluetoothGattServerCallback;

import android.bluetooth.GattIdentifier;
import android.bluetooth.UUID;

interface IBluetoothGattServer {

  boolean RegisterServer(in IBluetoothGattServerCallback callback);
  void UnregisterServer(int server_id);
  void UnregisterAll();

  boolean BeginServiceDeclaration(
      int server_id, boolean is_primary, in UUID uuid,
      out GattIdentifier id);
  boolean AddCharacteristic(
      int server_id, in UUID uuid,
      int properties, int permissions,
      out GattIdentifier id);
  boolean AddDescriptor(
      int server_id, in UUID uuid, int permissions,
      out GattIdentifier id);
  boolean EndServiceDeclaration(int server_id);

  boolean SendResponse(
      int server_id,
      String device_address,
      int request_id,
      int status, int offset,
      in byte[] value);

  boolean SendNotification(
      int server_id,
      String device_address,
      in GattIdentifier characteristic_id,
      boolean confirm,
      in byte[] value);
}