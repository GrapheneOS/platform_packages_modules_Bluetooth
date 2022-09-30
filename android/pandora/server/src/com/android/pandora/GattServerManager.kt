/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.pandora

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.content.Context
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map

class GattServerManager(bluetoothManager: BluetoothManager, context: Context, globalScope: CoroutineScope) {
  val services = mutableMapOf<UUID, BluetoothGattService>()
  val server: BluetoothGattServer

  val newServiceFlow = MutableSharedFlow<BluetoothGattService>(extraBufferCapacity = 8)

  init {
    newServiceFlow.map {
      services[it.uuid] = it
    }.launchIn(globalScope)
  }

  init {
    val callback =
      object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
          check(status == BluetoothGatt.GATT_SUCCESS)
          check(newServiceFlow.tryEmit(service))
        }
      }
    server = bluetoothManager.openGattServer(context, callback)
  }
}
