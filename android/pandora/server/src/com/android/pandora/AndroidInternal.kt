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

import android.util.Log
import android.content.Context
import com.google.protobuf.Empty
import io.grpc.stub.StreamObserver
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import pandora.AndroidGrpc.AndroidImplBase
import pandora.AndroidProto.*

private const val TAG = "PandoraAndroidInternal"

@kotlinx.coroutines.ExperimentalCoroutinesApi
class AndroidInternal(context: Context) : AndroidImplBase() {

  private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default)
  private val bluetoothManager = context.getSystemService(BluetoothManager::class.java)!!
  private val bluetoothAdapter = bluetoothManager.adapter

  fun deinit() {
    scope.cancel()
  }

  override fun log(request: LogRequest, responseObserver: StreamObserver<LogResponse>) {
    grpcUnary(scope, responseObserver) {
      Log.i(TAG, request.text)
      LogResponse.getDefaultInstance()
    }
  }

  override fun setAccessPermission(request: SetAccessPermissionRequest, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
      val bluetoothDevice = request.address.toBluetoothDevice(bluetoothAdapter)
      when (request.accessType!!) {
        AccessType.ACCESS_MESSAGE -> bluetoothDevice.setMessageAccessPermission(BluetoothDevice.ACCESS_ALLOWED)
        AccessType.ACCESS_PHONEBOOK -> bluetoothDevice.setPhonebookAccessPermission(BluetoothDevice.ACCESS_ALLOWED)
        AccessType.ACCESS_SIM -> bluetoothDevice.setSimAccessPermission(BluetoothDevice.ACCESS_ALLOWED)
        else -> {}
      }
      Empty.getDefaultInstance()
    }
  }
}
