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

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.util.Log

import com.google.protobuf.Empty
import com.google.protobuf.ByteString
import io.grpc.stub.StreamObserver

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.launch

import pandora.SMGrpc.SMImplBase
import pandora.HostProto.*
import pandora.SmProto.*

@kotlinx.coroutines.ExperimentalCoroutinesApi
class Sm(private val context: Context) : SMImplBase() {
  private val TAG = "PandoraSm"

  private val scope: CoroutineScope
  private val flow: Flow<Intent>

  private val bluetoothManager = context.getSystemService(BluetoothManager::class.java)!!
  private val bluetoothAdapter = bluetoothManager.adapter

  init {
    scope = CoroutineScope(Dispatchers.Default)

    val intentFilter = IntentFilter()
    intentFilter.addAction(BluetoothDevice.ACTION_PAIRING_REQUEST)

    flow = intentFlow(context, intentFilter).shareIn(scope, SharingStarted.Eagerly)
  }

  fun deinit() {
    scope.cancel()
  }

  override fun pair(request: PairRequest, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
      val bluetoothDevice = request.connection.toBluetoothDevice(bluetoothAdapter)
      Log.i(TAG, "pair: ${bluetoothDevice.getAddress()}")
      bluetoothDevice.createBond()
      Empty.getDefaultInstance()
    }
  }

  override fun providePairingConfirmation(
      request: PairingConfirmationRequest,
      responseObserver: StreamObserver<Empty>
  ) {
    grpcUnary<Empty>(scope, responseObserver) {
      val bluetoothDevice = request.connection.toBluetoothDevice(bluetoothAdapter)
      Log.i(TAG, "Confirm pairing for: address=${bluetoothDevice.getAddress()}")
      flow
        .filter { it.getAction() == BluetoothDevice.ACTION_PAIRING_REQUEST }
        .filter { it.getBluetoothDeviceExtra() == bluetoothDevice }
        .first()
      bluetoothDevice.setPairingConfirmation(request.pairingConfirmationValue)
      Empty.getDefaultInstance()
    }
  }
}
