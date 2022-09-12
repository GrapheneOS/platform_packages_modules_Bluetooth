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
import android.bluetooth.BluetoothDevice.BOND_BONDED
import android.bluetooth.BluetoothDevice.TRANSPORT_LE
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.MacAddress
import android.util.Log
import com.google.protobuf.ByteString
import com.google.protobuf.Empty
import io.grpc.Status
import io.grpc.stub.StreamObserver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import pandora.HostGrpc.HostImplBase
import pandora.HostProto.*

@kotlinx.coroutines.ExperimentalCoroutinesApi
class Host(private val context: Context, private val server: Server) : HostImplBase() {
  private val TAG = "PandoraHost"

  private val scope: CoroutineScope
  private val flow: Flow<Intent>

  private val bluetoothManager = context.getSystemService(BluetoothManager::class.java)!!
  private val bluetoothAdapter = bluetoothManager.adapter

  init {
    scope = CoroutineScope(Dispatchers.Default)

    // Add all intent actions to be listened.
    val intentFilter = IntentFilter()
    intentFilter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
    intentFilter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
    intentFilter.addAction(BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED)
    intentFilter.addAction(BluetoothDevice.ACTION_PAIRING_REQUEST)

    // Creates a shared flow of intents that can be used in all methods in the coroutine scope.
    // This flow is started eagerly to make sure that the broadcast receiver is registered before
    // any function call. This flow is only cancelled when the corresponding scope is cancelled.
    flow = intentFlow(context, intentFilter).shareIn(scope, SharingStarted.Eagerly)
  }

  fun deinit() {
    scope.cancel()
  }

  private suspend fun rebootBluetooth() {
    Log.i(TAG, "rebootBluetooth")

    val stateFlow =
      flow
        .filter { it.getAction() == BluetoothAdapter.ACTION_STATE_CHANGED }
        .map { it.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR) }

    if (bluetoothAdapter.isEnabled) {
      bluetoothAdapter.disable()
      stateFlow.filter { it == BluetoothAdapter.STATE_OFF }.first()
    }

    // TODO: b/234892968
    delay(2000L)

    bluetoothAdapter.enable()
    stateFlow.filter { it == BluetoothAdapter.STATE_ON }.first()
  }

  override fun hardReset(request: Empty, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
        Log.i(TAG, "hardReset")

        bluetoothAdapter.clearBluetooth()

        rebootBluetooth()

      Log.i(TAG, "Shutdown the gRPC Server")
      server.shutdown()

      // The last expression is the return value.
      Empty.getDefaultInstance()
    }
  }

  override fun softReset(request: Empty, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
      Log.i(TAG, "softReset")

      rebootBluetooth()

      Empty.getDefaultInstance()
    }
  }

  override fun readLocalAddress(
    request: Empty,
    responseObserver: StreamObserver<ReadLocalAddressResponse>
  ) {
    grpcUnary<ReadLocalAddressResponse>(scope, responseObserver) {
      Log.i(TAG, "readLocalAddress")
      val localMacAddress = MacAddress.fromString(bluetoothAdapter.getAddress())
      ReadLocalAddressResponse.newBuilder()
        .setAddress(ByteString.copyFrom(localMacAddress.toByteArray()))
        .build()
    }
  }

  private suspend fun waitPairingRequestIntent(bluetoothDevice: BluetoothDevice) {
    Log.i(TAG, "waitPairingRequestIntent: device=$bluetoothDevice")
    var pairingVariant =
      flow
        .filter { it.getAction() == BluetoothDevice.ACTION_PAIRING_REQUEST }
        .filter { it.getBluetoothDeviceExtra() == bluetoothDevice }
        .first()
        .getIntExtra(BluetoothDevice.EXTRA_PAIRING_VARIANT, BluetoothDevice.ERROR)

    val confirmationCases =
      intArrayOf(
        BluetoothDevice.PAIRING_VARIANT_PASSKEY_CONFIRMATION,
        BluetoothDevice.PAIRING_VARIANT_CONSENT,
        BluetoothDevice.PAIRING_VARIANT_PIN,
      )

    if (pairingVariant in confirmationCases) {
      bluetoothDevice.setPairingConfirmation(true)
    }
  }

  private suspend fun waitConnectionIntent(bluetoothDevice: BluetoothDevice) {
    Log.i(TAG, "waitConnectionIntent: device=$bluetoothDevice")
    flow
      .filter { it.action == BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED }
      .filter { it.getBluetoothDeviceExtra() == bluetoothDevice }
      .map { it.getIntExtra(BluetoothAdapter.EXTRA_CONNECTION_STATE, BluetoothAdapter.ERROR) }
      .filter { it == BluetoothAdapter.STATE_CONNECTED }
      .first()
  }

  private suspend fun waitBondIntent(bluetoothDevice: BluetoothDevice) {
    // We only wait for bonding to be completed since we only need the ACL connection to be
    // established with the peer device (on Android state connected is sent when all profiles
    // have been connected).
    Log.i(TAG, "waitBondIntent: device=$bluetoothDevice")
    flow
      .filter { it.action == BluetoothDevice.ACTION_BOND_STATE_CHANGED }
      .filter { it.getBluetoothDeviceExtra() == bluetoothDevice }
      .map { it.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothAdapter.ERROR) }
      .filter { it == BOND_BONDED }
      .first()
  }

  private suspend fun acceptPairingAndAwaitBonded(bluetoothDevice: BluetoothDevice) {
    val acceptPairingJob = scope.launch { waitPairingRequestIntent(bluetoothDevice) }
    waitBondIntent(bluetoothDevice)
    if (acceptPairingJob.isActive) {
      acceptPairingJob.cancel()
    }
  }

  override fun waitConnection(
    request: WaitConnectionRequest,
    responseObserver: StreamObserver<WaitConnectionResponse>
  ) {
    grpcUnary(scope, responseObserver) {
      val bluetoothDevice = request.address.toBluetoothDevice(bluetoothAdapter)

      Log.i(TAG, "waitConnection: device=$bluetoothDevice")

      if (!bluetoothAdapter.isEnabled) {
        Log.e(TAG, "Bluetooth is not enabled, cannot waitConnection")
        throw Status.UNKNOWN.asException()
      }

      acceptPairingAndAwaitBonded(bluetoothDevice)

      WaitConnectionResponse.newBuilder()
        .setConnection(
          Connection.newBuilder()
            .setCookie(ByteString.copyFromUtf8(bluetoothDevice.address))
            .build()
        )
        .build()
    }
  }

  override fun connect(request: ConnectRequest, responseObserver: StreamObserver<ConnectResponse>) {
    grpcUnary(scope, responseObserver) {
      val bluetoothDevice = request.address.toBluetoothDevice(bluetoothAdapter)

      Log.i(TAG, "connect: address=$bluetoothDevice")

      if (!bluetoothDevice.isConnected()) {
        if (bluetoothDevice.bondState == BOND_BONDED) {
          // already bonded, just reconnect
          bluetoothDevice.connect()
          waitConnectionIntent(bluetoothDevice)
        } else {
          // need to bond
          bluetoothDevice.createBond()
          acceptPairingAndAwaitBonded(bluetoothDevice)
        }
      }

      ConnectResponse.newBuilder()
        .setConnection(
          Connection.newBuilder()
            .setCookie(ByteString.copyFromUtf8(bluetoothDevice.address))
            .build()
        )
        .build()
    }
  }

  override fun disconnect(
    request: DisconnectRequest,
    responseObserver: StreamObserver<DisconnectResponse>
  ) {
    grpcUnary<DisconnectResponse>(scope, responseObserver) {
      val bluetoothDevice = request.connection.toBluetoothDevice(bluetoothAdapter)
      Log.i(TAG, "disconnect: device=$bluetoothDevice")

      if (!bluetoothDevice.isConnected()) {
        Log.e(TAG, "Device is not connected, cannot disconnect")
        throw Status.UNKNOWN.asException()
      }

      val connectionStateChangedFlow =
        flow
          .filter { it.getAction() == BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED }
          .filter { it.getBluetoothDeviceExtra() == bluetoothDevice }
          .map { it.getIntExtra(BluetoothAdapter.EXTRA_CONNECTION_STATE, BluetoothAdapter.ERROR) }

      bluetoothDevice.disconnect()
      connectionStateChangedFlow.filter { it == BluetoothAdapter.STATE_DISCONNECTED }.first()

      DisconnectResponse.getDefaultInstance()
    }
  }

  override fun connectLE(
    request: ConnectLERequest,
    responseObserver: StreamObserver<ConnectLEResponse>
  ) {
    grpcUnary<ConnectLEResponse>(scope, responseObserver) {
      val ptsAddress = request.address.decodeToString()
      Log.i(TAG, "connect LE: $ptsAddress")
      val device = scanLeDevice(ptsAddress)
      GattInstance(device!!, TRANSPORT_LE, context).waitForState(BluetoothProfile.STATE_CONNECTED)
      ConnectLEResponse.newBuilder()
        .setConnection(
          Connection.newBuilder().setCookie(ByteString.copyFromUtf8(device.address)).build()
        )
        .build()
    }
  }

  override fun disconnectLE(request: DisconnectLERequest, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
      val ptsAddress = request.connection.cookie.toByteArray().decodeToString()
      Log.i(TAG, "disconnect: $ptsAddress")
      GattInstance.get(ptsAddress).disconnectInstance()
      Empty.getDefaultInstance()
    }
  }

  private fun scanLeDevice(ptsAddress: String): BluetoothDevice? {
    Log.d(TAG, "scanLeDevice")
    var bluetoothDevice: BluetoothDevice? = null
    runBlocking {
      val flow = callbackFlow {
        val leScanCallback =
          object : ScanCallback() {
            override fun onScanFailed(errorCode: Int) {
              super.onScanFailed(errorCode)
              Log.d(TAG, "onScanFailed: errorCode: $errorCode")
              trySendBlocking(null)
            }
            override fun onScanResult(callbackType: Int, result: ScanResult) {
              super.onScanResult(callbackType, result)
              val deviceAddress = result.device.address
              if (deviceAddress == ptsAddress) {
                Log.d(TAG, "found device address: $deviceAddress")
                trySendBlocking(result.device)
              }
            }
          }
        val bluetoothLeScanner = bluetoothAdapter.bluetoothLeScanner
        bluetoothLeScanner?.startScan(leScanCallback) ?: run { trySendBlocking(null) }
        awaitClose { bluetoothLeScanner?.stopScan(leScanCallback) }
      }
      bluetoothDevice = flow.first()
    }
    return bluetoothDevice
  }
}
