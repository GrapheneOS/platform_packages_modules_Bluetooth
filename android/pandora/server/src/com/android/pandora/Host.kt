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
import android.bluetooth.BluetoothAssignedNumbers
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothDevice.ADDRESS_TYPE_PUBLIC
import android.bluetooth.BluetoothDevice.ADDRESS_TYPE_RANDOM
import android.bluetooth.BluetoothDevice.BOND_BONDED
import android.bluetooth.BluetoothDevice.TRANSPORT_LE
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.MacAddress
import android.os.ParcelUuid
import android.util.Log
import com.google.protobuf.ByteString
import com.google.protobuf.Empty
import io.grpc.Status
import io.grpc.stub.StreamObserver
import java.io.IOException
import java.time.Duration
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.sendBlocking
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
import kotlinx.coroutines.withTimeout
import pandora.HostGrpc.HostImplBase
import pandora.HostProto.*

@kotlinx.coroutines.ExperimentalCoroutinesApi
class Host(private val context: Context, private val server: Server) : HostImplBase() {
  private val TAG = "PandoraHost"

  private val scope: CoroutineScope
  private val flow: Flow<Intent>

  private val bluetoothManager = context.getSystemService(BluetoothManager::class.java)!!
  private val bluetoothAdapter = bluetoothManager.adapter

  private var connectability = ConnectabilityMode.CONNECTABILITY_UNSPECIFIED
  private var discoverability = DiscoverabilityMode.DISCOVERABILITY_UNSPECIFIED

  private val advertisers = mutableMapOf<UUID, AdvertiseCallback>()

  init {
    scope = CoroutineScope(Dispatchers.Default)

    // Add all intent actions to be listened.
    val intentFilter = IntentFilter()
    intentFilter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
    intentFilter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
    intentFilter.addAction(BluetoothAdapter.ACTION_CONNECTION_STATE_CHANGED)
    intentFilter.addAction(BluetoothDevice.ACTION_PAIRING_REQUEST)
    intentFilter.addAction(BluetoothDevice.ACTION_FOUND)

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
        .setConnection(newConnection(bluetoothDevice, Transport.TRANSPORT_BREDR))
        .build()
    }
  }

  override fun connect(request: ConnectRequest, responseObserver: StreamObserver<ConnectResponse>) {
    grpcUnary(scope, responseObserver) {
      val bluetoothDevice = request.address.toBluetoothDevice(bluetoothAdapter)

      Log.i(TAG, "connect: address=$bluetoothDevice")

      bluetoothAdapter.cancelDiscovery()

      if (!bluetoothDevice.isConnected()) {
        if (request.skipPairing) {
          // do an SDP request to trigger a temporary BREDR connection
          try {
            withTimeout(1500) { bluetoothDevice.createRfcommSocket(3).connect() }
          } catch (e: IOException) {
            // ignore
          }
        } else {
          if (bluetoothDevice.bondState == BOND_BONDED) {
            // already bonded, just reconnect
            bluetoothDevice.connect()
            waitConnectionIntent(bluetoothDevice)
          } else {
            // need to bond
            bluetoothDevice.createBond()
            if (!request.manuallyConfirm) {
              acceptPairingAndAwaitBonded(bluetoothDevice)
            }
          }
        }
      }

      ConnectResponse.newBuilder()
        .setConnection(newConnection(bluetoothDevice, Transport.TRANSPORT_BREDR))
        .build()
    }
  }

  override fun getConnection(
    request: GetConnectionRequest,
    responseObserver: StreamObserver<GetConnectionResponse>
  ) {
    grpcUnary(scope, responseObserver) {
      val device = bluetoothAdapter.getRemoteDevice(request.address.toByteArray())
      check(
        device.isConnected() && device.type != BluetoothDevice.DEVICE_TYPE_LE
      ) // either classic or dual
      GetConnectionResponse.newBuilder()
        .setConnection(newConnection(device, Transport.TRANSPORT_BREDR))
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
      val address = request.address.decodeAsMacAddressToString()
      Log.i(TAG, "connectLE: $address")
      val device = scanLeDevice(address)
      GattInstance(device!!, TRANSPORT_LE, context).waitForState(BluetoothProfile.STATE_CONNECTED)
      ConnectLEResponse.newBuilder()
        .setConnection(newConnection(device, Transport.TRANSPORT_LE))
        .build()
    }
  }

  override fun getLEConnection(
    request: GetLEConnectionRequest,
    responseObserver: StreamObserver<GetLEConnectionResponse>,
  ) {
    grpcUnary<GetLEConnectionResponse>(scope, responseObserver) {
      val address = request.address.decodeAsMacAddressToString()
      Log.i(TAG, "getLEConnection: $address")
      val device = bluetoothAdapter.getRemoteLeDevice(address, BluetoothDevice.ADDRESS_TYPE_PUBLIC)
      if (device.isConnected) {
        GetLEConnectionResponse.newBuilder()
          .setConnection(newConnection(device, Transport.TRANSPORT_LE))
          .build()
      } else {
        Log.e(TAG, "Device: $device is not connected")
        throw Status.UNKNOWN.asException()
      }
    }
  }

  override fun disconnectLE(request: DisconnectLERequest, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
      val address = request.connection.address
      Log.i(TAG, "disconnectLE: $address")
      val gattInstance = GattInstance.get(address)

      if (gattInstance.isDisconnected()) {
        Log.e(TAG, "Device is not connected, cannot disconnect")
        throw Status.UNKNOWN.asException()
      }

      gattInstance.disconnectInstance()
      gattInstance.waitForState(BluetoothProfile.STATE_DISCONNECTED)
      Empty.getDefaultInstance()
    }
  }

  private fun scanLeDevice(address: String): BluetoothDevice? {
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
              if (deviceAddress == address) {
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

  override fun startAdvertising(
    request: StartAdvertisingRequest,
    responseObserver: StreamObserver<StartAdvertisingResponse>
  ) {
    Log.d(TAG, "startAdvertising")
    grpcUnary(scope, responseObserver) {
      val handle = UUID.randomUUID()

      callbackFlow {
          val callback =
            object : AdvertiseCallback() {
              override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                sendBlocking(
                  StartAdvertisingResponse.newBuilder()
                    .setHandle(
                      AdvertisingHandle.newBuilder()
                        .setCookie(ByteString.copyFromUtf8(handle.toString()))
                    )
                    .build()
                )
              }
              override fun onStartFailure(errorCode: Int) {
                error("failed to start advertising")
              }
            }

          advertisers[handle] = callback

          val advertisingDataBuilder = AdvertiseData.Builder()

          for (service_uuid in request.advertisingData.serviceUuidsList) {
            advertisingDataBuilder.addServiceUuid(ParcelUuid.fromString(service_uuid))
          }

          advertisingDataBuilder
            .setIncludeDeviceName(request.advertisingData.includeLocalName)
            .setIncludeTxPowerLevel(request.advertisingData.includeTxPowerLevel)
            .addManufacturerData(
              BluetoothAssignedNumbers.GOOGLE,
              request.advertisingData.manufacturerSpecificData.toByteArray()
            )

          bluetoothAdapter.bluetoothLeAdvertiser.startAdvertising(
            AdvertiseSettings.Builder()
              .setConnectable(
                request.connectabilityMode == ConnectabilityMode.CONECTABILITY_CONNECTABLE
              )
              .setOwnAddressType(
                when (request.ownAddressType!!) {
                  AddressType.PUBLIC -> ADDRESS_TYPE_PUBLIC
                  AddressType.RANDOM -> ADDRESS_TYPE_RANDOM
                  AddressType.UNRECOGNIZED ->
                    error("unrecognized address type ${request.ownAddressType}")
                }
              )
              .build(),
            advertisingDataBuilder.build(),
            callback,
          )

          awaitClose { /* no-op */}
        }
        .first()
    }
  }

  override fun runInquiry(
    request: RunInquiryRequest,
    responseObserver: StreamObserver<RunInquiryResponse>
  ) {
    Log.d(TAG, "runInquiry")
    grpcServerStream(scope, responseObserver) {
      launch {
        try {
          bluetoothAdapter.startDiscovery()
          awaitCancellation()
        } finally {
          bluetoothAdapter.cancelDiscovery()
        }
      }
      flow
        .filter { it.action == BluetoothDevice.ACTION_FOUND }
        .map {
          val device = it.getBluetoothDeviceExtra()
          Log.i(TAG, "Device found: $device")
          RunInquiryResponse.newBuilder()
            .addDevice(
              Device.newBuilder()
                .setName(device.name)
                .setAddress(device.toByteString())
            )
            .build()
        }
    }
  }

  override fun setConnectabilityMode(
    request: SetConnectabilityModeRequest,
    responseObserver: StreamObserver<SetConnectabilityModeResponse>
  ) {
    grpcUnary(scope, responseObserver) {
      Log.d(TAG, "setConnectabilityMode")
      connectability = request.connectability!!

      val scanMode =
        when (connectability) {
          ConnectabilityMode.CONNECTABILITY_UNSPECIFIED,
          ConnectabilityMode.UNRECOGNIZED -> null
          ConnectabilityMode.CONNECTABILITY_NOT_CONNECTABLE -> {
            BluetoothAdapter.SCAN_MODE_NONE
          }
          ConnectabilityMode.CONECTABILITY_CONNECTABLE -> {
            if (
              discoverability == DiscoverabilityMode.DISCOVERABILITY_LIMITED ||
                discoverability == DiscoverabilityMode.DISCOVERABILITY_GENERAL
            ) {
              BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE
            } else {
              BluetoothAdapter.SCAN_MODE_CONNECTABLE
            }
          }
        }

      if (scanMode != null) {
        bluetoothAdapter.setScanMode(scanMode)
      }
      SetConnectabilityModeResponse.getDefaultInstance()
    }
  }

  override fun setDiscoverabilityMode(
    request: SetDiscoverabilityModeRequest,
    responseObserver: StreamObserver<SetDiscoverabilityModeResponse>
  ) {
    Log.d(TAG, "setDiscoverabilityMode")
    grpcUnary(scope, responseObserver) {
      discoverability = request.discoverability!!

      val scanMode =
        when (discoverability) {
          DiscoverabilityMode.DISCOVERABILITY_UNSPECIFIED,
          DiscoverabilityMode.UNRECOGNIZED -> null
          DiscoverabilityMode.DISCOVERABILITY_NONE ->
            if (connectability == ConnectabilityMode.CONECTABILITY_CONNECTABLE) {
              BluetoothAdapter.SCAN_MODE_CONNECTABLE
            } else {
              BluetoothAdapter.SCAN_MODE_NONE
            }
          DiscoverabilityMode.DISCOVERABILITY_LIMITED,
          DiscoverabilityMode.DISCOVERABILITY_GENERAL ->
            BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE
        }

      if (scanMode != null) {
        bluetoothAdapter.setScanMode(scanMode)
      }

      if (request.discoverability == DiscoverabilityMode.DISCOVERABILITY_LIMITED) {
        bluetoothAdapter.setDiscoverableTimeout(
          Duration.ofSeconds(120)
        ) // limited discoverability needs a timeout, 120s is Android default
      }
      SetDiscoverabilityModeResponse.getDefaultInstance()
    }
  }

  override fun runDiscovery(
    request: RunDiscoveryRequest,
    responseObserver: StreamObserver<RunDiscoveryResponse>
  ) {
    Log.d(TAG, "runDiscovery")
    grpcServerStream(scope, responseObserver) {
      callbackFlow {
        val callback =
          object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
              sendBlocking(
                RunDiscoveryResponse.newBuilder()
                  .setDevice(
                    Device.newBuilder()
                      .setAddress(
                        ByteString.copyFrom(
                          MacAddress.fromString(result.device.address).toByteArray()
                        )
                      )
                      .setName(result.device.name ?: "")
                  )
                  .setFlags(result.scanRecord?.advertiseFlags ?: 0)
                  .build()
              )
            }

            override fun onScanFailed(errorCode: Int) {
              error("scan failed")
            }
          }
        bluetoothAdapter.bluetoothLeScanner.startScan(callback)

        awaitClose { bluetoothAdapter.bluetoothLeScanner.stopScan(callback) }
      }
    }
  }

  override fun getDeviceName(
    request: GetDeviceNameRequest,
    responseObserver: StreamObserver<GetDeviceNameResponse>
  ) {
    grpcUnary(scope, responseObserver) {
      val device = request.connection.toBluetoothDevice(bluetoothAdapter)
      GetDeviceNameResponse.newBuilder().setName(device.name).build()
    }
  }
}
