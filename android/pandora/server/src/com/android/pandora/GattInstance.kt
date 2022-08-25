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

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.util.Log

import com.google.protobuf.ByteString

import java.util.UUID

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull

/**
 * GattInstance extends and simplifies Android GATT APIs without re-implementing them.
 */
@kotlinx.coroutines.ExperimentalCoroutinesApi
class GattInstance(val mDevice: BluetoothDevice, val mTransport: Int, val mContext: Context) {
  private val TAG = "GattInstance"
  public val mGatt: BluetoothGatt

  private var mServiceDiscovered = MutableStateFlow(false)
  private var mConnectionState = MutableStateFlow(BluetoothProfile.STATE_DISCONNECTED)
  private var mValueRead = MutableStateFlow(false)

  /**
   * Wrapper for characteristic and descriptor reading.
   * Uuid, startHandle and endHandle are used to compare with the callback returned object.
   * Value and status can be read once the read has been done.
   */
  class GattInstanceValueRead(var uuid: UUID?, var startHandle: Int, var endHandle: Int,
      var value: ByteArray?, var status: Int) {}
  private var mGattInstanceValueRead = GattInstanceValueRead(
      null, 0, 0, byteArrayOf(), BluetoothGatt.GATT_FAILURE)

  companion object GattManager {
    val gattInstances: MutableMap<String, GattInstance> = mutableMapOf<String, GattInstance>()
    fun get(address: String):  GattInstance {
      val instance = gattInstances.get(address)
      requireNotNull(instance) {
        "Unable to find GATT instance for $address"
      }
      return instance
    }
    fun get(address: ByteString):  GattInstance {
      val instance = gattInstances.get(address.toByteArray().decodeToString())
      requireNotNull(instance) {
        "Unable to find GATT instance for $address"
      }
      return instance
    }
  }

  private val mCallback = object : BluetoothGattCallback() {
    override fun onConnectionStateChange(bluetoothGatt: BluetoothGatt,
        status: Int, newState: Int) {
      Log.i(TAG, "$mDevice connection state changed to $newState")
      mConnectionState.value = newState
      if (newState == BluetoothProfile.STATE_DISCONNECTED) {
        gattInstances.remove(mDevice.address)
      }
    }

    override fun onServicesDiscovered(bluetoothGatt: BluetoothGatt, status: Int) {
      if (status == BluetoothGatt.GATT_SUCCESS) {
        Log.i(TAG, "Services have been discovered for $mDevice")
        mServiceDiscovered.value = true
      }
    }

    override fun onCharacteristicRead(bluetoothGatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic, value: ByteArray, status: Int) {
      Log.i(TAG, "onCharacteristicRead, status: $status")
      if (characteristic.getUuid() == mGattInstanceValueRead.uuid
          && characteristic.getInstanceId() >= mGattInstanceValueRead.startHandle
          && characteristic.getInstanceId() <= mGattInstanceValueRead.endHandle) {
        mGattInstanceValueRead.value = value
        mGattInstanceValueRead.status = status
        mValueRead.value = true
      }
    }

    override fun onDescriptorRead(bluetoothGatt: BluetoothGatt,
        descriptor: BluetoothGattDescriptor, status: Int, value: ByteArray) {
      Log.i(TAG, "onDescriptorRead, status: $status")
      if (descriptor.getUuid() == mGattInstanceValueRead.uuid
          && descriptor.getInstanceId() >= mGattInstanceValueRead.startHandle
          && descriptor.getInstanceId() <= mGattInstanceValueRead.endHandle) {
        mGattInstanceValueRead.value = value
        mGattInstanceValueRead.status = status
        mValueRead.value = true
      }
    }
  }

  init {
    if (!isBLETransport()) {
      require(isBonded()) {
        "Trying to connect non BLE GATT on a not bonded device $mDevice"
      }
    }
    require(gattInstances.get(mDevice.address) == null) {
      "Trying to connect GATT on an already connected device $mDevice"
    }

    mGatt = mDevice.connectGatt(mContext, false, mCallback, mTransport)

    checkNotNull(mGatt) {
      "Failed to connect GATT on $mDevice"
    }
    gattInstances.put(mDevice.address, this)
  }

  public fun isConnected(): Boolean {
    return mConnectionState.value == BluetoothProfile.STATE_CONNECTED
  }

  public fun isDisconnected(): Boolean {
    return mConnectionState.value == BluetoothProfile.STATE_DISCONNECTED
  }

  public fun isBonded(): Boolean {
    return mDevice.getBondState() == BluetoothDevice.BOND_BONDED
  }

  public fun isBLETransport(): Boolean {
    return mTransport == BluetoothDevice.TRANSPORT_LE
  }

  public fun servicesDiscovered(): Boolean {
    return mServiceDiscovered.value
  }

  public suspend fun waitForState(newState: Int) {
    if (mConnectionState.value != newState) {
      mConnectionState.first { it == newState }
    }
  }

  public suspend fun waitForDiscoveryEnd() {
    if (mServiceDiscovered.value != true) {
      mServiceDiscovered.first { it == true }
    }
  }

  public suspend fun waitForValueReadEnd() {
    if (mValueRead.value != true) {
      mValueRead.first { it == true }
    }
    mValueRead.value = false
  }

  public suspend fun readCharacteristicBlocking(
      characteristic: BluetoothGattCharacteristic): GattInstanceValueRead {
    // Init mGattInstanceValueRead with characteristic values.
    mGattInstanceValueRead = GattInstanceValueRead(
        characteristic.getUuid(), characteristic.getInstanceId(), characteristic.getInstanceId(),
        byteArrayOf(), BluetoothGatt.GATT_FAILURE)
    if (mGatt.readCharacteristic(characteristic)){
      waitForValueReadEnd()
    }
    return mGattInstanceValueRead
  }

  public suspend fun readCharacteristicUuidBlocking(
      uuid: UUID, startHandle: Int, endHandle: Int): GattInstanceValueRead {
    // Init mGattInstanceValueRead with characteristic values.
    mGattInstanceValueRead = GattInstanceValueRead(
        uuid, startHandle, endHandle, byteArrayOf(), BluetoothGatt.GATT_FAILURE)
    if (mGatt.readUsingCharacteristicUuid(uuid, startHandle, endHandle)){
      // We have to timeout here as one test will try to read on an inexistant
      // characteristic. We don't discover services when reading by uuid so we
      // can't check if the characteristic exists beforehand. PTS is also waiting
      // for the read to happen so we have to read anyway.
      withTimeoutOrNull(1000L) { waitForValueReadEnd() }
    }
    return mGattInstanceValueRead
  }

  public suspend fun readDescriptorBlocking(
      descriptor: BluetoothGattDescriptor): GattInstanceValueRead {
    // Init mGattInstanceValueRead with descriptor values.
    mGattInstanceValueRead = GattInstanceValueRead(
        descriptor.getUuid(), descriptor.getInstanceId(), descriptor.getInstanceId(),
        byteArrayOf(), BluetoothGatt.GATT_FAILURE)
    if (mGatt.readDescriptor(descriptor)){
      waitForValueReadEnd()
    }
    return mGattInstanceValueRead
  }

  public fun disconnectInstance() {
    require(isConnected()) {
      "Trying to disconnect an already disconnected device $mDevice"
    }
    mGatt.disconnect()
    gattInstances.remove(mDevice.address)
  }

  override fun toString(): String {
    return "GattInstance($mDevice)"
  }
}