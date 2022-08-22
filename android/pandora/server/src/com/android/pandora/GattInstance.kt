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
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.util.Log

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first

/**
 * GattInstance extends and simplifies Android GATT APIs without re-implementing them.
 */
@kotlinx.coroutines.ExperimentalCoroutinesApi
class GattInstance(val mDevice: BluetoothDevice, val mTransport: Int, val mContext: Context) {
  private val TAG = "GattInstance"
  public val mGatt: BluetoothGatt

  private var mServiceDiscovered = MutableStateFlow(false)
  private var mConnectionState = MutableStateFlow(BluetoothProfile.STATE_DISCONNECTED)

  companion object GattManager {
    val gattInstances: MutableMap<String, GattInstance> = mutableMapOf<String, GattInstance>()
    fun get(address: String):  GattInstance {
      val instance = gattInstances.get(address)
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