/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.bluetooth

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.android.compatibility.common.util.AdoptShellPermissionsRule
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.Empty
import io.grpc.Deadline
import java.util.UUID
import java.util.concurrent.TimeUnit
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.any
import org.mockito.Mockito.eq
import org.mockito.Mockito.mock
import org.mockito.Mockito.timeout
import org.mockito.Mockito.verify
import pandora.HostProto.AdvertiseRequest
import pandora.HostProto.OwnAddressType

@RunWith(AndroidJUnit4::class)
public class DckTest {
    private val TAG = "DckTest"
    private val TIMEOUT: Long = 2000

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val bluetoothManager = context.getSystemService(BluetoothManager::class.java)!!
    private val bluetoothAdapter = bluetoothManager.adapter

    // CCC DK Specification R3 1.2.0 r14 section 19.2.1.2 Bluetooth Le Pairing
    private val CCC_DK_UUID = UUID.fromString("0000FFF5-0000-1000-8000-00805f9b34fb")

    @Rule @JvmField val mPermissionRule = AdoptShellPermissionsRule()

    @Rule @JvmField val mBumble = PandoraDevice()

    @Test
    fun testDiscoverDkGattService() {
        mBumble
            .dckBlocking()
            .withDeadline(Deadline.after(TIMEOUT, TimeUnit.MILLISECONDS))
            .register(Empty.getDefaultInstance())

        mBumble
            .hostBlocking()
            .advertise(
                AdvertiseRequest.newBuilder()
                    .setLegacy(true)
                    .setConnectable(true)
                    .setOwnAddressType(OwnAddressType.RANDOM)
                    .build()
            )

        val bumbleDevice =
            bluetoothAdapter.getRemoteLeDevice(
                Utils.BUMBLE_RANDOM_ADDRESS,
                BluetoothDevice.ADDRESS_TYPE_RANDOM
            )
        val gattCallback = mock(BluetoothGattCallback::class.java)
        var bumbleGatt = bumbleDevice.connectGatt(context, false, gattCallback)
        verify(gattCallback, timeout(TIMEOUT))
            .onConnectionStateChange(
                any(),
                eq(BluetoothGatt.GATT_SUCCESS),
                eq(BluetoothProfile.STATE_CONNECTED)
            )

        bumbleGatt.discoverServices()
        verify(gattCallback, timeout(TIMEOUT))
            .onServicesDiscovered(any(), eq(BluetoothGatt.GATT_SUCCESS))
        assertThat(bumbleGatt.getService(CCC_DK_UUID)).isNotNull()

        bumbleGatt.disconnect()
        verify(gattCallback, timeout(TIMEOUT))
            .onConnectionStateChange(
                any(),
                eq(BluetoothGatt.GATT_SUCCESS),
                eq(BluetoothProfile.STATE_DISCONNECTED)
            )
    }
}
