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

package android.bluetooth;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import android.bluetooth.le.BluetoothLeScanner;
import android.content.Context;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.android.compatibility.common.util.AdoptShellPermissionsRule;

import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.invocation.Invocation;

import pandora.GattProto.GattCharacteristicParams;
import pandora.GattProto.GattServiceParams;
import pandora.GattProto.RegisterServiceRequest;
import pandora.HostProto.AdvertiseRequest;
import pandora.HostProto.AdvertiseResponse;
import pandora.HostProto.OwnAddressType;

import java.util.Collection;
import java.util.UUID;

@RunWith(AndroidJUnit4.class)
public class GattClientTest {
    private static final String TAG = "GattClientTest";
    private static final int ANDROID_MTU = 517;
    private static final int MTU_REQUESTED = 23;
    private static final int ANOTHER_MTU_REQUESTED = 42;

    private static final UUID GAP_UUID = UUID.fromString("00001800-0000-1000-8000-00805f9b34fb");

    @ClassRule public static final AdoptShellPermissionsRule PERM = new AdoptShellPermissionsRule();

    @Rule public final PandoraDevice mBumble = new PandoraDevice();

    private final Context mContext = ApplicationProvider.getApplicationContext();
    private final BluetoothManager mManager = mContext.getSystemService(BluetoothManager.class);
    private final BluetoothAdapter mAdapter = mManager.getAdapter();
    private final BluetoothLeScanner mLeScanner = mAdapter.getBluetoothLeScanner();

    @Test
    public void directConnectGattAfterClose() throws Exception {
        advertiseWithBumble();

        BluetoothDevice device =
                mAdapter.getRemoteLeDevice(
                        Utils.BUMBLE_RANDOM_ADDRESS, BluetoothDevice.ADDRESS_TYPE_RANDOM);

        for (int i = 0; i < 10; i++) {
            BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
            BluetoothGatt gatt = device.connectGatt(mContext, false, gattCallback);
            gatt.close();

            // Save the number of call in the callback to be checked later
            Collection<Invocation> invocations = mockingDetails(gattCallback).getInvocations();
            int numberOfCalls = invocations.size();

            BluetoothGattCallback gattCallback2 = mock(BluetoothGattCallback.class);
            BluetoothGatt gatt2 = device.connectGatt(mContext, false, gattCallback2);
            verify(gattCallback2, timeout(1000))
                    .onConnectionStateChange(any(), anyInt(), eq(BluetoothProfile.STATE_CONNECTED));
            gatt2.close();

            // After reconnecting with the second set of callback, check that nothing happened on
            // the first set of callback
            Collection<Invocation> invocationsAfterSomeTimes =
                    mockingDetails(gattCallback).getInvocations();
            int numberOfCallsAfterSomeTimes = invocationsAfterSomeTimes.size();
            assertThat(numberOfCallsAfterSomeTimes).isEqualTo(numberOfCalls);
        }
    }

    @Test
    public void fullGattClientLifecycle() throws Exception {
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);
        disconnectAndWaitDisconnection(gatt, gattCallback);
    }

    @Test
    public void reconnectExistingClient() throws Exception {
        advertiseWithBumble();

        BluetoothDevice device =
                mAdapter.getRemoteLeDevice(
                        Utils.BUMBLE_RANDOM_ADDRESS, BluetoothDevice.ADDRESS_TYPE_RANDOM);
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        InOrder inOrder = inOrder(gattCallback);

        BluetoothGatt gatt = device.connectGatt(mContext, false, gattCallback);
        inOrder.verify(gattCallback, timeout(1000))
                .onConnectionStateChange(any(), anyInt(), eq(BluetoothProfile.STATE_CONNECTED));

        gatt.disconnect();
        inOrder.verify(gattCallback, timeout(1000))
                .onConnectionStateChange(any(), anyInt(), eq(BluetoothProfile.STATE_DISCONNECTED));

        gatt.connect();
        inOrder.verify(gattCallback, timeout(1000))
                .onConnectionStateChange(any(), anyInt(), eq(BluetoothProfile.STATE_CONNECTED));

        gatt.close();
        verifyNoMoreInteractions(gattCallback);
    }

    @Test
    public void clientGattDiscoverServices() throws Exception {
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);

        try {
            gatt.discoverServices();
            verify(gattCallback, timeout(10000))
                    .onServicesDiscovered(any(), eq(BluetoothGatt.GATT_SUCCESS));

            assertThat(gatt.getServices().stream().map(BluetoothGattService::getUuid))
                    .contains(GAP_UUID);

        } finally {
            disconnectAndWaitDisconnection(gatt, gattCallback);
        }
    }

    @Test
    public void clientGattReadCharacteristics() throws Exception {
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);

        try {
            gatt.discoverServices();
            verify(gattCallback, timeout(10000))
                    .onServicesDiscovered(any(), eq(BluetoothGatt.GATT_SUCCESS));

            BluetoothGattService firstService = gatt.getServices().get(0);

            BluetoothGattCharacteristic firstCharacteristic =
                    firstService.getCharacteristics().get(0);

            gatt.readCharacteristic(firstCharacteristic);

            verify(gattCallback, timeout(5000)).onCharacteristicRead(any(), any(), any(), anyInt());

        } finally {
            disconnectAndWaitDisconnection(gatt, gattCallback);
        }
    }

    @Test
    public void clientGattWriteCharacteristic() throws Exception {
        registerWritableGattService();

        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);

        try {
            gatt.discoverServices();
            verify(gattCallback, timeout(10000))
                    .onServicesDiscovered(any(), eq(BluetoothGatt.GATT_SUCCESS));

            BluetoothGattCharacteristic characteristic = null;

            outer:
            for (BluetoothGattService candidateService : gatt.getServices()) {
                for (BluetoothGattCharacteristic candidateCharacteristic :
                        candidateService.getCharacteristics()) {
                    if ((candidateCharacteristic.getProperties()
                                    & BluetoothGattCharacteristic.PROPERTY_WRITE)
                            != 0) {
                        characteristic = candidateCharacteristic;
                        break outer;
                    }
                }
            }

            byte[] newValue = new byte[] {13};

            gatt.writeCharacteristic(
                    characteristic, newValue, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);

            verify(gattCallback, timeout(5000))
                    .onCharacteristicWrite(
                            any(), eq(characteristic), eq(BluetoothGatt.GATT_SUCCESS));

        } finally {
            disconnectAndWaitDisconnection(gatt, gattCallback);
        }
    }

    private void registerWritableGattService() {

        String characteristicUuidString = "11111111-1111-1111-1111-111111111111";
        String serviceUuidString = "00000000-0000-0000-0000-000000000000";

        GattCharacteristicParams characteristicParams =
                GattCharacteristicParams.newBuilder()
                        .setProperties(BluetoothGattCharacteristic.PROPERTY_WRITE)
                        .setUuid(characteristicUuidString)
                        .build();

        GattServiceParams serviceParams =
                GattServiceParams.newBuilder()
                        .addCharacteristics(characteristicParams)
                        .setUuid(serviceUuidString)
                        .build();

        RegisterServiceRequest request =
                RegisterServiceRequest.newBuilder().setService(serviceParams).build();

        mBumble.gattBlocking().registerService(request);
    }

    private void advertiseWithBumble() {
        AdvertiseRequest request =
                AdvertiseRequest.newBuilder()
                        .setLegacy(true)
                        .setConnectable(true)
                        .setOwnAddressType(OwnAddressType.RANDOM)
                        .build();

        StreamObserverSpliterator<AdvertiseResponse> responseObserver =
                new StreamObserverSpliterator<>();

        mBumble.host().advertise(request, responseObserver);
    }

    private BluetoothGatt connectGattAndWaitConnection(BluetoothGattCallback callback) {
        final int status = BluetoothGatt.GATT_SUCCESS;
        final int state = BluetoothProfile.STATE_CONNECTED;

        advertiseWithBumble();

        BluetoothDevice device =
                mAdapter.getRemoteLeDevice(
                        Utils.BUMBLE_RANDOM_ADDRESS, BluetoothDevice.ADDRESS_TYPE_RANDOM);

        BluetoothGatt gatt = device.connectGatt(mContext, false, callback);
        verify(callback, timeout(1000)).onConnectionStateChange(eq(gatt), eq(status), eq(state));

        return gatt;
    }

    private void disconnectAndWaitDisconnection(
            BluetoothGatt gatt, BluetoothGattCallback callback) {
        final int state = BluetoothProfile.STATE_DISCONNECTED;
        gatt.disconnect();
        verify(callback, timeout(1000)).onConnectionStateChange(eq(gatt), anyInt(), eq(state));

        gatt.close();
        gatt = null;
    }

    @Test
    @Ignore("b/307981748: requestMTU should return a direct error")
    public void requestMtu_notConnected_isFalse() {
        advertiseWithBumble();

        BluetoothDevice device =
                mAdapter.getRemoteLeDevice(
                        Utils.BUMBLE_RANDOM_ADDRESS, BluetoothDevice.ADDRESS_TYPE_RANDOM);
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);

        BluetoothGatt gatt = device.connectGatt(mContext, false, gattCallback);
        // Do not wait for connection state change callback and ask MTU directly
        assertThat(gatt.requestMtu(MTU_REQUESTED)).isFalse();
    }

    @Test
    @Ignore("b/307981748: requestMTU should return a direct error or a error on the callback")
    public void requestMtu_invalidParamer_isFalse() {
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);

        try {
            assertThat(gatt.requestMtu(1024)).isTrue();
            // verify(gattCallback, timeout(5000).atLeast(1)).onMtuChanged(eq(gatt),
            // eq(ANDROID_MTU), eq(BluetoothGatt.GATT_FAILURE));
        } finally {
            disconnectAndWaitDisconnection(gatt, gattCallback);
        }
    }

    @Test
    public void requestMtu_once_isSuccess() {
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);

        try {
            assertThat(gatt.requestMtu(MTU_REQUESTED)).isTrue();
            // Check that only the ANDROID_MTU is returned, not the MTU_REQUESTED
            verify(gattCallback, timeout(5000))
                    .onMtuChanged(eq(gatt), eq(ANDROID_MTU), eq(BluetoothGatt.GATT_SUCCESS));
        } finally {
            disconnectAndWaitDisconnection(gatt, gattCallback);
        }
    }

    @Test
    public void requestMtu_multipleTimeFromSameClient_isRejected() {
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);

        try {
            assertThat(gatt.requestMtu(MTU_REQUESTED)).isTrue();
            // Check that only the ANDROID_MTU is returned, not the MTU_REQUESTED
            verify(gattCallback, timeout(5000))
                    .onMtuChanged(eq(gatt), eq(ANDROID_MTU), eq(BluetoothGatt.GATT_SUCCESS));

            assertThat(gatt.requestMtu(ANOTHER_MTU_REQUESTED)).isTrue();
            verify(gattCallback, timeout(5000).times(2))
                    .onMtuChanged(eq(gatt), eq(ANDROID_MTU), eq(BluetoothGatt.GATT_SUCCESS));
        } finally {
            disconnectAndWaitDisconnection(gatt, gattCallback);
        }
    }

    @Test
    public void requestMtu_onceFromMultipleClient_secondIsSuccessWithoutUpdate() {
        BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
        BluetoothGatt gatt = connectGattAndWaitConnection(gattCallback);

        try {
            assertThat(gatt.requestMtu(MTU_REQUESTED)).isTrue();
            verify(gattCallback, timeout(5000))
                    .onMtuChanged(eq(gatt), eq(ANDROID_MTU), eq(BluetoothGatt.GATT_SUCCESS));

            BluetoothGattCallback gattCallback2 = mock(BluetoothGattCallback.class);
            BluetoothGatt gatt2 = connectGattAndWaitConnection(gattCallback2);
            try {
                // first callback because there is already a connected device
                verify(gattCallback2, timeout(9000))
                        .onMtuChanged(eq(gatt2), eq(ANDROID_MTU), eq(BluetoothGatt.GATT_SUCCESS));
                assertThat(gatt2.requestMtu(ANOTHER_MTU_REQUESTED)).isTrue();
                verify(gattCallback2, timeout(9000).times(2))
                        .onMtuChanged(eq(gatt2), eq(ANDROID_MTU), eq(BluetoothGatt.GATT_SUCCESS));
            } finally {
                disconnectAndWaitDisconnection(gatt2, gattCallback2);
            }
        } finally {
            disconnectAndWaitDisconnection(gatt, gattCallback);
        }
    }
}
