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

import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.os.ParcelUuid;
import android.util.Log;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.runner.AndroidJUnit4;

import com.android.compatibility.common.util.AdoptShellPermissionsRule;

import io.grpc.stub.StreamObserver;

import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.Invocation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import pandora.HostProto;
import pandora.HostProto.AdvertiseRequest;
import pandora.HostProto.AdvertiseResponse;

@RunWith(AndroidJUnit4.class)
public class GattClientTest {
    private static final String TAG = "GattClientTest";

    private static final String TEST_UUID_STRING = "00001805-0000-1000-8000-00805f9b34fb";

    private static final int TIMEOUT_SCANNING_MS = 2000;

    @ClassRule public static final AdoptShellPermissionsRule PERM = new AdoptShellPermissionsRule();

    @Rule public final PandoraDevice mBumble = new PandoraDevice();

    private final Context mContext = ApplicationProvider.getApplicationContext();
    private final BluetoothManager mManager = mContext.getSystemService(BluetoothManager.class);
    private final BluetoothAdapter mAdapter = mManager.getAdapter();
    private final BluetoothLeScanner mLeScanner = mAdapter.getBluetoothLeScanner();

    @Test
    public void directConnectGattAfterClose() throws Exception {
        advertiseWithBumble(TEST_UUID_STRING);

        List<ScanResult> results =
                startScanning(TEST_UUID_STRING, ScanSettings.CALLBACK_TYPE_ALL_MATCHES).join();

        BluetoothDevice device = results.get(0).getDevice();
        assertThat(device).isNotNull();

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
        advertiseWithBumble(TEST_UUID_STRING);

        List<ScanResult> results =
                startScanning(TEST_UUID_STRING, ScanSettings.CALLBACK_TYPE_ALL_MATCHES).join();

        BluetoothDevice device = results.get(0).getDevice();
        assertThat(device).isNotNull();

        for (int i = 0; i < 10; i++) {
            BluetoothGattCallback gattCallback = mock(BluetoothGattCallback.class);
            BluetoothGatt gatt = device.connectGatt(mContext, false, gattCallback);
            verify(gattCallback, timeout(1000))
                    .onConnectionStateChange(any(), anyInt(), eq(BluetoothProfile.STATE_CONNECTED));

            gatt.disconnect();
            verify(gattCallback, timeout(1000))
                    .onConnectionStateChange(
                            any(), anyInt(), eq(BluetoothProfile.STATE_DISCONNECTED));

            gatt.close();
        }
    }

    private CompletableFuture<List<ScanResult>> startScanning(
            String serviceUuid, int callbackType) {
        CompletableFuture<List<ScanResult>> future = new CompletableFuture<>();
        List<ScanResult> scanResults = new ArrayList<>();

        // Start scanning
        ScanSettings scanSettings =
                new ScanSettings.Builder()
                        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                        .setCallbackType(callbackType)
                        .build();

        List<ScanFilter> scanFilters =
                List.of(
                        new ScanFilter.Builder()
                                .setServiceUuid(ParcelUuid.fromString(serviceUuid))
                                .build());

        ScanCallback scanCallback =
                new ScanCallback() {
                    @Override
                    public void onScanResult(int callbackType, ScanResult result) {
                        Log.i(
                                TAG,
                                "onScanResult "
                                        + "callbackType: "
                                        + callbackType
                                        + ", service uuids: "
                                        + result.getScanRecord().getServiceUuids());
                        scanResults.add(result);
                        future.complete(scanResults);
                    }

                    @Override
                    public void onScanFailed(int errorCode) {
                        Log.i(TAG, "onScanFailed errorCode: " + errorCode);
                        future.complete(null);
                    }
                };

        mLeScanner.startScan(scanFilters, scanSettings, scanCallback);

        // Make sure completableFuture object completes with null after some timeout
        return future.completeOnTimeout(null, TIMEOUT_SCANNING_MS, TimeUnit.MILLISECONDS);
    }

    private void advertiseWithBumble(String serviceUuid) {
        HostProto.DataTypes dataType =
                HostProto.DataTypes.newBuilder()
                        .addCompleteServiceClassUuids128(serviceUuid)
                        .build();

        AdvertiseRequest request =
                AdvertiseRequest.newBuilder()
                        .setLegacy(true)
                        .setData(dataType)
                        .setConnectable(true)
                        .build();

        StreamObserver<AdvertiseResponse> responseObserver =
                new StreamObserver<>() {
                    @Override
                    public void onNext(AdvertiseResponse response) {
                        Log.i(TAG, "advertise observer: onNext");
                    }

                    @Override
                    public void onError(Throwable e) {
                        Log.e(TAG, "advertise observer: on error " + e);
                    }

                    @Override
                    public void onCompleted() {
                        Log.i(TAG, "advertise observer: on completed");
                    }
                };

        mBumble.host().advertise(request, responseObserver);
    }
}
