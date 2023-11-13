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

import static com.google.common.io.BaseEncoding.base16;
import static com.google.common.truth.Truth.assertThat;

import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.os.ParcelUuid;
import android.util.Log;

import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.android.compatibility.common.util.AdoptShellPermissionsRule;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import pandora.HostProto;
import pandora.HostProto.AdvertiseRequest;
import pandora.HostProto.AdvertiseResponse;
import pandora.HostProto.OwnAddressType;

@RunWith(AndroidJUnit4.class)
public class LeScanningTest {
    private static final String TAG = "LeScanningTest";
    private static final int TIMEOUT_SCANNING_MS = 2000;

    @Rule public final AdoptShellPermissionsRule mPermissionRule = new AdoptShellPermissionsRule();

    @Rule public final PandoraDevice mBumble = new PandoraDevice();

    private static final String TEST_ADDRESS_RANDOM_STATIC = "F0:43:A8:23:10:11";

    // IRK must match what's defined in bumble_config.json
    private static final byte[] TEST_IRK = base16().decode("1F66F4B5F0C742F807DD0DDBF64E9213");

    private final String TEST_UUID_STRING = "00001805-0000-1000-8000-00805f9b34fb";

    @Test
    public void startBleScan_withCallbackTypeAllMatches() {
        advertiseWithBumble(TEST_UUID_STRING, OwnAddressType.PUBLIC);

        ScanFilter scanFilter =
                new ScanFilter.Builder()
                        .setServiceUuid(ParcelUuid.fromString(TEST_UUID_STRING))
                        .build();

        List<ScanResult> results =
                startScanning(scanFilter, ScanSettings.CALLBACK_TYPE_ALL_MATCHES).join();

        assertThat(results.get(0).getScanRecord().getServiceUuids().get(0))
                .isEqualTo(ParcelUuid.fromString(TEST_UUID_STRING));
        assertThat(results.get(1).getScanRecord().getServiceUuids().get(0))
                .isEqualTo(ParcelUuid.fromString(TEST_UUID_STRING));
    }

    @Test
    public void scanForIrkIdentityAddress_withCallbackTypeAllMatches() {
        advertiseWithBumble(null, OwnAddressType.RANDOM);

        ScanFilter scanFilter =
                new ScanFilter.Builder()
                        .setDeviceAddress(
                                TEST_ADDRESS_RANDOM_STATIC,
                                BluetoothDevice.ADDRESS_TYPE_RANDOM,
                                TEST_IRK)
                        .build();

        List<ScanResult> results =
                startScanning(scanFilter, ScanSettings.CALLBACK_TYPE_ALL_MATCHES).join();

        assertThat(results).isNotEmpty();
        assertThat(results.get(0).getDevice().getAddress()).isEqualTo(TEST_ADDRESS_RANDOM_STATIC);
    }

    private CompletableFuture<List<ScanResult>> startScanning(
            ScanFilter scanFilter, int callbackType) {
        CompletableFuture<List<ScanResult>> future = new CompletableFuture<>();
        List<ScanResult> scanResults = new ArrayList<>();

        android.content.Context context = ApplicationProvider.getApplicationContext();
        BluetoothManager bluetoothManager = context.getSystemService(BluetoothManager.class);
        BluetoothAdapter bluetoothAdapter = bluetoothManager.getAdapter();

        // Start scanning
        BluetoothLeScanner leScanner = bluetoothAdapter.getBluetoothLeScanner();

        ScanSettings scanSettings =
                new ScanSettings.Builder()
                        .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                        .setCallbackType(callbackType)
                        .build();

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

                        if (callbackType == ScanSettings.CALLBACK_TYPE_ALL_MATCHES) {
                            if (scanResults.size() < 2) {
                                scanResults.add(result);
                            } else {
                                future.complete(scanResults);
                            }
                        } else {
                            scanResults.add(result);
                            future.complete(scanResults);
                        }
                    }

                    @Override
                    public void onScanFailed(int errorCode) {
                        Log.i(TAG, "onScanFailed " + "errorCode: " + errorCode);
                        future.complete(null);
                    }
                };

        leScanner.startScan(List.of(scanFilter), scanSettings, scanCallback);

        // Make sure completableFuture object completes with null after some timeout
        return future.completeOnTimeout(null, TIMEOUT_SCANNING_MS, TimeUnit.MILLISECONDS);
    }

    private void advertiseWithBumble(String serviceUuid, OwnAddressType addressType) {
        AdvertiseRequest.Builder requestBuilder =
                AdvertiseRequest.newBuilder().setLegacy(true).setOwnAddressType(addressType);

        if (serviceUuid != null) {
            HostProto.DataTypes.Builder dataTypeBuilder = HostProto.DataTypes.newBuilder();
            dataTypeBuilder.addCompleteServiceClassUuids128(serviceUuid);
            requestBuilder.setData(dataTypeBuilder.build());
        }

        StreamObserverSpliterator<AdvertiseResponse> responseObserver =
                new StreamObserverSpliterator<>();

        mBumble.host().advertise(requestBuilder.build(), responseObserver);
    }
}
