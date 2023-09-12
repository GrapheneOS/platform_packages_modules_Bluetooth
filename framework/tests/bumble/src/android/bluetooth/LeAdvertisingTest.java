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

import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertisingSet;
import android.bluetooth.le.AdvertisingSetCallback;
import android.bluetooth.le.AdvertisingSetParameters;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.util.Log;

import androidx.core.util.Pair;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

import io.grpc.Context.CancellableContext;
import io.grpc.Deadline;
import io.grpc.stub.StreamObserver;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import pandora.HostProto.ScanRequest;
import pandora.HostProto.ScanningResponse;

/** Test cases for {@link AdvertiseManager}. */
@RunWith(AndroidJUnit4.class)
public class LeAdvertisingTest {
    private static final String TAG = "LeAdvertisingTest";

    private static final int TIMEOUT_ADVERTISING_MS = 1000;

    @Rule public final PandoraDevice mBumble = new PandoraDevice();

    @BeforeClass
    public static void setUpClass() throws Exception {
        InstrumentationRegistry.getInstrumentation()
                .getUiAutomation()
                .adoptShellPermissionIdentity();
    }

    @Test
    public void advertisingSet() throws Exception {
        ScanningResponse response =
                startAdvertising()
                        .thenCompose(advAddressPair -> scanWithBumble(advAddressPair))
                        .join();

        Log.i(TAG, "scan response: " + response);
        assertThat(response).isNotNull();
    }

    private CompletableFuture<Pair<String, Integer>> startAdvertising() {
        CompletableFuture<Pair<String, Integer>> future =
                new CompletableFuture<Pair<String, Integer>>();

        android.content.Context context = ApplicationProvider.getApplicationContext();
        BluetoothManager bluetoothManager = context.getSystemService(BluetoothManager.class);
        BluetoothAdapter bluetoothAdapter = bluetoothManager.getAdapter();

        // Start advertising
        BluetoothLeAdvertiser leAdvertiser = bluetoothAdapter.getBluetoothLeAdvertiser();
        AdvertisingSetParameters parameters =
                new AdvertisingSetParameters.Builder()
                        .setOwnAddressType(AdvertisingSetParameters.ADDRESS_TYPE_RANDOM)
                        .build();
        AdvertiseData advertiseData = new AdvertiseData.Builder().build();
        AdvertiseData scanResponse = new AdvertiseData.Builder().build();
        AdvertisingSetCallback advertisingSetCallback =
                new AdvertisingSetCallback() {
                    @Override
                    public void onAdvertisingSetStarted(
                            AdvertisingSet advertisingSet, int txPower, int status) {
                        Log.i(
                                TAG,
                                "onAdvertisingSetStarted "
                                        + " txPower:"
                                        + txPower
                                        + " status:"
                                        + status);
                        advertisingSet.enableAdvertising(true, TIMEOUT_ADVERTISING_MS, 0);
                    }

                    @Override
                    public void onOwnAddressRead(
                            AdvertisingSet advertisingSet, int addressType, String address) {
                        Log.i(
                                TAG,
                                "onOwnAddressRead "
                                        + " addressType:"
                                        + addressType
                                        + " address:"
                                        + address);
                        future.complete(new Pair<String, Integer>(address, addressType));
                    }

                    @Override
                    public void onAdvertisingEnabled(
                            AdvertisingSet advertisingSet, boolean enabled, int status) {
                        Log.i(
                                TAG,
                                "onAdvertisingEnabled "
                                        + " enabled:"
                                        + enabled
                                        + " status:"
                                        + status);
                        advertisingSet.getOwnAddress();
                    }
                };
        leAdvertiser.startAdvertisingSet(
                parameters, advertiseData, scanResponse, null, null, 0, 0, advertisingSetCallback);

        return future;
    }

    private CompletableFuture<ScanningResponse> scanWithBumble(Pair<String, Integer> addressPair) {
        final CompletableFuture<ScanningResponse> future =
                new CompletableFuture<ScanningResponse>();
        CancellableContext withCancellation = io.grpc.Context.current().withCancellation();

        String address = addressPair.first;
        int addressType = addressPair.second;

        ScanRequest request = ScanRequest.newBuilder().build();
        StreamObserver<ScanningResponse> responseObserver =
                new StreamObserver<ScanningResponse>() {
                    public void onNext(ScanningResponse response) {
                        String addr = "";
                        if (addressType == AdvertisingSetParameters.ADDRESS_TYPE_PUBLIC) {
                            addr = Utils.addressStringFromByteString(response.getPublic());
                        } else {
                            addr = Utils.addressStringFromByteString(response.getRandom());
                        }
                        Log.i(TAG, "scan observer: scan response address: " + addr);

                        if (addr.equals(address)) {
                            future.complete(response);
                        }
                    }

                    @Override
                    public void onError(Throwable e) {
                        Log.e(TAG, "scan observer: on error " + e);
                        future.completeExceptionally(e);
                    }

                    @Override
                    public void onCompleted() {
                        Log.i(TAG, "scan observer: on completed");
                        future.complete(null);
                    }
                };

        Deadline initialDeadline = Deadline.after(TIMEOUT_ADVERTISING_MS, TimeUnit.MILLISECONDS);
        withCancellation.run(
                () -> mBumble.host().withDeadline(initialDeadline).scan(request, responseObserver));

        return future.whenComplete(
                (input, exception) -> {
                    withCancellation.cancel(null);
                });
    }
}
