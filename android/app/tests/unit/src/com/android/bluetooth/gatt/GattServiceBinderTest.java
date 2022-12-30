/*
 * Copyright 2022 The Android Open Source Project
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

package com.android.bluetooth.gatt;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.app.PendingIntent;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.IBluetoothGattCallback;
import android.bluetooth.IBluetoothGattServerCallback;
import android.bluetooth.le.IScannerCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanSettings;
import android.content.AttributionSource;
import android.content.Context;
import android.content.Intent;
import android.os.ParcelUuid;
import android.os.WorkSource;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.x.com.android.modules.utils.SynchronousResultReceiver;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@SmallTest
@RunWith(AndroidJUnit4.class)
public class GattServiceBinderTest {

    private static final String REMOTE_DEVICE_ADDRESS = "00:00:00:00:00:00";

    @Mock
    private GattService mService;

    private Context mContext;
    private PendingIntent mPendingIntent;
    private AttributionSource mAttributionSource;

    private GattService.BluetoothGattBinder mBinder;

    @Before
    public void setUp() throws Exception {
        mContext = InstrumentationRegistry.getTargetContext();
        Intent intent = new Intent();
        mPendingIntent = PendingIntent.getBroadcast(mContext, 0, intent,
                PendingIntent.FLAG_IMMUTABLE);
        MockitoAnnotations.initMocks(this);
        when(mService.isAvailable()).thenReturn(true);
        mBinder = new GattService.BluetoothGattBinder(mService);
        mAttributionSource = new AttributionSource.Builder(1).build();
    }

    @Test
    public void getDevicesMatchingConnectionStates() {
        int[] states = new int[] {BluetoothProfile.STATE_CONNECTED};

        mBinder.getDevicesMatchingConnectionStates(states, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).getDevicesMatchingConnectionStates(states, mAttributionSource);
    }

    @Test
    public void registerClient() {
        UUID uuid = UUID.randomUUID();
        IBluetoothGattCallback callback = mock(IBluetoothGattCallback.class);
        boolean eattSupport = true;

        mBinder.registerClient(new ParcelUuid(uuid), callback, eattSupport, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).registerClient(uuid, callback, eattSupport, mAttributionSource);
    }

    @Test
    public void unregisterClient() {
        int clientIf = 3;

        mBinder.unregisterClient(clientIf, mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).unregisterClient(clientIf, mAttributionSource);
    }

    @Test
    public void registerScanner() throws Exception {
        IScannerCallback callback = mock(IScannerCallback.class);
        WorkSource workSource = mock(WorkSource.class);

        mBinder.registerScanner(callback, workSource, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).registerScanner(callback, workSource, mAttributionSource);
    }

    @Test
    public void unregisterScanner() {
        int scannerId = 3;

        mBinder.unregisterScanner(scannerId, mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).unregisterScanner(scannerId, mAttributionSource);
    }

    @Test
    public void startScan() throws Exception {
        int scannerId = 1;
        ScanSettings settings = new ScanSettings.Builder().build();
        List<ScanFilter> filters = new ArrayList<>();

        mBinder.startScan(scannerId, settings, filters, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).startScan(scannerId, settings, filters, mAttributionSource);
    }

    @Test
    public void startScanForIntent() throws Exception {
        ScanSettings settings = new ScanSettings.Builder().build();
        List<ScanFilter> filters = new ArrayList<>();

        mBinder.startScanForIntent(mPendingIntent, settings, filters, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).registerPiAndStartScan(mPendingIntent, settings, filters,
                mAttributionSource);
    }

    @Test
    public void stopScanForIntent() throws Exception {
        mBinder.stopScanForIntent(mPendingIntent, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).stopScan(mPendingIntent, mAttributionSource);
    }

    @Test
    public void stopScan() throws Exception {
        int scannerId = 3;

        mBinder.stopScan(scannerId, mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).stopScan(scannerId, mAttributionSource);
    }

    @Test
    public void flushPendingBatchResults() throws Exception {
        int scannerId = 3;

        mBinder.flushPendingBatchResults(scannerId, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).flushPendingBatchResults(scannerId, mAttributionSource);
    }

    @Test
    public void clientConnect() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        boolean isDirect = true;
        int transport = 2;
        boolean opportunistic = true;
        int phy = 3;

        mBinder.clientConnect(clientIf, address, isDirect, transport, opportunistic, phy,
                mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).clientConnect(clientIf, address, isDirect, transport, opportunistic, phy,
                mAttributionSource);
    }

    @Test
    public void clientDisconnect() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        mBinder.clientDisconnect(clientIf, address, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).clientDisconnect(clientIf, address, mAttributionSource);
    }

    @Test
    public void clientSetPreferredPhy() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int txPhy = 2;
        int rxPhy = 1;
        int phyOptions = 3;

        mBinder.clientSetPreferredPhy(clientIf, address, txPhy, rxPhy, phyOptions,
                mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).clientSetPreferredPhy(clientIf, address, txPhy, rxPhy, phyOptions,
                mAttributionSource);
    }

    @Test
    public void clientReadPhy() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        mBinder.clientReadPhy(clientIf, address, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).clientReadPhy(clientIf, address, mAttributionSource);
    }

    @Test
    public void refreshDevice() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        mBinder.refreshDevice(clientIf, address, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).refreshDevice(clientIf, address, mAttributionSource);
    }

    @Test
    public void discoverServices() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        mBinder.discoverServices(clientIf, address, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).discoverServices(clientIf, address, mAttributionSource);
    }

    @Test
    public void discoverServiceByUuid() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        UUID uuid = UUID.randomUUID();

        mBinder.discoverServiceByUuid(clientIf, address, new ParcelUuid(uuid), mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).discoverServiceByUuid(clientIf, address, uuid, mAttributionSource);
    }

    @Test
    public void readCharacteristic() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int handle = 2;
        int authReq = 3;

        mBinder.readCharacteristic(clientIf, address, handle, authReq, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).readCharacteristic(clientIf, address, handle, authReq, mAttributionSource);
    }

    @Test
    public void readUsingCharacteristicUuid() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        UUID uuid = UUID.randomUUID();
        int startHandle = 2;
        int endHandle = 3;
        int authReq = 4;

        mBinder.readUsingCharacteristicUuid(clientIf, address, new ParcelUuid(uuid),
                startHandle, endHandle, authReq, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).readUsingCharacteristicUuid(clientIf, address, uuid, startHandle,
                endHandle, authReq, mAttributionSource);
    }

    @Test
    public void writeCharacteristic() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int handle = 2;
        int writeType = 3;
        int authReq = 4;
        byte[] value = new byte[] {5, 6};

        mBinder.writeCharacteristic(clientIf, address, handle, writeType, authReq,
                value, mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).writeCharacteristic(clientIf, address, handle, writeType, authReq, value,
                mAttributionSource);
    }

    @Test
    public void readDescriptor() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int handle = 2;
        int authReq = 3;

        mBinder.readDescriptor(clientIf, address, handle, authReq, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).readDescriptor(clientIf, address, handle, authReq, mAttributionSource);
    }

    @Test
    public void writeDescriptor() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int handle = 2;
        int authReq = 3;
        byte[] value = new byte[] {4, 5};

        mBinder.writeDescriptor(clientIf, address, handle, authReq, value,
                mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).writeDescriptor(clientIf, address, handle, authReq, value,
                mAttributionSource);
    }

    @Test
    public void beginReliableWrite() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        mBinder.beginReliableWrite(clientIf, address, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).beginReliableWrite(clientIf, address, mAttributionSource);
    }

    @Test
    public void endReliableWrite() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        boolean execute = true;

        mBinder.endReliableWrite(clientIf, address, execute, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).endReliableWrite(clientIf, address, execute, mAttributionSource);
    }

    @Test
    public void registerForNotification() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int handle = 2;
        boolean enable = true;

        mBinder.registerForNotification(clientIf, address, handle, enable,
                mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).registerForNotification(clientIf, address, handle, enable,
                mAttributionSource);
    }

    @Test
    public void readRemoteRssi() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;

        mBinder.readRemoteRssi(clientIf, address, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).readRemoteRssi(clientIf, address, mAttributionSource);
    }

    @Test
    public void configureMTU() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int mtu = 2;

        mBinder.configureMTU(clientIf, address, mtu, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).configureMTU(clientIf, address, mtu, mAttributionSource);
    }

    @Test
    public void connectionParameterUpdate() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int connectionPriority = 2;

        mBinder.connectionParameterUpdate(clientIf, address, connectionPriority,
                mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).connectionParameterUpdate(clientIf, address, connectionPriority,
                mAttributionSource);
    }

    @Test
    public void leConnectionUpdate() throws Exception {
        int clientIf = 1;
        String address = REMOTE_DEVICE_ADDRESS;
        int minConnectionInterval = 3;
        int maxConnectionInterval = 4;
        int peripheralLatency = 5;
        int supervisionTimeout = 6;
        int minConnectionEventLen = 7;
        int maxConnectionEventLen = 8;

        mBinder.leConnectionUpdate(clientIf, address, minConnectionInterval, maxConnectionInterval,
                peripheralLatency, supervisionTimeout, minConnectionEventLen,
                maxConnectionEventLen, mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).leConnectionUpdate(
                clientIf, address, minConnectionInterval, maxConnectionInterval,
                peripheralLatency, supervisionTimeout, minConnectionEventLen,
                maxConnectionEventLen, mAttributionSource);
    }

    @Test
    public void registerServer() {
        UUID uuid = UUID.randomUUID();
        IBluetoothGattServerCallback callback = mock(IBluetoothGattServerCallback.class);
        boolean eattSupport = true;

        mBinder.registerServer(new ParcelUuid(uuid), callback, eattSupport, mAttributionSource,
                SynchronousResultReceiver.get());

        verify(mService).registerServer(uuid, callback, eattSupport, mAttributionSource);
    }

    @Test
    public void unregisterServer() {
        int serverIf = 3;

        mBinder.unregisterServer(serverIf, mAttributionSource, SynchronousResultReceiver.get());

        verify(mService).unregisterServer(serverIf, mAttributionSource);
    }

    @Test
    public void cleanUp_doesNotCrash() {
        mBinder.cleanup();
    }
}
