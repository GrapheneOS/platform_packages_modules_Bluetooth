/*
 * Copyright (C) 2021 The Android Open Source Project
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

package com.android.bluetooth.hfpclient.connserv;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth.assertWithMessage;

import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadsetClient;
import android.bluetooth.BluetoothHeadsetClientCall;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.telecom.Connection;
import android.telecom.ConnectionRequest;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;

import androidx.test.InstrumentationRegistry;
import androidx.test.filters.MediumTest;
import androidx.test.rule.ServiceTestRule;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.R;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class HfpClientConnectionServiceTest {
    private static final BluetoothDevice TEST_DEVICE =
            ((BluetoothManager) InstrumentationRegistry.getTargetContext()
                    .getSystemService(Context.BLUETOOTH_SERVICE))
            .getAdapter().getRemoteDevice("00:11:22:33:44:55");
    private static final long TIMEOUT_MS = 1000;

    @Rule
    public final MockitoRule mockito = MockitoJUnit.rule();
    @Rule
    public final ServiceTestRule mServiceRule = new ServiceTestRule();

    @Mock
    private BluetoothHeadsetClientProxy mBluetoothHeadsetClientProxy;

    private BlockingHfpClientDeviceBlock mHfpClientDeviceBlock;
    private HfpClientConnectionService mHfpClientConnectionService;
    private PhoneAccountHandle mPhoneAccountHandle;

    @Before
    public void setUp() {
        // HfpClientConnectionService is only enabled for some form factors, and the tests should
        // only be run if the service is enabled.
        assumeTrue(
                InstrumentationRegistry.getTargetContext()
                        .getResources().getBoolean(R.bool.hfp_client_connection_service_enabled));
    }

    @Test
    public void serviceConnectedWithAlreadyConnectedDevice_blockIsCreated() throws Exception {
        when(mBluetoothHeadsetClientProxy.getConnectedDevices()).thenReturn(
                List.of(TEST_DEVICE));
        BluetoothHeadsetClientProxy.Factory.setInstance(new BluetoothHeadsetClientProxy.Factory() {
            @Override
            protected BluetoothHeadsetClientProxy buildInternal(BluetoothHeadsetClient proxy) {
                return mBluetoothHeadsetClientProxy;
            }
        });
        HfpClientDeviceBlock mockHfpClientDeviceBlock = mock(HfpClientDeviceBlock.class);
        HfpClientDeviceBlock.Factory.setInstance(new HfpClientDeviceBlock.Factory() {
            @Override
            protected HfpClientDeviceBlock buildInternal(
                    com.android.bluetooth.hfpclient.connserv.HfpClientConnectionService connServ,
                    BluetoothDevice device, BluetoothHeadsetClientProxy profileProxy) {
                return mockHfpClientDeviceBlock;
            }
        });

        mHfpClientConnectionService = new HfpClientConnectionService();
        // Call onServiceConnected with a null proxy, because it isn't used by the test Factory
        // to create the mock BluetoothHeadsetClientProxy
        mHfpClientConnectionService.mServiceListener.onServiceConnected(
                BluetoothProfile.HEADSET_CLIENT,
                /* proxy= */ null);

        assertThat(mHfpClientConnectionService.findBlockForDevice(TEST_DEVICE)).isEqualTo(
                mockHfpClientDeviceBlock);
    }

    @Test
    public void startServiceAndConnectDevice_blockIsCreated() throws Exception {
        startServiceAndConnectDevice(TEST_DEVICE);

        assertThat(mHfpClientConnectionService.findBlockForDevice(TEST_DEVICE)).isEqualTo(
                mHfpClientDeviceBlock);
    }

    @Test
    public void disconnectDevice_blockIsRemoved() throws Exception {
        startServiceAndConnectDevice(TEST_DEVICE);

        InstrumentationRegistry.getTargetContext().sendBroadcast(
                createDeviceDisconnectedIntent(TEST_DEVICE));

        assertThat(mHfpClientDeviceBlock.blockIsCleanedUp()).isTrue();
        assertThat(mHfpClientConnectionService.findBlockForDevice(TEST_DEVICE)).isNull();
    }

    @Test
    public void callChanged_handleCall() throws Exception {
        startServiceAndConnectDevice(TEST_DEVICE);
        BluetoothHeadsetClientCall call = new BluetoothHeadsetClientCall(TEST_DEVICE, /* id= */0,
                BluetoothHeadsetClientCall.CALL_STATE_ACTIVE, /* number= */ "000-111-2222",
                /* multiParty= */ false, /* outgoing= */false, /* inBandRing= */true);

        InstrumentationRegistry.getTargetContext().sendBroadcast(createCallChangedIntent(call));
        assertThat(mHfpClientDeviceBlock.callIsHandled()).isTrue();
    }

    @Test
    public void audioStateChanged_onAudioStateChanged() throws Exception {
        startServiceAndConnectDevice(TEST_DEVICE);

        InstrumentationRegistry.getTargetContext().sendBroadcast(
                createAudioStateChangedIntent(TEST_DEVICE));
        assertThat(mHfpClientDeviceBlock.audioStateIsChanged()).isTrue();
    }

    @Test
    public void onCreateIncomingConnection() throws Exception {
        startServiceAndConnectDevice(TEST_DEVICE);

        BluetoothHeadsetClientCall call = new BluetoothHeadsetClientCall(TEST_DEVICE, /* id= */0,
                BluetoothHeadsetClientCall.CALL_STATE_ACTIVE, /* number= */ "000-111-2222",
                /* multiParty= */ false, /* outgoing= */false, /* inBandRing= */true);
        mHfpClientDeviceBlock.handleCall(call);

        Bundle extras = new Bundle();
        extras.putParcelable(TelecomManager.EXTRA_INCOMING_CALL_EXTRAS, call);
        ConnectionRequest connectionRequest = new ConnectionRequest.Builder().setExtras(
                extras).build();

        Connection connection = mHfpClientConnectionService.onCreateIncomingConnection(
                mPhoneAccountHandle,
                connectionRequest);

        assertThat(connection).isNotNull();
        assertThat(((HfpClientConnection) connection).getHfpClientConnectionService())
                .isEqualTo(mHfpClientConnectionService);
    }

    @Test
    public void onCreateOutgoingConnection() throws Exception {
        startServiceAndConnectDevice(TEST_DEVICE);

        BluetoothHeadsetClientCall call = new BluetoothHeadsetClientCall(TEST_DEVICE, /* id= */0,
                BluetoothHeadsetClientCall.CALL_STATE_ACTIVE, /* number= */ "000-111-2222",
                /* multiParty= */ false, /* outgoing= */true, /* inBandRing= */true);

        Bundle extras = new Bundle();
        extras.putParcelable(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS, call);
        ConnectionRequest connectionRequest = new ConnectionRequest.Builder().setExtras(
                extras).setAddress(Uri.fromParts(
                PhoneAccount.SCHEME_TEL, "000-111-2222", null)).build();

        Connection connection = mHfpClientConnectionService.onCreateOutgoingConnection(
                mPhoneAccountHandle,
                connectionRequest);

        assertThat(connection).isNotNull();
        assertThat(((HfpClientConnection) connection).getHfpClientConnectionService())
                .isEqualTo(mHfpClientConnectionService);
    }

    @Test
    public void onCreateUnknownConnection() throws Exception {
        startServiceAndConnectDevice(TEST_DEVICE);

        BluetoothHeadsetClientCall call = new BluetoothHeadsetClientCall(TEST_DEVICE, /* id= */0,
                BluetoothHeadsetClientCall.CALL_STATE_ACTIVE, /* number= */ "000-111-2222",
                /* multiParty= */ false, /* outgoing= */true, /* inBandRing= */true);
        mHfpClientDeviceBlock.handleCall(call);

        Bundle extras = new Bundle();
        extras.putParcelable(TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS, call);
        ConnectionRequest connectionRequest = new ConnectionRequest.Builder().setExtras(
                extras).setAddress(Uri.fromParts(
                PhoneAccount.SCHEME_TEL, "000-111-2222", null)).build();

        Connection connection = mHfpClientConnectionService.onCreateUnknownConnection(
                mPhoneAccountHandle,
                connectionRequest);

        assertThat(connection).isNotNull();
        assertThat(((HfpClientConnection) connection).getHfpClientConnectionService())
                .isEqualTo(mHfpClientConnectionService);
    }

    private static Intent createDeviceConnectedIntent(BluetoothDevice device) {
        Intent intent = new Intent(BluetoothHeadsetClient.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, BluetoothProfile.STATE_CONNECTED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        return intent;
    }

    private static Intent createDeviceDisconnectedIntent(BluetoothDevice device) {
        Intent intent = new Intent(BluetoothHeadsetClient.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, BluetoothProfile.STATE_DISCONNECTED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        return intent;
    }

    private static Intent createCallChangedIntent(BluetoothHeadsetClientCall call) {
        Intent intent = new Intent(BluetoothHeadsetClient.ACTION_CALL_CHANGED);
        intent.putExtra(BluetoothHeadsetClient.EXTRA_CALL, call);
        return intent;
    }

    private static Intent createAudioStateChangedIntent(BluetoothDevice device) {
        Intent intent = new Intent(BluetoothHeadsetClient.ACTION_AUDIO_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, BluetoothProfile.STATE_CONNECTING);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, BluetoothProfile.STATE_DISCONNECTED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        return intent;
    }

    private static Intent createServiceIntent() {
        return new Intent(InstrumentationRegistry.getTargetContext(),
                HfpClientConnectionService.class);
    }

    private void startServiceAndConnectDevice(BluetoothDevice device) throws Exception {
        CountDownLatch buildLatch = new CountDownLatch(1);
        HfpClientDeviceBlock.Factory.setInstance(createDeviceBlockFactoryForTest(buildLatch));

        mServiceRule.startService(createServiceIntent());
        InstrumentationRegistry.getTargetContext().sendBroadcast(
                createDeviceConnectedIntent(device));

        buildLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        long startTime = System.currentTimeMillis();
        while (mHfpClientConnectionService.findBlockForDevice(device) == null) {
            if (System.currentTimeMillis() - startTime > TIMEOUT_MS) {
                assertWithMessage(
                        "Timeout waiting for block to be added to HfpClientConnectionService")
                        .fail();
            }
        }
    }

    private HfpClientDeviceBlock.Factory createDeviceBlockFactoryForTest(
            CountDownLatch blockCreationLatch) {
        return new HfpClientDeviceBlock.Factory() {
            @Override
            protected HfpClientDeviceBlock buildInternal(HfpClientConnectionService connServ,
                    BluetoothDevice device,
                    BluetoothHeadsetClientProxy profileProxy) {

                // Inject spyTelecomManager so that calls to HfpClientDeviceBlock#handleCall do
                // not start HfpClientConnectionService
                TelecomManager spyTelecomManager = spy(TelecomManager.class);
                doNothing().when(spyTelecomManager).addNewIncomingCall(any(), any());
                doNothing().when(spyTelecomManager).addNewUnknownCall(any(), any());
                HfpClientConnectionService spyConnServ = spy(connServ);
                when(spyConnServ.getSystemService(TelecomManager.class)).thenReturn(
                        spyTelecomManager);

                mPhoneAccountHandle = new PhoneAccountHandle(
                        new ComponentName(connServ,
                                HfpClientConnectionService.class),
                        TEST_DEVICE.getAddress());
                BlockingHfpClientDeviceBlock block = new BlockingHfpClientDeviceBlock(spyConnServ,
                        device,
                        mBluetoothHeadsetClientProxy);
                mHfpClientConnectionService = spyConnServ;
                mHfpClientDeviceBlock = block;

                blockCreationLatch.countDown();

                return block;
            }
        };
    }

    static class BlockingHfpClientDeviceBlock extends HfpClientDeviceBlock {
        private final CountDownLatch mAudioStateChangeCountDownLatch = new CountDownLatch(1);
        private final CountDownLatch mCleanupCountDownLatch = new CountDownLatch(1);
        private final CountDownLatch mHandleCallCountDownLatch = new CountDownLatch(1);

        BlockingHfpClientDeviceBlock(HfpClientConnectionService connServ, BluetoothDevice device,
                BluetoothHeadsetClientProxy headsetProfile) {
            super(connServ, device, headsetProfile);
        }

        @Override
        synchronized void onAudioStateChange(int newState, int oldState) {
            super.onAudioStateChange(newState, oldState);
            mAudioStateChangeCountDownLatch.countDown();
        }

        @Override
        synchronized void cleanup() {
            super.cleanup();
            mCleanupCountDownLatch.countDown();
        }

        @Override
        synchronized void handleCall(BluetoothHeadsetClientCall call) {
            super.handleCall(call);
            mHandleCallCountDownLatch.countDown();
        }

        boolean audioStateIsChanged() throws InterruptedException {
            return mAudioStateChangeCountDownLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }

        boolean blockIsCleanedUp() throws InterruptedException {
            return mCleanupCountDownLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }

        boolean callIsHandled() throws InterruptedException {
            return mHandleCallCountDownLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS);
        }
    }
}
