package com.android.bluetooth.hfpclient;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadsetClient;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.os.HandlerThread;
import android.support.test.espresso.intent.matcher.IntentMatchers;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;

import org.hamcrest.core.AllOf;
import org.hamcrest.core.IsInstanceOf;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.hamcrest.MockitoHamcrest;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class HeadsetClientStateMachineTest {
    private BluetoothAdapter mAdapter;
    private HandlerThread mHandlerThread;
    private HeadsetClientStateMachine mHeadsetClientStateMachine;
    private BluetoothDevice mTestDevice;

    @Mock private HeadsetClientService mHeadsetClientService;
    @Mock private AudioManager mAudioManager;

    @Before
    public void setUp() {
        // Setup mocks and test assets
        MockitoAnnotations.initMocks(this);
        // Set a valid volume
        when(mAudioManager.getStreamVolume(anyInt())).thenReturn(2);
        when(mAudioManager.getStreamMaxVolume(anyInt())).thenReturn(10);
        when(mAudioManager.getStreamMinVolume(anyInt())).thenReturn(1);
        when(mHeadsetClientService.getSystemService(Context.AUDIO_SERVICE)).thenReturn(
                mAudioManager);
        // This line must be called to make sure relevant objects are initialized properly
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        // Get a device for testing
        mTestDevice = mAdapter.getRemoteDevice("00:01:02:03:04:05");

        // Setup thread and looper
        mHandlerThread = new HandlerThread("HeadsetClientStateMachineTestHandlerThread");
        mHandlerThread.start();
        // Manage looper execution in main test thread explicitly to guarantee timing consistency
        mHeadsetClientStateMachine =
                new HeadsetClientStateMachine(mHeadsetClientService, mHandlerThread.getLooper());
        mHeadsetClientStateMachine.start();
    }

    @After
    public void tearDown() {
        mHeadsetClientStateMachine.doQuit();
        mHandlerThread.quit();
    }

    /**
     * Test that default state is disconnected
     */
    @Test
    public void testDefaultDisconnectedState() {
        Assert.assertEquals(mHeadsetClientStateMachine.getConnectionState(null),
                BluetoothProfile.STATE_DISCONNECTED);
    }

    /**
     * Test that an incoming connection with low priority is rejected
     */
    @Test
    public void testIncomingPriorityReject() {
        // Return false for priority.
        when(mHeadsetClientService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_OFF);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that only DISCONNECTED -> DISCONNECTED broadcast is fired
        verify(mHeadsetClientService, timeout(1000)).sendBroadcast(MockitoHamcrest.argThat(
                AllOf.allOf(IntentMatchers.hasAction(
                        BluetoothHeadsetClient.ACTION_CONNECTION_STATE_CHANGED),
                        IntentMatchers.hasExtra(BluetoothProfile.EXTRA_STATE,
                                BluetoothProfile.STATE_DISCONNECTED),
                        IntentMatchers.hasExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                                BluetoothProfile.STATE_DISCONNECTED))), anyString());
        // Check we are in disconnected state still.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Disconnected.class));
    }

    /**
     * Test that an incoming connection with high priority is accepted
     */
    @Test
    public void testIncomingPriorityAccept() {
        // Return true for priority.
        when(mHeadsetClientService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_ON);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(1000)).sendBroadcast(intentArgument1.capture(),
                anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Connecting.class));

        // Send a message to trigger SLC connection
        StackEvent slcEvent = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        slcEvent.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_SLC_CONNECTED;
        slcEvent.valueInt2 = HeadsetClientHalConstants.PEER_FEAT_ECS;
        slcEvent.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, slcEvent);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(1000).times(2)).sendBroadcast(
                intentArgument2.capture(), anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        // Check we are in connecting state now.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Connected.class));
    }

    /**
     * Test that an incoming connection that times out
     */
    @Test
    public void testIncomingTimeout() {
        // Return true for priority.
        when(mHeadsetClientService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_ON);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(1000)).sendBroadcast(intentArgument1.capture(),
                anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Connecting.class));

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService,
                timeout(HeadsetClientStateMachine.CONNECTING_TIMEOUT_MS * 2).times(
                        2)).sendBroadcast(intentArgument2.capture(), anyString());
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Disconnected.class));
    }
}
