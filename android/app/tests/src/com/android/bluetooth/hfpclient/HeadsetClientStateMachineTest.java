package com.android.bluetooth.hfpclient;

import static org.mockito.Mockito.*;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;

import com.android.bluetooth.btservice.AdapterService;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;

@MediumTest
@RunWith(AndroidJUnit4.class)
public class HeadsetClientStateMachineTest {
    private BluetoothAdapter mAdapter = null;
    private Context mTargetContext;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        AdapterService inst = mock(AdapterService.class);
        Assert.assertTrue(inst != null);
        mAdapter = BluetoothAdapter.getDefaultAdapter();
    }

    /**
     * Test that default state is disconnected
     */
    @Test
    public void testDefaultDisconnectedState() {
        HeadsetClientService mockService = mock(HeadsetClientService.class);
        AudioManager mockAudioManager = mock(AudioManager.class);

        when(mockService.getSystemService(Context.AUDIO_SERVICE)).thenReturn(mockAudioManager);

        HeadsetClientStateMachine mockSM =
                new HeadsetClientStateMachine(mockService, mTargetContext.getMainLooper());
        Assert.assertEquals(mockSM.getConnectionState((BluetoothDevice) null),
                BluetoothProfile.STATE_DISCONNECTED);
    }

    /**
     * Test that an incoming connection with low priority is rejected
     */
    @Test
    public void testIncomingPriorityReject() {
        HeadsetClientService mockService = mock(HeadsetClientService.class);
        AudioManager mockAudioManager = mock(AudioManager.class);
        BluetoothDevice device = mAdapter.getRemoteDevice("00:01:02:03:04:05");

        when(mockService.getSystemService(Context.AUDIO_SERVICE)).thenReturn(mockAudioManager);

        HeadsetClientStateMachine mockSM =
                new HeadsetClientStateMachine(mockService, mTargetContext.getMainLooper());
        mockSM.start();

        // Return false for priority.
        when(mockService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_OFF);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.valueInt2 = 0;
        connStCh.valueInt3 = 0;
        connStCh.device = device;
        mockSM.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that no connection state broadcast is executed
        verify(mockService, never()).sendBroadcast(any(Intent.class), anyString());
        // Check we are in disconnected state still.
        Assert.assertTrue(
                mockSM.getCurrentState() instanceof HeadsetClientStateMachine.Disconnected);
    }

    /**
     * Test that an incoming connection with high priority is accepted
     */
    @Test
    public void testIncomingPriorityAccept() {
        HeadsetClientService mockService = mock(HeadsetClientService.class);
        AudioManager mockAudioManager = mock(AudioManager.class);
        BluetoothDevice device = mAdapter.getRemoteDevice("00:01:02:03:04:05");

        when(mockService.getSystemService(Context.AUDIO_SERVICE)).thenReturn(mockAudioManager);
        // Set a valid volume
        when(mockAudioManager.getStreamVolume(anyInt())).thenReturn(2);
        when(mockAudioManager.getStreamMaxVolume(anyInt())).thenReturn(10);
        when(mockAudioManager.getStreamMinVolume(anyInt())).thenReturn(1);


        HeadsetClientStateMachine mockSM =
                new HeadsetClientStateMachine(mockService, mTargetContext.getMainLooper());
        mockSM.start();

        // Return false for priority.
        when(mockService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_ON);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.valueInt2 = 0;
        connStCh.valueInt3 = 0;
        connStCh.device = device;
        mockSM.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mockService, timeout(1000)).sendBroadcast(intentArgument1.capture(), anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertTrue(mockSM.getCurrentState() instanceof HeadsetClientStateMachine.Connecting);

        // Send a message to trigger SLC connection
        StackEvent slcEvent = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        slcEvent.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_SLC_CONNECTED;
        slcEvent.valueInt2 = HeadsetClientHalConstants.PEER_FEAT_ECS;
        slcEvent.valueInt3 = 0;
        slcEvent.device = device;
        mockSM.sendMessage(StackEvent.STACK_EVENT, slcEvent);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mockService, timeout(1000).times(2)).sendBroadcast(intentArgument2.capture(),
                anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        // Check we are in connecting state now.
        Assert.assertTrue(mockSM.getCurrentState() instanceof HeadsetClientStateMachine.Connected);
    }

    /**
     * Test that an incoming connection that times out
     */
    @Test
    public void testIncomingTimeout() {
        HeadsetClientService mockService = mock(HeadsetClientService.class);
        AudioManager mockAudioManager = mock(AudioManager.class);
        BluetoothDevice device = mAdapter.getRemoteDevice("00:01:02:03:04:05");

        when(mockService.getSystemService(Context.AUDIO_SERVICE)).thenReturn(mockAudioManager);
        // Set a valid volume
        when(mockAudioManager.getStreamVolume(anyInt())).thenReturn(2);
        when(mockAudioManager.getStreamMaxVolume(anyInt())).thenReturn(10);
        when(mockAudioManager.getStreamMinVolume(anyInt())).thenReturn(1);


        HeadsetClientStateMachine mockSM =
                new HeadsetClientStateMachine(mockService, mTargetContext.getMainLooper());
        mockSM.start();

        // Return false for priority.
        when(mockService.getPriority(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.PRIORITY_ON);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.valueInt2 = 0;
        connStCh.valueInt3 = 0;
        connStCh.device = device;
        mockSM.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mockService, timeout(1000)).sendBroadcast(intentArgument1.capture(), anyString());
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertTrue(mockSM.getCurrentState() instanceof HeadsetClientStateMachine.Connecting);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mockService, timeout(HeadsetClientStateMachine.CONNECTING_TIMEOUT_MS * 2).times(
                2)).sendBroadcast(intentArgument2.capture(), anyString());
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertTrue(
                mockSM.getCurrentState() instanceof HeadsetClientStateMachine.Disconnected);
    }
}
