package com.android.bluetooth.hfpclient;

import static com.android.bluetooth.hfpclient.HeadsetClientStateMachine.AT_OK;
import static com.android.bluetooth.hfpclient.HeadsetClientStateMachine.ENTER_PRIVATE_MODE;
import static com.android.bluetooth.hfpclient.HeadsetClientStateMachine.EXPLICIT_CALL_TRANSFER;
import static com.android.bluetooth.hfpclient.HeadsetClientStateMachine.VOICE_RECOGNITION_START;
import static com.android.bluetooth.hfpclient.HeadsetClientStateMachine.VOICE_RECOGNITION_STOP;

import static org.mockito.Mockito.*;

import android.app.BroadcastOptions;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothAssignedNumbers;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothHeadsetClient;
import android.bluetooth.BluetoothAudioPolicy;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.media.AudioManager;
import android.os.Bundle;
import android.os.HandlerThread;
import android.os.Message;
import android.util.Pair;

import androidx.test.InstrumentationRegistry;
import androidx.test.espresso.intent.matcher.IntentMatchers;
import androidx.test.filters.FlakyTest;
import androidx.test.filters.LargeTest;
import androidx.test.filters.MediumTest;
import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.bluetooth.R;
import com.android.bluetooth.TestUtils;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;

import org.hamcrest.core.AllOf;
import org.hamcrest.core.IsInstanceOf;
import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.hamcrest.MockitoHamcrest;

import java.util.List;
import java.util.Set;

@LargeTest
@RunWith(AndroidJUnit4.class)
public class HeadsetClientStateMachineTest {
    private BluetoothAdapter mAdapter;
    private HandlerThread mHandlerThread;
    private HeadsetClientStateMachine mHeadsetClientStateMachine;
    private BluetoothDevice mTestDevice;
    private Context mTargetContext;

    @Mock
    private AdapterService mAdapterService;
    @Mock
    private Resources mMockHfpResources;
    @Mock
    private HeadsetClientService mHeadsetClientService;
    @Mock
    private AudioManager mAudioManager;

    private NativeInterface mNativeInterface;

    private static final int STANDARD_WAIT_MILLIS = 1000;
    private static final int QUERY_CURRENT_CALLS_WAIT_MILLIS = 2000;
    private static final int QUERY_CURRENT_CALLS_TEST_WAIT_MILLIS = QUERY_CURRENT_CALLS_WAIT_MILLIS
            * 3 / 2;

    @Before
    public void setUp() throws Exception {
        mTargetContext = InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue("Ignore test when HeadsetClientService is not enabled",
                HeadsetClientService.isEnabled());
        // Setup mocks and test assets
        MockitoAnnotations.initMocks(this);
        // Set a valid volume
        when(mAudioManager.getStreamVolume(anyInt())).thenReturn(2);
        when(mAudioManager.getStreamMaxVolume(anyInt())).thenReturn(10);
        when(mAudioManager.getStreamMinVolume(anyInt())).thenReturn(1);
        when(mHeadsetClientService.getAudioManager()).thenReturn(
                mAudioManager);
        when(mHeadsetClientService.getResources()).thenReturn(mMockHfpResources);
        when(mMockHfpResources.getBoolean(R.bool.hfp_clcc_poll_during_call)).thenReturn(true);
        when(mMockHfpResources.getInteger(R.integer.hfp_clcc_poll_interval_during_call))
                .thenReturn(2000);

        TestUtils.setAdapterService(mAdapterService);
        mNativeInterface = spy(NativeInterface.getInstance());
        doReturn(true).when(mNativeInterface).sendAndroidAt(anyObject(), anyString());

        // This line must be called to make sure relevant objects are initialized properly
        mAdapter = BluetoothAdapter.getDefaultAdapter();
        // Get a device for testing
        mTestDevice = mAdapter.getRemoteDevice("00:01:02:03:04:05");

        // Setup thread and looper
        mHandlerThread = new HandlerThread("HeadsetClientStateMachineTestHandlerThread");
        mHandlerThread.start();
        // Manage looper execution in main test thread explicitly to guarantee timing consistency
        mHeadsetClientStateMachine =
                new HeadsetClientStateMachine(mHeadsetClientService, mHandlerThread.getLooper(),
                                              mNativeInterface);
        mHeadsetClientStateMachine.start();
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());
    }

    @After
    public void tearDown() throws Exception {
        if (!HeadsetClientService.isEnabled()) {
            return;
        }
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());
        TestUtils.clearAdapterService(mAdapterService);
        mHeadsetClientStateMachine.doQuit();
        mHandlerThread.quit();
    }

    /**
     * Test that default state is disconnected
     */
    @SmallTest
    @Test
    public void testDefaultDisconnectedState() {
        Assert.assertEquals(mHeadsetClientStateMachine.getConnectionState(null),
                BluetoothProfile.STATE_DISCONNECTED);
    }

    /**
     * Test that an incoming connection with low priority is rejected
     */
    @MediumTest
    @Test
    public void testIncomingPriorityReject() {
        // Return false for priority.
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_FORBIDDEN);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that only DISCONNECTED -> DISCONNECTED broadcast is fired
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS))
                .sendBroadcastMultiplePermissions(MockitoHamcrest.argThat(
                AllOf.allOf(IntentMatchers.hasAction(
                        BluetoothHeadsetClient.ACTION_CONNECTION_STATE_CHANGED),
                        IntentMatchers.hasExtra(BluetoothProfile.EXTRA_STATE,
                                BluetoothProfile.STATE_DISCONNECTED),
                        IntentMatchers.hasExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                                BluetoothProfile.STATE_DISCONNECTED))),
                any(String[].class),
                any(BroadcastOptions.class));
        // Check we are in disconnected state still.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Disconnected.class));
    }

    /**
     * Test that an incoming connection with high priority is accepted
     */
    @MediumTest
    @Test
    public void testIncomingPriorityAccept() {
        // Return true for priority.
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS))
                .sendBroadcastMultiplePermissions(intentArgument1.capture(),
                any(String[].class), any(BroadcastOptions.class));
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
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());

        setUpAndroidAt(false);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(2))
                .sendBroadcastMultiplePermissions(intentArgument2.capture(),
                any(String[].class), any(BroadcastOptions.class));
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        // Check we are in connecting state now.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Connected.class));
    }

    /**
     * Test that an incoming connection that times out
     */
    @MediumTest
    @Test
    public void testIncomingTimeout() {
        // Return true for priority.
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument1 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS))
                .sendBroadcastMultiplePermissions(intentArgument1.capture(),
                any(String[].class), any(BroadcastOptions.class));
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument1.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Connecting.class));

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument2 = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService,
                timeout(HeadsetClientStateMachine.CONNECTING_TIMEOUT_MS * 2).times(2))
                .sendBroadcastMultiplePermissions(intentArgument2.capture(),
                any(String[].class), any(BroadcastOptions.class));
        Assert.assertEquals(BluetoothProfile.STATE_DISCONNECTED,
                intentArgument2.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Check we are in connecting state now.
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Disconnected.class));
    }

    /**
     * Test that In Band Ringtone information is relayed from phone.
     */
    @LargeTest
    @Test
    @FlakyTest
    public void testInBandRingtone() {
        // Return true for priority.
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);

        Assert.assertEquals(false, mHeadsetClientStateMachine.getInBandRing());

        // Inject an event for when incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);

        int expectedBroadcastIndex = 1;
        int expectedBroadcastMultiplePermissionsIndex = 1;

        // Verify that one connection state broadcast is executed
        ArgumentCaptor<Intent> intentArgument = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService,
                timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastMultiplePermissionsIndex++))
                .sendBroadcastMultiplePermissions(intentArgument.capture(),
                any(String[].class), any(BroadcastOptions.class));
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        // Send a message to trigger SLC connection
        StackEvent slcEvent = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        slcEvent.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_SLC_CONNECTED;
        slcEvent.valueInt2 = HeadsetClientHalConstants.PEER_FEAT_ECS;
        slcEvent.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, slcEvent);
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());

        setUpAndroidAt(false);

        verify(mHeadsetClientService,
                timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastMultiplePermissionsIndex++))
                .sendBroadcastMultiplePermissions(intentArgument.capture(),
                any(String[].class), any(BroadcastOptions.class));

        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                intentArgument.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));

        StackEvent event = new StackEvent(StackEvent.EVENT_TYPE_IN_BAND_RINGTONE);
        event.valueInt = 0;
        event.device = mTestDevice;

        // Enable In Band Ring and verify state gets propagated.
        StackEvent eventInBandRing = new StackEvent(StackEvent.EVENT_TYPE_IN_BAND_RINGTONE);
        eventInBandRing.valueInt = 1;
        eventInBandRing.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, eventInBandRing);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastIndex++))
                .sendBroadcast(
                intentArgument.capture(),
                anyString(), any(Bundle.class));
        Assert.assertEquals(1,
                intentArgument.getValue().getIntExtra(BluetoothHeadsetClient.EXTRA_IN_BAND_RING,
                        -1));
        Assert.assertEquals(true, mHeadsetClientStateMachine.getInBandRing());

        // Simulate a new incoming phone call
        StackEvent eventCallStatusUpdated = new StackEvent(StackEvent.EVENT_TYPE_CLIP);
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, eventCallStatusUpdated);
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());
        verify(mHeadsetClientService,
                timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastIndex - 1))
                .sendBroadcast(
                intentArgument.capture(),
                anyString(),any(Bundle.class));

        // Provide information about the new call
        StackEvent eventIncomingCall = new StackEvent(StackEvent.EVENT_TYPE_CURRENT_CALLS);
        eventIncomingCall.valueInt = 1; //index
        eventIncomingCall.valueInt2 = 1; //direction
        eventIncomingCall.valueInt3 = 4; //state
        eventIncomingCall.valueInt4 = 0; //multi party
        eventIncomingCall.valueString = "5551212"; //phone number
        eventIncomingCall.device = mTestDevice;

        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, eventIncomingCall);
        verify(mHeadsetClientService,
                timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastIndex - 1))
                .sendBroadcast(
                intentArgument.capture(),
                anyString(), any(Bundle.class));


        // Signal that the complete list of calls was received.
        StackEvent eventCommandStatus = new StackEvent(StackEvent.EVENT_TYPE_CMD_RESULT);
        eventCommandStatus.valueInt = AT_OK;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, eventCommandStatus);
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());
        verify(mHeadsetClientService,
                timeout(QUERY_CURRENT_CALLS_TEST_WAIT_MILLIS).times(expectedBroadcastIndex++))
                .sendBroadcast(
                intentArgument.capture(),
                anyString(), any(Bundle.class));
        // Verify that the new call is being registered with the inBandRing flag set.
        Assert.assertEquals(true,
                ((HfpClientCall) intentArgument.getValue().getParcelableExtra(
                        BluetoothHeadsetClient.EXTRA_CALL)).isInBandRing());

        // Disable In Band Ring and verify state gets propagated.
        eventInBandRing.valueInt = 0;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, eventInBandRing);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastIndex++))
                .sendBroadcast(
                intentArgument.capture(),
                anyString(), any(Bundle.class));
        Assert.assertEquals(0,
                intentArgument.getValue().getIntExtra(BluetoothHeadsetClient.EXTRA_IN_BAND_RING,
                        -1));
        Assert.assertEquals(false, mHeadsetClientStateMachine.getInBandRing());

    }

    /* Utility function to simulate HfpClient is connected. */
    private int setUpHfpClientConnection(int startBroadcastIndex) {
        // Trigger an incoming connection is requested
        StackEvent connStCh = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        connStCh.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_CONNECTED;
        connStCh.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, connStCh);
        ArgumentCaptor<Intent> intentArgument = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(startBroadcastIndex))
                .sendBroadcastMultiplePermissions(intentArgument.capture(),
                                                  any(String[].class), any(BroadcastOptions.class));
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTING,
                intentArgument.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        startBroadcastIndex++;
        return startBroadcastIndex;
    }

    /* Utility function to simulate SLC connection. */
    private int setUpServiceLevelConnection(int startBroadcastIndex) {
        return setUpServiceLevelConnection(startBroadcastIndex, false);
    }

    private int setUpServiceLevelConnection(int startBroadcastIndex, boolean androidAtSupported) {
        // Trigger SLC connection
        StackEvent slcEvent = new StackEvent(StackEvent.EVENT_TYPE_CONNECTION_STATE_CHANGED);
        slcEvent.valueInt = HeadsetClientHalConstants.CONNECTION_STATE_SLC_CONNECTED;
        slcEvent.valueInt2 = HeadsetClientHalConstants.PEER_FEAT_ECS;
        slcEvent.valueInt2 |= HeadsetClientHalConstants.PEER_FEAT_HF_IND;
        slcEvent.device = mTestDevice;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, slcEvent);
        TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());

        setUpAndroidAt(androidAtSupported);

        ArgumentCaptor<Intent> intentArgument = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(startBroadcastIndex))
                .sendBroadcastMultiplePermissions(intentArgument.capture(),
                                                  any(String[].class), any(BroadcastOptions.class));
        Assert.assertEquals(BluetoothProfile.STATE_CONNECTED,
                intentArgument.getValue().getIntExtra(BluetoothProfile.EXTRA_STATE, -1));
        Assert.assertThat(mHeadsetClientStateMachine.getCurrentState(),
                IsInstanceOf.instanceOf(HeadsetClientStateMachine.Connected.class));

        startBroadcastIndex++;
        return startBroadcastIndex;
    }

    /**
     * Set up and verify AT Android related commands and events.
     * Make sure this method is invoked after SLC is setup.
     */
    private void setUpAndroidAt(boolean androidAtSupported) {
        verify(mNativeInterface).sendAndroidAt(mTestDevice, "+ANDROID=?");
        if (androidAtSupported) {
            StackEvent unknownEvt = new StackEvent(StackEvent.EVENT_TYPE_UNKNOWN_EVENT);
            unknownEvt.valueString = "+ANDROID: 1";
            unknownEvt.device = mTestDevice;
            mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, unknownEvt);
            TestUtils.waitForLooperToFinishScheduledTask(mHandlerThread.getLooper());
            verify(mHeadsetClientService).setAudioPolicyRemoteSupported(mTestDevice, true);
            mHeadsetClientStateMachine.setAudioPolicyRemoteSupported(true);
        } else {
            // receive CMD_RESULT CME_ERROR due to remote not supporting Android AT
            StackEvent cmdResEvt = new StackEvent(StackEvent.EVENT_TYPE_CMD_RESULT);
            cmdResEvt.valueInt = StackEvent.CMD_RESULT_TYPE_CME_ERROR;
            cmdResEvt.device = mTestDevice;
            mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, cmdResEvt);
        }
    }

    /* Utility function: supported AT command should lead to native call */
    private void runSupportedVendorAtCommand(String atCommand, int vendorId) {
        // Return true for priority.
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);

        int expectedBroadcastIndex = 1;

        expectedBroadcastIndex = setUpHfpClientConnection(expectedBroadcastIndex);
        expectedBroadcastIndex = setUpServiceLevelConnection(expectedBroadcastIndex);

        Message msg = mHeadsetClientStateMachine.obtainMessage(
                HeadsetClientStateMachine.SEND_VENDOR_AT_COMMAND, vendorId, 0, atCommand);
        mHeadsetClientStateMachine.sendMessage(msg);

        verify(mNativeInterface, timeout(STANDARD_WAIT_MILLIS).times(1)).sendATCmd(
                mTestDevice,
                HeadsetClientHalConstants.HANDSFREECLIENT_AT_CMD_VENDOR_SPECIFIC_CMD,
                0, 0, atCommand);
    }

    /**
     *  Test: supported vendor specific command: set operation
     */
    @LargeTest
    @Test
    public void testSupportedVendorAtCommandSet() {
        int vendorId = BluetoothAssignedNumbers.APPLE;
        String atCommand = "+XAPL=ABCD-1234-0100,100";
        runSupportedVendorAtCommand(atCommand, vendorId);
    }

    /**
     *  Test: supported vendor specific command: read operation
     */
    @LargeTest
    @Test
    public void testSupportedVendorAtCommandRead() {
        int vendorId = BluetoothAssignedNumbers.APPLE;
        String atCommand = "+APLSIRI?";
        runSupportedVendorAtCommand(atCommand, vendorId);
    }

    /* utility function: unsupported vendor specific command shall be filtered. */
    public void runUnsupportedVendorAtCommand(String atCommand, int vendorId) {
        // Return true for priority.
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);

        int expectedBroadcastIndex = 1;

        expectedBroadcastIndex = setUpHfpClientConnection(expectedBroadcastIndex);
        expectedBroadcastIndex = setUpServiceLevelConnection(expectedBroadcastIndex);

        Message msg = mHeadsetClientStateMachine.obtainMessage(
                HeadsetClientStateMachine.SEND_VENDOR_AT_COMMAND, vendorId, 0, atCommand);
        mHeadsetClientStateMachine.sendMessage(msg);

        verify(mNativeInterface, timeout(STANDARD_WAIT_MILLIS).times(0))
                .sendATCmd(any(), anyInt(), anyInt(), anyInt(), any());
    }

    /**
     *  Test: unsupported vendor specific command shall be filtered: bad command code
     */
    @LargeTest
    @Test
    public void testUnsupportedVendorAtCommandBadCode() {
        String atCommand = "+XAAPL=ABCD-1234-0100,100";
        int vendorId = BluetoothAssignedNumbers.APPLE;
        runUnsupportedVendorAtCommand(atCommand, vendorId);
    }

    /**
     *  Test: unsupported vendor specific command shall be filtered:
     *  no back to back command
     */
    @LargeTest
    @Test
    public void testUnsupportedVendorAtCommandBackToBack() {
        String atCommand = "+XAPL=ABCD-1234-0100,100; +XAPL=ab";
        int vendorId = BluetoothAssignedNumbers.APPLE;
        runUnsupportedVendorAtCommand(atCommand, vendorId);
    }

    /* Utility test function: supported vendor specific event
     * shall lead to broadcast intent
     */
    private void runSupportedVendorEvent(int vendorId, String vendorEventCode,
            String vendorEventArgument) {
        // Setup connection state machine to be in connected state
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        int expectedBroadcastIndex = 1;
        int expectedBroadcastMultiplePermissionsIndex = 1;
        expectedBroadcastMultiplePermissionsIndex =
            setUpHfpClientConnection(expectedBroadcastMultiplePermissionsIndex);
        expectedBroadcastMultiplePermissionsIndex =
            setUpServiceLevelConnection(expectedBroadcastMultiplePermissionsIndex);

        // Simulate a known event arrive
        String vendorEvent = vendorEventCode + vendorEventArgument;
        StackEvent event = new StackEvent(StackEvent.EVENT_TYPE_UNKNOWN_EVENT);
        event.device = mTestDevice;
        event.valueString = vendorEvent;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, event);

        // Validate broadcast intent
        ArgumentCaptor<Intent> intentArgument = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastIndex))
                .sendBroadcast(intentArgument.capture(), anyString(), any(Bundle.class));
        Assert.assertEquals(BluetoothHeadsetClient.ACTION_VENDOR_SPECIFIC_HEADSETCLIENT_EVENT,
                intentArgument.getValue().getAction());
        Assert.assertEquals(vendorId,
                intentArgument.getValue().getIntExtra(BluetoothHeadsetClient.EXTRA_VENDOR_ID, -1));
        Assert.assertEquals(vendorEventCode,
                intentArgument.getValue().getStringExtra(
                    BluetoothHeadsetClient.EXTRA_VENDOR_EVENT_CODE));
        Assert.assertEquals(vendorEvent,
                intentArgument.getValue().getStringExtra(
                    BluetoothHeadsetClient.EXTRA_VENDOR_EVENT_FULL_ARGS));
    }

    /**
     *  Test: supported vendor specific response: response to read command
     */
    @LargeTest
    @Test
    public void testSupportedVendorEventReadResponse() {
        final int vendorId = BluetoothAssignedNumbers.APPLE;
        final String vendorResponseCode = "+XAPL=";
        final String vendorResponseArgument = "iPhone,2";
        runSupportedVendorEvent(vendorId, vendorResponseCode, vendorResponseArgument);
    }

    /**
     *  Test: supported vendor specific response: response to test command
     */
    @LargeTest
    @Test
    public void testSupportedVendorEventTestResponse() {
        final int vendorId = BluetoothAssignedNumbers.APPLE;
        final String vendorResponseCode = "+APLSIRI:";
        final String vendorResponseArgumentWithSpace = "  2";
        runSupportedVendorEvent(vendorId, vendorResponseCode, vendorResponseArgumentWithSpace);
    }

    /* Utility test function: unsupported vendor specific response shall be filtered out*/
    public void runUnsupportedVendorEvent(int vendorId, String vendorEventCode,
            String vendorEventArgument) {
        // Setup connection state machine to be in connected state
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        int expectedBroadcastIndex = 1;
        expectedBroadcastIndex = setUpHfpClientConnection(expectedBroadcastIndex);
        expectedBroadcastIndex = setUpServiceLevelConnection(expectedBroadcastIndex);

        // Simulate an unknown event arrive
        String vendorEvent = vendorEventCode + vendorEventArgument;
        StackEvent event = new StackEvent(StackEvent.EVENT_TYPE_UNKNOWN_EVENT);
        event.device = mTestDevice;
        event.valueString = vendorEvent;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, event);

        // Validate no broadcast intent
        verify(mHeadsetClientService, atMost(expectedBroadcastIndex - 1))
                .sendBroadcast(any(), anyString(), any(Bundle.class));
    }

    /**
     * Test unsupported vendor response: bad read response
     */
    @LargeTest
    @Test
    public void testUnsupportedVendorEventBadReadResponse() {
        final int vendorId = BluetoothAssignedNumbers.APPLE;
        final String vendorResponseCode = "+XAAPL=";
        final String vendorResponseArgument = "iPhone,2";
        runUnsupportedVendorEvent(vendorId, vendorResponseCode, vendorResponseArgument);
    }

    /**
     * Test unsupported vendor response: bad test response
     */
    @LargeTest
    @Test
    public void testUnsupportedVendorEventBadTestResponse() {
        final int vendorId = BluetoothAssignedNumbers.APPLE;
        final String vendorResponseCode = "+AAPLSIRI:";
        final String vendorResponseArgument = "2";
        runUnsupportedVendorEvent(vendorId, vendorResponseCode, vendorResponseArgument);
    }

    /**
     * Test voice recognition state change broadcast.
     */
    @MediumTest
    @Test
    public void testVoiceRecognitionStateChange() {
        // Setup connection state machine to be in connected state
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        doReturn(true).when(mNativeInterface).startVoiceRecognition(any(BluetoothDevice.class));
        doReturn(true).when(mNativeInterface).stopVoiceRecognition(any(BluetoothDevice.class));

        int expectedBroadcastIndex = 1;
        int expectedBroadcastMultiplePermissionsIndex = 1;
        expectedBroadcastMultiplePermissionsIndex =
            setUpHfpClientConnection(expectedBroadcastMultiplePermissionsIndex);
        expectedBroadcastMultiplePermissionsIndex =
            setUpServiceLevelConnection(expectedBroadcastMultiplePermissionsIndex);

        // Simulate a voice recognition start
        mHeadsetClientStateMachine.sendMessage(VOICE_RECOGNITION_START);

        // Signal that the complete list of actions was received.
        StackEvent event = new StackEvent(StackEvent.EVENT_TYPE_CMD_RESULT);
        event.device = mTestDevice;
        event.valueInt = AT_OK;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, event);

        expectedBroadcastIndex = verifyVoiceRecognitionBroadcast(expectedBroadcastIndex,
                HeadsetClientHalConstants.VR_STATE_STARTED);

        // Simulate a voice recognition stop
        mHeadsetClientStateMachine.sendMessage(VOICE_RECOGNITION_STOP);

        // Signal that the complete list of actions was received.
        event = new StackEvent(StackEvent.EVENT_TYPE_CMD_RESULT);
        event.device = mTestDevice;
        event.valueInt = AT_OK;
        mHeadsetClientStateMachine.sendMessage(StackEvent.STACK_EVENT, event);

        verifyVoiceRecognitionBroadcast(expectedBroadcastIndex,
                HeadsetClientHalConstants.VR_STATE_STOPPED);
    }

    private int verifyVoiceRecognitionBroadcast(int expectedBroadcastIndex, int expectedState) {
        // Validate broadcast intent
        ArgumentCaptor<Intent> intentArgument = ArgumentCaptor.forClass(Intent.class);
        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(expectedBroadcastIndex))
                .sendBroadcast(intentArgument.capture(), anyString(), any(Bundle.class));
        Assert.assertEquals(BluetoothHeadsetClient.ACTION_AG_EVENT,
                intentArgument.getValue().getAction());
        int state = intentArgument.getValue().getIntExtra(
                BluetoothHeadsetClient.EXTRA_VOICE_RECOGNITION, -1);
        Assert.assertEquals(expectedState, state);
        return expectedBroadcastIndex + 1;
    }

    /**
     * Test send BIEV command
     */
    @MediumTest
    @Test
    public void testSendBIEVCommand() {
        // Setup connection state machine to be in connected state
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        int expectedBroadcastIndex = 1;
        expectedBroadcastIndex = setUpHfpClientConnection(expectedBroadcastIndex);
        expectedBroadcastIndex = setUpServiceLevelConnection(expectedBroadcastIndex);

        int indicator_id = 2;
        int indicator_value = 50;

        Message msg = mHeadsetClientStateMachine.obtainMessage(HeadsetClientStateMachine.SEND_BIEV);
        msg.arg1 = indicator_id;
        msg.arg2 = indicator_value;

        mHeadsetClientStateMachine.sendMessage(msg);

        verify(mNativeInterface, timeout(STANDARD_WAIT_MILLIS).times(1))
                .sendATCmd(
                        mTestDevice,
                        HeadsetClientHalConstants.HANDSFREECLIENT_AT_CMD_BIEV,
                        indicator_id,
                        indicator_value,
                        null);
    }

    /**
     * Test state machine shall try to send AT+BIEV command to AG
     * to update an init battery level.
     */
    @MediumTest
    @Test
    public void testSendBatteryUpdateIndicatorWhenConnect() {
        // Setup connection state machine to be in connected state
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        int expectedBroadcastIndex = 1;

        expectedBroadcastIndex = setUpHfpClientConnection(expectedBroadcastIndex);
        expectedBroadcastIndex = setUpServiceLevelConnection(expectedBroadcastIndex);

        verify(mHeadsetClientService, timeout(STANDARD_WAIT_MILLIS).times(1))
                .updateBatteryLevel();
    }

    @Test
    public void testBroadcastAudioState() {
        mHeadsetClientStateMachine.broadcastAudioState(mTestDevice,
                BluetoothHeadsetClient.STATE_AUDIO_CONNECTED,
                BluetoothHeadsetClient.STATE_AUDIO_CONNECTING);

        verify(mHeadsetClientService).sendBroadcast(any(), any(), any());
    }

    @Test
    public void testCallsInState() {
        HfpClientCall call = new HfpClientCall(mTestDevice, 0, HfpClientCall.CALL_STATE_WAITING,
                "1", false, false, false);
        mHeadsetClientStateMachine.mCalls.put(0, call);

        Assert.assertEquals(
                mHeadsetClientStateMachine.callsInState(HfpClientCall.CALL_STATE_WAITING), 1);
    }

    @Test
    public void testEnterPrivateMode() {
        HfpClientCall call = new HfpClientCall(mTestDevice, 0, HfpClientCall.CALL_STATE_ACTIVE,
                "1", true, false, false);
        mHeadsetClientStateMachine.mCalls.put(0, call);
        doReturn(true).when(mNativeInterface).handleCallAction(null,
                HeadsetClientHalConstants.CALL_ACTION_CHLD_2X, 0);

        mHeadsetClientStateMachine.enterPrivateMode(0);

        Pair expectedPair = new Pair<Integer, Object>(ENTER_PRIVATE_MODE, call);
        Assert.assertEquals(mHeadsetClientStateMachine.mQueuedActions.peek(), expectedPair);
    }

    @Test
    public void testExplicitCallTransfer() {
        HfpClientCall callOne = new HfpClientCall(mTestDevice, 0, HfpClientCall.CALL_STATE_ACTIVE,
                "1", true, false, false);
        HfpClientCall callTwo = new HfpClientCall(mTestDevice, 0, HfpClientCall.CALL_STATE_ACTIVE,
                "1", true, false, false);
        mHeadsetClientStateMachine.mCalls.put(0, callOne);
        mHeadsetClientStateMachine.mCalls.put(1, callTwo);
        doReturn(true).when(mNativeInterface).handleCallAction(null,
                HeadsetClientHalConstants.CALL_ACTION_CHLD_4, -1);

        mHeadsetClientStateMachine.explicitCallTransfer();

        Pair expectedPair = new Pair<Integer, Object>(EXPLICIT_CALL_TRANSFER, 0);
        Assert.assertEquals(mHeadsetClientStateMachine.mQueuedActions.peek(), expectedPair);
    }

    @Test
    public void testSetAudioRouteAllowed() {
        mHeadsetClientStateMachine.setAudioRouteAllowed(true);

        Assert.assertTrue(mHeadsetClientStateMachine.getAudioRouteAllowed());
    }

    @Test
    public void testGetAudioState_withCurrentDeviceNull() {
        Assert.assertNull(mHeadsetClientStateMachine.mCurrentDevice);

        Assert.assertEquals(mHeadsetClientStateMachine.getAudioState(mTestDevice),
                BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED);
    }

    @Test
    public void testGetAudioState_withCurrentDeviceNotNull() {
        int audioState = 1;
        mHeadsetClientStateMachine.mAudioState = audioState;
        mHeadsetClientStateMachine.mCurrentDevice = mTestDevice;

        Assert.assertEquals(mHeadsetClientStateMachine.getAudioState(mTestDevice), audioState);
    }

    @Test
    public void testGetCall_withMatchingState() {
        HfpClientCall call = new HfpClientCall(mTestDevice, 0, HfpClientCall.CALL_STATE_ACTIVE,
                "1", true, false, false);
        mHeadsetClientStateMachine.mCalls.put(0, call);
        int[] states = new int[1];
        states[0] = HfpClientCall.CALL_STATE_ACTIVE;

        Assert.assertEquals(mHeadsetClientStateMachine.getCall(states), call);
    }

    @Test
    public void testGetCall_withNoMatchingState() {
        HfpClientCall call = new HfpClientCall(mTestDevice, 0, HfpClientCall.CALL_STATE_WAITING,
                "1", true, false, false);
        mHeadsetClientStateMachine.mCalls.put(0, call);
        int[] states = new int[1];
        states[0] = HfpClientCall.CALL_STATE_ACTIVE;

        Assert.assertNull(mHeadsetClientStateMachine.getCall(states));
    }

    @Test
    public void testGetConnectionState_withNullDevice() {
        Assert.assertEquals(mHeadsetClientStateMachine.getConnectionState(null),
                BluetoothProfile.STATE_DISCONNECTED);
    }

    @Test
    public void testGetConnectionState_withNonNullDevice() {
        mHeadsetClientStateMachine.mCurrentDevice = mTestDevice;

        Assert.assertEquals(mHeadsetClientStateMachine.getConnectionState(mTestDevice),
                BluetoothProfile.STATE_DISCONNECTED);
    }

    @Test
    public void testGetConnectionStateFromAudioState() {
        Assert.assertEquals(HeadsetClientStateMachine.getConnectionStateFromAudioState(
                BluetoothHeadsetClient.STATE_AUDIO_CONNECTED), BluetoothAdapter.STATE_CONNECTED);
        Assert.assertEquals(HeadsetClientStateMachine.getConnectionStateFromAudioState(
                BluetoothHeadsetClient.STATE_AUDIO_CONNECTING), BluetoothAdapter.STATE_CONNECTING);
        Assert.assertEquals(HeadsetClientStateMachine.getConnectionStateFromAudioState(
                        BluetoothHeadsetClient.STATE_AUDIO_DISCONNECTED),
                BluetoothAdapter.STATE_DISCONNECTED);
        int invalidAudioState = 3;
        Assert.assertEquals(
                HeadsetClientStateMachine.getConnectionStateFromAudioState(invalidAudioState),
                BluetoothAdapter.STATE_DISCONNECTED);
    }

    @Test
    public void testGetCurrentAgEvents() {
        Bundle bundle = mHeadsetClientStateMachine.getCurrentAgEvents();

        Assert.assertEquals(bundle.getString(BluetoothHeadsetClient.EXTRA_SUBSCRIBER_INFO),
                mHeadsetClientStateMachine.mSubscriberInfo);
    }

    @Test
    public void testGetCurrentAgFeatures() {
        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_3WAY;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_HOLD_ACC;
        Set<Integer> features = mHeadsetClientStateMachine.getCurrentAgFeatures();
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.PEER_FEAT_3WAY));
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.CHLD_FEAT_HOLD_ACC));

        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_VREC;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_REL;
        features = mHeadsetClientStateMachine.getCurrentAgFeatures();
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.PEER_FEAT_VREC));
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.CHLD_FEAT_REL));

        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_REJECT;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_REL_ACC;
        features = mHeadsetClientStateMachine.getCurrentAgFeatures();
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.PEER_FEAT_REJECT));
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.CHLD_FEAT_REL_ACC));

        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_ECC;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_MERGE;
        features = mHeadsetClientStateMachine.getCurrentAgFeatures();
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.PEER_FEAT_ECC));
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.CHLD_FEAT_MERGE));

        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_MERGE_DETACH;
        features = mHeadsetClientStateMachine.getCurrentAgFeatures();
        Assert.assertTrue(features.contains(HeadsetClientHalConstants.CHLD_FEAT_MERGE_DETACH));
    }

    @Test
    public void testGetCurrentAgFeaturesBundle() {
        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_3WAY;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_HOLD_ACC;
        Bundle bundle = mHeadsetClientStateMachine.getCurrentAgFeaturesBundle();
        Assert.assertTrue(bundle.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_3WAY_CALLING));
        Assert.assertTrue(bundle.getBoolean(
                BluetoothHeadsetClient.EXTRA_AG_FEATURE_ACCEPT_HELD_OR_WAITING_CALL));

        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_VREC;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_REL;
        bundle = mHeadsetClientStateMachine.getCurrentAgFeaturesBundle();
        Assert.assertTrue(
                bundle.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_VOICE_RECOGNITION));
        Assert.assertTrue(bundle.getBoolean(
                BluetoothHeadsetClient.EXTRA_AG_FEATURE_RELEASE_HELD_OR_WAITING_CALL));

        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_REJECT;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_REL_ACC;
        bundle = mHeadsetClientStateMachine.getCurrentAgFeaturesBundle();
        Assert.assertTrue(bundle.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_REJECT_CALL));
        Assert.assertTrue(
                bundle.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_RELEASE_AND_ACCEPT));

        mHeadsetClientStateMachine.mPeerFeatures = HeadsetClientHalConstants.PEER_FEAT_ECC;
        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_MERGE;
        bundle = mHeadsetClientStateMachine.getCurrentAgFeaturesBundle();
        Assert.assertTrue(bundle.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_ECC));
        Assert.assertTrue(bundle.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_MERGE));

        mHeadsetClientStateMachine.mChldFeatures = HeadsetClientHalConstants.CHLD_FEAT_MERGE_DETACH;
        bundle = mHeadsetClientStateMachine.getCurrentAgFeaturesBundle();
        Assert.assertTrue(
                bundle.getBoolean(BluetoothHeadsetClient.EXTRA_AG_FEATURE_MERGE_AND_DETACH));
    }

    @Test
    public void testGetCurrentCalls() {
        HfpClientCall call = new HfpClientCall(mTestDevice, 0, HfpClientCall.CALL_STATE_WAITING,
                "1", true, false, false);
        mHeadsetClientStateMachine.mCalls.put(0, call);

        List<HfpClientCall> currentCalls = mHeadsetClientStateMachine.getCurrentCalls();

        Assert.assertEquals(currentCalls.get(0), call);
    }

    @Test
    public void testGetMessageName() {
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(StackEvent.STACK_EVENT),
                "STACK_EVENT");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.CONNECT),
                "CONNECT");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.DISCONNECT),
                "DISCONNECT");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.CONNECT_AUDIO),
                "CONNECT_AUDIO");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(
                HeadsetClientStateMachine.DISCONNECT_AUDIO), "DISCONNECT_AUDIO");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(VOICE_RECOGNITION_START),
                "VOICE_RECOGNITION_START");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(VOICE_RECOGNITION_STOP),
                "VOICE_RECOGNITION_STOP");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.SET_MIC_VOLUME),
                "SET_MIC_VOLUME");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(
                HeadsetClientStateMachine.SET_SPEAKER_VOLUME), "SET_SPEAKER_VOLUME");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.DIAL_NUMBER),
                "DIAL_NUMBER");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.ACCEPT_CALL),
                "ACCEPT_CALL");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.REJECT_CALL),
                "REJECT_CALL");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.HOLD_CALL),
                "HOLD_CALL");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.TERMINATE_CALL),
                "TERMINATE_CALL");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(ENTER_PRIVATE_MODE),
                "ENTER_PRIVATE_MODE");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.SEND_DTMF),
                "SEND_DTMF");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(EXPLICIT_CALL_TRANSFER),
                "EXPLICIT_CALL_TRANSFER");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.DISABLE_NREC),
                "DISABLE_NREC");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(
                HeadsetClientStateMachine.SEND_VENDOR_AT_COMMAND), "SEND_VENDOR_AT_COMMAND");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.SEND_BIEV),
                "SEND_BIEV");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(
                HeadsetClientStateMachine.QUERY_CURRENT_CALLS), "QUERY_CURRENT_CALLS");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(
                HeadsetClientStateMachine.QUERY_OPERATOR_NAME), "QUERY_OPERATOR_NAME");
        Assert.assertEquals(
                HeadsetClientStateMachine.getMessageName(HeadsetClientStateMachine.SUBSCRIBER_INFO),
                "SUBSCRIBER_INFO");
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(
                HeadsetClientStateMachine.CONNECTING_TIMEOUT), "CONNECTING_TIMEOUT");
        int unknownMessageInt = 54;
        Assert.assertEquals(HeadsetClientStateMachine.getMessageName(unknownMessageInt),
                "UNKNOWN(" + unknownMessageInt + ")");
    }
    /**
     * Tests and verify behavior of the case where remote device doesn't support
     * At Android but tries to send audio policy.
     */
    @Test
    public void testAndroidAtRemoteNotSupported_StateTransition_setAudioPolicy() {
        // Setup connection state machine to be in connected state
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);
        int expectedBroadcastIndex = 1;

        expectedBroadcastIndex = setUpHfpClientConnection(expectedBroadcastIndex);
        expectedBroadcastIndex = setUpServiceLevelConnection(expectedBroadcastIndex);

        BluetoothAudioPolicy dummyAudioPolicy = new BluetoothAudioPolicy.Builder().build();
        mHeadsetClientStateMachine.setAudioPolicy(dummyAudioPolicy);
        verify(mNativeInterface, never()).sendAndroidAt(mTestDevice, "+ANDROID:1,0,0,0");
    }

    @SmallTest
    @Test
    public void testSetGetCallAudioPolicy() {
        // Return true for priority.
        when(mHeadsetClientService.getConnectionPolicy(any(BluetoothDevice.class))).thenReturn(
                BluetoothProfile.CONNECTION_POLICY_ALLOWED);

        int expectedBroadcastIndex = 1;

        expectedBroadcastIndex = setUpHfpClientConnection(expectedBroadcastIndex);
        expectedBroadcastIndex = setUpServiceLevelConnection(expectedBroadcastIndex, true);

        BluetoothAudioPolicy dummyAudioPolicy = new BluetoothAudioPolicy.Builder()
                .setCallEstablishPolicy(BluetoothAudioPolicy.POLICY_ALLOWED)
                .setConnectingTimePolicy(BluetoothAudioPolicy.POLICY_NOT_ALLOWED)
                .setInBandRingtonePolicy(BluetoothAudioPolicy.POLICY_ALLOWED)
                .build();

        mHeadsetClientStateMachine.setAudioPolicy(dummyAudioPolicy);
        verify(mNativeInterface).sendAndroidAt(mTestDevice, "+ANDROID=1,1,2,1");
    }
}
