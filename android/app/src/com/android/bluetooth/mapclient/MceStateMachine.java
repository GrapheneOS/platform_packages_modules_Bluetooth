/*
 * Copyright (C) 2016 The Android Open Source Project
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

// Bluetooth MAP MCE StateMachine
//         (Disconnected)
//             |    ^
//     CONNECT |    | DISCONNECTED
//             V    |
//    (Connecting) (Disconnecting)
//             |    ^
//   CONNECTED |    | DISCONNECT
//             V    |
//           (Connected)

// Valid Transitions: State + Event -> Transition:

// Disconnected + CONNECT -> Connecting
// Connecting + CONNECTED -> Connected
// Connecting + TIMEOUT -> Disconnecting
// Connecting + DISCONNECT/CONNECT -> Defer Message
// Connected + DISCONNECT -> Disconnecting
// Connected + CONNECT -> Disconnecting + Defer Message
// Disconnecting + DISCONNECTED -> (Safe) Disconnected
// Disconnecting + TIMEOUT -> (Force) Disconnected
// Disconnecting + DISCONNECT/CONNECT : Defer Message
package com.android.bluetooth.mapclient;

import static android.Manifest.permission.BLUETOOTH_CONNECT;
import static android.Manifest.permission.BLUETOOTH_PRIVILEGED;
import static android.Manifest.permission.RECEIVE_SMS;
import static android.bluetooth.BluetoothProfile.STATE_CONNECTED;
import static android.bluetooth.BluetoothProfile.STATE_CONNECTING;
import static android.bluetooth.BluetoothProfile.STATE_DISCONNECTED;
import static android.bluetooth.BluetoothProfile.STATE_DISCONNECTING;

import static java.util.Objects.requireNonNull;

import android.app.Activity;
import android.app.PendingIntent;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothMapClient;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.SdpMasRecord;
import android.content.Intent;
import android.net.Uri;
import android.os.Looper;
import android.os.Message;
import android.os.SystemProperties;
import android.provider.Telephony;
import android.telecom.PhoneAccount;
import android.telephony.SmsManager;
import android.util.Log;

import com.android.bluetooth.Util;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.flags.Flags;
import com.android.bluetooth.map.BluetoothMapbMessageMime;
import com.android.bluetooth.profile.ProfileService;
import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;
import com.android.vcard.VCardConstants;
import com.android.vcard.VCardEntry;
import com.android.vcard.VCardProperty;

import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/* The MceStateMachine is responsible for setting up and maintaining a connection to a single
 * specific Messaging Server Equipment endpoint.  Upon connect command an SDP record is retrieved,
 * a connection to the Message Access Server is created and a request to enable notification of new
 * messages is sent.
 */
class MceStateMachine extends StateMachine {
    private static final String TAG = MceStateMachine.class.getSimpleName();

    // Messages for events handled by the StateMachine
    static final int MSG_MAS_CONNECTED = 1001;
    static final int MSG_MAS_DISCONNECTED = 1002;
    static final int MSG_MAS_REQUEST_COMPLETED = 1003;
    static final int MSG_MAS_REQUEST_FAILED = 1004;
    static final int MSG_MAS_SDP_DONE = 1005;
    static final int MSG_MAS_SDP_UNSUCCESSFUL = 1006;
    static final int MSG_OUTBOUND_MESSAGE = 2001;
    static final int MSG_INBOUND_MESSAGE = 2002;
    static final int MSG_NOTIFICATION = 2003;
    static final int MSG_GET_LISTING = 2004;
    static final int MSG_GET_MESSAGE_LISTING = 2005;
    // Set message status to read or deleted
    static final int MSG_SET_MESSAGE_STATUS = 2006;
    static final int MSG_SEARCH_OWN_NUMBER_TIMEOUT = 2007;

    // SAVE_OUTBOUND_MESSAGES defaults to true to place the responsibility of managing content on
    // Bluetooth, to work with the default Car Messenger.  This may need to be set to false if the
    // messaging app takes that responsibility.
    private static final Boolean SAVE_OUTBOUND_MESSAGES = true;
    @VisibleForTesting static final Duration DISCONNECT_TIMEOUT = Duration.ofSeconds(3);
    @VisibleForTesting static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final int MAX_MESSAGES = 20;
    private static final int MSG_CONNECT = 1;
    private static final int MSG_DISCONNECT = 2;
    private static final int MSG_CONNECTING_TIMEOUT = 3;
    private static final int MSG_DISCONNECTING_TIMEOUT = 4;

    // Constants for SDP. Note that these values come from the native stack, but no centralized
    // constants exist for them as part of the various SDP APIs.
    public static final int SDP_SUCCESS = 0;
    public static final int SDP_FAILED = 1;
    public static final int SDP_BUSY = 2;

    private static final boolean MESSAGE_SEEN = true;
    private static final boolean MESSAGE_NOT_SEEN = false;

    // Do we download attachments, e.g., if a MMS contains an image.
    private static final boolean DOWNLOAD_ATTACHMENTS = false;

    // Folder names as defined in Bluetooth.org MAP spec V10
    private static final String FOLDER_TELECOM = "telecom";
    private static final String FOLDER_MSG = "msg";
    private static final String FOLDER_OUTBOX = "outbox";
    static final String FOLDER_INBOX = "inbox";
    static final String FOLDER_SENT = "sent";
    private static final String INBOX_PATH = "telecom/msg/inbox";

    // URI Scheme for messages with email contact
    private static final String SCHEME_MAILTO = "mailto";

    private static final String EXCLUDED_MESSAGE_TYPES =
            "persist.bluetooth.pts.mapclient.excludedmessagetypes";
    private static final String SEND_MESSAGE_TYPE =
            "persist.bluetooth.pts.mapclient.sendmessagetype";

    private final State mDisconnected = new Disconnected();
    private final State mConnecting = new Connecting();
    private final State mConnected = new Connected();
    private final State mDisconnecting = new Disconnecting();

    private final HashMap<String, Bmessage> mSentMessageLog = new HashMap<>(MAX_MESSAGES);
    private final HashMap<Bmessage, PendingIntent> mSentReceiptRequested =
            new HashMap<>(MAX_MESSAGES);
    private final HashMap<Bmessage, PendingIntent> mDeliveryReceiptRequested =
            new HashMap<>(MAX_MESSAGES);

    private final BluetoothDevice mDevice;
    private final MapClientService mService;
    private final AdapterService mAdapterService;

    // Connectivity States
    private int mPreviousState = STATE_DISCONNECTED;
    private int mMostRecentState = STATE_DISCONNECTED;
    private MasClient mMasClient;
    private MapClientContent mDatabase;

    private final Object mLock = new Object();

    @GuardedBy("mLock")
    private Bmessage.Type mDefaultMessageType = Bmessage.Type.SMS_CDMA;

    // The amount of time for MCE to search for remote device's own phone number before:
    // (1) MCE registering itself for being notified of the arrival of new messages; and
    // (2) MCE start downloading existing messages off of MSE.
    // NOTE: the value is not "final" so that it can be modified in the unit tests
    @VisibleForTesting static int sOwnNumberSearchTimeoutMs = 3_000;

    /**
     * An object to hold the necessary meta-data for each message so we can broadcast it alongside
     * the message content.
     *
     * <p>This is necessary because the metadata is inferred or received separately from the actual
     * message content.
     *
     * <p>Note: In the future it may be best to use the entries from the MessageListing in full
     * instead of this small subset.
     */
    @VisibleForTesting
    static class MessageMetadata {
        private final String mHandle;
        private final Long mTimestamp;
        private boolean mRead;
        private final boolean mSeen;

        MessageMetadata(String handle, Long timestamp, boolean read, boolean seen) {
            mHandle = handle;
            mTimestamp = timestamp;
            mRead = read;
            mSeen = seen;
        }

        public String getHandle() {
            return mHandle;
        }

        public Long getTimestamp() {
            return mTimestamp;
        }

        public synchronized boolean getRead() {
            return mRead;
        }

        public synchronized void setRead(boolean read) {
            mRead = read;
        }

        public synchronized boolean getSeen() {
            return mSeen;
        }
    }

    // Map each message to its metadata via the handle
    @VisibleForTesting
    ConcurrentHashMap<String, MessageMetadata> mMessages = new ConcurrentHashMap<>();

    MceStateMachine(
            MapClientService service, BluetoothDevice device, AdapterService adapterService) {
        super(TAG); // Create a state machine with its own separate thread
        mAdapterService = requireNonNull(adapterService);
        mService = service;
        mDevice = device;
        initStateMachine();
    }

    MceStateMachine(
            MapClientService service,
            BluetoothDevice device,
            AdapterService adapterService,
            Looper looper) {
        this(service, device, adapterService, looper, null, null);
    }

    @VisibleForTesting
    MceStateMachine(
            MapClientService service,
            BluetoothDevice device,
            AdapterService adapterService,
            Looper looper,
            MasClient masClient,
            MapClientContent database) {
        super(TAG, requireNonNull(looper));
        mAdapterService = requireNonNull(adapterService);
        mService = service;
        mMasClient = masClient;
        mDevice = device;
        mDatabase = database;
        initStateMachine();
    }

    private void initStateMachine() {
        mPreviousState = STATE_DISCONNECTED;

        addState(mDisconnected);
        addState(mConnecting);
        addState(mDisconnecting);
        addState(mConnected);
        setInitialState(mConnecting);
        start();
    }

    public void doQuit() {
        quitNow();
    }

    @Override
    protected void onQuitting() {
        if (mService != null) {
            mService.cleanupDevice(mDevice, this);
        }
    }

    private void onConnectionStateChanged(int prevState, int state) {
        if (mMostRecentState == state) {
            return;
        }
        // mDevice == null only at setInitialState
        if (mDevice == null) {
            return;
        }
        Log.d(TAG, mDevice + ": Connection state changed, prev=" + prevState + ", new=" + state);
        setState(state);

        mAdapterService.updateProfileConnectionAdapterProperties(
                mDevice, BluetoothProfile.MAP_CLIENT, state, prevState);

        Intent intent = new Intent(BluetoothMapClient.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, state);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        mService.sendBroadcastMultiplePermissions(
                intent,
                new String[] {BLUETOOTH_CONNECT, BLUETOOTH_PRIVILEGED},
                Util.getTempBroadcastOptions());
    }

    private synchronized void setState(int state) {
        mMostRecentState = state;
    }

    public synchronized int getState() {
        return mMostRecentState;
    }

    /** Notify of SDP completion. */
    public void sendSdpResult(int status, SdpMasRecord record) {
        Log.d(TAG, "Received SDP Result, status=" + status + ", record=" + record);
        if (status != SDP_SUCCESS || record == null) {
            Log.w(TAG, "SDP unsuccessful, status: " + status + ", record: " + record);
            sendMessage(MceStateMachine.MSG_MAS_SDP_UNSUCCESSFUL, status);
            return;
        }
        sendMessage(MceStateMachine.MSG_MAS_SDP_DONE, record);
    }

    public boolean disconnect() {
        Log.d(TAG, "Disconnect Request " + mDevice);
        sendMessage(MSG_DISCONNECT, mDevice);
        return true;
    }

    public synchronized boolean sendMapMessage(
            Uri[] contacts,
            String message,
            PendingIntent sentIntent,
            PendingIntent deliveredIntent) {
        Log.d(TAG, mDevice + ": Send, message=" + message);
        if (contacts == null || contacts.length <= 0) {
            return false;
        }
        if (mMostRecentState == STATE_CONNECTED) {
            Bmessage bmsg = new Bmessage();
            // Set type and status.
            bmsg.setType(getDefaultMessageType());
            bmsg.setStatus(Bmessage.Status.READ);

            for (Uri contact : contacts) {
                // Who to send the message to.
                Log.v(TAG, "Scheme " + contact.getScheme());
                if (PhoneAccount.SCHEME_TEL.equals(contact.getScheme())) {
                    String path = contact.getPath();
                    if (path != null && path.contains(Telephony.Threads.CONTENT_URI.toString())) {
                        mDatabase.addThreadContactsToEntries(bmsg, contact.getLastPathSegment());
                    } else {
                        VCardEntry destEntry = new VCardEntry();
                        VCardProperty destEntryPhone = new VCardProperty();
                        destEntryPhone.setName(VCardConstants.PROPERTY_TEL);
                        destEntryPhone.addValues(contact.getSchemeSpecificPart());
                        destEntry.addProperty(destEntryPhone);
                        bmsg.addRecipient(destEntry);
                        Log.v(TAG, "Sending to phone numbers " + destEntryPhone.getValueList());
                    }
                } else if (SCHEME_MAILTO.equals(contact.getScheme())) {
                    VCardEntry destEntry = new VCardEntry();
                    VCardProperty destEntryContact = new VCardProperty();
                    destEntryContact.setName(VCardConstants.PROPERTY_EMAIL);
                    destEntryContact.addValues(contact.getSchemeSpecificPart());
                    destEntry.addProperty(destEntryContact);
                    bmsg.addRecipient(destEntry);
                    Log.d(TAG, "SPECIFIC: " + contact.getSchemeSpecificPart());
                    Log.d(TAG, "Sending to emails " + destEntryContact.getValueList());
                } else {
                    Log.w(TAG, "Scheme " + contact.getScheme() + " not supported.");
                    return false;
                }
            }

            // Message of the body.
            bmsg.setBodyContent(message);
            if (sentIntent != null) {
                mSentReceiptRequested.put(bmsg, sentIntent);
            }
            if (deliveredIntent != null) {
                mDeliveryReceiptRequested.put(bmsg, deliveredIntent);
            }
            sendMessage(MSG_OUTBOUND_MESSAGE, bmsg);
            return true;
        }
        return false;
    }

    synchronized boolean getMessage(String handle) {
        Log.d(TAG, "getMessage" + handle);
        if (mMostRecentState == STATE_CONNECTED) {
            sendMessage(MSG_INBOUND_MESSAGE, handle);
            return true;
        }
        return false;
    }

    synchronized boolean getUnreadMessages() {
        Log.d(TAG, "getMessage");
        if (mMostRecentState == STATE_CONNECTED) {
            sendMessage(MSG_GET_MESSAGE_LISTING, FOLDER_INBOX);
            return true;
        }
        return false;
    }

    synchronized int getSupportedFeatures() {
        if (mMostRecentState == STATE_CONNECTED && mMasClient != null) {
            Log.d(TAG, "returning getSupportedFeatures from SDP record");
            return mMasClient.getSdpMasRecord().getSupportedFeatures();
        }
        Log.d(TAG, "getSupportedFeatures: no connection, returning 0");
        return 0;
    }

    synchronized boolean setMessageStatus(String handle, int status) {
        Log.d(TAG, "setMessageStatus(" + handle + ", " + status + ")");
        if (mMostRecentState == STATE_CONNECTED) {
            RequestSetMessageStatus.StatusIndicator statusIndicator;
            byte value;
            switch (status) {
                case BluetoothMapClient.UNREAD -> {
                    statusIndicator = RequestSetMessageStatus.StatusIndicator.READ;
                    value = RequestSetMessageStatus.STATUS_NO;
                }
                case BluetoothMapClient.READ -> {
                    statusIndicator = RequestSetMessageStatus.StatusIndicator.READ;
                    value = RequestSetMessageStatus.STATUS_YES;
                }
                case BluetoothMapClient.UNDELETED -> {
                    statusIndicator = RequestSetMessageStatus.StatusIndicator.DELETED;
                    value = RequestSetMessageStatus.STATUS_NO;
                }
                case BluetoothMapClient.DELETED -> {
                    statusIndicator = RequestSetMessageStatus.StatusIndicator.DELETED;
                    value = RequestSetMessageStatus.STATUS_YES;
                }
                default -> {
                    Log.e(TAG, "Invalid parameter for status" + status);
                    return false;
                }
            }
            sendMessage(
                    MSG_SET_MESSAGE_STATUS,
                    0,
                    0,
                    new RequestSetMessageStatus(handle, statusIndicator, value));
            return true;
        }
        return false;
    }

    private static String getContactURIFromPhone(String number) {
        return PhoneAccount.SCHEME_TEL + ":" + number;
    }

    private static String getContactURIFromEmail(String email) {
        return SCHEME_MAILTO + "://" + email;
    }

    @SuppressWarnings("EnumOrdinal")
    Bmessage.Type getDefaultMessageType() {
        synchronized (mLock) {
            if (Utils.isPtsTestMode()) {
                int messageType = SystemProperties.getInt(SEND_MESSAGE_TYPE, -1);
                if (messageType > 0 && messageType < Bmessage.Type.values().length) {
                    return Bmessage.Type.values()[messageType];
                }
            }
            return mDefaultMessageType;
        }
    }

    void setDefaultMessageType(SdpMasRecord sdpMasRecord) {
        int supportedMessageTypes = sdpMasRecord.getSupportedMessageTypes();
        synchronized (mLock) {
            if ((supportedMessageTypes & SdpMasRecord.MessageType.MMS) > 0) {
                mDefaultMessageType = Bmessage.Type.MMS;
            } else if ((supportedMessageTypes & SdpMasRecord.MessageType.SMS_CDMA) > 0) {
                mDefaultMessageType = Bmessage.Type.SMS_CDMA;
            } else if ((supportedMessageTypes & SdpMasRecord.MessageType.SMS_GSM) > 0) {
                mDefaultMessageType = Bmessage.Type.SMS_GSM;
            }

            Log.i(
                    TAG,
                    ("[" + mDevice + "] setDefaultMessageType():")
                            + (" Using message type=" + mDefaultMessageType));
        }
    }

    public void dump(StringBuilder sb) {
        ProfileService.println(sb, "mCurrentDevice: " + mDevice + " " + this.toString());
        ProfileService.println(sb, "  Preferred Message Type: " + getDefaultMessageType());
        if (mDatabase != null) {
            mDatabase.dump(sb);
        } else {
            ProfileService.println(sb, "  Device Message DB: null");
        }
        sb.append("\n");
    }

    class Disconnected extends State {
        @Override
        public void enter() {
            Log.d(
                    TAG,
                    mDevice
                            + " [Disconnected]: Entered, message="
                            + getMessageName(getCurrentMessage().what));
            onConnectionStateChanged(mPreviousState, STATE_DISCONNECTED);
            mPreviousState = STATE_DISCONNECTED;
            quit();
        }

        @Override
        public void exit() {
            mPreviousState = STATE_DISCONNECTED;
        }
    }

    class Connecting extends State {
        @Override
        public void enter() {
            Log.d(
                    TAG,
                    mDevice
                            + " [Connecting]: Entered, message="
                            + getMessageName(getCurrentMessage().what));
            onConnectionStateChanged(mPreviousState, STATE_CONNECTING);

            // When commanded to connect begin SDP to find the MAS server.
            mAdapterService.sdpSearch(mDevice, BluetoothUuid.MAS);

            sendMessageDelayed(MSG_CONNECTING_TIMEOUT, CONNECT_TIMEOUT.toMillis());
            Log.i(TAG, mDevice + " [Connecting]: Await SDP results");
        }

        @Override
        public boolean processMessage(Message message) {
            Log.d(TAG, mDevice + " [Connecting]: Received " + getMessageName(message.what));

            switch (message.what) {
                case MSG_MAS_SDP_DONE -> {
                    Log.i(TAG, mDevice + " [Connecting]: SDP Complete");
                    if (mMasClient == null) {
                        SdpMasRecord record = (SdpMasRecord) message.obj;
                        if (record == null) {
                            Log.e(TAG, mDevice + " [Connecting]: SDP record is null");
                            return NOT_HANDLED;
                        }

                        Log.i(TAG, mDevice + " [Connecting]: SDP record=" + record);

                        mMasClient =
                                new MasClient(
                                        mAdapterService, mDevice, MceStateMachine.this, record);
                        setDefaultMessageType(record);
                    }
                }
                case MSG_MAS_SDP_UNSUCCESSFUL -> {
                    int sdpStatus = message.arg1;
                    Log.i(TAG, mDevice + " [Connecting]: SDP unsuccessful, status=" + sdpStatus);
                    if (sdpStatus == SDP_BUSY) {
                        Log.d(TAG, mDevice + " [Connecting]: SDP was busy, try again");
                        mAdapterService.sdpSearch(mDevice, BluetoothUuid.MAS);
                    } else {
                        // This means the status is 0 (success, but no record) or 1 (organic
                        // failure). We historically have never retried SDP in failure cases, so we
                        // don't need to wait for the timeout anymore.
                        Log.d(TAG, mDevice + " [Connecting]: SDP failed completely, disconnecting");
                        transitionTo(mDisconnecting);
                    }
                }
                case MSG_MAS_DISCONNECTED -> {
                    if (mMasClient != null) {
                        mMasClient.shutdown();
                    }
                    transitionTo(mDisconnected);
                }
                case MSG_MAS_CONNECTED -> transitionTo(mConnected);
                case MSG_CONNECTING_TIMEOUT -> transitionTo(mDisconnecting);
                case MSG_CONNECT, MSG_DISCONNECT -> deferMessage(message);

                default -> {
                    Log.w(
                            TAG,
                            mDevice
                                    + " [Connecting]: Unexpected message: "
                                    + getMessageName(message.what));
                    return NOT_HANDLED;
                }
            }
            return HANDLED;
        }

        @Override
        public void exit() {
            mPreviousState = STATE_CONNECTING;
            removeMessages(MSG_CONNECTING_TIMEOUT);
        }
    }

    class Connected extends State {
        @Override
        public void enter() {
            Log.d(
                    TAG,
                    mDevice
                            + " [Connected]: Entered, message="
                            + getMessageName(getCurrentMessage().what));

            MapClientContent.Callbacks callbacks = MceStateMachine.this::setMessageStatus;
            // Keeps mock database from being overwritten in tests
            if (mDatabase == null) {
                mDatabase = new MapClientContent(mAdapterService, callbacks, mDevice);
            }
            onConnectionStateChanged(mPreviousState, STATE_CONNECTED);
            if (Utils.isPtsTestMode()) return;

            mMasClient.makeRequest(new RequestSetPath(FOLDER_TELECOM));
            mMasClient.makeRequest(new RequestSetPath(FOLDER_MSG));
            mMasClient.makeRequest(new RequestSetPath(FOLDER_INBOX));
            mMasClient.makeRequest(new RequestGetFolderListing(0, 0));
            mMasClient.makeRequest(new RequestSetPath(false));
            // Start searching for remote device's own phone number. Only until either:
            //   (a) the search completes (with or without finding the number), or
            //   (b) the timeout expires,
            // does the MCE:
            //   (a) register itself for being notified of the arrival of new messages, and
            //   (b) start downloading existing messages off of MSE.
            // In other words, the MCE shouldn't handle any messages (new or existing) until after
            // it has tried obtaining the remote's own phone number.
            RequestGetMessagesListingForOwnNumber requestForOwnNumber =
                    new RequestGetMessagesListingForOwnNumber();
            mMasClient.makeRequest(requestForOwnNumber);
            sendMessageDelayed(
                    MSG_SEARCH_OWN_NUMBER_TIMEOUT, requestForOwnNumber, sOwnNumberSearchTimeoutMs);
            Log.i(TAG, mDevice + "[Connected]: Find phone number");
        }

        @Override
        public boolean processMessage(Message message) {
            Log.d(TAG, mDevice + " [Connected]: Received " + getMessageName(message.what));
            switch (message.what) {
                case MSG_DISCONNECT -> {
                    if (mDevice.equals(message.obj)) {
                        transitionTo(mDisconnecting);
                    }
                }
                case MSG_MAS_DISCONNECTED -> {
                    deferMessage(message);
                    transitionTo(mDisconnecting);
                }
                case MSG_OUTBOUND_MESSAGE -> {
                    mMasClient.makeRequest(
                            new RequestPushMessage(
                                    FOLDER_OUTBOX, (Bmessage) message.obj, null, false, false));
                }
                case MSG_INBOUND_MESSAGE -> {
                    mMasClient.makeRequest(
                            new RequestGetMessage(
                                    (String) message.obj,
                                    MasClient.CharsetType.UTF_8,
                                    DOWNLOAD_ATTACHMENTS));
                }
                case MSG_NOTIFICATION -> {
                    EventReport notification = (EventReport) message.obj;
                    processNotification(notification);
                }
                case MSG_GET_LISTING -> mMasClient.makeRequest(new RequestGetFolderListing(0, 0));
                case MSG_GET_MESSAGE_LISTING -> {
                    // Get the 50 most recent messages from the last week
                    Calendar calendar = Calendar.getInstance();
                    calendar.add(Calendar.DATE, -7);
                    // bit mask - excludedMessageType filters out unsupported message types
                    byte excludedMessageTypes =
                            MessagesFilter.MESSAGE_TYPE_EMAIL | MessagesFilter.MESSAGE_TYPE_IM;
                    if (Utils.isPtsTestMode()) {
                        excludedMessageTypes =
                                (byte)
                                        SystemProperties.getInt(
                                                EXCLUDED_MESSAGE_TYPES, excludedMessageTypes);
                    }

                    mMasClient.makeRequest(
                            new RequestGetMessagesListing(
                                    (String) message.obj,
                                    0,
                                    new MessagesFilter.Builder()
                                            .setPeriod(calendar.getTime(), null)
                                            .setExcludedMessageTypes(excludedMessageTypes)
                                            .build(),
                                    0,
                                    50,
                                    0));
                }
                case MSG_SET_MESSAGE_STATUS -> {
                    if (message.obj instanceof RequestSetMessageStatus) {
                        mMasClient.makeRequest((RequestSetMessageStatus) message.obj);
                    }
                }
                case MSG_MAS_REQUEST_COMPLETED -> {
                    if (message.obj instanceof RequestGetMessage) {
                        processInboundMessage((RequestGetMessage) message.obj);
                    } else if (message.obj instanceof RequestPushMessage) {
                        RequestPushMessage requestPushMessage = (RequestPushMessage) message.obj;
                        String messageHandle = requestPushMessage.getMsgHandle();
                        Log.i(TAG, mDevice + " [Connected]: Message Sent, handle=" + messageHandle);
                        if (Flags.useEntireMessageHandle()) {
                            // some test devices don't populate messageHandle field.
                            // in such cases, no need to wait up for response for such messages.
                            if (messageHandle != null) {
                                if (SAVE_OUTBOUND_MESSAGES) {
                                    mDatabase.storeMessage(
                                            requestPushMessage.getBMsg(),
                                            messageHandle,
                                            System.currentTimeMillis(),
                                            MESSAGE_SEEN);
                                }
                                mSentMessageLog.put(messageHandle, requestPushMessage.getBMsg());
                            }
                        } else {
                            // ignore the top-order byte (converted to string) in the handle for now
                            // some test devices don't populate messageHandle field.
                            // in such cases, no need to wait up for response for such messages.
                            if (messageHandle != null && messageHandle.length() > 2) {
                                if (SAVE_OUTBOUND_MESSAGES) {
                                    mDatabase.storeMessage(
                                            requestPushMessage.getBMsg(),
                                            messageHandle,
                                            System.currentTimeMillis(),
                                            MESSAGE_SEEN);
                                }
                                mSentMessageLog.put(
                                        messageHandle.substring(2), requestPushMessage.getBMsg());
                            }
                        }
                    } else if (message.obj instanceof RequestGetMessagesListing) {
                        processMessageListing((RequestGetMessagesListing) message.obj);
                    } else if (message.obj instanceof RequestSetMessageStatus) {
                        processSetMessageStatus((RequestSetMessageStatus) message.obj);
                    } else if (message.obj instanceof RequestGetMessagesListingForOwnNumber) {
                        processMessageListingForOwnNumber(
                                (RequestGetMessagesListingForOwnNumber) message.obj);
                    }
                }
                case MSG_CONNECT -> {
                    if (!mDevice.equals(message.obj)) {
                        deferMessage(message);
                        transitionTo(mDisconnecting);
                    }
                }
                case MSG_SEARCH_OWN_NUMBER_TIMEOUT -> {
                    Log.w(TAG, "Timeout while searching for own phone number.");
                    // Abort any outstanding Request so it doesn't execute on MasClient
                    RequestGetMessagesListingForOwnNumber request =
                            (RequestGetMessagesListingForOwnNumber) message.obj;
                    mMasClient.abortRequest(request);
                    // Remove any executed/completed Request that MasClient has passed back to
                    // state machine. Note: {@link StateMachine} doesn't provide a {@code
                    // removeMessages(int what, Object obj)}, nor direct access to {@link
                    // mSmHandler}, so this will remove *all* {@code MSG_MAS_REQUEST_COMPLETED}
                    // messages. However, {@link RequestGetMessagesListingForOwnNumber} should be
                    // the only MAS Request enqueued at this point, since none of the other MAS
                    // Requests should trigger/start until after getOwnNumber has completed.
                    removeMessages(MSG_MAS_REQUEST_COMPLETED);
                    // If failed to complete search for remote device's own phone number,
                    // proceed without it (i.e., register MCE for MNS and start download
                    // of existing messages from MSE).
                    notificationRegistrationAndStartDownloadMessages();
                }
                default -> {
                    Log.w(
                            TAG,
                            mDevice
                                    + " [Connected]: Unexpected message: "
                                    + getMessageName(message.what));
                    return NOT_HANDLED;
                }
            }
            return HANDLED;
        }

        @Override
        public void exit() {
            mDatabase.cleanUp();
            mDatabase = null;
            mPreviousState = STATE_CONNECTED;
        }

        /**
         * Given a message notification event, will ensure message caching and updating and update
         * interested applications.
         *
         * <p>Message notifications arrive for both remote message reception and Message-Listing
         * object updates that are triggered by the server side.
         *
         * @param event - object describing the remote event
         */
        private void processNotification(EventReport event) {
            Log.i(TAG, mDevice + " [Connected]: Received Notification, event=" + event);

            if (event == null) {
                Log.w(TAG, mDevice + "[Connected]: Notification event is null");
                return;
            }

            switch (event.getType()) {
                case NEW_MESSAGE:
                    if (!mMessages.containsKey(event.getHandle())) {
                        Long timestamp = event.getTimestamp();
                        if (timestamp == null) {
                            // Infer the timestamp for this message as 'now' and read status
                            // false instead of getting the message listing data for it
                            timestamp = Instant.now().toEpochMilli();
                        }
                        MessageMetadata metadata =
                                new MessageMetadata(
                                        event.getHandle(), timestamp, false, MESSAGE_NOT_SEEN);
                        mMessages.put(event.getHandle(), metadata);
                    }
                    mMasClient.makeRequest(
                            new RequestGetMessage(
                                    event.getHandle(),
                                    MasClient.CharsetType.UTF_8,
                                    DOWNLOAD_ATTACHMENTS));
                    break;
                case DELIVERY_FAILURE:
                // fall through
                case SENDING_FAILURE:
                    if (!Flags.handleDeliverySendingFailureEvents()) {
                        break;
                    }
                // fall through
                case DELIVERY_SUCCESS:
                // fall through
                case SENDING_SUCCESS:
                    notifySentMessageStatus(event.getHandle(), event.getType());
                    break;
                case READ_STATUS_CHANGED:
                    mDatabase.markRead(event.getHandle());
                    break;
                case MESSAGE_DELETED:
                    mDatabase.deleteMessage(event.getHandle());
                    break;
                default:
                    Log.d(TAG, "processNotification: ignoring event type=" + event.getType());
            }
        }

        /**
         * Given the result of a Message Listing request, will cache the contents of each Message in
         * the Message Listing Object and kick off requests to retrieve message contents from the
         * remote device.
         *
         * @param request - A request object that has been resolved and returned with a message list
         */
        @SuppressWarnings("JavaUtilDate") // TODO: b/365629730 -- prefer Instant or LocalDate
        private void processMessageListing(RequestGetMessagesListing request) {
            Log.i(
                    TAG,
                    mDevice + " [Connected]: Received Message Listing=" + request.getList().size());

            List<com.android.bluetooth.mapclient.Message> messageListing = request.getList();
            // Message listings by spec arrive ordered newest first but we wish to broadcast as
            // oldest first. Iterate in reverse order so we initiate requests oldest first.
            for (int i = messageListing.size() - 1; i >= 0; i--) {
                com.android.bluetooth.mapclient.Message msg = messageListing.get(i);
                Log.d(
                        TAG,
                        mDevice + " [Connected]: fetch message content, handle=" + msg.getHandle());
                // A message listing coming from the server should always have up to date data
                if (msg.getDateTime() == null) {
                    Log.w(
                            TAG,
                            "message with handle "
                                    + msg.getHandle()
                                    + " has a null datetime, ignoring");
                    continue;
                }
                mMessages.put(
                        msg.getHandle(),
                        new MessageMetadata(
                                msg.getHandle(),
                                msg.getDateTime().getTime(),
                                msg.isRead(),
                                MESSAGE_SEEN));
                getMessage(msg.getHandle());
            }
        }

        /**
         * Process the result of a MessageListing request that was made specifically to obtain the
         * remote device's own phone number.
         *
         * @param request - A request object that has been resolved and returned with: - a phone
         *     number (possibly null if a number wasn't found) - a flag indicating whether there are
         *     still messages that can be searched/requested. - the request will automatically
         *     update itself if a number wasn't found and there are still messages that can be
         *     searched.
         */
        private void processMessageListingForOwnNumber(
                RequestGetMessagesListingForOwnNumber request) {
            if (request.isSearchCompleted()) {
                Log.d(TAG, "processMessageListingForOwnNumber: search completed");
                if (request.getOwnNumber() != null) {
                    // A phone number was found (should be the remote device's).
                    Log.d(
                            TAG,
                            "processMessageListingForOwnNumber: number found = "
                                    + request.getOwnNumber());
                    mDatabase.setRemoteDeviceOwnNumber(request.getOwnNumber());
                }
                // Remove any outstanding timeouts from state machine queue
                removeDeferredMessages(MSG_SEARCH_OWN_NUMBER_TIMEOUT);
                removeMessages(MSG_SEARCH_OWN_NUMBER_TIMEOUT);
                // Move on to next stage of connection process
                notificationRegistrationAndStartDownloadMessages();
            } else {
                // A phone number wasn't found, but there are still additional messages that can
                // be requested and searched.
                Log.d(TAG, "processMessageListingForOwnNumber: continuing search");
                mMasClient.makeRequest(request);
            }
        }

        /**
         * (1) MCE registering itself for being notified of the arrival of new messages; and (2) MCE
         * downloading existing messages of off MSE.
         */
        private void notificationRegistrationAndStartDownloadMessages() {
            Log.i(TAG, mDevice + "[Connected]: Queue Message downloads");
            mMasClient.makeRequest(new RequestSetNotificationRegistration(true));
            sendMessage(MSG_GET_MESSAGE_LISTING, FOLDER_SENT);
            sendMessage(MSG_GET_MESSAGE_LISTING, FOLDER_INBOX);
        }

        private void processSetMessageStatus(RequestSetMessageStatus request) {
            Log.d(TAG, "processSetMessageStatus");
            int result = BluetoothMapClient.RESULT_SUCCESS;
            if (!request.isSuccess()) {
                Log.e(TAG, "Set message status failed");
                result = BluetoothMapClient.RESULT_FAILURE;
            }
            RequestSetMessageStatus.StatusIndicator status = request.getStatusIndicator();
            switch (status) {
                case READ -> {
                    Intent intent =
                            new Intent(BluetoothMapClient.ACTION_MESSAGE_READ_STATUS_CHANGED);
                    intent.putExtra(
                            BluetoothMapClient.EXTRA_MESSAGE_READ_STATUS,
                            request.getValue() == RequestSetMessageStatus.STATUS_YES
                                    ? true
                                    : false);
                    intent.putExtra(BluetoothMapClient.EXTRA_MESSAGE_HANDLE, request.getHandle());
                    intent.putExtra(BluetoothMapClient.EXTRA_RESULT_CODE, result);
                    mService.sendBroadcast(intent, BLUETOOTH_CONNECT);
                }
                case DELETED -> {
                    Intent intent =
                            new Intent(BluetoothMapClient.ACTION_MESSAGE_DELETED_STATUS_CHANGED);
                    intent.putExtra(
                            BluetoothMapClient.EXTRA_MESSAGE_DELETED_STATUS,
                            request.getValue() == RequestSetMessageStatus.STATUS_YES
                                    ? true
                                    : false);
                    intent.putExtra(BluetoothMapClient.EXTRA_MESSAGE_HANDLE, request.getHandle());
                    intent.putExtra(BluetoothMapClient.EXTRA_RESULT_CODE, result);
                    mService.sendBroadcast(intent, BLUETOOTH_CONNECT);
                }
            }
        }

        /**
         * Given the response of a GetMessage request, will broadcast the bMessage contents on to
         * all registered applications.
         *
         * <p>Inbound messages arrive as bMessage objects following a GetMessage request. GetMessage
         * uses a message handle that can arrive from both a GetMessageListing request or a Message
         * Notification event.
         *
         * @param request - A request object that has been resolved and returned with message data
         */
        private void processInboundMessage(RequestGetMessage request) {
            Bmessage message = request.getMessage();
            Log.d(TAG, "Notify inbound Message" + message);

            if (message == null) {
                return;
            }

            MessageMetadata metadata = mMessages.get(request.getHandle());
            if (metadata == null) {
                Log.e(TAG, "No request record of received message, handle=" + request.getHandle());
                return;
            }

            mDatabase.storeMessage(
                    message, request.getHandle(), metadata.getTimestamp(), metadata.getSeen());

            if (!INBOX_PATH.equalsIgnoreCase(message.getFolder())) {
                Log.d(TAG, "Ignoring message received in " + message.getFolder() + ".");
                return;
            }

            switch (message.getType()) {
                case SMS_CDMA, SMS_GSM, MMS -> {
                    Log.d(TAG, "Body: " + message.getBodyContent());
                    Log.d(TAG, message.toString());
                    Log.d(TAG, "Recipients" + message.getRecipients().toString());

                    // Grab the message metadata and update the cached read status from the bMessage
                    metadata.setRead(request.getMessage().getStatus() == Bmessage.Status.READ);

                    Intent intent = new Intent();
                    intent.setAction(BluetoothMapClient.ACTION_MESSAGE_RECEIVED);
                    intent.putExtra(BluetoothDevice.EXTRA_DEVICE, mDevice);
                    intent.putExtra(BluetoothMapClient.EXTRA_MESSAGE_HANDLE, request.getHandle());
                    intent.putExtra(
                            BluetoothMapClient.EXTRA_MESSAGE_TIMESTAMP, metadata.getTimestamp());
                    intent.putExtra(
                            BluetoothMapClient.EXTRA_MESSAGE_READ_STATUS, metadata.getRead());
                    intent.putExtra(android.content.Intent.EXTRA_TEXT, message.getBodyContent());
                    VCardEntry originator = message.getOriginator();
                    if (originator != null) {
                        Log.d(TAG, originator.toString());
                        List<VCardEntry.PhoneData> phoneData = originator.getPhoneList();
                        List<VCardEntry.EmailData> emailData = originator.getEmailList();
                        if (phoneData != null && phoneData.size() > 0) {
                            String phoneNumber = phoneData.get(0).getNumber();
                            Log.d(TAG, "Originator number: " + phoneNumber);
                            intent.putExtra(
                                    BluetoothMapClient.EXTRA_SENDER_CONTACT_URI,
                                    getContactURIFromPhone(phoneNumber));
                        } else if (emailData != null && emailData.size() > 0) {
                            String email = emailData.get(0).getAddress();
                            Log.d(TAG, "Originator email: " + email);
                            intent.putExtra(
                                    BluetoothMapClient.EXTRA_SENDER_CONTACT_URI,
                                    getContactURIFromEmail(email));
                        }
                        intent.putExtra(
                                BluetoothMapClient.EXTRA_SENDER_CONTACT_NAME,
                                originator.getDisplayName());
                    }
                    if (message.getType() == Bmessage.Type.MMS) {
                        BluetoothMapbMessageMime mmsBmessage = new BluetoothMapbMessageMime();
                        mmsBmessage.parseMsgPart(message.getBodyContent());
                        intent.putExtra(
                                android.content.Intent.EXTRA_TEXT, mmsBmessage.getMessageAsText());
                        List<VCardEntry> recipients = message.getRecipients();
                        if (recipients != null && !recipients.isEmpty()) {
                            intent.putExtra(
                                    android.content.Intent.EXTRA_CC, getRecipientsUri(recipients));
                        }
                    }
                    String defaultMessagingPackage = Telephony.Sms.getDefaultSmsPackage(mService);
                    if (defaultMessagingPackage == null) {
                        // Broadcast to all RECEIVE_SMS recipients, including the SMS receiver
                        // package defined in system properties if one exists
                        mService.sendBroadcast(intent, RECEIVE_SMS);
                    } else {
                        String smsReceiverPackageName =
                                SystemProperties.get(
                                        "bluetooth.profile.map_client.sms_receiver_package", null);
                        if (smsReceiverPackageName != null && !smsReceiverPackageName.isEmpty()) {
                            // Clone intent and broadcast to SMS receiver package if one exists
                            Intent messageNotificationIntent = (Intent) intent.clone();
                            // Repeat action for easier static analyze of the intent
                            messageNotificationIntent.setAction(
                                    BluetoothMapClient.ACTION_MESSAGE_RECEIVED);
                            messageNotificationIntent.setPackage(smsReceiverPackageName);
                            mService.sendBroadcast(messageNotificationIntent, RECEIVE_SMS);
                        }
                        // Broadcast to default messaging package
                        intent.setPackage(defaultMessagingPackage);
                        mService.sendBroadcastAsUser(intent, mService.getUser(), RECEIVE_SMS);
                    }
                }
                default -> Log.e(TAG, "Received unhandled type" + message.getType().toString());
            }
        }

        /**
         * Retrieves the URIs of all the participants of a group conversation, besides the sender of
         * the message.
         */
        private static String[] getRecipientsUri(List<VCardEntry> recipients) {
            Set<String> uris = new HashSet<>();

            for (VCardEntry recipient : recipients) {
                List<VCardEntry.PhoneData> phoneData = recipient.getPhoneList();
                if (phoneData != null && phoneData.size() > 0) {
                    String phoneNumber = phoneData.get(0).getNumber();
                    Log.d(TAG, "CC Recipient number: " + phoneNumber);
                    uris.add(getContactURIFromPhone(phoneNumber));
                }
            }
            String[] stringUris = new String[uris.size()];
            return uris.toArray(stringUris);
        }

        private void notifySentMessageStatus(String handle, EventReport.Type status) {
            Log.d(TAG, "got a status for " + handle + " Status = " + status);
            // some test devices don't populate messageHandle field.
            // in such cases, ignore such messages.
            if (Flags.useEntireMessageHandle()) {
                if (handle == null) return;
            } else {
                if (handle == null || handle.length() <= 2) return;
            }
            PendingIntent intentToSend = null;
            if (Flags.useEntireMessageHandle()) {
                if (status == EventReport.Type.SENDING_FAILURE
                        || status == EventReport.Type.SENDING_SUCCESS) {
                    intentToSend = mSentReceiptRequested.remove(mSentMessageLog.get(handle));
                } else if (status == EventReport.Type.DELIVERY_SUCCESS
                        || status == EventReport.Type.DELIVERY_FAILURE) {
                    intentToSend = mDeliveryReceiptRequested.remove(mSentMessageLog.get(handle));
                }
            } else {
                // ignore the top-order byte (converted to string) in the handle for now
                String shortHandle = handle.substring(2);
                if (status == EventReport.Type.SENDING_FAILURE
                        || status == EventReport.Type.SENDING_SUCCESS) {
                    intentToSend = mSentReceiptRequested.remove(mSentMessageLog.get(shortHandle));
                } else if (status == EventReport.Type.DELIVERY_SUCCESS
                        || status == EventReport.Type.DELIVERY_FAILURE) {
                    intentToSend =
                            mDeliveryReceiptRequested.remove(mSentMessageLog.get(shortHandle));
                }
            }

            if (intentToSend != null) {
                try {
                    Log.d(TAG, "*******Sending " + intentToSend);
                    int result = Activity.RESULT_OK;
                    if (status == EventReport.Type.SENDING_FAILURE
                            || status == EventReport.Type.DELIVERY_FAILURE) {
                        result = SmsManager.RESULT_ERROR_GENERIC_FAILURE;
                    }
                    intentToSend.send(result);
                } catch (PendingIntent.CanceledException e) {
                    Log.w(TAG, "Notification Request Canceled" + e);
                }
            } else {
                Log.e(
                        TAG,
                        "Received a notification on message with handle = "
                                + handle
                                + ", but it is NOT found in mSentMessageLog! where did it go?");
            }
        }
    }

    class Disconnecting extends State {
        @Override
        public void enter() {
            Log.d(
                    TAG,
                    mDevice
                            + " [Disconnecting]: Entered, message="
                            + getMessageName(getCurrentMessage().what));

            onConnectionStateChanged(mPreviousState, STATE_DISCONNECTING);

            if (mMasClient != null) {
                mMasClient.makeRequest(new RequestSetNotificationRegistration(false));
                mMasClient.shutdown();
                sendMessageDelayed(MSG_DISCONNECTING_TIMEOUT, DISCONNECT_TIMEOUT.toMillis());
            } else {
                // MAP was never connected
                transitionTo(mDisconnected);
            }
        }

        @Override
        public boolean processMessage(Message message) {
            Log.d(TAG, mDevice + " [Disconnecting]: Received " + getMessageName(message.what));
            switch (message.what) {
                case MSG_DISCONNECTING_TIMEOUT, MSG_MAS_DISCONNECTED -> {
                    mMasClient = null;
                    transitionTo(mDisconnected);
                }
                case MSG_CONNECT, MSG_DISCONNECT -> {
                    deferMessage(message);
                }
                default -> {
                    Log.w(
                            TAG,
                            mDevice
                                    + " [Disconnecting]: Unexpected message: "
                                    + getMessageName(message.what));
                    return NOT_HANDLED;
                }
            }
            return HANDLED;
        }

        @Override
        public void exit() {
            mPreviousState = STATE_DISCONNECTING;
            removeMessages(MSG_DISCONNECTING_TIMEOUT);
        }
    }

    void receiveEvent(EventReport ev) {
        Log.d(TAG, "Message Type = " + ev.getType() + ", Message handle = " + ev.getHandle());
        sendMessage(MSG_NOTIFICATION, ev);
    }

    private static String getMessageName(int what) {
        return switch (what) {
            case MSG_MAS_CONNECTED -> "MSG_MAS_CONNECTED";
            case MSG_MAS_DISCONNECTED -> "MSG_MAS_DISCONNECTED";
            case MSG_MAS_REQUEST_COMPLETED -> "MSG_MAS_REQUEST_COMPLETED";
            case MSG_MAS_REQUEST_FAILED -> "MSG_MAS_REQUEST_FAILED";
            case MSG_MAS_SDP_DONE -> "MSG_MAS_SDP_DONE";
            case MSG_MAS_SDP_UNSUCCESSFUL -> "MSG_MAS_SDP_UNSUCCESSFUL";
            case MSG_OUTBOUND_MESSAGE -> "MSG_OUTBOUND_MESSAGE";
            case MSG_INBOUND_MESSAGE -> "MSG_INBOUND_MESSAGE";
            case MSG_NOTIFICATION -> "MSG_NOTIFICATION";
            case MSG_GET_LISTING -> "MSG_GET_LISTING";
            case MSG_GET_MESSAGE_LISTING -> "MSG_GET_MESSAGE_LISTING";
            case MSG_SET_MESSAGE_STATUS -> "MSG_SET_MESSAGE_STATUS";
            case MSG_CONNECT -> "MSG_CONNECT";
            case MSG_DISCONNECT -> "MSG_DISCONNECT";
            case MSG_CONNECTING_TIMEOUT -> "MSG_CONNECTING_TIMEOUT";
            case MSG_DISCONNECTING_TIMEOUT -> "MSG_DISCONNECTING_TIMEOUT";
            default -> "UNKNOWN";
        };
    }
}
