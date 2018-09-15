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

package com.android.bluetooth.avrcpcontroller;

import android.bluetooth.BluetoothAvrcpController;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.media.MediaMetadata;
import android.media.browse.MediaBrowser.MediaItem;
import android.media.session.PlaybackState;
import android.os.Message;
import android.util.Log;
import android.util.SparseArray;

import com.android.bluetooth.BluetoothMetricsProto;
import com.android.bluetooth.Utils;
import com.android.bluetooth.a2dpsink.A2dpSinkService;
import com.android.bluetooth.btservice.MetricsLogger;
import com.android.bluetooth.btservice.ProfileService;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.util.ArrayList;
import java.util.List;

/**
 * Provides Bluetooth AVRCP Controller State Machine responsible for all remote control connections
 * and interactions with a remote controlable device.
 */
class AvrcpControllerStateMachine extends StateMachine {

    // commands from Binder service
    static final int MESSAGE_SEND_PASS_THROUGH_CMD = 1;
    static final int MESSAGE_SEND_GROUP_NAVIGATION_CMD = 3;
    static final int MESSAGE_GET_FOLDER_LIST = 6;
    static final int MESSAGE_FETCH_ATTR_AND_PLAY_ITEM = 9;

    // commands from native layer
    static final int MESSAGE_PROCESS_SET_ABS_VOL_CMD = 103;
    static final int MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION = 104;
    static final int MESSAGE_PROCESS_TRACK_CHANGED = 105;
    static final int MESSAGE_PROCESS_PLAY_POS_CHANGED = 106;
    static final int MESSAGE_PROCESS_PLAY_STATUS_CHANGED = 107;
    static final int MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION = 108;
    static final int MESSAGE_PROCESS_GET_FOLDER_ITEMS = 109;
    static final int MESSAGE_PROCESS_GET_FOLDER_ITEMS_OUT_OF_RANGE = 110;
    static final int MESSAGE_PROCESS_GET_PLAYER_ITEMS = 111;
    static final int MESSAGE_PROCESS_FOLDER_PATH = 112;
    static final int MESSAGE_PROCESS_SET_BROWSED_PLAYER = 113;
    static final int MESSAGE_PROCESS_SET_ADDRESSED_PLAYER = 114;
    static final int MESSAGE_PROCESS_ADDRESSED_PLAYER_CHANGED = 115;
    static final int MESSAGE_PROCESS_NOW_PLAYING_CONTENTS_CHANGED = 116;

    // commands for connection
    static final int MESSAGE_PROCESS_RC_FEATURES = 301;
    static final int MESSAGE_PROCESS_CONNECTION_CHANGE = 302;
    static final int MESSAGE_PROCESS_BROWSE_CONNECTION_CHANGE = 303;

    // Interal messages
    static final int MESSAGE_INTERNAL_CMD_TIMEOUT = 403;
    static final int MESSAGE_INTERNAL_ABS_VOL_TIMEOUT = 404;

    static final int ABS_VOL_TIMEOUT_MILLIS = 1000; //1s
    static final int CMD_TIMEOUT_MILLIS = 5000; // 5s
    // Fetch only 20 items at a time.
    static final int GET_FOLDER_ITEMS_PAGINATION_SIZE = 20;
    // Fetch no more than 1000 items per directory.
    static final int MAX_FOLDER_ITEMS = 1000;

    /*
     * Base value for absolute volume from JNI
     */
    private static final int ABS_VOL_BASE = 127;

    /*
     * Notification types for Avrcp protocol JNI.
     */
    private static final byte NOTIFICATION_RSP_TYPE_INTERIM = 0x00;
    private static final byte NOTIFICATION_RSP_TYPE_CHANGED = 0x01;


    private static final String TAG = "AvrcpControllerSM";
    private static final boolean DBG = true;
    private static final boolean VDBG = false;

    private final Context mContext;
    private final AudioManager mAudioManager;

    private final State mDisconnected;
    private final State mConnected;
    private final SetAddresedPlayerAndPlayItem mSetAddrPlayer;
    private final GetFolderList mGetFolderList;

    private final Object mLock = new Object();
    private static final MediaMetadata EMPTY_MEDIA_METADATA = new MediaMetadata.Builder().build();

    // APIs exist to access these so they must be thread safe
    private Boolean mIsConnected = false;
    private RemoteDevice mRemoteDevice;
    private AvrcpPlayer mAddressedPlayer;

    // Only accessed from State Machine processMessage
    private int mVolumeChangedNotificationsToIgnore = 0;
    private int mPreviousPercentageVol = -1;
    private int mAddressedPlayerID = -1;
    private SparseArray<AvrcpPlayer> mAvailablePlayerList = new SparseArray<AvrcpPlayer>();

    // Browse tree.
    private BrowseTree mBrowseTree = new BrowseTree();

    AvrcpControllerStateMachine(Context context) {
        super(TAG);
        mContext = context;

        mAudioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
        IntentFilter filter = new IntentFilter(AudioManager.VOLUME_CHANGED_ACTION);
        mContext.registerReceiver(mBroadcastReceiver, filter);

        mDisconnected = new Disconnected();
        mConnected = new Connected();

        // Used to change folder path and fetch the new folder listing.
        mSetAddrPlayer = new SetAddresedPlayerAndPlayItem();
        mGetFolderList = new GetFolderList();

        addState(mDisconnected);
        addState(mConnected);

        // Any action that needs blocking other requests to the state machine will be implemented as
        // a separate substate of the mConnected state. Once transtition to the sub-state we should
        // only handle the messages that are relevant to the sub-action. Everything else should be
        // deferred so that once we transition to the mConnected we can process them hence.
        addState(mSetAddrPlayer, mConnected);
        addState(mGetFolderList, mConnected);

        setInitialState(mDisconnected);
    }

    class Disconnected extends State {

        @Override
        public boolean processMessage(Message msg) {
            if (DBG) Log.d(TAG, " HandleMessage: " + dumpMessageString(msg.what));
            switch (msg.what) {
                case MESSAGE_PROCESS_CONNECTION_CHANGE:
                    if (msg.arg1 == BluetoothProfile.STATE_CONNECTED) {
                        mBrowseTree = new BrowseTree();
                        transitionTo(mConnected);
                        BluetoothDevice rtDevice = (BluetoothDevice) msg.obj;
                        synchronized (mLock) {
                            mRemoteDevice = new RemoteDevice(rtDevice);
                            mAddressedPlayer = new AvrcpPlayer();
                            mIsConnected = true;
                        }
                        MetricsLogger.logProfileConnectionEvent(
                                BluetoothMetricsProto.ProfileId.AVRCP_CONTROLLER);
                        Intent intent = new Intent(
                                BluetoothAvrcpController.ACTION_CONNECTION_STATE_CHANGED);
                        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                                BluetoothProfile.STATE_DISCONNECTED);
                        intent.putExtra(BluetoothProfile.EXTRA_STATE,
                                BluetoothProfile.STATE_CONNECTED);
                        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, rtDevice);
                        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                    }
                    break;

                default:
                    Log.w(TAG,
                            "Currently Disconnected not handling " + dumpMessageString(msg.what));
                    return false;
            }
            return true;
        }
    }

    class Connected extends State {
        @Override
        public boolean processMessage(Message msg) {
            if (DBG) Log.d(TAG, " HandleMessage: " + dumpMessageString(msg.what));
            A2dpSinkService a2dpSinkService = A2dpSinkService.getA2dpSinkService();
            synchronized (mLock) {
                switch (msg.what) {
                    case MESSAGE_SEND_PASS_THROUGH_CMD:
                        BluetoothDevice device = (BluetoothDevice) msg.obj;
                        AvrcpControllerService.sendPassThroughCommandNative(
                                Utils.getByteAddress(device), msg.arg1, msg.arg2);
                        if (a2dpSinkService != null) {
                            if (DBG) Log.d(TAG, " inform AVRCP Commands to A2DP Sink ");
                            a2dpSinkService.informAvrcpPassThroughCmd(device, msg.arg1, msg.arg2);
                        }
                        break;

                    case MESSAGE_SEND_GROUP_NAVIGATION_CMD:
                        AvrcpControllerService.sendGroupNavigationCommandNative(
                                mRemoteDevice.getBluetoothAddress(), msg.arg1, msg.arg2);
                        break;

                    case MESSAGE_GET_FOLDER_LIST:
                        // Whenever we transition we set the information for folder we need to
                        // return result.
                        if (DBG) Log.d(TAG, "Message_GET_FOLDER_LIST" + (String) msg.obj);
                        mGetFolderList.setFolder((String) msg.obj);
                        transitionTo(mGetFolderList);
                        break;

                    case MESSAGE_FETCH_ATTR_AND_PLAY_ITEM: {
                        int scope = msg.arg1;
                        String playItemUid = (String) msg.obj;
                        BrowseTree.BrowseNode currBrPlayer = mBrowseTree.getCurrentBrowsedPlayer();
                        BrowseTree.BrowseNode currAddrPlayer =
                                mBrowseTree.getCurrentAddressedPlayer();
                        BrowseTree.BrowseNode itemToPlay =
                                mBrowseTree.findBrowseNodeByID(playItemUid);
                        if (DBG) {
                            Log.d(TAG, "currBrPlayer " + currBrPlayer + " currAddrPlayer "
                                    + currAddrPlayer);
                        }
                        if (currBrPlayer == null
                                || currBrPlayer.equals(currAddrPlayer)
                                || scope == AvrcpControllerService.BROWSE_SCOPE_NOW_PLAYING) {
                            // String is encoded as a Hex String (mostly for display purposes)
                            // hence convert this back to real byte string.
                            // NOTE: It may be possible that sending play while the same item is
                            // playing leads to reset of track.
                            AvrcpControllerService.playItemNative(
                                    mRemoteDevice.getBluetoothAddress(), (byte) scope,
                                    AvrcpControllerService.hexStringToByteUID(playItemUid), 0);
                        } else {
                            // Send out the request for setting addressed player.
                            AvrcpControllerService.setAddressedPlayerNative(
                                    mRemoteDevice.getBluetoothAddress(),
                                    currBrPlayer.getPlayerID());
                            mSetAddrPlayer.setItemAndScope(currBrPlayer.getID(), playItemUid,
                                    scope);
                            transitionTo(mSetAddrPlayer);
                        }
                        break;
                    }

                    case MESSAGE_PROCESS_CONNECTION_CHANGE:
                        if (msg.arg1 == BluetoothProfile.STATE_DISCONNECTED) {
                            synchronized (mLock) {
                                mIsConnected = false;
                                mRemoteDevice = null;
                            }
                            mBrowseTree.clear();
                            transitionTo(mDisconnected);
                            BluetoothDevice rtDevice = (BluetoothDevice) msg.obj;
                            Intent intent = new Intent(
                                    BluetoothAvrcpController.ACTION_CONNECTION_STATE_CHANGED);
                            intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE,
                                    BluetoothProfile.STATE_CONNECTED);
                            intent.putExtra(BluetoothProfile.EXTRA_STATE,
                                    BluetoothProfile.STATE_DISCONNECTED);
                            intent.putExtra(BluetoothDevice.EXTRA_DEVICE, rtDevice);
                            mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                        }
                        break;

                    case MESSAGE_PROCESS_BROWSE_CONNECTION_CHANGE:
                        // Service tells us if the browse is connected or disconnected.
                        // This is useful only for deciding whether to send browse commands rest of
                        // the connection state handling should be done via the message
                        // MESSAGE_PROCESS_CONNECTION_CHANGE.
                        Intent intent = new Intent(
                                AvrcpControllerService.ACTION_BROWSE_CONNECTION_STATE_CHANGED);
                        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, (BluetoothDevice) msg.obj);
                        if (DBG) {
                            Log.d(TAG, "Browse connection state " + msg.arg1);
                        }
                        if (msg.arg1 == 1) {
                            intent.putExtra(BluetoothProfile.EXTRA_STATE,
                                    BluetoothProfile.STATE_CONNECTED);
                        } else if (msg.arg1 == 0) {
                            intent.putExtra(BluetoothProfile.EXTRA_STATE,
                                    BluetoothProfile.STATE_DISCONNECTED);
                        } else {
                            Log.w(TAG, "Incorrect browse state " + msg.arg1);
                        }

                        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
                        break;

                    case MESSAGE_PROCESS_RC_FEATURES:
                        mRemoteDevice.setRemoteFeatures(msg.arg1);
                        break;

                    case MESSAGE_PROCESS_SET_ABS_VOL_CMD:
                        mVolumeChangedNotificationsToIgnore++;
                        removeMessages(MESSAGE_INTERNAL_ABS_VOL_TIMEOUT);
                        sendMessageDelayed(MESSAGE_INTERNAL_ABS_VOL_TIMEOUT,
                                ABS_VOL_TIMEOUT_MILLIS);
                        setAbsVolume(msg.arg1, msg.arg2);
                        break;

                    case MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION: {
                        mRemoteDevice.setNotificationLabel(msg.arg1);
                        mRemoteDevice.setAbsVolNotificationRequested(true);
                        int percentageVol = getVolumePercentage();
                        if (DBG) {
                            Log.d(TAG, " Sending Interim Response = " + percentageVol + " label "
                                    + msg.arg1);
                        }
                        AvrcpControllerService.sendRegisterAbsVolRspNative(
                                mRemoteDevice.getBluetoothAddress(), NOTIFICATION_RSP_TYPE_INTERIM,
                                percentageVol, mRemoteDevice.getNotificationLabel());
                    }
                    break;

                    case MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION: {
                        if (mVolumeChangedNotificationsToIgnore > 0) {
                            mVolumeChangedNotificationsToIgnore--;
                            if (mVolumeChangedNotificationsToIgnore == 0) {
                                removeMessages(MESSAGE_INTERNAL_ABS_VOL_TIMEOUT);
                            }
                        } else {
                            if (mRemoteDevice.getAbsVolNotificationRequested()) {
                                int percentageVol = getVolumePercentage();
                                if (percentageVol != mPreviousPercentageVol) {
                                    AvrcpControllerService.sendRegisterAbsVolRspNative(
                                            mRemoteDevice.getBluetoothAddress(),
                                            NOTIFICATION_RSP_TYPE_CHANGED, percentageVol,
                                            mRemoteDevice.getNotificationLabel());
                                    mPreviousPercentageVol = percentageVol;
                                    mRemoteDevice.setAbsVolNotificationRequested(false);
                                }
                            }
                        }
                    }
                    break;

                    case MESSAGE_INTERNAL_ABS_VOL_TIMEOUT:
                        // Volume changed notifications should come back promptly from the
                        // AudioManager, if for some reason some notifications were squashed don't
                        // prevent future notifications.
                        if (DBG) Log.d(TAG, "Timed out on volume changed notification");
                        mVolumeChangedNotificationsToIgnore = 0;
                        break;

                    case MESSAGE_PROCESS_TRACK_CHANGED:
                        // Music start playing automatically and update Metadata
                        boolean updateTrack =
                                mAddressedPlayer.updateCurrentTrack((TrackInfo) msg.obj);
                        if (updateTrack) {
                            broadcastMetaDataChanged(
                                    mAddressedPlayer.getCurrentTrack().getMediaMetaData());
                        }
                        break;

                    case MESSAGE_PROCESS_PLAY_POS_CHANGED:
                        if (msg.arg2 != -1) {
                            mAddressedPlayer.setPlayTime(msg.arg2);
                            broadcastPlayBackStateChanged(getCurrentPlayBackState());
                        }
                        break;

                    case MESSAGE_PROCESS_PLAY_STATUS_CHANGED:
                        int status = msg.arg1;
                        mAddressedPlayer.setPlayStatus(status);
                        if (status == PlaybackState.STATE_PLAYING) {
                            a2dpSinkService.informTGStatePlaying(mRemoteDevice.mBTDevice, true);
                        } else if (status == PlaybackState.STATE_PAUSED
                                || status == PlaybackState.STATE_STOPPED) {
                            a2dpSinkService.informTGStatePlaying(mRemoteDevice.mBTDevice, false);
                        }
                        break;

                    case MESSAGE_PROCESS_ADDRESSED_PLAYER_CHANGED:
                        mAddressedPlayerID = msg.arg1;
                        if (DBG) Log.d(TAG, "AddressedPlayer = " + mAddressedPlayerID);
                        AvrcpPlayer updatedPlayer = mAvailablePlayerList.get(mAddressedPlayerID);
                        if (updatedPlayer != null) {
                            mAddressedPlayer = updatedPlayer;
                            if (DBG) Log.d(TAG, "AddressedPlayer = " + mAddressedPlayer.getName());
                        } else {
                            mBrowseTree.mRootNode.setCached(false);
                        }
                        sendMessage(MESSAGE_PROCESS_SET_ADDRESSED_PLAYER);
                        break;

                    case MESSAGE_PROCESS_NOW_PLAYING_CONTENTS_CHANGED:
                        mBrowseTree.mNowPlayingNode.setCached(false);
                        mGetFolderList.setFolder(mBrowseTree.mNowPlayingNode.getID());
                        transitionTo(mGetFolderList);
                        break;

                    default:
                        Log.d(TAG, "Unhandled message" + msg.what);
                        return false;
                }
            }
            return true;
        }
    }

    // Handle the get folder listing action
    // a) Fetch the listing of folders
    // b) Once completed return the object listing
    class GetFolderList extends CmdState {
        private static final String STATE_TAG = "AVRCPSM.GetFolderList";

        boolean mAbort;
        BrowseTree.BrowseNode mBrowseNode;
        BrowseTree.BrowseNode mNextStep;

        @Override
        public void enter() {
            // Setup the timeouts.
            super.enter();
            mAbort = false;
            if (mBrowseNode == null) {
                transitionTo(mConnected);
            } else {
                navigateToFolderOrRetrieve(mBrowseNode);
            }
        }

        public void setFolder(String id) {
            if (DBG) Log.d(STATE_TAG, "Setting folder to " + id);
            mBrowseNode = mBrowseTree.findBrowseNodeByID(id);
        }

        @Override
        public boolean processMessage(Message msg) {
            Log.d(STATE_TAG, "processMessage " + msg.what);
            switch (msg.what) {
                case MESSAGE_PROCESS_GET_FOLDER_ITEMS:
                    ArrayList<MediaItem> folderList = (ArrayList<MediaItem>) msg.obj;
                    int endIndicator = mBrowseNode.getExpectedChildren() - 1;
                    if (DBG) {
                        Log.d(STATE_TAG,
                                " End " + endIndicator
                                        + " received " + folderList.size());
                    }

                    // Always update the node so that the user does not wait forever
                    // for the list to populate.
                    mBrowseNode.addChildren(folderList);
                    broadcastFolderList(mBrowseNode.getID());

                    if (mBrowseNode.getChildrenCount() >= endIndicator || folderList.size() == 0
                            || mAbort) {
                        // If we have fetched all the elements or if the remotes sends us 0 elements
                        // (which can lead us into a loop since mCurrInd does not proceed) we simply
                        // abort.
                        mBrowseNode.setCached(true);
                        transitionTo(mConnected);
                    } else {
                        // Fetch the next set of items.
                        fetchContents(mBrowseNode);
                        // Reset the timeout message since we are doing a new fetch now.
                        removeMessages(MESSAGE_INTERNAL_CMD_TIMEOUT);
                        sendMessageDelayed(MESSAGE_INTERNAL_CMD_TIMEOUT, CMD_TIMEOUT_MILLIS);
                    }
                    break;
                case MESSAGE_PROCESS_SET_BROWSED_PLAYER:
                    mBrowseTree.setCurrentBrowsedPlayer(mNextStep.getID(), msg.arg1, msg.arg2);
                    removeMessages(MESSAGE_INTERNAL_CMD_TIMEOUT);
                    sendMessageDelayed(MESSAGE_INTERNAL_CMD_TIMEOUT, CMD_TIMEOUT_MILLIS);
                    navigateToFolderOrRetrieve(mBrowseNode);
                    break;

                case MESSAGE_PROCESS_FOLDER_PATH:
                    mBrowseTree.setCurrentBrowsedFolder(mNextStep.getID());
                    mBrowseTree.getCurrentBrowsedFolder().setExpectedChildren(msg.arg1);

                    if (mAbort) {
                        transitionTo(mConnected);
                    } else {
                        removeMessages(MESSAGE_INTERNAL_CMD_TIMEOUT);
                        sendMessageDelayed(MESSAGE_INTERNAL_CMD_TIMEOUT, CMD_TIMEOUT_MILLIS);
                        navigateToFolderOrRetrieve(mBrowseNode);
                    }
                    break;

                case MESSAGE_PROCESS_GET_PLAYER_ITEMS:
                    BrowseTree.BrowseNode rootNode = mBrowseTree.mRootNode;
                    if (!rootNode.isCached()) {
                        List<AvrcpPlayer> playerList = (List<AvrcpPlayer>) msg.obj;
                        mAvailablePlayerList.clear();
                        for (AvrcpPlayer player : playerList) {
                            mAvailablePlayerList.put(player.getId(), player);
                        }
                        rootNode.addChildren(playerList);
                        mBrowseTree.setCurrentBrowsedFolder(BrowseTree.ROOT);
                        rootNode.setExpectedChildren(playerList.size());
                        rootNode.setCached(true);
                        broadcastFolderList(BrowseTree.ROOT);
                    }
                    transitionTo(mConnected);
                    break;


                case MESSAGE_INTERNAL_CMD_TIMEOUT:
                    // We have timed out to execute the request, we should simply send
                    // whatever listing we have gotten until now.
                    broadcastFolderList(mBrowseNode.getID());
                    transitionTo(mConnected);
                    break;

                case MESSAGE_PROCESS_GET_FOLDER_ITEMS_OUT_OF_RANGE:
                    // If we have gotten an error for OUT OF RANGE we have
                    // already sent all the items to the client hence simply
                    // transition to Connected state here.
                    mBrowseNode.setCached(true);
                    broadcastFolderList(mBrowseNode.getID());
                    transitionTo(mConnected);
                    break;

                case MESSAGE_GET_FOLDER_LIST:
                    if (!mBrowseNode.equals((String) msg.obj)) {
                        mAbort = true;
                        deferMessage(msg);
                        Log.d(STATE_TAG, "Go Get Another Directory");
                    } else {
                        Log.d(STATE_TAG, "Get The Same Directory, ignore");
                    }
                    break;

                case MESSAGE_FETCH_ATTR_AND_PLAY_ITEM:
                    // A new request has come in, no need to fetch more.
                    mAbort = true;
                    deferMessage(msg);
                    break;

                case MESSAGE_SEND_PASS_THROUGH_CMD:
                case MESSAGE_SEND_GROUP_NAVIGATION_CMD:
                case MESSAGE_PROCESS_SET_ABS_VOL_CMD:
                case MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION:
                case MESSAGE_PROCESS_TRACK_CHANGED:
                case MESSAGE_PROCESS_PLAY_POS_CHANGED:
                case MESSAGE_PROCESS_PLAY_STATUS_CHANGED:
                case MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION:
                case MESSAGE_PROCESS_CONNECTION_CHANGE:
                case MESSAGE_PROCESS_BROWSE_CONNECTION_CHANGE:
                    // All of these messages should be handled by parent state immediately.
                    return false;

                default:
                    if (DBG) Log.d(STATE_TAG, "deferring message " + msg.what + " to connected!");
                    deferMessage(msg);
            }
            return true;
        }

        private void fetchContents(BrowseTree.BrowseNode target) {
            switch (target.getScope()) {
                case AvrcpControllerService.BROWSE_SCOPE_PLAYER_LIST:
                    AvrcpControllerService.getPlayerListNative(mRemoteDevice.getBluetoothAddress(),
                            0, 255);
                    break;
                case AvrcpControllerService.BROWSE_SCOPE_NOW_PLAYING:
                    AvrcpControllerService.getNowPlayingListNative(
                            mRemoteDevice.getBluetoothAddress(), target.getChildrenCount(),
                            Math.min(target.getExpectedChildren(), target.getChildrenCount()
                            + GET_FOLDER_ITEMS_PAGINATION_SIZE - 1));
                    break;
                case AvrcpControllerService.BROWSE_SCOPE_VFS:
                    AvrcpControllerService.getFolderListNative(mRemoteDevice.getBluetoothAddress(),
                            target.getChildrenCount(), Math.min(target.getExpectedChildren(),
                                target.getChildrenCount() + GET_FOLDER_ITEMS_PAGINATION_SIZE - 1));
                    break;
                default:
                    Log.e(STATE_TAG, "Scope " + target.getScope() + " cannot be handled here.");
            }
        }

        /* One of several things can happen when trying to get a folder list
         *
         *
         * 0: The folder handle is no longer valid
         * 1: The folder contents can be retrieved directly (NowPlaying, Root, Current)
         * 2: The folder is a browsable player
         * 3: The folder is a non browsable player
         * 4: The folder is not a child of the current folder
         * 5: The folder is a child of the current folder
         *
         */
        private void navigateToFolderOrRetrieve(BrowseTree.BrowseNode target) {
            mNextStep = mBrowseTree.getNextStepToFolder(target);
            if (DBG) {
                Log.d(TAG, "NAVIGATING From " + mBrowseTree.getCurrentBrowsedFolder().toString());
                Log.d(TAG, "NAVIGATING Toward " + target.toString());
            }
            if (mNextStep == null) {
                sendMessage(MESSAGE_INTERNAL_CMD_TIMEOUT);
            } else if (target.equals(mBrowseTree.mNowPlayingNode)
                       || target.equals(mBrowseTree.mRootNode)
                       || mNextStep.equals(mBrowseTree.getCurrentBrowsedFolder())) {
                fetchContents(mNextStep);
            } else if (mNextStep.isPlayer()) {
                if (DBG) Log.d(TAG, "NAVIGATING Player " + mNextStep.toString());
                if (mNextStep.isBrowsable()) {
                    AvrcpControllerService.setBrowsedPlayerNative(
                            mRemoteDevice.getBluetoothAddress(), mNextStep.getPlayerID());
                } else {
                    if (DBG) Log.d(TAG, "Player doesn't support browsing");
                    mNextStep.setCached(true);
                    broadcastFolderList(mNextStep.getID());
                    transitionTo(mConnected);
                }
            } else if (mNextStep.equals(mBrowseTree.mNavigateUpNode)) {
                if (DBG) Log.d(TAG, "NAVIGATING UP " + mNextStep.toString());
                mNextStep = mBrowseTree.getCurrentBrowsedFolder().getParent();
                mBrowseTree.getCurrentBrowsedFolder().setCached(false);

                AvrcpControllerService.changeFolderPathNative(
                        mRemoteDevice.getBluetoothAddress(),
                        AvrcpControllerService.FOLDER_NAVIGATION_DIRECTION_UP,
                        AvrcpControllerService.hexStringToByteUID(null));

            } else {
                if (DBG) Log.d(TAG, "NAVIGATING DOWN " + mNextStep.toString());
                AvrcpControllerService.changeFolderPathNative(
                        mRemoteDevice.getBluetoothAddress(),
                        AvrcpControllerService.FOLDER_NAVIGATION_DIRECTION_DOWN,
                        AvrcpControllerService.hexStringToByteUID(mNextStep.getFolderUID()));
            }
        }

        @Override
        public void exit() {
            mBrowseNode = null;
            super.exit();
        }
    }

    class SetAddresedPlayerAndPlayItem extends CmdState {
        private static final String STATE_TAG = "AVRCPSM.SetAddresedPlayerAndPlayItem";
        int mScope;
        String mPlayItemId;
        String mAddrPlayerId;

        public void setItemAndScope(String addrPlayerId, String playItemId, int scope) {
            mAddrPlayerId = addrPlayerId;
            mPlayItemId = playItemId;
            mScope = scope;
        }

        @Override
        public boolean processMessage(Message msg) {
            if (DBG) Log.d(STATE_TAG, "processMessage " + msg.what);
            switch (msg.what) {
                case MESSAGE_PROCESS_SET_ADDRESSED_PLAYER:
                    // Set the new addressed player.
                    mBrowseTree.setCurrentAddressedPlayer(mAddrPlayerId);

                    // And now play the item.
                    AvrcpControllerService.playItemNative(mRemoteDevice.getBluetoothAddress(),
                            (byte) mScope, AvrcpControllerService.hexStringToByteUID(mPlayItemId),
                            (int) 0);

                    // Transition to connected state here.
                    transitionTo(mConnected);
                    break;

                case MESSAGE_INTERNAL_CMD_TIMEOUT:
                    transitionTo(mConnected);
                    break;

                case MESSAGE_SEND_PASS_THROUGH_CMD:
                case MESSAGE_SEND_GROUP_NAVIGATION_CMD:
                case MESSAGE_PROCESS_SET_ABS_VOL_CMD:
                case MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION:
                case MESSAGE_PROCESS_TRACK_CHANGED:
                case MESSAGE_PROCESS_PLAY_POS_CHANGED:
                case MESSAGE_PROCESS_PLAY_STATUS_CHANGED:
                case MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION:
                case MESSAGE_PROCESS_CONNECTION_CHANGE:
                case MESSAGE_PROCESS_BROWSE_CONNECTION_CHANGE:
                    // All of these messages should be handled by parent state immediately.
                    return false;

                default:
                    if (DBG) Log.d(STATE_TAG, "deferring message " + msg.what + " to connected!");
                    deferMessage(msg);
            }
            return true;
        }
    }

    // Class template for commands. Each state should do the following:
    // (a) In enter() send a timeout message which could be tracked in the
    // processMessage() stage.
    // (b) In exit() remove all the timeouts.
    //
    // Essentially the lifecycle of a timeout should be bounded to a CmdState always.
    abstract class CmdState extends State {
        @Override
        public void enter() {
            sendMessageDelayed(MESSAGE_INTERNAL_CMD_TIMEOUT, CMD_TIMEOUT_MILLIS);
        }

        @Override
        public void exit() {
            removeMessages(MESSAGE_INTERNAL_CMD_TIMEOUT);
        }
    }

    // Interface APIs
    boolean isConnected() {
        synchronized (mLock) {
            return mIsConnected;
        }
    }

    void doQuit() {
        try {
            mContext.unregisterReceiver(mBroadcastReceiver);
        } catch (IllegalArgumentException expected) {
            // If the receiver was never registered unregister will throw an
            // IllegalArgumentException.
        }
        quit();
    }

    void dump(StringBuilder sb) {
        if (mRemoteDevice == null) return;
        BluetoothDevice device = mRemoteDevice.mBTDevice;
        if (device == null) return;
        ProfileService.println(sb, "mCurrentDevice: " + device.getAddress() + "("
                + device.getName() + ") " + this.toString());
    }

    MediaMetadata getCurrentMetaData() {
        synchronized (mLock) {
            if (mAddressedPlayer != null && mAddressedPlayer.getCurrentTrack() != null) {
                MediaMetadata mmd = mAddressedPlayer.getCurrentTrack().getMediaMetaData();
                if (DBG) {
                    Log.d(TAG, "getCurrentMetaData mmd " + mmd);
                }
            }
            return EMPTY_MEDIA_METADATA;
        }
    }

    PlaybackState getCurrentPlayBackState() {
        return getCurrentPlayBackState(true);
    }

    PlaybackState getCurrentPlayBackState(boolean cached) {
        if (cached) {
            synchronized (mLock) {
                if (mAddressedPlayer == null) {
                    return new PlaybackState.Builder().setState(PlaybackState.STATE_ERROR,
                            PlaybackState.PLAYBACK_POSITION_UNKNOWN, 0).build();
                }
                return mAddressedPlayer.getPlaybackState();
            }
        } else {
            // Issue a native request, we return NULL since this is only for PTS.
            AvrcpControllerService.getPlaybackStateNative(mRemoteDevice.getBluetoothAddress());
            return null;
        }
    }

    List<MediaItem> getContents(String uid) {
        BrowseTree.BrowseNode currentNode = mBrowseTree.findBrowseNodeByID(uid);

        if (DBG) Log.d(TAG, "getContents(" + uid + ") currentNode = " + currentNode);
        if (currentNode != null) {
            if (!currentNode.isCached()) {
                sendMessage(AvrcpControllerStateMachine.MESSAGE_GET_FOLDER_LIST, uid);
            }
            return currentNode.getContents();
        }
        return null;
    }

    public void fetchAttrAndPlayItem(String uid) {
        BrowseTree.BrowseNode currItem = mBrowseTree.findBrowseNodeByID(uid);
        BrowseTree.BrowseNode currFolder = mBrowseTree.getCurrentBrowsedFolder();
        if (DBG) Log.d(TAG, "fetchAttrAndPlayItem mediaId=" + uid + " node=" + currItem);
        if (currItem != null) {
            int scope = currItem.getParent().isNowPlaying()
                    ? AvrcpControllerService.BROWSE_SCOPE_NOW_PLAYING
                    : AvrcpControllerService.BROWSE_SCOPE_VFS;
            Message msg =
                    obtainMessage(AvrcpControllerStateMachine.MESSAGE_FETCH_ATTR_AND_PLAY_ITEM,
                            scope, 0, currItem.getFolderUID());
            sendMessage(msg);
        }
    }

    private void broadcastMetaDataChanged(MediaMetadata metadata) {
        Intent intent = new Intent(AvrcpControllerService.ACTION_TRACK_EVENT);
        intent.putExtra(AvrcpControllerService.EXTRA_METADATA, metadata);
        if (VDBG) {
            Log.d(TAG, " broadcastMetaDataChanged = " + metadata.getDescription());
        }
        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);

    }

    private void broadcastFolderList(String id) {
        Intent intent = new Intent(AvrcpControllerService.ACTION_FOLDER_LIST);
        if (VDBG) Log.d(TAG, "broadcastFolderList id " + id);
        intent.putExtra(AvrcpControllerService.EXTRA_FOLDER_ID, id);
        BluetoothMediaBrowserService bluetoothMediaBrowserService =
                BluetoothMediaBrowserService.getBluetoothMediaBrowserService();
        if (bluetoothMediaBrowserService != null) {
            bluetoothMediaBrowserService.processInternalEvent(intent);
        }
    }

    private void broadcastPlayBackStateChanged(PlaybackState state) {
        Intent intent = new Intent(AvrcpControllerService.ACTION_TRACK_EVENT);
        intent.putExtra(AvrcpControllerService.EXTRA_PLAYBACK, state);
        if (DBG) {
            Log.d(TAG, " broadcastPlayBackStateChanged = " + state.toString());
        }
        mContext.sendBroadcast(intent, ProfileService.BLUETOOTH_PERM);
    }

    private void setAbsVolume(int absVol, int label) {
        int maxVolume = mAudioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC);
        int currIndex = mAudioManager.getStreamVolume(AudioManager.STREAM_MUSIC);
        // Ignore first volume command since phone may not know difference between stream volume
        // and amplifier volume.
        if (mRemoteDevice.getFirstAbsVolCmdRecvd()) {
            int newIndex = (maxVolume * absVol) / ABS_VOL_BASE;
            if (DBG) {
                Log.d(TAG, " setAbsVolume =" + absVol + " maxVol = " + maxVolume
                        + " cur = " + currIndex + " new = " + newIndex);
            }
            /*
             * In some cases change in percentage is not sufficient enough to warrant
             * change in index values which are in range of 0-15. For such cases
             * no action is required
             */
            if (newIndex != currIndex) {
                mAudioManager.setStreamVolume(AudioManager.STREAM_MUSIC, newIndex,
                        AudioManager.FLAG_SHOW_UI);
            }
        } else {
            mRemoteDevice.setFirstAbsVolCmdRecvd();
            absVol = (currIndex * ABS_VOL_BASE) / maxVolume;
            if (DBG) Log.d(TAG, " SetAbsVol recvd for first time, respond with " + absVol);
        }
        AvrcpControllerService.sendAbsVolRspNative(mRemoteDevice.getBluetoothAddress(), absVol,
                label);
    }

    private int getVolumePercentage() {
        int maxVolume = mAudioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC);
        int currIndex = mAudioManager.getStreamVolume(AudioManager.STREAM_MUSIC);
        int percentageVol = ((currIndex * ABS_VOL_BASE) / maxVolume);
        return percentageVol;
    }

    private final BroadcastReceiver mBroadcastReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action.equals(AudioManager.VOLUME_CHANGED_ACTION)) {
                int streamType = intent.getIntExtra(AudioManager.EXTRA_VOLUME_STREAM_TYPE, -1);
                if (streamType == AudioManager.STREAM_MUSIC) {
                    sendMessage(MESSAGE_PROCESS_VOLUME_CHANGED_NOTIFICATION);
                }
            }
        }
    };

    public static String dumpMessageString(int message) {
        String str = "UNKNOWN";
        switch (message) {
            case MESSAGE_SEND_PASS_THROUGH_CMD:
                str = "REQ_PASS_THROUGH_CMD";
                break;
            case MESSAGE_SEND_GROUP_NAVIGATION_CMD:
                str = "REQ_GRP_NAV_CMD";
                break;
            case MESSAGE_PROCESS_SET_ABS_VOL_CMD:
                str = "CB_SET_ABS_VOL_CMD";
                break;
            case MESSAGE_PROCESS_REGISTER_ABS_VOL_NOTIFICATION:
                str = "CB_REGISTER_ABS_VOL";
                break;
            case MESSAGE_PROCESS_TRACK_CHANGED:
                str = "CB_TRACK_CHANGED";
                break;
            case MESSAGE_PROCESS_PLAY_POS_CHANGED:
                str = "CB_PLAY_POS_CHANGED";
                break;
            case MESSAGE_PROCESS_PLAY_STATUS_CHANGED:
                str = "CB_PLAY_STATUS_CHANGED";
                break;
            case MESSAGE_PROCESS_RC_FEATURES:
                str = "CB_RC_FEATURES";
                break;
            case MESSAGE_PROCESS_CONNECTION_CHANGE:
                str = "CB_CONN_CHANGED";
                break;
            default:
                str = Integer.toString(message);
                break;
        }
        return str;
    }
}
