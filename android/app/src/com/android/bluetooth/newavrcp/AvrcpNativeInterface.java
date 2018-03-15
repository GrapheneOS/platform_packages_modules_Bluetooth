/*
 * Copyright 2018 The Android Open Source Project
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

package com.android.bluetooth.avrcp;

import android.util.Log;

import java.util.List;

/**
 * Native Interface to communicate with the JNI layer. This class should never be passed null
 * data.
 */
public class AvrcpNativeInterface {
    private static final String TAG = "NewAvrcpNativeInterface";
    private static final boolean DEBUG = true;
    private static AvrcpNativeInterface sInstance;

    static {
        classInitNative();
    }

    static AvrcpNativeInterface getInterface() {
        if (sInstance == null) {
            sInstance = new AvrcpNativeInterface();
        }

        return sInstance;
    }

    // TODO (apanicke): Hook into the AVRCP Service when checked in
    void init(/* AvrcpTargetService service */) {
        d("Init AvrcpNativeInterface");
        initNative();
    }

    void cleanup() {
        d("Cleanup AvrcpNativeInterface");
        cleanupNative();
    }

    Metadata getCurrentSongInfo() {
        d("getCurrentSongInfo");
        // TODO (apanicke): Hook into the AVRCP Service when checked in
        return null;
    }

    PlayStatus getPlayStatus() {
        d("getPlayStatus");
        // TODO (apanicke): Hook into the AVRCP Service when checked in
        return null;
    }

    void sendMediaKeyEvent(int keyEvent, int state) {
        d("sendMediaKeyEvent: keyEvent=" + keyEvent + " state=" + state);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    String getCurrentMediaId() {
        d("getCurrentMediaId");
        // TODO (apanicke): Hook into the AVRCP Service when checked in
        return null;
    }

    List<Metadata> getNowPlayingList() {
        d("getNowPlayingList");
        // TODO (apanicke): Hook into the AVRCP Service when checked in
        return null;
    }

    int getCurrentPlayerId() {
        d("getCurrentPlayerId");
        // TODO (apanicke): Hook into the AVRCP Service when checked in
        return -1;
    }

    List<PlayerInfo> getMediaPlayerList() {
        d("getMediaPlayerList");
        // TODO (apanicke): Hook into the AVRCP Service when checked in
        return null;
    }

    // TODO(apanicke): This shouldn't be named setBrowsedPlayer as it doesn't actually connect
    // anything internally. It just returns the number of items in the root folder.
    void setBrowsedPlayer(int playerId) {
        d("setBrowsedPlayer: playerId=" + playerId);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    void getFolderItemsRequest(int playerId, String mediaId) {
        d("getFolderItemsRequest: playerId=" + playerId + " mediaId=" + mediaId);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    void setBrowsedPlayerResponse(int playerId, boolean success, String rootId, int numItems) {
        d("setBrowsedPlayerResponse: playerId=" + playerId
                + " success=" + success
                + " rootId=" + rootId
                + " numItems=" + numItems);
        setBrowsedPlayerResponseNative(playerId, success, rootId, numItems);
    }

    void getFolderItemsResponse(String parentId, List<ListItem> items) {
        d("getFolderItemsResponse: parentId=" + parentId + " items.size=" + items.size());
        getFolderItemsResponseNative(parentId, items);
    }

    void sendMediaUpdate(boolean metadata, boolean playStatus, boolean queue) {
        d("sendMediaUpdate: metadata=" + metadata
                + " playStatus=" + playStatus
                + " queue=" + queue);
        sendMediaUpdateNative(metadata, playStatus, queue);
    }

    void sendFolderUpdate(boolean availablePlayers, boolean addressedPlayers, boolean uids) {
        d("sendFolderUpdate: availablePlayers=" + availablePlayers
                + " addressedPlayers=" + addressedPlayers
                + " uids=" + uids);
        sendFolderUpdateNative(availablePlayers, addressedPlayers, uids);
    }

    void playItem(int playerId, boolean nowPlaying, String mediaId) {
        d("playItem: playerId=" + playerId + " nowPlaying=" + nowPlaying + " mediaId" + mediaId);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    boolean connectDevice(String bdaddr) {
        d("connectDevice: bdaddr=" + bdaddr);
        return connectDeviceNative(bdaddr);
    }

    boolean disconnectDevice(String bdaddr) {
        d("disconnectDevice: bdaddr=" + bdaddr);
        return disconnectDeviceNative(bdaddr);
    }

    void setActiveDevice(String bdaddr) {
        d("setActiveDevice: bdaddr=" + bdaddr);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    void deviceConnected(String bdaddr, boolean absoluteVolume) {
        d("deviceConnected: bdaddr=" + bdaddr + " absoluteVolume=" + absoluteVolume);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    void deviceDisconnected(String bdaddr) {
        d("deviceDisconnected: bdaddr=" + bdaddr);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    void sendVolumeChanged(int volume) {
        d("sendVolumeChanged: volume=" + volume);
        sendVolumeChangedNative(volume);
    }

    void setVolume(int volume) {
        d("setVolume: volume=" + volume);
        // TODO (apanicke): Hook into the AVRCP Service when checked in
    }

    private static native void classInitNative();
    private native void initNative();
    private native void sendMediaUpdateNative(
            boolean trackChanged, boolean playState, boolean playPos);
    private native void sendFolderUpdateNative(
            boolean availablePlayers, boolean addressedPlayers, boolean uids);
    private native void setBrowsedPlayerResponseNative(
            int playerId, boolean success, String rootId, int numItems);
    private native void getFolderItemsResponseNative(String parentId, List<ListItem> list);
    private native void cleanupNative();
    private native boolean connectDeviceNative(String bdaddr);
    private native boolean disconnectDeviceNative(String bdaddr);
    private native void sendVolumeChangedNative(int volume);

    private static void d(String msg) {
        if (DEBUG) {
            Log.d(TAG, msg);
        }
    }
}
