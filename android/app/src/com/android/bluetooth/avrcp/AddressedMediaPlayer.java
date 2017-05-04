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

package com.android.bluetooth.avrcp;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.bluetooth.BluetoothAvrcp;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.media.session.MediaSession.QueueItem;
import android.media.MediaDescription;
import android.media.MediaMetadata;
import android.os.Bundle;
import android.util.Log;

import com.android.bluetooth.Utils;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;

/*************************************************************************************************
 * Provides functionality required for Addressed Media Player, like Now Playing List related
 * browsing commands, control commands to the current addressed player(playItem, play, pause, etc)
 * Acts as an Interface to communicate with media controller APIs for NowPlayingItems.
 ************************************************************************************************/

public class AddressedMediaPlayer {
    static private final String TAG = "AddressedMediaPlayer";
    static private final Boolean DEBUG = false;

    static private final long SINGLE_QID = 1;
    static private final String UNKNOWN_TITLE = "(unknown)";

    private AvrcpMediaRspInterface mMediaInterface;
    private List<MediaSession.QueueItem> mNowPlayingList;

    private final List<MediaSession.QueueItem> mUnknownNowPlayingList;

    private long mLastTrackIdSent;

    public AddressedMediaPlayer(AvrcpMediaRspInterface mediaInterface) {
        mNowPlayingList = null;
        mMediaInterface = mediaInterface;
        mLastTrackIdSent = MediaSession.QueueItem.UNKNOWN_ID;
        List<MediaSession.QueueItem> unknown = new ArrayList<MediaSession.QueueItem>();
        unknown.add(getCurrentQueueItem(null, SINGLE_QID));
        mUnknownNowPlayingList = unknown;
    }

    void cleanup() {
        if (DEBUG) Log.v(TAG, "cleanup");
        mNowPlayingList = null;
        mMediaInterface = null;
        mLastTrackIdSent = MediaSession.QueueItem.UNKNOWN_ID;
    }

    /* get now playing list from addressed player */
    void getFolderItemsNowPlaying(byte[] bdaddr, AvrcpCmd.FolderItemsCmd reqObj,
            @Nullable MediaController mediaController) {
        if (DEBUG) Log.v(TAG, "getFolderItemsNowPlaying");
        if (mediaController == null) {
            // No players (if a player exists, we would have selected it)
            Log.e(TAG, "mediaController = null, sending no available players response");
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_NO_AVBL_PLAY, null);
            return;
        }
        List<MediaSession.QueueItem> items = getNowPlayingList(mediaController);
        getFolderItemsFilterAttr(bdaddr, reqObj, items, AvrcpConstants.BTRC_SCOPE_NOW_PLAYING,
                reqObj.mStartItem, reqObj.mEndItem, mediaController);
    }

    /* get item attributes for item in now playing list */
    void getItemAttr(byte[] bdaddr, AvrcpCmd.ItemAttrCmd itemAttr,
            @Nullable MediaController mediaController) {
        int status = AvrcpConstants.RSP_NO_ERROR;
        long mediaId = ByteBuffer.wrap(itemAttr.mUid).getLong();
        List<MediaSession.QueueItem> items = getNowPlayingList(mediaController);

        /* checking if item attributes has been asked for now playing item or
         * some other item with specific media id */
        if (Arrays.equals(itemAttr.mUid, AvrcpConstants.TRACK_IS_SELECTED)) {
            if (DEBUG) Log.d(TAG, "getItemAttr: Remote requests for now playing contents:");

            // get the current playing metadata and send.
            getItemAttrFilterAttr(bdaddr, itemAttr, getCurrentQueueItem(mediaController, mediaId),
                    mediaController);
            return;
        }

        if (DEBUG) Log.d(TAG, "getItemAttr-UID: 0x" + Utils.byteArrayToString(itemAttr.mUid));
        for (MediaSession.QueueItem item : items) {
            if (item.getQueueId() == mediaId) {
                getItemAttrFilterAttr(bdaddr, itemAttr, item, mediaController);
                return;
            }
        }

        // Couldn't find it, so the id is invalid
        mMediaInterface.getItemAttrRsp(bdaddr, AvrcpConstants.RSP_INV_ITEM, null);
    }

    /* Refresh and get the queue of now playing.
     */
    private List<MediaSession.QueueItem> getNowPlayingList(
            @Nullable MediaController mediaController) {
        if (mediaController == null) return mUnknownNowPlayingList;
        if (mNowPlayingList != null) return mNowPlayingList;
        List<MediaSession.QueueItem> items = mediaController.getQueue();
        if (items == null) {
            Log.i(TAG, "null queue from " + mediaController.getPackageName()
                            + ", constructing current-item list");
            MediaMetadata metadata = mediaController.getMetadata();
            // Because we are database-unaware, we can just number the item here whatever we want
            // because they have to re-poll it every time.
            MediaSession.QueueItem current = getCurrentQueueItem(mediaController, SINGLE_QID);
            items = new ArrayList<MediaSession.QueueItem>();
            items.add(current);
        }
        mNowPlayingList = items;
        return items;
    }

    /* Constructs a queue item representing the current playing metadata from an
     * active controller with queue id |qid|.
     */
    private MediaSession.QueueItem getCurrentQueueItem(
            @Nullable MediaController controller, long qid) {
        if (controller == null) {
            MediaDescription.Builder bob = new MediaDescription.Builder();
            bob.setTitle(UNKNOWN_TITLE);
            return new QueueItem(bob.build(), qid);
        }

        MediaMetadata metadata = controller.getMetadata();
        if (metadata == null) {
            Log.w(TAG, "Controller has no metadata!? Making an empty one");
            metadata = (new MediaMetadata.Builder()).build();
        }

        MediaDescription.Builder bob = new MediaDescription.Builder();
        MediaDescription desc = metadata.getDescription();

        // set the simple ones that MediaMetadata builds for us
        bob.setMediaId(desc.getMediaId());
        bob.setTitle(desc.getTitle());
        bob.setSubtitle(desc.getSubtitle());
        bob.setDescription(desc.getDescription());
        // fill the ones that we use later
        bob.setExtras(fillBundle(metadata, desc.getExtras()));

        // build queue item with the new metadata
        desc = bob.build();
        return new QueueItem(desc, qid);
    }

    private Bundle fillBundle(MediaMetadata metadata, Bundle currentExtras) {
        if (metadata == null) {
            return currentExtras;
        }

        String[] stringKeys = {MediaMetadata.METADATA_KEY_ARTIST, MediaMetadata.METADATA_KEY_ALBUM,
                MediaMetadata.METADATA_KEY_GENRE};
        String[] longKeys = {MediaMetadata.METADATA_KEY_TRACK_NUMBER,
                MediaMetadata.METADATA_KEY_NUM_TRACKS, MediaMetadata.METADATA_KEY_DURATION};

        Bundle bundle = currentExtras;
        if (bundle == null) bundle = new Bundle();

        for (String key : stringKeys) {
            String current = bundle.getString(key);
            if (current == null) bundle.putString(key, metadata.getString(key));
        }
        for (String key : longKeys) {
            if (!bundle.containsKey(key)) bundle.putLong(key, metadata.getLong(key));
        }
        return bundle;
    }

    void updateNowPlayingList(List<MediaSession.QueueItem> queue){
        mNowPlayingList = queue;
    }

    /* Instructs media player to play particular media item */
    void playItem(byte[] bdaddr, byte[] uid, @Nullable MediaController mediaController) {
        long qid = ByteBuffer.wrap(uid).getLong();
        List<MediaSession.QueueItem> items = mNowPlayingList;

        if (mediaController == null) {
            Log.e(TAG, "No mediaController when PlayItem " + qid + " requested");
            mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_INTERNAL_ERR);
            return;
        }

        MediaController.TransportControls mediaControllerCntrl =
                mediaController.getTransportControls();

        if (items == null) {
            Log.w(TAG, "nowPlayingItems is null");
            mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_INTERNAL_ERR);
            return;
        }

        for (MediaSession.QueueItem item : items) {
            if (qid == item.getQueueId()) {
                if (DEBUG) Log.d(TAG, "Skipping to ID " + qid);
                mediaControllerCntrl.skipToQueueItem(qid);
                mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR);
                return;
            }
        }

        Log.w(TAG, "Invalid now playing Queue ID " + qid);
        mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_INV_ITEM);
    }

    void getTotalNumOfItems(byte[] bdaddr, @Nullable MediaController mediaController) {
        if (DEBUG) Log.d(TAG, "getTotalNumOfItems");
        List<MediaSession.QueueItem> items = mNowPlayingList;
        if (items != null) {
            // We already have the cached list, send the response to remote
            mMediaInterface.getTotalNumOfItemsRsp(
                    bdaddr, AvrcpConstants.RSP_NO_ERROR, 0, items.size());
            return;
        }

        if (mediaController == null) {
            Log.e(TAG, "getTotalNumOfItems with no mediaController, sending no items");
            mMediaInterface.getTotalNumOfItemsRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR, 0, 0);
            return;
        }

        // We don't have the cached list, fetch it from Media Controller
        items = mediaController.getQueue();
        if (items == null) {
            // We may be presenting a queue with only 1 item (the current one)
            int count = mediaController.getMetadata() != null ? 1 : 0;
            mMediaInterface.getTotalNumOfItemsRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR, 0, count);
        }
        // Cache the response for later
        mNowPlayingList = items;
        mMediaInterface.getTotalNumOfItemsRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR, 0, items.size());
    }

    boolean sendTrackChangeWithId(boolean requesting, @Nullable MediaController mediaController) {
        if (DEBUG)
            Log.d(TAG, "sendTrackChangeWithId (" + requesting + "): controller " + mediaController);
        byte[] track;
        long qid = MediaSession.QueueItem.UNKNOWN_ID;
        if (mediaController != null) {
            PlaybackState state = mediaController.getPlaybackState();
            /* for any item associated with NowPlaying, uid is queueId */
            if (state != null) qid = state.getActiveQueueItemId();
        }
        if (!requesting && qid == mLastTrackIdSent) {
            if (DEBUG) Log.d(TAG, "not sending duplicate track changed id " + qid);
            return false;
        }
        track = ByteBuffer.allocate(AvrcpConstants.UID_SIZE).putLong(qid).array();
        if (DEBUG) Log.d(TAG, "trackChangedRsp: 0x" + Utils.byteArrayToString(track));

        int trackChangedNT = AvrcpConstants.NOTIFICATION_TYPE_CHANGED;
        if (requesting) trackChangedNT = AvrcpConstants.NOTIFICATION_TYPE_INTERIM;
        mMediaInterface.trackChangedRsp(trackChangedNT, track);
        mLastTrackIdSent = qid;
        return (trackChangedNT == AvrcpConstants.NOTIFICATION_TYPE_CHANGED);
    }

    /*
     * helper method to check if startItem and endItem index is with range of
     * MediaItem list. (Resultset containing all items in current path)
     */
    private List<MediaSession.QueueItem> checkIndexOutofBounds(
            byte[] bdaddr, List<MediaSession.QueueItem> items, long startItem, long endItem) {
        if (endItem > items.size()) endItem = items.size() - 1;
        if (startItem > Integer.MAX_VALUE) startItem = Integer.MAX_VALUE;
        try {
            List<MediaSession.QueueItem> selected =
                    items.subList((int) startItem, (int) Math.min(items.size(), endItem + 1));
            if (selected.isEmpty()) {
                Log.i(TAG, "itemsSubList is empty.");
                return null;
            }
            return selected;
        } catch (IndexOutOfBoundsException ex) {
            Log.i(TAG, "Range (" + startItem + ", " + endItem + ") invalid");
        } catch (IllegalArgumentException ex) {
            Log.i(TAG, "Range start " + startItem + " > size (" + items.size() + ")");
        }
        return null;
    }

    /*
     * helper method to filter required attibutes before sending GetFolderItems
     * response
     */
    private void getFolderItemsFilterAttr(byte[] bdaddr, AvrcpCmd.FolderItemsCmd folderItemsReqObj,
            List<MediaSession.QueueItem> items, byte scope, long startItem, long endItem,
            @NonNull MediaController mediaController) {
        if (DEBUG) Log.d(TAG, "getFolderItemsFilterAttr: startItem =" + startItem + ", endItem = "
                + endItem);

        List<MediaSession.QueueItem> result_items = new ArrayList<MediaSession.QueueItem>();

        if (items == null) {
            Log.e(TAG, "items is null in getFolderItemsFilterAttr");
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INV_RANGE, null);
            return;
        }

        result_items = checkIndexOutofBounds(bdaddr, items, startItem, endItem);
        /* check for index out of bound errors */
        if (result_items == null) {
            Log.w(TAG, "result_items is null.");
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INV_RANGE, null);
            return;
        }

        FolderItemsData folderDataNative = new FolderItemsData(result_items.size());

        /* variables to accumulate attrs */
        ArrayList<String> attrArray = new ArrayList<String>();
        ArrayList<Integer> attrId = new ArrayList<Integer>();

        for (int itemIndex = 0; itemIndex < result_items.size(); itemIndex++) {
            MediaSession.QueueItem item = result_items.get(itemIndex);
            // get the queue id
            long qid = item.getQueueId();
            byte[] uid = ByteBuffer.allocate(AvrcpConstants.UID_SIZE).putLong(qid).array();

            // get the array of uid from 2d to array 1D array
            for (int idx = 0; idx < AvrcpConstants.UID_SIZE; idx++) {
                folderDataNative.mItemUid[itemIndex * AvrcpConstants.UID_SIZE + idx] = uid[idx];
            }

            /* Set display name for current item */
            folderDataNative.mDisplayNames[itemIndex] =
                    getAttrValue(AvrcpConstants.ATTRID_TITLE, item, mediaController);

            int maxAttributesRequested = 0;
            boolean isAllAttribRequested = false;
            /* check if remote requested for attributes */
            if (folderItemsReqObj.mNumAttr != AvrcpConstants.NUM_ATTR_NONE) {
                int attrCnt = 0;

                /* add requested attr ids to a temp array */
                if (folderItemsReqObj.mNumAttr == AvrcpConstants.NUM_ATTR_ALL) {
                    isAllAttribRequested = true;
                    maxAttributesRequested = AvrcpConstants.MAX_NUM_ATTR;
                } else {
                    /* get only the requested attribute ids from the request */
                    maxAttributesRequested = folderItemsReqObj.mNumAttr;
                }

                /* lookup and copy values of attributes for ids requested above */
                for (int idx = 0; idx < maxAttributesRequested; idx++) {
                    /* check if media player provided requested attributes */
                    String value = null;

                    int attribId =
                            isAllAttribRequested ? (idx + 1) : folderItemsReqObj.mAttrIDs[idx];
                    value = getAttrValue(attribId, item, mediaController);
                    if (value != null) {
                        attrArray.add(value);
                        attrId.add(attribId);
                        attrCnt++;
                    }
                }
                /* add num attr actually received from media player for a particular item */
                folderDataNative.mAttributesNum[itemIndex] = attrCnt;
            }
        }

        /* copy filtered attr ids and attr values to response parameters */
        if (folderItemsReqObj.mNumAttr != AvrcpConstants.NUM_ATTR_NONE) {
            folderDataNative.mAttrIds = new int[attrId.size()];
            for (int attrIndex = 0; attrIndex < attrId.size(); attrIndex++)
                folderDataNative.mAttrIds[attrIndex] = attrId.get(attrIndex);
            folderDataNative.mAttrValues = attrArray.toArray(new String[attrArray.size()]);
        }
        for (int attrIndex = 0; attrIndex < folderDataNative.mAttributesNum.length; attrIndex++)
            if (DEBUG)
                Log.d(TAG, "folderDataNative.mAttributesNum"
                                + folderDataNative.mAttributesNum[attrIndex] + " attrIndex "
                                + attrIndex);

        /* create rsp object and send response to remote device */
        FolderItemsRsp rspObj = new FolderItemsRsp(AvrcpConstants.RSP_NO_ERROR, Avrcp.sUIDCounter,
                scope, folderDataNative.mNumItems, folderDataNative.mFolderTypes,
                folderDataNative.mPlayable, folderDataNative.mItemTypes, folderDataNative.mItemUid,
                folderDataNative.mDisplayNames, folderDataNative.mAttributesNum,
                folderDataNative.mAttrIds, folderDataNative.mAttrValues);
        mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR, rspObj);
    }

    private String getAttrValue(
            int attr, MediaSession.QueueItem item, @Nullable MediaController mediaController) {
        String attrValue = null;
        if (item == null) {
            if (DEBUG) Log.d(TAG, "getAttrValue received null item");
            return null;
        }
        try {
            MediaDescription desc = item.getDescription();
            Bundle extras = desc.getExtras();
            if (mediaController != null) {
                PlaybackState state = mediaController.getPlaybackState();
                if (state != null && (item.getQueueId() == state.getActiveQueueItemId())) {
                    if (DEBUG) Log.d(TAG, "getAttrValue: item is active, filling extra data");
                    extras = fillBundle(mediaController.getMetadata(), extras);
                }
            }
            if (DEBUG) Log.d(TAG, "getAttrValue: item " + item + " : " + desc);
            switch (attr) {
                case AvrcpConstants.ATTRID_TITLE:
                    /* Title is mandatory attribute */
                    attrValue = desc.getTitle().toString();
                    break;

                case AvrcpConstants.ATTRID_ARTIST:
                    attrValue = extras.getString(MediaMetadata.METADATA_KEY_ARTIST);
                    break;

                case AvrcpConstants.ATTRID_ALBUM:
                    attrValue = extras.getString(MediaMetadata.METADATA_KEY_ALBUM);
                    break;

                case AvrcpConstants.ATTRID_TRACK_NUM:
                    attrValue =
                            Long.toString(extras.getLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER));
                    break;

                case AvrcpConstants.ATTRID_NUM_TRACKS:
                    attrValue =
                            Long.toString(extras.getLong(MediaMetadata.METADATA_KEY_NUM_TRACKS));
                    break;

                case AvrcpConstants.ATTRID_GENRE:
                    attrValue = extras.getString(MediaMetadata.METADATA_KEY_GENRE);
                    break;

                case AvrcpConstants.ATTRID_PLAY_TIME:
                    attrValue = Long.toString(extras.getLong(MediaMetadata.METADATA_KEY_DURATION));
                    break;

                case AvrcpConstants.ATTRID_COVER_ART:
                    Log.e(TAG, "getAttrValue: Cover art attribute not supported");
                    return null;

                default:
                    Log.e(TAG, "getAttrValue: Unknown attribute ID requested: " + attr);
                    return null;
            }
        } catch (NullPointerException ex) {
            Log.w(TAG, "getAttrValue: attr id not found in result");
            /* checking if attribute is title, then it is mandatory and cannot send null */
            if (attr == AvrcpConstants.ATTRID_TITLE) {
                attrValue = "<Unknown Title>";
            } else {
                return null;
            }
        }
        if (DEBUG) Log.d(TAG, "getAttrValue: attrvalue = " + attrValue + ", attr id:" + attr);
        return attrValue;
    }

    private void getItemAttrFilterAttr(byte[] bdaddr, AvrcpCmd.ItemAttrCmd mItemAttrReqObj,
            MediaSession.QueueItem mediaItem, @Nullable MediaController mediaController) {
        /* Response parameters */
        int[] attrIds = null; /* array of attr ids */
        String[] attrValues = null; /* array of attr values */
        int attrCounter = 0; /* num attributes for each item */
        /* variables to temperorily add attrs */
        ArrayList<String> attrArray = new ArrayList<String>();
        ArrayList<Integer> attrId = new ArrayList<Integer>();

        ArrayList<Integer> attrTempId = new ArrayList<Integer>();

        /* check if remote device has requested for attributes */
        if (mItemAttrReqObj.mNumAttr != AvrcpConstants.NUM_ATTR_NONE) {
            if (mItemAttrReqObj.mNumAttr == AvrcpConstants.NUM_ATTR_ALL) {
                for (int idx = 1; idx < AvrcpConstants.MAX_NUM_ATTR; idx++) {
                    attrTempId.add(idx); /* attr id 0x00 is unused */
                }
            } else {
                /* get only the requested attribute ids from the request */
                for (int idx = 0; idx < mItemAttrReqObj.mNumAttr; idx++) {
                    if (DEBUG)
                        Log.d(TAG, "getItemAttrFilterAttr: attr id[" + idx + "] :"
                                        + mItemAttrReqObj.mAttrIDs[idx]);
                    attrTempId.add(mItemAttrReqObj.mAttrIDs[idx]);
                }
            }
        }

        if (DEBUG) Log.d(TAG, "getItemAttrFilterAttr: attr id list size:" + attrTempId.size());
        /* lookup and copy values of attributes for ids requested above */
        for (int idx = 0; idx < attrTempId.size(); idx++) {
            /* check if media player provided requested attributes */
            String value = getAttrValue(attrTempId.get(idx), mediaItem, mediaController);
            if (value != null) {
                attrArray.add(value);
                attrId.add(attrTempId.get(idx));
                attrCounter++;
            }
        }

        /* copy filtered attr ids and attr values to response parameters */
        if (mItemAttrReqObj.mNumAttr != AvrcpConstants.NUM_ATTR_NONE) {
            attrIds = new int[attrId.size()];

            for (int attrIndex = 0; attrIndex < attrId.size(); attrIndex++)
                attrIds[attrIndex] = attrId.get(attrIndex);

            attrValues = attrArray.toArray(new String[attrId.size()]);

            /* create rsp object and send response */
            ItemAttrRsp rspObj = new ItemAttrRsp(AvrcpConstants.RSP_NO_ERROR,
                    (byte)attrCounter, attrIds, attrValues);
            mMediaInterface.getItemAttrRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR, rspObj);
            return;
        }
    }
}
