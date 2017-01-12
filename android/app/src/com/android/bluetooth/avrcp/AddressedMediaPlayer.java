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

import android.bluetooth.BluetoothAvrcp;
import android.media.session.MediaSession;
import android.media.session.MediaSession.QueueItem;
import android.media.MediaDescription;
import android.media.MediaMetadata;
import android.os.Bundle;
import android.util.Log;

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

    private AvrcpMediaRspInterface mMediaInterface;
    private NowPlayingListManager mNowPlayingListManager = new NowPlayingListManager();

    /* Now playing UID */
    private static final byte[] NOW_PLAYING_UID = {(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                                                  (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};

    public AddressedMediaPlayer(AvrcpMediaRspInterface _mediaInterface) {
        mMediaInterface = _mediaInterface;
    }

    void cleanup() {
        if (DEBUG) Log.v(TAG, "cleanup");
        mNowPlayingListManager = null;
        mMediaInterface = null;
    }

    /* get now playing list from addressed player */
    void getFolderItemsNowPlaying(byte[] bdaddr, AvrcpCmd.FolderItemsCmd reqObj,
            MediaController mediaController) {
        List<QueueItem> tempItems;
        List<MediaSession.QueueItem> mNowPlayingItems = mNowPlayingListManager.getNowPlayingList();
        if (DEBUG) Log.v(TAG, "getFolderItemsNowPlaying");

        if (mNowPlayingItems != null) {
            // We already have the cached list sending the response to remote
            if (DEBUG) Log.i(TAG, "sending cached now playing list");
            /* Filter attributes from cached NowPlayingList and send response */
            getFolderItemsFilterAttr(bdaddr, reqObj, mNowPlayingItems,
                    AvrcpConstants.BTRC_SCOPE_FILE_SYSTEM, reqObj.mStartItem, reqObj.mEndItem);
        } else if (mediaController == null) {
            Log.e(TAG, "mediaController = null, sending internal error response");
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INTERNAL_ERR, null);
        } else {
            // We don't have the cached list, fetching it from Media Controller
            mNowPlayingItems = mediaController.getQueue();
            if (mNowPlayingItems == null) {
                Log.w(TAG, "Received Now playing list is null from: " +
                        mediaController.getPackageName() + ", sending internal error response");
                mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INTERNAL_ERR, null);
            } else {
                mNowPlayingListManager.setNowPlayingList(mNowPlayingItems);
                getFolderItemsFilterAttr(bdaddr, reqObj, mNowPlayingItems,
                        AvrcpConstants.BTRC_SCOPE_NOW_PLAYING, reqObj.mStartItem,
                        reqObj.mEndItem);
            }
        }
    }

    /* get item attributes for item in now playing list */
    void getItemAttr(byte[] bdaddr, AvrcpCmd.ItemAttrCmd itemAttr,
            MediaController mediaController) {
        int status = AvrcpConstants.RSP_NO_ERROR;
        int idx;
        long mediaID = ByteBuffer.wrap(itemAttr.mUid).getLong();
        List<MediaSession.QueueItem> mNowPlayingItems = mNowPlayingListManager.getNowPlayingList();

        /* checking if item attributes has been asked for now playing item or
         * some other item with specific media id */
        if (Arrays.equals(itemAttr.mUid, NOW_PLAYING_UID)) {
            if (DEBUG) Log.d(TAG, "getItemAttr: Remote requests for now playing contents:");

            // get the current playing song metadata and sending the queueitem.
            if (mediaController != null) {
                MediaMetadata metadata = mediaController.getMetadata();
                if (metadata != null) {
                    getItemAttrFilterAttr(bdaddr, itemAttr, getQueueItem(metadata));
                } else {
                    Log.e(TAG, "getItemAttr: metadata = null");
                    status = AvrcpConstants.RSP_INTERNAL_ERR;
                }
            } else {
                Log.e(TAG, "getItemAttr: mediaController = null");
                status = AvrcpConstants.RSP_INTERNAL_ERR;
            }
        } else if (mNowPlayingItems != null) {
            if(DEBUG) printByteArray("getItemAttr-UID", itemAttr.mUid);
            for (idx = 0; idx < mNowPlayingItems.size(); idx++) {
                if (mediaID == mNowPlayingItems.get(idx).getQueueId()) {
                    getItemAttrFilterAttr(bdaddr, itemAttr, mNowPlayingItems.get(idx));
                    break;
                }
            }
            if (idx >= mNowPlayingItems.size()) {
                Log.e(TAG, "getItemAttr: idx is more than now playing list: idx = " + idx
                        + ", now playing list size = " + mNowPlayingItems.size());
                status = AvrcpConstants.RSP_INV_ITEM;
            }
        } else {
            Log.e(TAG, "getItemAttr: mNowPlayingItems is null!");
            status = AvrcpConstants.RSP_INTERNAL_ERR;
        }

        // sending error status in case of error
        if (status != AvrcpConstants.RSP_NO_ERROR) {
            mMediaInterface.getItemAttrRsp(bdaddr, status, null);
        }
    }

    private MediaSession.QueueItem getQueueItem(MediaMetadata metadata) {
        MediaDescription.Builder builder = new MediaDescription.Builder();

        // getting the media id
        String mediaId = metadata.getDescription().getMediaId();
        if (mediaId != null) {
            builder.setMediaId(mediaId);
            if(DEBUG) Log.d(TAG, "Item mediaId = " + mediaId);
        }

        // getting the title
        if (metadata.getDescription().getTitle() != null) {
            String title = metadata.getDescription().getTitle().toString();
            builder.setTitle(title);
            if(DEBUG) Log.d(TAG, "Item title = " + title);
        }

        // getting the metadata from the key-value pairs and filling to bundle
        String artist = metadata.getString(MediaMetadata.METADATA_KEY_ARTIST);
        String album = metadata.getString(MediaMetadata.METADATA_KEY_ALBUM);
        String track_num = metadata.getLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER) + "";
        String num_tracks = metadata.getLong(MediaMetadata.METADATA_KEY_NUM_TRACKS) + "";
        String genre = metadata.getString(MediaMetadata.METADATA_KEY_GENRE);
        String duration = metadata.getLong(MediaMetadata.METADATA_KEY_DURATION) + "";

        Bundle bundle = fillBundle(artist, album, track_num, num_tracks, genre, duration);
        builder.setExtras(bundle);

        // building a queue item from the above metadata
        MediaDescription desc = builder.build();
        return new QueueItem((desc), ByteBuffer.wrap(NOW_PLAYING_UID).getLong());
    }

    private Bundle fillBundle(String artist, String album, String trackNum, String numTracks,
            String genre, String playTime) {

        Bundle bundle = new Bundle();

        bundle.putString(MediaMetadata.METADATA_KEY_ARTIST, artist);
        bundle.putString(MediaMetadata.METADATA_KEY_ALBUM, album);
        bundle.putString(MediaMetadata.METADATA_KEY_GENRE, genre);
        bundle.putString(MediaMetadata.METADATA_KEY_NUM_TRACKS, numTracks);
        bundle.putString(MediaMetadata.METADATA_KEY_DURATION, playTime);
        bundle.putString(MediaMetadata.METADATA_KEY_TRACK_NUMBER, trackNum);
        return bundle;
    }

    void updateNowPlayingList(List<MediaSession.QueueItem> queue){
        mNowPlayingListManager.setNowPlayingList(queue);
    }

    /* Instructs media player to play particular media item */
    void playItem(byte[] bdaddr, byte[] uid, byte scope, MediaController mediaController) {
        long qid = ByteBuffer.wrap(uid).getLong();
        List<MediaSession.QueueItem> mNowPlayingItems = mNowPlayingListManager.getNowPlayingList();

        if (mediaController != null) {
            MediaController.TransportControls mediaControllerCntrl =
                    mediaController.getTransportControls();
            if (DEBUG) Log.d(TAG, "Sending playID");

            if (scope == AvrcpConstants.BTRC_SCOPE_NOW_PLAYING) {
                int idx;
                /* find the queueId of the mediaId to play */
                if (mNowPlayingItems != null) {
                    for (idx = 0; idx < mNowPlayingItems.size(); idx++) {
                        if (qid == mNowPlayingItems.get(idx).getQueueId()) {
                            mediaControllerCntrl.skipToQueueItem(qid);
                            break;
                        }
                    }
                    /* if mediaId is not found in nowplaying list */
                    if (idx >= mNowPlayingItems.size()) {
                        Log.w(TAG, "item is not present in queue");
                        mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_INV_ITEM);
                    }
                } else {
                    Log.w(TAG, "nowPlayingItems is null");
                    mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_INTERNAL_ERR);
                }
            }
            mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR);
        } else {
            Log.e(TAG, "mediaController is null");
            mMediaInterface.playItemRsp(bdaddr, AvrcpConstants.RSP_INTERNAL_ERR);
        }
    }

    void getTotalNumOfItems(byte[] bdaddr, byte scope, MediaController mediaController) {
        if (DEBUG) Log.d(TAG, "getTotalNumOfItems scope = " + scope);
        List<MediaSession.QueueItem> mNowPlayingItems = mNowPlayingListManager.getNowPlayingList();
        if (mNowPlayingItems != null) {
            // We already have the cached list sending the response to remote
            mMediaInterface.getTotalNumOfItemsRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR, 0,
                    mNowPlayingItems.size());
        } else if (mediaController == null) {
            Log.e(TAG, "mediaController is null");
            mMediaInterface.getTotalNumOfItemsRsp(bdaddr,
                    AvrcpConstants.RSP_INTERNAL_ERR, 0, 0);
        } else {
            // We don't have the cached list, fetching it from Media Controller
            mNowPlayingItems = mediaController.getQueue();
            if (mNowPlayingItems == null) {
                Log.e(TAG, "mNowPlayingItems is null");
                mMediaInterface.getTotalNumOfItemsRsp(bdaddr,
                        AvrcpConstants.RSP_INV_ITEM, 0, 0);
            } else {
                mNowPlayingListManager.setNowPlayingList(mediaController.getQueue());
                mMediaInterface.getTotalNumOfItemsRsp(bdaddr,
                        AvrcpConstants.RSP_NO_ERROR, 0, mNowPlayingItems.size());
            }
        }
    }

    void sendTrackChangeWithId(int trackChangedNT, MediaController mediaController) {
        if (DEBUG) Log.d(TAG, "sendTrackChangeWithId");
        byte[] track;
        try {
            String mediaId = mediaController.getMetadata().getDescription().getMediaId();
            long qid = 0;
            List<MediaSession.QueueItem> mNowPlayingItems = mNowPlayingListManager.getNowPlayingList();
            /* traverse now playing list for current playing item */
            for (QueueItem qitem : mNowPlayingItems) {
                if (qitem.getDescription().getMediaId().equals(mediaId)) {
                    qid = qitem.getQueueId();
                    if (DEBUG) Log.d(TAG, "sendTrackChangeWithId: Found matching qid= " + qid);
                    break;
                }
            }
            /* for any item associated with NowPlaying, uid is queueId */
            track = ByteBuffer.allocate(AvrcpConstants.UID_SIZE).putLong(qid).array();
        } catch (NullPointerException e) {
            Log.w(TAG, "NullPointerException getting uid, sending no track selected");
            // Track selected (0x0) is not allowed for browsable players (AVRCP 1.6.1 p64)
            track = AvrcpConstants.NO_TRACK_SELECTED;
        }
        if (DEBUG) printByteArray("trackChangedRsp", track);
        mMediaInterface.trackChangedRsp(trackChangedNT, track);
    }

    /*
     * helper method to check if startItem and endItem index is with range of
     * MediaItem list. (Resultset containing all items in current path)
     */
    private List<MediaSession.QueueItem> checkIndexOutofBounds(byte[] bdaddr,
            List<MediaSession.QueueItem> children, int startItem, int endItem) {
        try {
            List<MediaSession.QueueItem> childrenSubList =
                children.subList(startItem, Math.min(children.size(), endItem + 1));
            if (childrenSubList.isEmpty()) {
                Log.i(TAG, "childrenSubList is empty.");
                throw new IndexOutOfBoundsException();
            }
            return childrenSubList;
        } catch (IndexOutOfBoundsException ex) {
            Log.i(TAG, "Index out of bounds start item =" + startItem + " end item = "
                    + Math.min(children.size(), endItem + 1));
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INV_RANGE, null);
            return null;
        } catch (IllegalArgumentException ex) {
            Log.i(TAG, "Index out of bounds start item =" + startItem + " > size");
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INV_RANGE, null);
            return null;
        }
    }

    /*
     * helper method to filter required attibutes before sending GetFolderItems
     * response
     */
    private void getFolderItemsFilterAttr(byte[] bdaddr,
            AvrcpCmd.FolderItemsCmd mFolderItemsReqObj,
            List<MediaSession.QueueItem> children, byte scope, int startItem, int endItem) {
        if (DEBUG) Log.d(TAG, "getFolderItemsFilterAttr: startItem =" + startItem + ", endItem = "
                + endItem);

        List<MediaSession.QueueItem> result_items = new ArrayList<MediaSession.QueueItem>();

        if (children != null) {
            /* check for index out of bound errors */
            if ((result_items = checkIndexOutofBounds(bdaddr, children, startItem, endItem))
                    == null) {
                Log.w(TAG, "result_items is null.");
                mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INV_RANGE, null);
                return;
            }
            FolderItemsData folderDataNative = new FolderItemsData(result_items.size());

            /* variables to temperorily add attrs */
            ArrayList<String> attrArray = new ArrayList<String>();
            ArrayList<Integer> attrId = new ArrayList<Integer>();

            for (int itemIndex = 0; itemIndex < result_items.size(); itemIndex++) {
                // get the queue id
                long qid = result_items.get(itemIndex).getQueueId();
                byte[] uid = ByteBuffer.allocate(AvrcpConstants.UID_SIZE).putLong(qid).array();

                // get the array of uid from 2d to array 1D array
                for (int idx = 0; idx < AvrcpConstants.UID_SIZE; idx++) {
                    folderDataNative.mItemUid[itemIndex * AvrcpConstants.UID_SIZE + idx] = uid[idx];
                }

                /* Set display name for current item */
                folderDataNative.mDisplayNames[itemIndex] = result_items.get(itemIndex)
                        .getDescription().getTitle().toString();

                int maxAttributesRequested = 0;
                boolean isAllAttribRequested = false;
                /* check if remote requested for attributes */
                if (mFolderItemsReqObj.mNumAttr != AvrcpConstants.NUM_ATTR_NONE) {
                    int attrCnt = 0;

                    /* add requested attr ids to a temp array */
                    if (mFolderItemsReqObj.mNumAttr == AvrcpConstants.NUM_ATTR_ALL) {
                        isAllAttribRequested = true;
                        maxAttributesRequested = AvrcpConstants.MAX_NUM_ATTR;
                    } else {
                        /* get only the requested attribute ids from the request */
                        maxAttributesRequested = mFolderItemsReqObj.mNumAttr;
                    }

                    /* lookup and copy values of attributes for ids requested above */
                    for (int idx = 0; idx < maxAttributesRequested; idx++) {
                        /* check if media player provided requested attributes */
                        String value = null;

                        int attribId = isAllAttribRequested ? (idx + 1)
                                : mFolderItemsReqObj.mAttrIDs[idx];
                        if (attribId >= AvrcpConstants.ATTRID_TITLE
                                && attribId <= AvrcpConstants.ATTRID_PLAY_TIME) {
                            if ((value = getAttrValue(attribId, result_items, itemIndex))
                                    != null) {
                                attrArray.add(value);
                                attrId.add(attribId);
                                attrCnt++;
                            }
                        } else {
                            Log.w(TAG, "invalid attributed id is requested: " + attribId);
                        }
                    }
                     /* add num attr actually received from media player for a particular item */
                    folderDataNative.mAttributesNum[itemIndex] = attrCnt;
                }
            }

            /* copy filtered attr ids and attr values to response parameters */
            if (mFolderItemsReqObj.mNumAttr != AvrcpConstants.NUM_ATTR_NONE) {
                folderDataNative.mAttrIds = new int[attrId.size()];
                for (int attrIndex = 0; attrIndex < attrId.size(); attrIndex++)
                    folderDataNative.mAttrIds[attrIndex] = attrId.get(attrIndex);
                folderDataNative.mAttrValues = attrArray.toArray(new String[attrArray.size()]);
            }
            for (int attrIndex = 0; attrIndex < folderDataNative.mAttributesNum.length; attrIndex++)
                if (DEBUG) Log.d(TAG, "folderDataNative.mAttributesNum"
                        + folderDataNative.mAttributesNum[attrIndex] + " attrIndex " + attrIndex);

            /* create rsp object and send response to remote device */
            FolderItemsRsp rspObj = new FolderItemsRsp(AvrcpConstants.RSP_NO_ERROR,
                    Avrcp.sUIDCounter, scope, folderDataNative.mNumItems,
                    folderDataNative.mFolderTypes, folderDataNative.mPlayable,
                    folderDataNative.mItemTypes, folderDataNative.mItemUid,
                    folderDataNative.mDisplayNames, folderDataNative.mAttributesNum,
                    folderDataNative.mAttrIds, folderDataNative.mAttrValues);
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_NO_ERROR, rspObj);
        } else {
            Log.e(TAG, "Error: children are null in getFolderItemsFilterAttr");
            mMediaInterface.folderItemsRsp(bdaddr, AvrcpConstants.RSP_INV_RANGE, null);
            return;
        }
    }

    private String getAttrValue(int attr, List<MediaSession.QueueItem> resultItems,
            int itemIndex) {
        String attrValue = null;
        try {
            switch (attr) {
            /* Title is mandatory attribute */
                case AvrcpConstants.ATTRID_TITLE:
                    attrValue = resultItems.get(itemIndex).getDescription().getTitle().toString();
                    break;

                case AvrcpConstants.ATTRID_ARTIST:
                    attrValue = resultItems.get(itemIndex).getDescription().getExtras()
                            .getString(MediaMetadata.METADATA_KEY_ARTIST);
                    break;

                case AvrcpConstants.ATTRID_ALBUM:
                    attrValue = resultItems.get(itemIndex).getDescription().getExtras()
                            .getString(MediaMetadata.METADATA_KEY_ALBUM);
                    break;

                case AvrcpConstants.ATTRID_TRACK_NUM:
                    attrValue = resultItems.get(itemIndex).getDescription().getExtras()
                            .getString(MediaMetadata.METADATA_KEY_TRACK_NUMBER);
                    break;

                case AvrcpConstants.ATTRID_NUM_TRACKS:
                    attrValue = resultItems.get(itemIndex).getDescription().getExtras()
                            .getString(MediaMetadata.METADATA_KEY_NUM_TRACKS);
                    break;

                case AvrcpConstants.ATTRID_GENRE:
                    attrValue = resultItems.get(itemIndex).getDescription().getExtras()
                            .getString(MediaMetadata.METADATA_KEY_GENRE);
                    break;

                case AvrcpConstants.ATTRID_PLAY_TIME:
                    attrValue = resultItems.get(itemIndex).getDescription().getExtras()
                            .getString(MediaMetadata.METADATA_KEY_DURATION);
                    break;

                case AvrcpConstants.ATTRID_COVER_ART:
                    Log.e(TAG, "Cover art attribute not supported");
                    break;

                default:
                    Log.e(TAG, "Unknown attribute ID");
            }
        } catch (IndexOutOfBoundsException ex) {
            Log.w(TAG, "getAttrValue: requested item index out of bounds");
            return null;
        } catch (NullPointerException ex) {
            Log.w(TAG, "getAttrValue: attr id not found in result");
            /* checking if attribute is title, then it is mandatory and cannot send null */
            if (attr == AvrcpConstants.ATTRID_TITLE) {
                return "<Unknown Title>";
            }
            return null;
        }
        if (DEBUG) Log.d(TAG, "getAttrValue: attrvalue = " + attrValue + ", attr id:" + attr);
        return attrValue;
    }

    private void getItemAttrFilterAttr(byte[] bdaddr, AvrcpCmd.ItemAttrCmd mItemAttrReqObj,
            MediaSession.QueueItem mediaItem) {
        /* Response parameters */
        int[] attrIds = null; /* array of attr ids */
        String[] attrValues = null; /* array of attr values */
        int attrCounter = 0; /* num attributes for each item */
        List<MediaSession.QueueItem> resultItems = new ArrayList<MediaSession.QueueItem>();
        resultItems.add(mediaItem);
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
                    if (DEBUG) Log.d(TAG, "getAttrValue: attr id[" + idx + "] :" +
                        mItemAttrReqObj.mAttrIDs[idx]);
                    attrTempId.add(mItemAttrReqObj.mAttrIDs[idx]);
                }
            }

            if (DEBUG) Log.d(TAG, "getAttrValue: attr id list size:" + attrTempId.size());
            /* lookup and copy values of attributes for ids requested above */
            for (int idx = 0; idx < attrTempId.size(); idx++) {
                /* check if media player provided requested attributes */
                String value = null;
                if ((value = getAttrValue(attrTempId.get(idx), resultItems, 0)) != null) {
                    attrArray.add(value);
                    attrId.add(attrTempId.get(idx));
                    attrCounter++;
                }
            }
            attrTempId = null;
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

    void handlePassthroughCmd(int id, int keyState, byte[] bdAddr,
            MediaController mediaController) {

        if (mediaController != null) {
            MediaController.TransportControls mediaControllerCntrl =
                mediaController.getTransportControls();
            if (DEBUG) Log.v(TAG, "handlePassthroughCmd - id:" + id + " keyState:" + keyState);
            if (keyState == AvrcpConstants.KEY_STATE_PRESS) {
                switch (id) {
                    case BluetoothAvrcp.PASSTHROUGH_ID_REWIND:
                        mediaControllerCntrl.rewind();
                        break;
                    case BluetoothAvrcp.PASSTHROUGH_ID_FAST_FOR:
                        mediaControllerCntrl.fastForward();
                        break;
                    case BluetoothAvrcp.PASSTHROUGH_ID_PLAY:
                        mediaControllerCntrl.play();
                        break;
                    case BluetoothAvrcp.PASSTHROUGH_ID_PAUSE:
                        mediaControllerCntrl.pause();
                        break;
                    case BluetoothAvrcp.PASSTHROUGH_ID_STOP:
                        mediaControllerCntrl.stop();
                        break;
                    case BluetoothAvrcp.PASSTHROUGH_ID_FORWARD:
                        mediaControllerCntrl.skipToNext();
                        break;
                    case BluetoothAvrcp.PASSTHROUGH_ID_BACKWARD:
                        mediaControllerCntrl.skipToPrevious();
                        break;
                    default:
                        Log.w(TAG, "unknown id:" + id + " keyState:" + keyState);
                }
            } else {
                Log.i(TAG, "ignoring the release event for id:" + id + " keyState:" + keyState);
            }
        } else {
            Log.e(TAG, "Unable to handlePassthroughCmd, mediaController is null!");
        }
    }

    private void printByteArray(String arrName, byte[] array) {
        StringBuilder byteArray = new StringBuilder(arrName + ": 0x");

        for (int idx = 0; idx < array.length; idx++) {
            byteArray.append(String.format(" %02x", array[idx]));
        }
        Log.d(TAG, byteArray + "");
    }

}
