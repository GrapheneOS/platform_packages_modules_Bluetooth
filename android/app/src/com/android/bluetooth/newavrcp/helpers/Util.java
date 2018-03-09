/*
 * Copyright (C) 2018 The Android Open Source Project
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

import android.media.MediaDescription;
import android.media.MediaMetadata;
import android.media.session.MediaSession;
import android.os.Bundle;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

class Util {
    public static String TAG = "NewAvrcpUtil";
    public static boolean DEBUG = true;

    private static final String GPM_KEY = "com.google.android.music.mediasession.music_metadata";

    public static final Metadata empty_data() {
        Metadata ret = new Metadata();
        ret.mediaId = "Not Provided";
        ret.title = "Not Provided";
        ret.artist = "Not Provided";
        ret.album = "Not Provided";
        ret.genre = "Not Provided";
        ret.trackNum = "1";
        ret.numTracks = "1";
        ret.duration = "0";
        return ret;
    }

    public static Metadata bundleToMetadata(Bundle bundle) {
        if (bundle == null) return empty_data();

        Metadata temp = new Metadata();
        temp.title = bundle.getString(MediaMetadata.METADATA_KEY_TITLE, "Not Provided");
        temp.artist = bundle.getString(MediaMetadata.METADATA_KEY_ARTIST, "Not Provided");
        temp.album = bundle.getString(MediaMetadata.METADATA_KEY_ALBUM, "Not Provided");
        temp.trackNum = "" + bundle.getLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER, 1);
        temp.numTracks = "" + bundle.getLong(MediaMetadata.METADATA_KEY_NUM_TRACKS, 1);
        temp.genre = bundle.getString(MediaMetadata.METADATA_KEY_GENRE, "Not Provided");
        temp.duration = "" + bundle.getLong(MediaMetadata.METADATA_KEY_DURATION, 0);
        return temp;
    }

    public static Bundle descriptionToBundle(MediaDescription desc) {
        Bundle ret = new Bundle();
        if (desc == null) return ret;

        if (desc.getTitle() != null) {
            ret.putString(MediaMetadata.METADATA_KEY_TITLE, desc.getTitle().toString());
        }

        if (desc.getSubtitle() != null) {
            ret.putString(MediaMetadata.METADATA_KEY_ARTIST, desc.getSubtitle().toString());
        }

        // If the bundle has title or artist use those over the description title or subtitle.
        if (desc.getExtras() != null) ret.putAll(desc.getExtras());

        return ret;
    }

    public static Bundle mediaMetadataToBundle(MediaMetadata data) {
        Bundle bundle = new Bundle();
        if (data == null) return bundle;

        if (data.containsKey(MediaMetadata.METADATA_KEY_TITLE)) {
            bundle.putString(MediaMetadata.METADATA_KEY_TITLE,
                    data.getString(MediaMetadata.METADATA_KEY_TITLE));
        }

        if (data.containsKey(MediaMetadata.METADATA_KEY_ARTIST)) {
            bundle.putString(MediaMetadata.METADATA_KEY_ARTIST,
                    data.getString(MediaMetadata.METADATA_KEY_ARTIST));
        }

        if (data.containsKey(MediaMetadata.METADATA_KEY_ALBUM)) {
            bundle.putString(MediaMetadata.METADATA_KEY_ALBUM,
                    data.getString(MediaMetadata.METADATA_KEY_ALBUM));
        }

        if (data.containsKey(MediaMetadata.METADATA_KEY_TRACK_NUMBER)) {
            bundle.putLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER,
                    data.getLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER));
        }

        if (data.containsKey(MediaMetadata.METADATA_KEY_NUM_TRACKS)) {
            bundle.putLong(MediaMetadata.METADATA_KEY_NUM_TRACKS,
                    data.getLong(MediaMetadata.METADATA_KEY_NUM_TRACKS));
        }

        if (data.containsKey(MediaMetadata.METADATA_KEY_GENRE)) {
            bundle.putString(MediaMetadata.METADATA_KEY_GENRE,
                    data.getString(MediaMetadata.METADATA_KEY_GENRE));
        }

        if (data.containsKey(MediaMetadata.METADATA_KEY_DURATION)) {
            bundle.putLong(MediaMetadata.METADATA_KEY_DURATION,
                    data.getLong(MediaMetadata.METADATA_KEY_DURATION));
        }

        return bundle;
    }

    public static Metadata toMetadata(MediaSession.QueueItem item) {
        if (item == null) {
            return empty_data();
        }

        Bundle bundle = descriptionToBundle(item.getDescription());
        if (bundle.containsKey(GPM_KEY)) {
            if (DEBUG) Log.d(TAG, "Queue item contains GPM data");
            bundle.putAll(mediaMetadataToBundle((MediaMetadata) bundle.get(GPM_KEY)));
        }


        if (DEBUG) {
            for (String key : bundle.keySet()) {
                Log.e(TAG, "toMetadata: MediaDescription: ContainsKey: " + key);
            }
        }

        Metadata ret = bundleToMetadata(bundle);

        // For Queue Items, the Media Id will always be just its Queue ID
        // We don't need to use its actual ID since we don't promise UIDS being valid
        // between a file system and it's now playing list.
        // TODO (apanicke): Remove this prefix later, for now it makes debugging
        // easier.
        ret.mediaId = "NowPlayingId" + item.getQueueId();

        return ret;
    }

    public static Metadata toMetadata(MediaMetadata data) {
        if (data == null) {
            return empty_data();
        }

        MediaDescription desc = data.getDescription();

        Bundle dataBundle = mediaMetadataToBundle(data);
        Bundle bundle = descriptionToBundle(data.getDescription());

        // Prioritize the media metadata over the media description
        bundle.putAll(dataBundle);
        Metadata ret = bundleToMetadata(bundle);

        // This will always be currsong. The AVRCP service will overwrite the mediaId if it needs to
        // TODO (apanicke): Remove when the service is ready, right now it makes debugging much more
        // convenient
        ret.mediaId = "currsong";

        return ret;
    }

    public static List<Metadata> toMetadataList(List<MediaSession.QueueItem> items) {
        ArrayList<Metadata> list = new ArrayList<Metadata>();

        if (items == null) return list;

        for (MediaSession.QueueItem item : items) {
            list.add(toMetadata(item));
        }

        return list;
    }

    // Helper method to close a list of ListItems so that if the callee wants
    // to mutate the list they can do it without affecting any internally cached info
    public static List<ListItem> cloneList(List<ListItem> list) {
        List<ListItem> clone = new ArrayList<ListItem>(list.size());
        for (ListItem item : list) clone.add(item.clone());
        return clone;
    }
}
