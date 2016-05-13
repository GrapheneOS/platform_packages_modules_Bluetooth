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

import android.media.MediaMetadata;
import android.util.Log;

import java.util.HashMap;

/*
 * Contains information about tracks that either currently playing or maintained in playlist
 * This is used as a local repository for information that will be passed on as MediaMetadata to the
 * MediaSessionServicve
 */
class TrackInfo {
    private static final String TAG = "AvrcpTrackInfo";
    private static final boolean DBG = Log.isLoggable(TAG, Log.DEBUG);

    /*
     * Default values for each of the items from JNI
     */
    private static final int TRACK_NUM_INVALID = -1;
    private static final int TOTAL_TRACKS_INVALID = -1;
    private static final int TOTAL_TRACK_TIME_INVALID = -1;
    private static final String UNPOPULATED_ATTRIBUTE = "";

    /*
     *Element Id Values for GetMetaData  from JNI
     */
    private static final int MEDIA_ATTRIBUTE_TITLE = 0x01;
    private static final int MEDIA_ATTRIBUTE_ARTIST_NAME = 0x02;
    private static final int MEDIA_ATTRIBUTE_ALBUM_NAME = 0x03;
    private static final int MEDIA_ATTRIBUTE_TRACK_NUMBER = 0x04;
    private static final int MEDIA_ATTRIBUTE_TOTAL_TRACK_NUMBER = 0x05;
    private static final int MEDIA_ATTRIBUTE_GENRE = 0x06;
    private static final int MEDIA_ATTRIBUTE_PLAYING_TIME = 0x07;


    private final String mArtistName;
    private final String mTrackTitle;
    private final String mAlbumTitle;
    private final String mGenre;
    private final long mTrackNum; // number of audio file on original recording.
    private final long mTotalTracks;// total number of tracks on original recording
    private final long mTrackLen;// full length of AudioFile.

    public TrackInfo() {
        this(new HashMap<Integer,String>());
    }

    public TrackInfo(HashMap<Integer, String> attributeMap) {
        String attribute;
        attribute = attributeMap.get(MEDIA_ATTRIBUTE_TITLE);
        mTrackTitle = (attribute != null) ? attribute : UNPOPULATED_ATTRIBUTE;

        attribute = attributeMap.get(MEDIA_ATTRIBUTE_ARTIST_NAME);
        mArtistName = (attribute != null) ? attribute : UNPOPULATED_ATTRIBUTE;

        attribute = attributeMap.get(MEDIA_ATTRIBUTE_ALBUM_NAME);
        mAlbumTitle = (attribute != null) ? attribute : UNPOPULATED_ATTRIBUTE;

        attribute = attributeMap.get(MEDIA_ATTRIBUTE_TRACK_NUMBER);
        mTrackNum = (attribute != null && !attribute.isEmpty()) ? Long.valueOf(attribute) : TRACK_NUM_INVALID;

        attribute = attributeMap.get(MEDIA_ATTRIBUTE_TOTAL_TRACK_NUMBER);
        mTotalTracks = (attribute != null && !attribute.isEmpty()) ? Long.valueOf(attribute) : TOTAL_TRACKS_INVALID;

        attribute = attributeMap.get(MEDIA_ATTRIBUTE_GENRE);
        mGenre = (attribute != null) ? attribute : UNPOPULATED_ATTRIBUTE;

        attribute = attributeMap.get(MEDIA_ATTRIBUTE_PLAYING_TIME);
        mTrackLen = (attribute != null && !attribute.isEmpty()) ? Long.valueOf(attribute) : TOTAL_TRACK_TIME_INVALID;
    }

    public String toString() {
        return "Metadata [artist=" + mArtistName + " trackTitle= " + mTrackTitle +
                " albumTitle= " + mAlbumTitle + " genre= " +mGenre+" trackNum= "+
                Long.toString(mTrackNum) + " track_len : "+ Long.toString(mTrackLen) +
                " TotalTracks " + Long.toString(mTotalTracks) + "]";
    }

    public MediaMetadata getMediaMetaData() {
        if (DBG) Log.d(TAG, " TrackInfo " + toString());
        MediaMetadata.Builder mMetaDataBuilder = new MediaMetadata.Builder();
        mMetaDataBuilder.putString(MediaMetadata.METADATA_KEY_ARTIST,
            mArtistName);
        mMetaDataBuilder.putString(MediaMetadata.METADATA_KEY_TITLE,
            mTrackTitle);
        mMetaDataBuilder.putString(MediaMetadata.METADATA_KEY_ALBUM,
            mAlbumTitle);
        mMetaDataBuilder.putString(MediaMetadata.METADATA_KEY_GENRE,
            mGenre);
        mMetaDataBuilder.putLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER,
            mTrackNum);
        mMetaDataBuilder.putLong(MediaMetadata.METADATA_KEY_NUM_TRACKS,
            mTotalTracks);
        mMetaDataBuilder.putLong(MediaMetadata.METADATA_KEY_DURATION,
            mTrackLen);
        return mMetaDataBuilder.build();
    }


    public String displayMetaData() {
        MediaMetadata metaData = getMediaMetaData();
        StringBuffer sb = new StringBuffer();
        /* getDescription only contains artist, title and album */
        sb.append(metaData.getDescription().toString() + " ");
        if(metaData.containsKey(MediaMetadata.METADATA_KEY_GENRE))
            sb.append(metaData.getString(MediaMetadata.METADATA_KEY_GENRE) + " ");
        if(metaData.containsKey(MediaMetadata.METADATA_KEY_MEDIA_ID))
            sb.append(metaData.getString(MediaMetadata.METADATA_KEY_MEDIA_ID) + " ");
        if(metaData.containsKey(MediaMetadata.METADATA_KEY_TRACK_NUMBER))
            sb.append(Long.toString(metaData.getLong(MediaMetadata.METADATA_KEY_TRACK_NUMBER)) + " ");
        if(metaData.containsKey(MediaMetadata.METADATA_KEY_NUM_TRACKS))
            sb.append(Long.toString(metaData.getLong(MediaMetadata.METADATA_KEY_NUM_TRACKS)) + " ");
        if(metaData.containsKey(MediaMetadata.METADATA_KEY_TRACK_NUMBER))
            sb.append(Long.toString(metaData.getLong(MediaMetadata.METADATA_KEY_DURATION)) + " ");
        if(metaData.containsKey(MediaMetadata.METADATA_KEY_TRACK_NUMBER))
            sb.append(Long.toString(metaData.getLong(MediaMetadata.METADATA_KEY_DURATION)) + " ");
        return sb.toString();
    }
}
