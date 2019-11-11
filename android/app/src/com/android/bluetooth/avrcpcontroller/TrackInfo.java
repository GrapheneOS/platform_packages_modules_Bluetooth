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

import android.support.v4.media.MediaMetadataCompat;

final class TrackInfo {
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

    static MediaMetadataCompat getMetadata(int[] attrIds, String[] attrMap) {
        MediaMetadataCompat.Builder metaDataBuilder = new MediaMetadataCompat.Builder();
        int attributeCount = Math.max(attrIds.length, attrMap.length);
        for (int i = 0; i < attributeCount; i++) {
            switch (attrIds[i]) {
                case MEDIA_ATTRIBUTE_TITLE:
                    metaDataBuilder.putString(MediaMetadataCompat.METADATA_KEY_TITLE, attrMap[i]);
                    break;
                case MEDIA_ATTRIBUTE_ARTIST_NAME:
                    metaDataBuilder.putString(MediaMetadataCompat.METADATA_KEY_ARTIST, attrMap[i]);
                    break;
                case MEDIA_ATTRIBUTE_ALBUM_NAME:
                    metaDataBuilder.putString(MediaMetadataCompat.METADATA_KEY_ALBUM, attrMap[i]);
                    break;
                case MEDIA_ATTRIBUTE_TRACK_NUMBER:
                    try {
                        metaDataBuilder.putLong(MediaMetadataCompat.METADATA_KEY_TRACK_NUMBER,
                                Long.valueOf(attrMap[i]));
                    } catch (java.lang.NumberFormatException e) {
                        // If Track Number doesn't parse, leave it unset
                    }
                    break;
                case MEDIA_ATTRIBUTE_TOTAL_TRACK_NUMBER:
                    try {
                        metaDataBuilder.putLong(MediaMetadataCompat.METADATA_KEY_NUM_TRACKS,
                                Long.valueOf(attrMap[i]));
                    } catch (java.lang.NumberFormatException e) {
                        // If Total Track Number doesn't parse, leave it unset
                    }
                    break;
                case MEDIA_ATTRIBUTE_GENRE:
                    metaDataBuilder.putString(MediaMetadataCompat.METADATA_KEY_GENRE, attrMap[i]);
                    break;
                case MEDIA_ATTRIBUTE_PLAYING_TIME:
                    try {
                        metaDataBuilder.putLong(MediaMetadataCompat.METADATA_KEY_DURATION,
                                Long.valueOf(attrMap[i]));
                    } catch (java.lang.NumberFormatException e) {
                        // If Playing Time doesn't parse, leave it unset
                    }
                    break;
            }
        }
        return metaDataBuilder.build();
    }
}
