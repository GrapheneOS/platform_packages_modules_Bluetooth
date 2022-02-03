/*
 * Copyright (C) 2022 The Android Open Source Project
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

package android.bluetooth;

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.annotation.SystemApi;
import android.os.Parcel;
import android.os.Parcelable;

/**
 * A class representing the media metadata information defined in the Basic Audio Profile.
 *
 * @hide
 */
@SystemApi
public final class BluetoothLeAudioContentMetadata implements Parcelable {
    private final String mProgramInfo;
    private final String mLanguage;
    private final byte[] mRawMetadata;

    private BluetoothLeAudioContentMetadata(String programInfo, String language,
            byte[] rawMetadata) {
        mProgramInfo = programInfo;
        mLanguage = language;
        mRawMetadata = rawMetadata;
    }

    /**
     * Get the title and/or summary of Audio Stream content in UTF-8 format.
     *
     * @return title and/or summary of Audio Stream content in UTF-8 format, null if this metadata
     * does not exist
     * @hide
     */
    @SystemApi
    public @Nullable String getProgramInfo() {
        return mProgramInfo;
    }

    /**
     * Get language of the audio stream in 3-byte, lower case language code as defined in ISO 639-3.
     *
     * @return ISO 639-3 formatted language code, null if this metadata does not exist
     * @hide
     */
    @SystemApi
    public @Nullable String getLanguage() {
        return mLanguage;
    }

    /**
     * Get the raw bytes of stream metadata in Bluetooth LTV format as defined in the Generic Audio
     * section of <a href="https://www.bluetooth.com/specifications/assigned-numbers/">Bluetooth Assigned Numbers</a>,
     * including metadata that was not covered by the getter methods in this class
     *
     * @return raw bytes of stream metadata in Bluetooth LTV format
     */
    public @NonNull byte[] getRawMetadata() {
        return mRawMetadata;
    }


    /**
     * {@inheritDoc}
     * @hide
     */
    @Override
    public int describeContents() {
        return 0;
    }

    /**
     * {@inheritDoc}
     * @hide
     */
    @Override
    public void writeToParcel(Parcel out, int flags) {
        out.writeString(mProgramInfo);
        out.writeString(mLanguage);
        out.writeInt(mRawMetadata.length);
        out.writeByteArray(mRawMetadata);
    }

    /**
     * A {@link Parcelable.Creator} to create {@link BluetoothLeAudioContentMetadata} from parcel.
     * @hide
     */
    @SystemApi
    public static final @NonNull Parcelable.Creator<BluetoothLeAudioContentMetadata> CREATOR =
            new Parcelable.Creator<BluetoothLeAudioContentMetadata>() {
                public @NonNull BluetoothLeAudioContentMetadata createFromParcel(
                        @NonNull Parcel in) {
                    final String programInfo = in.readString();
                    final String language = in.readString();
                    final int rawMetadataLength = in.readInt();
                    byte[] rawMetadata = new byte[rawMetadataLength];
                    in.readByteArray(rawMetadata);
                    return new BluetoothLeAudioContentMetadata(programInfo, language, rawMetadata);
                }

                public @NonNull BluetoothLeAudioContentMetadata[] newArray(int size) {
                    return new BluetoothLeAudioContentMetadata[size];
                }
            };

    /**
     * Construct a {@link BluetoothLeAudioContentMetadata} from raw bytes.
     *
     * The byte array will be parsed and values for each getter will be populated
     *
     * Raw metadata cannot be set using builder in order to maintain raw bytes and getter value
     * consistency
     *
     * @param rawBytes raw bytes of stream metadata in Bluetooth LTV format
     * @return parsed {@link BluetoothLeAudioContentMetadata} object
     * @throws IllegalArgumentException if <var>rawBytes</var> is null or when the raw bytes cannot
     * be parsed to build the object
     * @hide
     */
    @SystemApi
    public static @NonNull BluetoothLeAudioContentMetadata fromRawBytes(@NonNull byte[] rawBytes) {
        if (rawBytes == null) {
            throw new IllegalArgumentException("Raw bytes cannot be null");
        }
        return null;
    }

    /**
     * Builder for {@link BluetoothLeAudioContentMetadata}.
     * @hide
     */
    @SystemApi
    public static final class Builder {
        private String mProgramInfo = null;
        private String mLanguage = null;
        private byte[] mRawMetadata = null;

        /**
         * Create an empty builder
         *
         * @hide
         */
        @SystemApi
        public Builder() {}

        /**
         * Create a builder with copies of information from original object.
         *
         * @param original original object
         * @hide
         */
        @SystemApi
        public Builder(@NonNull BluetoothLeAudioContentMetadata original) {
            mProgramInfo = original.getProgramInfo();
            mLanguage = original.getLanguage();
            mRawMetadata = original.getRawMetadata();
        }

        /**
         * Set the title and/or summary of Audio Stream content in UTF-8 format.
         *
         * @param programInfo  title and/or summary of Audio Stream content in UTF-8 format, null
         *                     if this metadata does not exist
         * @return this builder
         * @hide
         */
        @SystemApi
        public @NonNull Builder setProgramInfo(@Nullable String programInfo) {
            mProgramInfo = programInfo;
            return this;
        }

        /**
         * Set language of the audio stream in 3-byte, lower case language code as defined in
         * ISO 639-3.
         *
         * @return ISO 639-3 formatted language code, null if this metadata does not exist
         * @hide
         */
        @SystemApi
        public @NonNull Builder setLanguage(@Nullable String language) {
            mLanguage = language;
            return this;
        }

        /**
         * Build {@link BluetoothLeAudioContentMetadata}.
         *
         * @return constructed {@link BluetoothLeAudioContentMetadata}
         * @throws IllegalArgumentException if the object cannot be built
         * @hide
         */
        @SystemApi
        public @NonNull BluetoothLeAudioContentMetadata build() {
            if (mRawMetadata == null) {
                mRawMetadata = new byte[0];
            }
            return new BluetoothLeAudioContentMetadata(mProgramInfo, mLanguage, mRawMetadata);
        }
    }
}
