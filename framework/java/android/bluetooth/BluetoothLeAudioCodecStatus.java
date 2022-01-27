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
import android.os.Parcel;
import android.os.Parcelable;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Represents the codec status (configuration and capability) for a Bluetooth
 * Le Audio source device.
 *
 * {@see BluetoothLeAudio}
 */
public final class BluetoothLeAudioCodecStatus implements Parcelable {
    /**
     * Extra for the codec configuration intents of the individual profiles.
     *
     * This extra represents the current codec status of the Le Audio
     * profile.
     */
    public static final String EXTRA_LE_AUDIO_CODEC_STATUS =
            "android.bluetooth.extra.LE_AUDIO_CODEC_STATUS";

    private final @Nullable BluetoothLeAudioCodecConfig mCodecConfig;
    private final @Nullable List<BluetoothLeAudioCodecConfig> mCodecsLocalCapabilities;
    private final @Nullable List<BluetoothLeAudioCodecConfig> mCodecsSelectableCapabilities;

    /**
     * Represents the codec status for a Bluetooth LE Audio source device.
     *
     * @param codecConfig the current code configutration.
     * @param codecsLocalCapabilities the local codecs capabilities.
     * @param codecsSelectableCapabilities the selectable codecs capabilities.
     */
    public BluetoothLeAudioCodecStatus(@Nullable BluetoothLeAudioCodecConfig codecConfig,
            @Nullable List<BluetoothLeAudioCodecConfig> codecsLocalCapabilities,
            @Nullable List<BluetoothLeAudioCodecConfig> codecsSelectableCapabilities) {
        mCodecConfig = codecConfig;
        mCodecsLocalCapabilities = codecsLocalCapabilities;
        mCodecsSelectableCapabilities = codecsSelectableCapabilities;
    }

    private BluetoothLeAudioCodecStatus(Parcel in) {
        mCodecConfig = in.readTypedObject(BluetoothLeAudioCodecConfig.CREATOR);
        mCodecsLocalCapabilities = in.createTypedArrayList(BluetoothLeAudioCodecConfig.CREATOR);
        mCodecsSelectableCapabilities =
                in.createTypedArrayList(BluetoothLeAudioCodecConfig.CREATOR);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o instanceof BluetoothLeAudioCodecStatus) {
            BluetoothLeAudioCodecStatus other = (BluetoothLeAudioCodecStatus) o;
            return (Objects.equals(other.mCodecConfig, mCodecConfig)
                    && sameCapabilities(other.mCodecsLocalCapabilities, mCodecsLocalCapabilities)
                    && sameCapabilities(other.mCodecsSelectableCapabilities,
                    mCodecsSelectableCapabilities));
        }
        return false;
    }

    /**
     * Checks whether two lists of capabilities contain same capabilities.
     * The order of the capabilities in each list is ignored.
     *
     * @param c1 the first list of capabilities to compare
     * @param c2 the second list of capabilities to compare
     * @return {@code true} if both lists contain same capabilities
     */
    private static boolean sameCapabilities(@Nullable List<BluetoothLeAudioCodecConfig> c1,
                                           @Nullable List<BluetoothLeAudioCodecConfig> c2) {
        if (c1 == null) {
            return (c2 == null);
        }
        if (c2 == null) {
            return false;
        }
        if (c1.size() != c2.size()) {
            return false;
        }
        return c1.containsAll(c2);
    }

    /**
     * Checks whether the codec config matches the selectable capabilities.
     * Any parameters of the codec config with NONE value will be considered a wildcard matching.
     *
     * @param codecConfig the codec config to compare against
     * @return {@code true} if the codec config matches, {@code false} otherwise
     */
    public boolean isCodecConfigSelectable(@Nullable BluetoothLeAudioCodecConfig codecConfig) {
        // TODO: Add the implementation to check the config is selectable
        return true;
    }

    /**
     * Returns a hash based on the codec config and local capabilities.
     */
    @Override
    public int hashCode() {
        return Objects.hash(mCodecConfig, mCodecsLocalCapabilities, mCodecsLocalCapabilities);
    }

    /**
     * Returns a {@link String} that describes each BluetoothLeAudioCodecStatus parameter
     * current value.
     */
    @Override
    public String toString() {
        return "{mCodecConfig:" + mCodecConfig
                + ",mCodecsLocalCapabilities:" + mCodecsLocalCapabilities
                + ",mCodecsSelectableCapabilities:" + mCodecsSelectableCapabilities
                + "}";
    }

    /**
     * @return 0
     */
    @Override
    public int describeContents() {
        return 0;
    }

    /**
     * {@link Parcelable.Creator} interface implementation.
     */
    public static final @android.annotation.NonNull
            Parcelable.Creator<BluetoothLeAudioCodecStatus> CREATOR =
            new Parcelable.Creator<BluetoothLeAudioCodecStatus>() {
                public BluetoothLeAudioCodecStatus createFromParcel(Parcel in) {
                    return new BluetoothLeAudioCodecStatus(in);
                }

                public BluetoothLeAudioCodecStatus[] newArray(int size) {
                    return new BluetoothLeAudioCodecStatus[size];
                }
            };

    /**
     * Flattens the object to a parcel.
     *
     * @param out The Parcel in which the object should be written
     * @param flags Additional flags about how the object should be written
     */
    @Override
    public void writeToParcel(@NonNull Parcel out, int flags) {
        out.writeTypedObject(mCodecConfig, 0);
        out.writeTypedList(mCodecsLocalCapabilities);
        out.writeTypedList(mCodecsSelectableCapabilities);
    }

    /**
     * Returns the current codec configuration.
     */
    public @Nullable BluetoothLeAudioCodecConfig getCodecConfig() {
        return mCodecConfig;
    }

    /**
     * Returns the codecs local capabilities.
     */
    public @NonNull List<BluetoothLeAudioCodecConfig> getCodecsLocalCapabilities() {
        return (mCodecsLocalCapabilities == null)
                ? Collections.emptyList() : mCodecsLocalCapabilities;
    }

    /**
     * Returns the codecs selectable capabilities.
     */
    public @NonNull List<BluetoothLeAudioCodecConfig> getCodecsSelectableCapabilities() {
        return (mCodecsSelectableCapabilities == null)
                ? Collections.emptyList() : mCodecsSelectableCapabilities;
    }
}
