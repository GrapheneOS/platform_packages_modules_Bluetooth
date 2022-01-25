/*
 * Copyright (C) 2021 The Android Open Source Project
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

import android.annotation.IntDef;
import android.annotation.NonNull;
import android.os.Parcel;
import android.os.Parcelable;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * Represents the codec configuration for a Bluetooth LE Audio source device.
 * <p>Contains the source codec type.
 * <p>The source codec type values are the same as those supported by the
 * device hardware.
 *
 * {@see BluetoothLeAudioCodecConfig}
 */
public final class BluetoothLeAudioCodecConfig implements Parcelable {
    // Add an entry for each source codec here.

    /** @hide */
    @IntDef(prefix = "SOURCE_CODEC_TYPE_", value = {
            SOURCE_CODEC_TYPE_LC3,
            SOURCE_CODEC_TYPE_INVALID
    })
    @Retention(RetentionPolicy.SOURCE)
    public @interface SourceCodecType {};

    public static final int SOURCE_CODEC_TYPE_LC3 = 0;
    public static final int SOURCE_CODEC_TYPE_INVALID = 1000 * 1000;

    /**
     * Represents the count of valid source codec types. Can be accessed via
     * {@link #getMaxCodecType}.
     */
    private static final int SOURCE_CODEC_TYPE_MAX = 1;

    /** @hide */
    @IntDef(prefix = "CODEC_PRIORITY_",
            value = {CODEC_PRIORITY_DISABLED, CODEC_PRIORITY_DEFAULT, CODEC_PRIORITY_HIGHEST})
    @Retention(RetentionPolicy.SOURCE)
    public @interface CodecPriority {}

    /**
     * Codec priority disabled.
     * Used to indicate that this codec is disabled and should not be used.
     */
    public static final int CODEC_PRIORITY_DISABLED = -1;

    /**
     * Codec priority default.
     * Default value used for codec priority.
     */
    public static final int CODEC_PRIORITY_DEFAULT = 0;

    /**
     * Codec priority highest.
     * Used to indicate the highest priority a codec can have.
     */
    public static final int CODEC_PRIORITY_HIGHEST = 1000 * 1000;

    /** @hide */
    @IntDef(prefix = "SAMPLE_RATE_",
            value = {SAMPLE_RATE_NONE, SAMPLE_RATE_8000, SAMPLE_RATE_16000, SAMPLE_RATE_24000,
                    SAMPLE_RATE_32000, SAMPLE_RATE_44100, SAMPLE_RATE_48000})
    @Retention(RetentionPolicy.SOURCE)
    public @interface SampleRate {}

    /**
     * Codec sample rate 0 Hz. Default value used for
     * codec sample rate.
     */
    public static final int SAMPLE_RATE_NONE = 0;

    /**
     * Codec sample rate 8000 Hz.
     */
    public static final int SAMPLE_RATE_8000 = 1;

    /**
     * Codec sample rate 16000 Hz.
     */
    public static final int SAMPLE_RATE_16000 = 2;

    /**
     * Codec sample rate 24000 Hz.
     */
    public static final int SAMPLE_RATE_24000 = 3;

    /**
     * Codec sample rate 32000 Hz.
     */
    public static final int SAMPLE_RATE_32000 = 4;

    /**
     * Codec sample rate 44100 Hz.
     */
    public static final int SAMPLE_RATE_44100 = 5;

    /**
     * Codec sample rate 48000 Hz.
     */
    public static final int SAMPLE_RATE_48000 = 6;

    /** @hide */
    @IntDef(prefix = "BITS_PER_SAMPLE_",
            value = {BITS_PER_SAMPLE_NONE, BITS_PER_SAMPLE_16, BITS_PER_SAMPLE_24,
                    BITS_PER_SAMPLE_32})
    @Retention(RetentionPolicy.SOURCE)
    public @interface BitsPerSample {}

    /**
     * Codec bits per sample 0. Default value of the codec
     * bits per sample.
     */
    public static final int BITS_PER_SAMPLE_NONE = 0;

    /**
     * Codec bits per sample 16.
     */
    public static final int BITS_PER_SAMPLE_16 = 1;

    /**
     * Codec bits per sample 24.
     */
    public static final int BITS_PER_SAMPLE_24 = 2;

    /**
     * Codec bits per sample 32.
     */
    public static final int BITS_PER_SAMPLE_32 = 3;

    /** @hide */
    @IntDef(prefix = "CHANNEL_MODE_",
            value = {CHANNEL_MODE_NONE, CHANNEL_MODE_MONO, CHANNEL_MODE_STEREO})
    @Retention(RetentionPolicy.SOURCE)
    public @interface ChannelMode {}

    /**
     * Codec channel mode NONE. Default value of the
     * codec channel mode.
     */
    public static final int CHANNEL_MODE_NONE = 0;

    /**
     * Codec channel mode MONO.
     */
    public static final int CHANNEL_MODE_MONO = 1;

    /**
     * Codec channel mode STEREO.
     */
    public static final int CHANNEL_MODE_STEREO = 2;

    /** @hide */
    @IntDef(prefix = "FRAME_DURATION_",
            value = {FRAME_DURATION_NONE, FRAME_DURATION_7500, FRAME_DURATION_10000})
    @Retention(RetentionPolicy.SOURCE)
    public @interface FrameDuration {}

    /**
     * Frame duration 0. Default value of the frame duration.
     */
    public static final int FRAME_DURATION_NONE = 0;

    /**
     * Frame duration 7500 us.
     */
    public static final int FRAME_DURATION_7500 = 1;

    /**
     * Frame duration 10000 us.
     */
    public static final int FRAME_DURATION_10000 = 2;

    private final @SourceCodecType int mCodecType;
    private final @CodecPriority int mCodecPriority;
    private final @SampleRate int mSampleRate;
    private final @BitsPerSample int mBitsPerSample;
    private final @ChannelMode int mChannelMode;
    private final @FrameDuration int mFrameDuration;
    private final int mOctetsPerFrame;

    /**
     * Creates a new BluetoothLeAudioCodecConfig.
     *
     * @param codecType the source codec type
     * @param codecPriority the priority of this codec
     * @param sampleRate the codec sample rate
     * @param bitsPerSample the bits per sample of this codec
     * @param channelMode the channel mode of this codec
     * @param frameDuration the frame duration of this codec
     * @param octetsPerFrame the octets per frame of this codec
     */
    private BluetoothLeAudioCodecConfig(@SourceCodecType int codecType,
            @CodecPriority int codecPriority, @SampleRate int sampleRate,
            @BitsPerSample int bitsPerSample, @ChannelMode int channelMode,
            @FrameDuration int frameDuration, int octetsPerFrame) {
        mCodecType = codecType;
        mCodecPriority = codecPriority;
        mSampleRate = sampleRate;
        mBitsPerSample = bitsPerSample;
        mChannelMode = channelMode;
        mFrameDuration = frameDuration;
        mOctetsPerFrame = octetsPerFrame;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    /**
     * {@link Parcelable.Creator} interface implementation.
     */
    public static final
            @android.annotation.NonNull Parcelable.Creator<BluetoothLeAudioCodecConfig> CREATOR =
            new Parcelable.Creator<BluetoothLeAudioCodecConfig>() {
                public BluetoothLeAudioCodecConfig createFromParcel(Parcel in) {
                    int codecType = in.readInt();
                    int codecPriority = in.readInt();
                    int sampleRate = in.readInt();
                    int bitsPerSample = in.readInt();
                    int channelMode = in.readInt();
                    int frameDuration = in.readInt();
                    int octetsPerFrame = in.readInt();
                    return new BluetoothLeAudioCodecConfig(codecType, codecPriority, sampleRate,
                            bitsPerSample, channelMode, frameDuration, octetsPerFrame);
                }

                public BluetoothLeAudioCodecConfig[] newArray(int size) {
                    return new BluetoothLeAudioCodecConfig[size];
                }
            };

    @Override
    public void writeToParcel(@NonNull Parcel out, int flags) {
        out.writeInt(mCodecType);
        out.writeInt(mCodecPriority);
        out.writeInt(mSampleRate);
        out.writeInt(mBitsPerSample);
        out.writeInt(mChannelMode);
        out.writeInt(mFrameDuration);
        out.writeInt(mOctetsPerFrame);
    }

    @Override
    public String toString() {
        return "{codecName:" + getCodecName() + ",mCodecType:" + mCodecType
                + ",mCodecPriority:" + mCodecPriority + ",mSampleRate:" + mSampleRate
                + ",mBitsPerSample:" + mBitsPerSample + ",mChannelMode:" + mChannelMode
                + ",mFrameDuration:" + mFrameDuration + ",mOctetsPerFrame:" + mOctetsPerFrame + "}";
    }

    /**
     * Gets the codec type.
     *
     * @return the codec type
     */
    public @SourceCodecType int getCodecType() {
        return mCodecType;
    }

    /**
     * Returns the valid codec types count.
     */
    public static int getMaxCodecType() {
        return SOURCE_CODEC_TYPE_MAX;
    }

    /**
     * Gets the codec name.
     *
     * @return the codec name
     */
    public @NonNull String getCodecName() {
        switch (mCodecType) {
            case SOURCE_CODEC_TYPE_LC3:
                return "LC3";
            case SOURCE_CODEC_TYPE_INVALID:
                return "INVALID CODEC";
            default:
                break;
        }
        return "UNKNOWN CODEC(" + mCodecType + ")";
    }

    /**
     * Returns the codec selection priority.
     * <p>The codec selection priority is relative to other codecs: larger value
     * means higher priority.
     */
    public @CodecPriority int getCodecPriority() {
        return mCodecPriority;
    }

    /**
     * Returns the codec sample rate.
     */
    public @SampleRate int getSampleRate() {
        return mSampleRate;
    }

    /**
     * Returns the codec bits per sample.
     */
    public @BitsPerSample int getBitsPerSample() {
        return mBitsPerSample;
    }

    /**
     * Returns the codec channel mode.
     */
    public @ChannelMode int getChannelMode() {
        return mChannelMode;
    }

    /**
     * Returns the frame duration.
     */
    public @ChannelMode int getFrameDuration() {
        return mFrameDuration;
    }

    /**
     * Returns the octets per frame
     */
    public @ChannelMode int getOctetsPerFrame() {
        return mOctetsPerFrame;
    }

    /**
     * Builder for {@link BluetoothLeAudioCodecConfig}.
     * <p> By default, the codec type will be set to
     * {@link BluetoothLeAudioCodecConfig#SOURCE_CODEC_TYPE_INVALID}
     */
    public static final class Builder {
        private int mCodecType = BluetoothLeAudioCodecConfig.SOURCE_CODEC_TYPE_INVALID;
        private int mCodecPriority = BluetoothLeAudioCodecConfig.CODEC_PRIORITY_DEFAULT;
        private int mSampleRate = BluetoothLeAudioCodecConfig.SAMPLE_RATE_NONE;
        private int mBitsPerSample = BluetoothLeAudioCodecConfig.BITS_PER_SAMPLE_NONE;
        private int mChannelMode = BluetoothLeAudioCodecConfig.CHANNEL_MODE_NONE;
        private int mFrameDuration = BluetoothLeAudioCodecConfig.FRAME_DURATION_NONE;
        private int mOctetsPerFrame = 0;

        public Builder() {}

        public Builder(@NonNull BluetoothLeAudioCodecConfig config) {
            mCodecType = config.getCodecType();
            mCodecPriority = config.getCodecPriority();
            mSampleRate = config.getSampleRate();
            mBitsPerSample = config.getBitsPerSample();
            mChannelMode = config.getChannelMode();
            mFrameDuration = config.getFrameDuration();
            mOctetsPerFrame = config.getOctetsPerFrame();
        }

        /**
         * Set codec type for Bluetooth LE audio codec config.
         *
         * @param codecType of this codec
         * @return the same Builder instance
         */
        public @NonNull Builder setCodecType(@SourceCodecType int codecType) {
            mCodecType = codecType;
            return this;
        }

        /**
         * Set codec priority for Bluetooth LE audio codec config.
         *
         * @param codecPriority of this codec
         * @return the same Builder instance
         */
        public @NonNull Builder setCodecPriority(@CodecPriority int codecPriority) {
            mCodecPriority = codecPriority;
            return this;
        }

        /**
         * Set sample rate for Bluetooth LE audio codec config.
         *
         * @param sampleRate of this codec
         * @return the same Builder instance
         */
        public @NonNull Builder setSampleRate(@SampleRate int sampleRate) {
            mSampleRate = sampleRate;
            return this;
        }

        /**
         * Set the bits per sample for LE audio codec config.
         *
         * @param bitsPerSample of this codec
         * @return the same Builder instance
         */
        public @NonNull Builder setBitsPerSample(@BitsPerSample int bitsPerSample) {
            mBitsPerSample = bitsPerSample;
            return this;
        }

        /**
         * Set the channel mode for Bluetooth LE audio codec config.
         *
         * @param channelMode of this codec
         * @return the same Builder instance
         */
        public @NonNull Builder setChannelMode(@ChannelMode int channelMode) {
            mChannelMode = channelMode;
            return this;
        }

        /**
         * Set the frame duration for Bluetooth LE audio codec config.
         *
         * @param frameDuration of this codec
         * @return the same Builder instance
         */
        public @NonNull Builder setFrameDuration(@FrameDuration int frameDuration) {
            mFrameDuration = frameDuration;
            return this;
        }

        /**
         * Set the octets per frame for Bluetooth LE audio codec config.
         *
         * @param octetsPerFrame of this codec
         * @return the same Builder instance
         */
        public @NonNull Builder setOctetsPerFrame(int octetsPerFrame) {
            mOctetsPerFrame = octetsPerFrame;
            return this;
        }

        /**
         * Build {@link BluetoothLeAudioCodecConfig}.
         * @return new BluetoothLeAudioCodecConfig built
         */
        public @NonNull BluetoothLeAudioCodecConfig build() {
            return new BluetoothLeAudioCodecConfig(mCodecType, mCodecPriority, mSampleRate,
                    mBitsPerSample, mChannelMode, mFrameDuration, mOctetsPerFrame);
        }
    }
}
