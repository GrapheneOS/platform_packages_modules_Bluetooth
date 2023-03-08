/*
 * Copyright 2022 The Android Open Source Project
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

package android.bluetooth.le;

import android.annotation.IntDef;
import android.annotation.IntRange;
import android.annotation.NonNull;
import android.annotation.SystemApi;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.le.DistanceMeasurementMethod.DistanceMeasurementMethodId;
import android.os.Parcel;
import android.os.Parcelable;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.Objects;

/**
 * The {@link DistanceMeasurementParams} provide a way to adjust distance measurement preferences.
 * Use {@link DistanceMeasurementParams.Builder} to create an instance of this class.
 *
 * @hide
 */
@SystemApi
public final class DistanceMeasurementParams implements Parcelable {

    /**
     * @hide
     */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef(value = {
            REPORT_FREQUENCY_LOW,
            REPORT_FREQUENCY_MEDIUM,
            REPORT_FREQUENCY_HIGH})
    @interface ReportFrequency  {}

    /**
     * Perform distance measurement in low frequency. This is the default frequency as it consumes
     * the least power.
     *
     * @hide
     */
    @SystemApi
    public static final int REPORT_FREQUENCY_LOW = 0;


    /**
     * Perform distance measurement in medium frequency. Provides a good trade-off between report
     * frequency and power consumption.
     *
     * @hide
     */
    @SystemApi
    public static final int REPORT_FREQUENCY_MEDIUM = 1;

    /**
     * Perform distance measurement in high frequency. It's recommended to only use this mode when
     * the application is running in the foreground.
     *
     * @hide
     */
    @SystemApi
    public static final int REPORT_FREQUENCY_HIGH = 2;

    private static final int REPORT_DURATION_DEFAULT = 60;
    private static final int REPORT_DURATION_MAX = 3600;

    private BluetoothDevice mDevice = null;
    private int mDuration;
    private int mFrequency;
    private int mMethod;

    /**
     * @hide
     */
    public DistanceMeasurementParams(BluetoothDevice device, int duration, int frequency,
            int method) {
        mDevice = Objects.requireNonNull(device);
        mDuration = duration;
        mFrequency = frequency;
        mMethod = method;
    }

    /**
     * Returns device of this DistanceMeasurementParams.
     *
     * @hide
     */
    @SystemApi
    public @NonNull BluetoothDevice getDevice() {
        return mDevice;
    }

    /**
     * Returns duration of this DistanceMeasurementParams.
     *
     * @hide
     */
    @SystemApi
    public int getDuration() {
        return mDuration;
    }

    /**
     * Returns frequency of this DistanceMeasurementParams.
     *
     * @hide
     */
    @SystemApi
    public int getFrequency() {
        return mFrequency;
    }

    /**
     * Returns method of this DistanceMeasurementParams.
     *
     * @hide
     */
    @SystemApi
    public int getMethod() {
        return mMethod;
    }

    /**
     * Get the default duration of the parameter.
     * @hide
     */
    @SystemApi
    public static int getDefaultDuration() {
        return REPORT_DURATION_DEFAULT;
    }

    /**
     * Get the maximum duration that can be set for the parameter.
     * @hide
     */
    @SystemApi
    public static int getMaxDuration() {
        return REPORT_DURATION_MAX;
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
        out.writeParcelable(mDevice, 0);
        out.writeInt(mDuration);
        out.writeInt(mFrequency);
        out.writeInt(mMethod);
    }

    /**
     * A {@link Parcelable.Creator} to create {@link DistanceMeasurementParams} from parcel.
     *
     */
    public static final @NonNull Parcelable.Creator<DistanceMeasurementParams> CREATOR =
            new Parcelable.Creator<DistanceMeasurementParams>() {
                @Override
                public @NonNull DistanceMeasurementParams createFromParcel(@NonNull Parcel in) {
                    Builder builder = new Builder((BluetoothDevice) in.readParcelable(null));
                    builder.setDuration(in.readInt());
                    builder.setFrequency(in.readInt());
                    builder.setMethod(in.readInt());
                    return builder.build();
                }

                @Override
                public @NonNull DistanceMeasurementParams[] newArray(int size) {
                    return new DistanceMeasurementParams[size];
                }
        };


    /**
     * Builder for {@link DistanceMeasurementParams}.
     *
     * @hide
     */
    @SystemApi
    public static final class Builder {
        private BluetoothDevice mDevice = null;
        private int mDuration = REPORT_DURATION_DEFAULT;
        private int mFrequency = REPORT_FREQUENCY_LOW;
        private int mMethod = DistanceMeasurementMethod.DISTANCE_MEASUREMENT_METHOD_RSSI;

        /**
         * Constructor of the Builder.
         *
         * @param device device of the DistanceMeasurementParams
         */
        public Builder(@NonNull BluetoothDevice device) {
            mDevice = Objects.requireNonNull(device);
        }

        /**
         * Set duration in seconds for the DistanceMeasurementParams.
         *
         * @param duration duration of this DistanceMeasurementParams
         * @return the same Builder instance
         * @throws IllegalArgumentException if duration greater than
         * {@link DistanceMeasurementParams#getMaxDuration()} or less than zero.
         * @hide
         */
        @SystemApi
        public @NonNull Builder setDuration(@IntRange(from = 0, to = 3600) int duration) {
            if (duration < 0 || duration > getMaxDuration()) {
                throw new IllegalArgumentException("illegal duration " + duration);
            }
            mDuration = duration;
            return this;
        }

        /**
         * Set frequency for the DistanceMeasurementParams.
         *
         * @param frequency frequency of this DistanceMeasurementParams
         * @return the same Builder instance
         *
         * @hide
         */
        @SystemApi
        public @NonNull Builder setFrequency(@ReportFrequency int frequency) {
            switch (frequency) {
                case REPORT_FREQUENCY_LOW:
                case REPORT_FREQUENCY_MEDIUM:
                case REPORT_FREQUENCY_HIGH:
                    mFrequency = frequency;
                    break;
                default:
                    throw new IllegalArgumentException("unknown frequency " + frequency);
            }
            return this;
        }

        /**
         * Set method for the DistanceMeasurementParams.
         *
         * @param method method of this DistanceMeasurementParams
         * @return the same Builder instance
         *
         * @hide
         */
        @SystemApi
        public @NonNull Builder setMethod(@DistanceMeasurementMethodId int method) {
            switch (method) {
                case DistanceMeasurementMethod.DISTANCE_MEASUREMENT_METHOD_AUTO:
                case DistanceMeasurementMethod.DISTANCE_MEASUREMENT_METHOD_RSSI:
                    mMethod = method;
                    break;
                default:
                    throw new IllegalArgumentException("unknown method " + method);
            }
            return this;
        }

        /**
         * Build the {@link DistanceMeasurementParams} object.
         *
         * @hide
         */
        @SystemApi
        public @NonNull DistanceMeasurementParams build() {
            return new DistanceMeasurementParams(mDevice, mDuration, mFrequency, mMethod);
        }
    }
}
