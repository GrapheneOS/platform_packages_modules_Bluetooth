/*
 * Copyright (C) 2012 The Android Open Source Project
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

package com.android.bluetooth.hfp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Looper;
import android.support.annotation.VisibleForTesting;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.SignalStrength;
import android.telephony.SubscriptionManager;
import android.telephony.SubscriptionManager.OnSubscriptionsChangedListener;
import android.telephony.TelephonyManager;
import android.util.Log;

import com.android.internal.telephony.IccCardConstants;
import com.android.internal.telephony.TelephonyIntents;

import java.util.Objects;


/**
 * Class that manages Telephony states
 *
 * Note:
 * The methods in this class are not thread safe, don't call them from
 * multiple threads. Call them from the HeadsetPhoneStateMachine message
 * handler only.
 */
public class HeadsetPhoneState {
    private static final String TAG = "HeadsetPhoneState";

    private final HeadsetService mHeadsetService;
    private final TelephonyManager mTelephonyManager;
    private final SubscriptionManager mSubscriptionManager;

    private ServiceState mServiceState;

    // HFP 1.6 CIND service value
    private int mCindService = HeadsetHalConstants.NETWORK_STATE_NOT_AVAILABLE;
    // Check this before sending out service state to the device -- if the SIM isn't fully
    // loaded, don't expose that the network is available.
    private boolean mIsSimStateLoaded;
    // Number of active (foreground) calls
    private int mNumActive;
    // Current Call Setup State
    private int mCallState = HeadsetHalConstants.CALL_STATE_IDLE;
    // Number of held (background) calls
    private int mNumHeld;
    // HFP 1.6 CIND signal value
    private int mCindSignal;
    // HFP 1.6 CIND roam value
    private int mCindRoam = HeadsetHalConstants.SERVICE_TYPE_HOME;
    // HFP 1.6 CIND battchg value
    private int mCindBatteryCharge;

    private boolean mListening;
    private PhoneStateListener mPhoneStateListener;
    private final OnSubscriptionsChangedListener mOnSubscriptionsChangedListener;

    HeadsetPhoneState(HeadsetService headsetService) {
        Objects.requireNonNull(headsetService, "headsetService is null");
        mHeadsetService = headsetService;
        mTelephonyManager =
                (TelephonyManager) mHeadsetService.getSystemService(Context.TELEPHONY_SERVICE);
        Objects.requireNonNull(mTelephonyManager, "TELEPHONY_SERVICE is null");
        // Register for SubscriptionInfo list changes which is guaranteed to invoke
        // onSubscriptionInfoChanged and which in turns calls loadInBackgroud.
        mSubscriptionManager = SubscriptionManager.from(mHeadsetService);
        Objects.requireNonNull(mSubscriptionManager, "TELEPHONY_SUBSCRIPTION_SERVICE is null");
        // Initialize subscription on the handler thread
        mOnSubscriptionsChangedListener = new HeadsetPhoneStateOnSubscriptionChangedListener(
                headsetService.getStateMachinesThreadLooper());
        mSubscriptionManager.addOnSubscriptionsChangedListener(mOnSubscriptionsChangedListener);
    }

    /**
     * Cleanup this instance. Instance can no longer be used after calling this method.
     */
    public void cleanup() {
        listenForPhoneState(false);
        mSubscriptionManager.removeOnSubscriptionsChangedListener(mOnSubscriptionsChangedListener);
    }

    @Override
    public String toString() {
        return "HeadsetPhoneState [mTelephonyServiceAvailability=" + mCindService + ", mNumActive="
                + mNumActive + ", mCallState=" + mCallState + ", mNumHeld=" + mNumHeld
                + ", mSignal=" + mCindSignal + ", mRoam=" + mCindRoam + ", mBatteryCharge="
                + mCindBatteryCharge + ", mListening=" + mListening + "]";
    }

    /**
     * Start or stop listening for phone state change
     * @param start True to start, False to stop
     */
    @VisibleForTesting
    public void listenForPhoneState(boolean start) {
        synchronized (mTelephonyManager) {
            if (start) {
                startListenForPhoneState();
            } else {
                stopListenForPhoneState();
            }
        }
    }

    private void startListenForPhoneState() {
        if (!mListening) {
            int subId = SubscriptionManager.getDefaultSubscriptionId();
            if (SubscriptionManager.isValidSubscriptionId(subId)) {
                mPhoneStateListener = new HeadsetPhoneStateListener(subId,
                        mHeadsetService.getStateMachinesThreadLooper());
                mTelephonyManager.listen(mPhoneStateListener,
                        PhoneStateListener.LISTEN_SERVICE_STATE
                                | PhoneStateListener.LISTEN_SIGNAL_STRENGTHS);
                mListening = true;
            } else {
                Log.w(TAG, "startListenForPhoneState, invalid subscription ID " + subId);
            }
        }
    }

    private void stopListenForPhoneState() {
        if (mListening) {
            mTelephonyManager.listen(mPhoneStateListener, PhoneStateListener.LISTEN_NONE);
            mListening = false;
        }
    }

    int getCindService() {
        return mCindService;
    }

    int getNumActiveCall() {
        return mNumActive;
    }

    void setNumActiveCall(int numActive) {
        mNumActive = numActive;
    }

    int getCallState() {
        return mCallState;
    }

    void setCallState(int callState) {
        mCallState = callState;
    }

    int getNumHeldCall() {
        return mNumHeld;
    }

    void setNumHeldCall(int numHeldCall) {
        mNumHeld = numHeldCall;
    }

    int getCindSignal() {
        return mCindSignal;
    }

    int getCindRoam() {
        return mCindRoam;
    }

    /**
     * Set battery level value used for +CIND result
     *
     * @param batteryLevel battery level value
     */
    public void setCindBatteryCharge(int batteryLevel) {
        if (mCindBatteryCharge != batteryLevel) {
            mCindBatteryCharge = batteryLevel;
            sendDeviceStateChanged();
        }
    }

    int getCindBatteryCharge() {
        return mCindBatteryCharge;
    }

    boolean isInCall() {
        return (mNumActive >= 1);
    }

    private void sendDeviceStateChanged() {
        int service =
                mIsSimStateLoaded ? mCindService : HeadsetHalConstants.NETWORK_STATE_NOT_AVAILABLE;
        // When out of service, send signal strength as 0. Some devices don't
        // use the service indicator, but only the signal indicator
        int signal = service == HeadsetHalConstants.NETWORK_STATE_AVAILABLE ? mCindSignal : 0;

        Log.d(TAG, "sendDeviceStateChanged. mService=" + mCindService + " mIsSimStateLoaded="
                + mIsSimStateLoaded + " mSignal=" + signal + " mRoam=" + mCindRoam
                + " mBatteryCharge=" + mCindBatteryCharge);
        mHeadsetService.onDeviceStateChanged(
                new HeadsetDeviceState(service, mCindRoam, signal, mCindBatteryCharge));
    }

    private class HeadsetPhoneStateOnSubscriptionChangedListener
            extends OnSubscriptionsChangedListener {
        HeadsetPhoneStateOnSubscriptionChangedListener(Looper looper) {
            super(looper);
        }

        @Override
        public void onSubscriptionsChanged() {
            listenForPhoneState(false);
            listenForPhoneState(true);
        }
    }

    private class HeadsetPhoneStateListener extends PhoneStateListener {
        HeadsetPhoneStateListener(Integer subId, Looper looper) {
            super(subId, looper);
        }

        @Override
        public synchronized void onServiceStateChanged(ServiceState serviceState) {
            mServiceState = serviceState;
            int cindService = (serviceState.getState() == ServiceState.STATE_IN_SERVICE)
                    ? HeadsetHalConstants.NETWORK_STATE_AVAILABLE
                    : HeadsetHalConstants.NETWORK_STATE_NOT_AVAILABLE;
            int newRoam = serviceState.getRoaming() ? HeadsetHalConstants.SERVICE_TYPE_ROAMING
                    : HeadsetHalConstants.SERVICE_TYPE_HOME;

            if (cindService == mCindService && newRoam == mCindRoam) {
                // De-bounce the state change
                return;
            }
            mCindService = cindService;
            mCindRoam = newRoam;

            // If this is due to a SIM insertion, we want to defer sending device state changed
            // until all the SIM config is loaded.
            if (cindService == HeadsetHalConstants.NETWORK_STATE_NOT_AVAILABLE) {
                mIsSimStateLoaded = false;
                sendDeviceStateChanged();
                return;
            }
            IntentFilter simStateChangedFilter =
                    new IntentFilter(TelephonyIntents.ACTION_SIM_STATE_CHANGED);
            mHeadsetService.registerReceiver(new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    if (TelephonyIntents.ACTION_SIM_STATE_CHANGED.equals(intent.getAction())) {
                        // This is a sticky broadcast, so if it's already been loaded,
                        // this'll execute immediately.
                        if (IccCardConstants.INTENT_VALUE_ICC_LOADED.equals(
                                intent.getStringExtra(IccCardConstants.INTENT_KEY_ICC_STATE))) {
                            mIsSimStateLoaded = true;
                            sendDeviceStateChanged();
                            mHeadsetService.unregisterReceiver(this);
                        }
                    }
                }
            }, simStateChangedFilter);

        }

        @Override
        public void onSignalStrengthsChanged(SignalStrength signalStrength) {

            int prevSignal = mCindSignal;
            if (mCindService == HeadsetHalConstants.NETWORK_STATE_NOT_AVAILABLE) {
                mCindSignal = 0;
            } else if (signalStrength.isGsm()) {
                mCindSignal = signalStrength.getLteLevel();
                if (mCindSignal == SignalStrength.SIGNAL_STRENGTH_NONE_OR_UNKNOWN) {
                    mCindSignal = gsmAsuToSignal(signalStrength);
                } else {
                    // SignalStrength#getLteLevel returns the scale from 0-4
                    // Bluetooth signal scales at 0-5
                    // Let's match up the larger side
                    mCindSignal++;
                }
            } else {
                mCindSignal = cdmaDbmEcioToSignal(signalStrength);
            }

            // network signal strength is scaled to BT 1-5 levels.
            // This results in a lot of duplicate messages, hence this check
            if (prevSignal != mCindSignal) {
                sendDeviceStateChanged();
            }
        }

        /* convert [0,31] ASU signal strength to the [0,5] expected by
         * bluetooth devices. Scale is similar to status bar policy
         */
        private int gsmAsuToSignal(SignalStrength signalStrength) {
            int asu = signalStrength.getGsmSignalStrength();
            if (asu == 99) {
                return 0;
            } else if (asu >= 16) {
                return 5;
            } else if (asu >= 8) {
                return 4;
            } else if (asu >= 4) {
                return 3;
            } else if (asu >= 2) {
                return 2;
            } else if (asu >= 1) {
                return 1;
            } else {
                return 0;
            }
        }

        /**
         * Convert the cdma / evdo db levels to appropriate icon level.
         * The scale is similar to the one used in status bar policy.
         *
         * @param signalStrength signal strength level
         * @return the icon level for remote device
         */
        private int cdmaDbmEcioToSignal(SignalStrength signalStrength) {
            int levelDbm = 0;
            int levelEcio = 0;
            int cdmaIconLevel = 0;
            int evdoIconLevel = 0;
            int cdmaDbm = signalStrength.getCdmaDbm();
            int cdmaEcio = signalStrength.getCdmaEcio();

            if (cdmaDbm >= -75) {
                levelDbm = 4;
            } else if (cdmaDbm >= -85) {
                levelDbm = 3;
            } else if (cdmaDbm >= -95) {
                levelDbm = 2;
            } else if (cdmaDbm >= -100) {
                levelDbm = 1;
            } else {
                levelDbm = 0;
            }

            // Ec/Io are in dB*10
            if (cdmaEcio >= -90) {
                levelEcio = 4;
            } else if (cdmaEcio >= -110) {
                levelEcio = 3;
            } else if (cdmaEcio >= -130) {
                levelEcio = 2;
            } else if (cdmaEcio >= -150) {
                levelEcio = 1;
            } else {
                levelEcio = 0;
            }

            cdmaIconLevel = (levelDbm < levelEcio) ? levelDbm : levelEcio;

            // STOPSHIP: Change back to getRilVoiceRadioTechnology
            if (mServiceState != null && (
                    mServiceState.getRadioTechnology() == ServiceState.RIL_RADIO_TECHNOLOGY_EVDO_0
                            || mServiceState.getRadioTechnology()
                            == ServiceState.RIL_RADIO_TECHNOLOGY_EVDO_A)) {
                int evdoEcio = signalStrength.getEvdoEcio();
                int evdoSnr = signalStrength.getEvdoSnr();
                int levelEvdoEcio = 0;
                int levelEvdoSnr = 0;

                // Ec/Io are in dB*10
                if (evdoEcio >= -650) {
                    levelEvdoEcio = 4;
                } else if (evdoEcio >= -750) {
                    levelEvdoEcio = 3;
                } else if (evdoEcio >= -900) {
                    levelEvdoEcio = 2;
                } else if (evdoEcio >= -1050) {
                    levelEvdoEcio = 1;
                } else {
                    levelEvdoEcio = 0;
                }

                if (evdoSnr > 7) {
                    levelEvdoSnr = 4;
                } else if (evdoSnr > 5) {
                    levelEvdoSnr = 3;
                } else if (evdoSnr > 3) {
                    levelEvdoSnr = 2;
                } else if (evdoSnr > 1) {
                    levelEvdoSnr = 1;
                } else {
                    levelEvdoSnr = 0;
                }

                evdoIconLevel = (levelEvdoEcio < levelEvdoSnr) ? levelEvdoEcio : levelEvdoSnr;
            }
            // TODO(): There is a bug open regarding what should be sent.
            return (cdmaIconLevel > evdoIconLevel) ? cdmaIconLevel : evdoIconLevel;
        }
    }
}
