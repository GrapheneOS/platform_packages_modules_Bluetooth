/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 **************************************************************************

/**
 * Bluetooth ActiveDeviceManagerService. There is one instance each for
 *  voice and media profile management..
 *  - "Idle" and "Active" are steady states.
 *  - "Activating" and "Deactivating" are transient states until the
 *     SHO / Deactivation is completed.
 *
 *
 *                               (Idle)
 *                             |        ^
 *                   SetActive |        | Removed
 *                             V        |
 *                 (Activating)          (Deactivating)
 *                             |        ^
 *                 Activated   |        | setActive(NULL) / removeDevice
 *                             V        |
 *                      (Active / Broadcasting)
 *
 *
 */

package com.android.bluetooth.apm;

import static android.Manifest.permission.BLUETOOTH_CONNECT;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothHeadset;
import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ActiveDeviceManager;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.hearingaid.HearingAidService;
import com.android.bluetooth.hfp.HeadsetService;
import com.android.bluetooth.mcp.McpService;
import com.android.bluetooth.broadcast.BroadcastService;
import com.android.bluetooth.cc.CCService;
import android.content.Intent;
import android.content.Context;
import android.os.Looper;
import android.os.Message;
import android.os.HandlerThread;
import android.os.UserHandle;
import android.os.SystemProperties;
import android.util.Log;
import android.media.AudioManager;

import com.android.bluetooth.BluetoothStatsLog;
import com.android.internal.util.State;
import com.android.internal.util.StateMachine;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.Boolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.lang.Integer;
import java.util.Scanner;
import java.util.Objects;

public class ActiveDeviceManagerService {
    private static final boolean DBG = true;
    private static final String TAG = "APM: ActiveDeviceManagerService";
    private static ActiveDeviceManagerService sActiveDeviceManager = null;
    private AudioManager mAudioManager;
    private HandlerThread[] thread = new HandlerThread[AudioType.SIZE];
    private ShoStateMachine[] sm = new ShoStateMachine[AudioType.SIZE];
    private ApmNativeInterface apmNative;
    private Context mContext;
    private boolean txStreamSuspended = false;
    private final Lock lock = new ReentrantLock();
    private final Condition mediaHandoffComplete = lock.newCondition();
    private final Condition voiceHandoffComplete = lock.newCondition();
    static class Event {
        static final int SET_ACTIVE = 1;
        static final int ACTIVE_DEVICE_CHANGE = 2;
        static final int REMOVE_DEVICE = 3;
        static final int DEVICE_REMOVED = 4;
        static final int ACTIVATE_TIMEOUT = 5;
        static final int DEACTIVATE_TIMEOUT = 6;
        static final int SUSPEND_RECORDING = 7;
        static final int RESUME_RECORDING = 8;
        static final int RETRY_DEACTIVATE = 9;
        static final int STOP_SM = 0;
    }

    public static final int SHO_SUCCESS = 0;
    public static final int SHO_PENDING = 1;
    public static final int SHO_FAILED = 2;
    public static final int ALREADY_ACTIVE = 3;

    static final int RETRY_LIMIT = 4;
    static final int ACTIVATE_TIMEOUT_DELAY = 3000;
    static final int DEACTIVATE_TIMEOUT_DELAY = 2000;
    static final int DEACTIVATE_TRY_DELAY = 500;

    private ActiveDeviceManagerService (Context context) {
        thread[AudioType.MEDIA] = new HandlerThread("ActiveDeviceManager.MediaThread");
        thread[AudioType.MEDIA].start();
        Looper mediaLooper = thread[AudioType.MEDIA].getLooper();
        sm[AudioType.MEDIA] = new ShoStateMachine(AudioType.MEDIA, mediaLooper);

        thread[AudioType.VOICE] = new HandlerThread("ActiveDeviceManager.VoiceThread");
        thread[AudioType.VOICE].start();
        Looper voiceLooper = thread[AudioType.VOICE].getLooper();
        sm[AudioType.VOICE] = new ShoStateMachine(AudioType.VOICE, voiceLooper);

        mContext = context;
        apmNative = ApmNativeInterface.getInstance();
        apmNative.init();

        mAudioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            Objects.requireNonNull(mAudioManager,
                               "AudioManager cannot be null when ActiveDeviceManagerService starts");
    }

    public static ActiveDeviceManagerService get(Context context) {
        if(sActiveDeviceManager == null) {
            sActiveDeviceManager = new ActiveDeviceManagerService(context);
            ActiveDeviceManagerServiceIntf.init(sActiveDeviceManager);
        }
        return sActiveDeviceManager;
    }

    public static ActiveDeviceManagerService get() {
        return sActiveDeviceManager;
    }

    public boolean setActiveDevice(BluetoothDevice device, Integer mAudioType, Boolean isUIReq, Boolean playReq) {
        Log.d(TAG, "setActiveDevice(" + device + ") audioType: " + mAudioType);
        boolean isCallActive = false;
        if(ApmConst.AudioFeatures.CALL_AUDIO == mAudioType) {
            CallAudio mCallAudio = CallAudio.get();
            isCallActive = mCallAudio.isAudioOn();
        }

        synchronized(sm[mAudioType]) {
            sm[mAudioType].mSHOQueue.device = device;
            sm[mAudioType].mSHOQueue.isUIReq = isUIReq;
            sm[mAudioType].mSHOQueue.PlayReq = (playReq || isCallActive);
            sm[mAudioType].mSHOQueue.isBroadcast = false;
            sm[mAudioType].mSHOQueue.isRecordingMode = false;
            sm[mAudioType].mSHOQueue.isGamingMode = false;
        }

        if(device != null) {
            sm[mAudioType].sendMessage(Event.SET_ACTIVE);
        }
        else {
            if (mAudioType == AudioType.MEDIA && sm[mAudioType].mState == sm[mAudioType].mBroadcasting) {
                Log.d(TAG, "LE Broadcast is active, ignore REMOVE_DEVICE");
            } else {
                sm[mAudioType].sendMessage(Event.REMOVE_DEVICE);
            }
        }
        return isUIReq;
    }

    public boolean setActiveDevice(BluetoothDevice device, Integer mAudioType, Boolean isUIReq) {
        return setActiveDevice(device, mAudioType, isUIReq, false);
    }

    public boolean setActiveDevice(BluetoothDevice device, Integer mAudioType) {
        return setActiveDevice(device, mAudioType, false, false);
    }

    public boolean setActiveDeviceBlocking(BluetoothDevice device, Integer mAudioType) {
        Log.d(TAG, "setActiveDeviceBlocking: Enter");
        if(ApmConst.AudioFeatures.CALL_AUDIO == mAudioType) {
            setActiveDevice(device, mAudioType, false, false);
            try {
                lock.lock();
                voiceHandoffComplete.await();
            } catch (InterruptedException e) {
                Log.d(TAG, "setActiveDeviceBlocking: Unblocked because of exception: " + e);
            } finally {
                Log.d(TAG, "setActiveDeviceBlocking: unlock");
                lock.unlock();
            }
        }
        Log.d(TAG, "setActiveDeviceBlocking: Exit");
        return true;
    }

    public BluetoothDevice getQueuedDevice(Integer mAudioType) {
        return sm[mAudioType].mSHOQueue.device;
    }

    public boolean removeActiveDevice(Integer mAudioType, Boolean forceStopAudio) {
        sm[mAudioType].mSHOQueue.forceStopAudio = forceStopAudio;
        setActiveDevice(null, mAudioType, false);
        return true;
    }

    public BluetoothDevice getActiveDevice(Integer mAudioType) {
        return sm[mAudioType].Current.Device;
    }

    public int getActiveProfile(Integer mAudioType) {
        if(sm[mAudioType].mState == sm[mAudioType].mBroadcasting) {
            // Use Current.Profile here
            return ApmConst.AudioProfiles.BROADCAST_LE;
        } else if(sm[mAudioType].mState == sm[mAudioType].mActive) {
            return sm[mAudioType].Current.Profile;
        }
        return ApmConst.AudioProfiles.NONE;
    }

    public boolean onActiveDeviceChange(BluetoothDevice device, Integer mAudioType) {
        return onActiveDeviceChange(device, mAudioType, ApmConst.AudioProfiles.NONE);
    }

    public boolean onActiveDeviceChange(BluetoothDevice device, Integer mAudioType, Integer mProfile) {
        if (device != null || mProfile == ApmConst.AudioProfiles.BROADCAST_LE) {
            DeviceProfileCombo mDeviceProfileCombo = new DeviceProfileCombo(device, mProfile);
            sm[mAudioType].sendMessage(Event.ACTIVE_DEVICE_CHANGE, mDeviceProfileCombo);
        }
        else
            sm[mAudioType].sendMessage(Event.DEVICE_REMOVED);
        return true;
    }

    public boolean enableBroadcast(BluetoothDevice device) {
        synchronized(sm[AudioType.MEDIA]) {
            sm[AudioType.MEDIA].mSHOQueue.device = device;
            sm[AudioType.MEDIA].mSHOQueue.isBroadcast = true;
            sm[AudioType.MEDIA].mSHOQueue.PlayReq = false;
        }
        sm[AudioType.MEDIA].sendMessage(Event.SET_ACTIVE);
        return true;
    }

    public boolean disableBroadcast() {
        Log.d(TAG, "disableBroadcast");
        synchronized(sm[AudioType.MEDIA]) {
            sm[AudioType.MEDIA].mSHOQueue.isBroadcast = false;
            sm[AudioType.MEDIA].mSHOQueue.PlayReq = false;
        }
        if (sm[AudioType.MEDIA].mState == sm[AudioType.MEDIA].mBroadcasting) {
            sm[AudioType.MEDIA].sendMessage(Event.REMOVE_DEVICE);
        }
        return true;
    }

    public boolean enableGaming(BluetoothDevice device) {
        if (sm[AudioType.MEDIA].mState == sm[AudioType.MEDIA].mGamingMode &&
                        device.equals(getActiveDevice(AudioType.MEDIA))) {
            Log.d(TAG, "Device already in Gaming Mode");
            return true;
        }

        Log.d(TAG, "enableGaming");
        synchronized(sm[AudioType.MEDIA]) {
            sm[AudioType.MEDIA].mSHOQueue.device = device;
            sm[AudioType.MEDIA].mSHOQueue.isBroadcast = false;
            sm[AudioType.MEDIA].mSHOQueue.isGamingMode = true;
            sm[AudioType.MEDIA].mSHOQueue.PlayReq = false;
        }
        sm[AudioType.MEDIA].sendMessage(Event.SET_ACTIVE);
        return true;
    }

    public boolean disableGaming(BluetoothDevice device) {
        if (sm[AudioType.MEDIA].mState != sm[AudioType.MEDIA].mGamingMode) {
            Log.e(TAG, "Gaming Mode not active");
            return true;
        }

        /*MediaAudio mMediaAudio = MediaAudio.get();
        if(mMediaAudio != null && mMediaAudio.isA2dpPlaying(device)) {
            Log.w(TAG, "Gaming Stream is Active");
            return false;
        }*/

        Log.d(TAG, "disableGaming");
        synchronized(sm[AudioType.MEDIA]) {
            sm[AudioType.MEDIA].mSHOQueue.device = device;
            sm[AudioType.MEDIA].mSHOQueue.isGamingMode = false;
            sm[AudioType.MEDIA].mSHOQueue.PlayReq = false;
            sm[AudioType.MEDIA].mSHOQueue.isUIReq = true;
        }

        //sm[AudioType.MEDIA].sendMessageDelayed(Event.SET_ACTIVE, DEACTIVATE_TRY_DELAY);
        sm[AudioType.MEDIA].sendMessage(Event.SET_ACTIVE);
        return true;
    }

    public boolean enableRecording(BluetoothDevice device) {
        Log.d(TAG, "enableRecording: " + device);

        MediaAudio mMediaAudio = MediaAudio.get();
        if(txStreamSuspended == false) {
            Log.d(TAG, "Set A2dpSuspended=true");
            mAudioManager.setParameters("A2dpSuspended=true");
            txStreamSuspended = true;
        }

        synchronized(sm[AudioType.MEDIA]) {
            sm[AudioType.MEDIA].mSHOQueue.device = device;
            sm[AudioType.MEDIA].mSHOQueue.isBroadcast = false;
            sm[AudioType.MEDIA].mSHOQueue.isGamingMode = false;
            sm[AudioType.MEDIA].mSHOQueue.isRecordingMode = true;
            sm[AudioType.MEDIA].mSHOQueue.PlayReq = false;
            sm[AudioType.MEDIA].mSHOQueue.isUIReq = true;
        }
        sm[AudioType.MEDIA].sendMessage(Event.SET_ACTIVE);
        return true;
    }

    public boolean disableRecording(BluetoothDevice device) {
        Log.d(TAG, "disableRecording: " + device);

        synchronized(sm[AudioType.MEDIA]) {
            sm[AudioType.MEDIA].mSHOQueue.device = device;
            sm[AudioType.MEDIA].mSHOQueue.isRecordingMode = false;
            sm[AudioType.MEDIA].mSHOQueue.PlayReq = false;
        }

        if (sm[AudioType.MEDIA].mState == sm[AudioType.MEDIA].mRecordingMode) {
            sm[AudioType.MEDIA].sendMessage(Event.SET_ACTIVE);
        }
        return true;
    }

    public boolean suspendRecording(Boolean suspend) {
        Log.d(TAG, "suspendRecording: " + suspend);

        if(sm[AudioType.MEDIA].mState == sm[AudioType.MEDIA].mRecordingMode) {
          if(suspend) {
            sm[AudioType.MEDIA].sendMessage(Event.SUSPEND_RECORDING);
          } else {
            sm[AudioType.MEDIA].sendMessage(Event.RESUME_RECORDING);
          }
        }
        return true;
    }

    public boolean isRecordingActive(BluetoothDevice device) {
        Log.d(TAG, "isRecordingActive");
        return sm[AudioType.MEDIA].mState == sm[AudioType.MEDIA].mRecordingMode;
    }

    public boolean isStableState(int mAudioType) {
        State state = sm[mAudioType].mState;
        return !(sm[mAudioType].mActivating == state || sm[mAudioType].mDeactivating == state);
    }

    private void broadcastActiveDeviceChange(BluetoothDevice device, int mAudioType) {
        if (DBG) {
            Log.d(TAG, "broadcastActiveDeviceChange(" + device + ")");
        }
        Intent intent;

        /*if (mAdapterService != null)
            BluetoothStatsLog.write(BluetoothStatsLog.BLUETOOTH_ACTIVE_DEVICE_CHANGED, BluetoothProfile.A2DP,
                      mAdapterService.obfuscateAddress(device), 0);*/

        if(mAudioType == AudioType.MEDIA)
            intent = new Intent(BluetoothA2dp.ACTION_ACTIVE_DEVICE_CHANGED);
        else
            intent = new Intent(BluetoothHeadset.ACTION_ACTIVE_DEVICE_CHANGED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        if(mAudioType == AudioType.MEDIA) {
            A2dpService mA2dpService = A2dpService.getA2dpService();
            if(mA2dpService == null) {
                Log.e(TAG, "A2dp Service not ready");
                return;
            }
            mA2dpService.sendBroadcast(intent, BLUETOOTH_CONNECT);
        } else {
            HeadsetService mHeadsetService = HeadsetService.getHeadsetService();
            if(mHeadsetService == null) {
                Log.e(TAG, "Headset Service not ready");
                return;
            }
            mHeadsetService.sendBroadcastAsUser(intent, UserHandle.ALL, BLUETOOTH_CONNECT,
                   Utils.getTempAllowlistBroadcastOptions());
        }
    }

    public void disable() {
        Log.d(TAG, "disable() called");
        sm[AudioType.MEDIA].sendMessage(Event.STOP_SM);
        sm[AudioType.VOICE].sendMessage(Event.STOP_SM);
    }

    public void cleanup() {
        sm[AudioType.VOICE].doQuit();
        sm[AudioType.MEDIA].doQuit();
        thread[AudioType.VOICE].quitSafely();
        thread[AudioType.MEDIA].quitSafely();
        thread[AudioType.VOICE] = null;
        thread[AudioType.MEDIA] = null;
        sActiveDeviceManager = null;
    }

    private class DeviceProfileCombo {
        BluetoothDevice Device;
        BluetoothDevice absoluteDevice;
        int Profile;

        DeviceProfileCombo(BluetoothDevice mDevice, int mProfile) {
            Device = mDevice;
            Profile = mProfile;
        }

        DeviceProfileCombo() {
            Device = null;
            Profile = ApmConst.AudioProfiles.NONE;
        }
    }

    private final class ShoStateMachine extends StateMachine {
        private static final boolean DBG = true;
        private static final String TAG = "APM: ActiveDeviceManagerService";

        static final int IDLE = 0;
        static final int ACTIVATING = 1;
        static final int ACTIVE = 2;
        static final int DEACTIVATING = 3;
        static final int BROADCAST_ACTIVE = 4;
        static final int GAMING_ACTIVE = 5;
        static final int RECORDING_ACTIVE = 6;

        private Idle mIdle;
        private Activating mActivating;
        private Active mActive;
        private Deactivating mDeactivating;
        private Broadcasting mBroadcasting;
        private Gaming mGamingMode;
        private Recording mRecordingMode;

        private DeviceProfileCombo Current;
        private DeviceProfileCombo Target;
        private SHOReq mTargetSHO;
        private SHOReq mSHOQueue;

        private DeviceProfileMap dpm;

        private int mAudioType;
        private State mState;
        private State mPrevState = null;
        private BluetoothDevice mPrevActiveDevice;
        private int mPrevActiveProfile = ApmConst.AudioProfiles.NONE;
        boolean enabled;
        boolean updatePending = false;
        boolean mRecordingSuspended = false;
        private String sAudioType;

        ShoStateMachine (int audioType, Looper looper) {
            super(TAG, looper);
            setDbg(DBG);

            mIdle = new Idle();
            mActivating = new Activating();
            mActive = new Active();
            mDeactivating = new Deactivating();
            mBroadcasting = new Broadcasting();
            mGamingMode = new Gaming();
            mRecordingMode = new Recording();

            Current = new DeviceProfileCombo();
            Target = new DeviceProfileCombo();
            mSHOQueue = new SHOReq();
            mTargetSHO = new SHOReq();

            addState(mIdle);
            addState(mActivating);
            addState(mActive);
            addState(mDeactivating);
            addState(mBroadcasting);
            addState(mGamingMode);
            addState(mRecordingMode);

            mAudioType = audioType;
            if(mAudioType == AudioType.MEDIA)
                sAudioType = new String("MEDIA");
            else if(mAudioType == AudioType.VOICE)
                sAudioType = new String("VOICE");

            enabled =  true;
            setInitialState(mIdle);
            start();
        }

        public void doQuit () {
            Log.i(TAG, "Stopping SHO StateMachine for " + mAudioType);
            sAudioType = null;
            quitNow();
        }

       /* public void cleanUp {

        }*/

        private String messageWhatToString(int msg) {
            switch (msg) {
                case Event.SET_ACTIVE:
                    return "SET ACTIVE";
                case Event.ACTIVE_DEVICE_CHANGE:
                    return "ACTIVE DEVICE CHANGED";
                case Event.REMOVE_DEVICE:
                    return "REMOVE DEVICE";
                case Event.DEVICE_REMOVED:
                    return "REMOVED";
                case Event.ACTIVATE_TIMEOUT:
                    return "SET ACTIVE TIMEOUT";
                case Event.DEACTIVATE_TIMEOUT:
                    return "REMOVE DEVICE TIMEOUT";
                case Event.STOP_SM:
                    return "STOP STATE MACHINE";
                default:
                    break;
            }
            return Integer.toString(msg);
        }

        int startSho(BluetoothDevice device, int profile) {
            MediaAudio mMediaAudio = MediaAudio.get();
            int ret = SHO_FAILED;
            StreamAudioService streamAudioService;
            Log.e(TAG, ": startSho() for device: " + device + ", for profile: " + profile);
            switch (profile) {
                case ApmConst.AudioProfiles.A2DP:
                    A2dpService a2dpService = A2dpService.getA2dpService();
                    if(a2dpService != null)
                        // pass play status here
                        ret = a2dpService.setActiveDevice(device, false);
                    break;
                case ApmConst.AudioProfiles.HFP:
                    HeadsetService headsetService = HeadsetService.getHeadsetService();
                    if(headsetService != null)
                        ret = headsetService.setActiveDeviceHF(device);
                    break;
                case ApmConst.AudioProfiles.TMAP_MEDIA:
                case ApmConst.AudioProfiles.BAP_MEDIA:
                    streamAudioService = StreamAudioService.getStreamAudioService();
                    ret = streamAudioService.setActiveDevice(device, ApmConst.AudioProfiles.BAP_MEDIA, false);
                    if (ret == ActiveDeviceManagerService.ALREADY_ACTIVE) {
                      ret = SHO_SUCCESS;
                    }
                    break;
                case ApmConst.AudioProfiles.BAP_RECORDING:
                    streamAudioService = StreamAudioService.getStreamAudioService();
                    ret = streamAudioService.setActiveDevice(device, ApmConst.AudioProfiles.BAP_RECORDING, false);
                    if (ret == ActiveDeviceManagerService.ALREADY_ACTIVE) {
                      ret = SHO_SUCCESS;
                    }
                    break;
                case ApmConst.AudioProfiles.TMAP_CALL:
                case ApmConst.AudioProfiles.BAP_CALL:
                    streamAudioService = StreamAudioService.getStreamAudioService();
                    ret = streamAudioService.setActiveDevice(device, profile, false);
                    break;
                case ApmConst.AudioProfiles.BAP_GCP:
                    streamAudioService = StreamAudioService.getStreamAudioService();
                    ret = streamAudioService.setActiveDevice(device, ApmConst.AudioProfiles.BAP_GCP, false);
                    if (ret == ActiveDeviceManagerService.ALREADY_ACTIVE) {
                      ret = SHO_SUCCESS;
                    }
                    break;
                case ApmConst.AudioProfiles.BROADCAST_LE:
                    //ret = SHO_SUCCESS;//broadcastService.setActiveDevice();
                    BroadcastService mBroadcastService = BroadcastService.getBroadcastService();
                    if (mBroadcastService != null)
                        ret = mBroadcastService.setActiveDevice(device);
                    break;
                case ApmConst.AudioProfiles.HAP_BREDR:
                    HearingAidService hearingAidService = HearingAidService.getHearingAidService();
                    ret = hearingAidService.setActiveDevice(device) ?  SHO_SUCCESS : SHO_FAILED;
                    break;
            }
            return ret;
        }

        class Idle extends State {
            @Override
            public void enter() {
                synchronized (this) {
                    mState = mIdle;
                }
                Current.Device = null;
                //2 Update dependent profiles
                if(mPrevState != null && mPrevActiveDevice != null) {
                    broadcastActiveDeviceChange (null, mAudioType);

                    if (mAudioType == AudioType.MEDIA &&
                        mPrevActiveProfile != ApmConst.AudioProfiles.HAP_BREDR) {
                        mPrevActiveProfile = ApmConst.AudioProfiles.NONE;
                        MediaAudio mMediaAudio = MediaAudio.get();
                        boolean suppressNoisyIntent = !mTargetSHO.forceStopAudio
                                && (mMediaAudio.getConnectionState(mPrevActiveDevice)
                                == BluetoothProfile.STATE_CONNECTED);
                        /*TODO: Add profile check here*/
                        if(mAudioManager != null) {
                            log("De-Activate Device " + mPrevActiveDevice + " Noisy Intent: " + suppressNoisyIntent);
                            mAudioManager.handleBluetoothA2dpActiveDeviceChange(
                               mPrevActiveDevice, BluetoothProfile.STATE_DISCONNECTED,
                               BluetoothProfile.A2DP, suppressNoisyIntent, -1);
                        }
                    }

                    VolumeManager mVolumeManager = VolumeManager.get();
                    if(mVolumeManager != null) {
                        mVolumeManager.onActiveDeviceChange(Current.Device, mAudioType);
                    }
                }

                if(txStreamSuspended && mAudioType == AudioType.MEDIA) {
                    mAudioManager.setParameters("A2dpSuspended=false");
                    txStreamSuspended = false;
                }

                if(!enabled)
                    log("state machine stopped");
            }

            @Override
            public void exit() {
                mPrevState = mIdle;
                mPrevActiveDevice = null;
            }

            @Override
            public boolean processMessage(Message message) {
                log("Idle: Process Message (" + mAudioType + "): "
                        + messageWhatToString(message.what));
                if(!enabled) {
                    log("State Machine not running. Returning");
                    return NOT_HANDLED;
                }

                switch(message.what) {
                    case Event.SET_ACTIVE:
                        transitionTo(mActivating);
                        break;

                    case Event.ACTIVE_DEVICE_CHANGE:
                        /* Might move to active here*/
                    case Event.REMOVE_DEVICE:
                        log("Idle: Process Message Ignored");
                        break;
                    case Event.STOP_SM:
                        enabled = false;
                        log("state machine stopped");
                        break;
                    default:
                        return NOT_HANDLED;
                }
                return HANDLED;
            }
        }

        class Activating extends State {
            int ret;
            @Override
            public void enter() {
                synchronized (this) {
                    mState = mActivating;
                    updatePending = true;

                    Target.Device = mSHOQueue.device;
                    Target.absoluteDevice = Target.Device;
                    mTargetSHO.copy(mSHOQueue);
                    mSHOQueue.reset();
                    Log.w(TAG, "Activating " + sAudioType + " Device: " + Target.Device);
                }

                dpm = DeviceProfileMap.getDeviceProfileMapInstance();
                if (mTargetSHO.isBroadcast) {
                    Target.Profile = dpm.getProfile(Target.Device, ApmConst.AudioFeatures.BROADCAST_AUDIO);
                    mSHOQueue.device = Current.Device;
                    mSHOQueue.isUIReq = false;
                } else if (mTargetSHO.isRecordingMode) {
                    mSHOQueue.device = Current.Device;
                    Target.Profile = ApmConst.AudioProfiles.BAP_RECORDING;
                    mSHOQueue.isUIReq = false;
                } else if (mTargetSHO.isGamingMode) {
                    /*Only single profile supports gaming Mode*/
                    Target.Profile = ApmConst.AudioProfiles.BAP_GCP;
                } else {
                    Target.Profile = dpm.getProfile(Target.Device, mAudioType);
                }

                if(Target.Profile == ApmConst.AudioProfiles.BAP_CALL ||
                        Target.Profile == ApmConst.AudioProfiles.BAP_MEDIA ||
                        Target.Profile == ApmConst.AudioProfiles.BAP_RECORDING ||
                        Target.Profile == ApmConst.AudioProfiles.BAP_GCP) {
                    StreamAudioService streamAudioService = StreamAudioService.getStreamAudioService();
                    Target.Device = streamAudioService.getDeviceGroup(Target.Device);
                }

                if(Target.Device == null) {
                    Log.e(TAG, "Target Device is null, Returning");
                    transitionTo(mPrevState);
                    updatePending = false;
                    return;
                }

                if(Target.Device.equals(Current.Device) && Target.Profile == Current.Profile){
                    Log.d(TAG,"Target Device: " + Target.Device + " and Profile: " + Target.Profile +
                                                            " already active");
                    transitionTo(mPrevState);
                    updatePending = false;
                    return;
                }

                if(Current.Device == null || isSameProfile(Current.Profile, Target.Profile, mAudioType)) {
                    /* Single Step SHO*/
                    ActivateDevice(Target, mTargetSHO);
                } else {
                    /*Multi Step SHO*/
                    ret = startSho(null, Current.Profile);
                    if(SHO_PENDING == ret) {
                        sendMessageDelayed(Event.DEACTIVATE_TIMEOUT, DEACTIVATE_TIMEOUT_DELAY);
                    } else if(ret == SHO_FAILED) {
                        mTargetSHO.retryCount = 1;
                        sendMessageDelayed(Event.RETRY_DEACTIVATE, DEACTIVATE_TRY_DELAY);
                    } else if(SHO_SUCCESS == ret) {
                        mPrevState = mIdle;
                        Current.Device = null;
                        ActivateDevice(Target, mTargetSHO);
                    }
                }
            }

            @Override
            public void exit() {
                removeMessages(Event.ACTIVATE_TIMEOUT);
                mPrevState = mActivating;
            }

            @Override
            public boolean processMessage(Message message) {
                log("Activating: Process Message (" + mAudioType + "): "
                        + messageWhatToString(message.what));

                switch(message.what) {
                    case Event.SET_ACTIVE:
                        log("New SHO request while handling previous. Add to queue");
                        removeDeferredMessages(Event.REMOVE_DEVICE);
                        removeDeferredMessages(Event.SET_ACTIVE);
                        deferMessage(message);
                        break;

                    case Event.ACTIVE_DEVICE_CHANGE:
                        DeviceProfileCombo mDeviceProfileCombo = (DeviceProfileCombo)message.obj;
                        removeMessages(Event.ACTIVATE_TIMEOUT);
                        if (Target.Profile == ApmConst.AudioProfiles.BAP_GCP
                                    && Target.Profile == mDeviceProfileCombo.Profile) {
                            Current.Device = Target.Device;
                            Current.Profile = Target.Profile;
                            transitionTo(mGamingMode);
                        } else if (Target.Profile == ApmConst.AudioProfiles.BROADCAST_LE
                                    && Target.Profile == mDeviceProfileCombo.Profile) {
                            Current.Device = Target.Device;
                            Current.Profile = Target.Profile;
                            transitionTo(mBroadcasting);
                        } else if(Target.Device != null && Target.Device.equals(mDeviceProfileCombo.Device)) {
                            Current.Device = mDeviceProfileCombo.Device;
                            Current.Profile = Target.Profile;
                            Current.absoluteDevice = Target.absoluteDevice;
                            transitionTo(mActive);
                        }
                        break;

                    case Event.REMOVE_DEVICE:
                        removeDeferredMessages(Event.REMOVE_DEVICE);
                        deferMessage(message);
                        break;

                    case Event.DEVICE_REMOVED:
                        mPrevState = mIdle;
                        Current.Device = null;
                        removeMessages(Event.DEACTIVATE_TIMEOUT);
                        ActivateDevice(Target, mTargetSHO);
                        break;

                    case Event.RETRY_DEACTIVATE:
                        ret = startSho(null, Current.Profile);
                        if(SHO_PENDING == ret) {
                            mTargetSHO.retryCount = 0;
                            sendMessageDelayed(Event.DEACTIVATE_TIMEOUT, DEACTIVATE_TIMEOUT_DELAY);
                        } else if(ret == SHO_FAILED) {
                            if(mTargetSHO.retryCount >= RETRY_LIMIT) {
                                updatePending = false;
                                transitionTo(mPrevState);
                            } else {
                                mTargetSHO.retryCount++;
                                sendMessageDelayed(Event.RETRY_DEACTIVATE, DEACTIVATE_TRY_DELAY);
                            }
                        } else if(SHO_SUCCESS == ret) {
                            mTargetSHO.retryCount = 0;
                            mPrevState = mIdle;
                            Current.Device = null;
                            ActivateDevice(Target, mTargetSHO);
                        }
                        break;

                    case Event.ACTIVATE_TIMEOUT:
                    case Event.DEACTIVATE_TIMEOUT:
                        transitionTo(mPrevState);
                        break;

                    case Event.STOP_SM:
                        deferMessage(message);
                        break;

                    default:
                        return NOT_HANDLED;
                }
                return HANDLED;
            }

            void ActivateDevice(DeviceProfileCombo mTarget, SHOReq mTargetSHO) {
                ret = startSho(mTarget.Device, mTarget.Profile);
                if(SHO_PENDING == ret) {
                    Current.Device = mTarget.Device;
                    Current.absoluteDevice = mTarget.absoluteDevice;
                    Current.Profile = mTarget.Profile;
                    if(mAudioType == AudioType.MEDIA) {
                        sendActiveDeviceMediaUpdate(Current);
                    }
                    sendMessageDelayed(Event.ACTIVATE_TIMEOUT, ACTIVATE_TIMEOUT_DELAY);
                } else if(ret == SHO_FAILED) {
                    if (mState == mBroadcasting) {
                        mTargetSHO.forceStopAudio = true;
                        Log.d(TAG,"Previous state was broadcasting, moving to idle");
                    }
                    updatePending = false;
                    transitionTo(mPrevState);
                } else if(SHO_SUCCESS == ret) {
                    Current.Device = mTarget.Device;
                    Current.absoluteDevice = mTarget.absoluteDevice;
                    Current.Profile = mTarget.Profile;
                    if(mTargetSHO.isBroadcast) {
                        transitionTo(mBroadcasting);
                    } else if (mTargetSHO.isGamingMode) {
                        transitionTo(mGamingMode);
                    } else if (mTargetSHO.isRecordingMode) {
                        transitionTo(mRecordingMode);
                    } else {
                        transitionTo(mActive);
                    }
                } else if(ALREADY_ACTIVE == ret) {
                    transitionTo(mActive);
                }
            }
        }

        class Deactivating extends State {
            int ret;
            @Override
            public void enter() {
                synchronized (this) {
                    mState = mDeactivating;
                }
                if (mPrevState == mBroadcasting) {
                    mPrevState = mIdle;
                }
                Target.Device = null;
                Target.Profile = Current.Profile;
                mTargetSHO.copy(mSHOQueue);
                mSHOQueue.reset();

                ret = startSho(Target.Device, Target.Profile);
                Log.d(TAG, "ret: " + ret);
                if (SHO_SUCCESS == ret) {
                    transitionTo(mIdle);
                } else if (SHO_PENDING == ret) {
                    sendMessageDelayed(Event.DEACTIVATE_TIMEOUT, DEACTIVATE_TIMEOUT_DELAY);
                } else {
                    transitionTo(mPrevState);
                }
            }

            @Override
            public void exit() {
                removeMessages(Event.DEACTIVATE_TIMEOUT);
                mPrevState = mDeactivating;
                mPrevActiveDevice =  Current.Device;
                Current.Device = null;
                mPrevActiveProfile = Current.Profile;
                Current.Profile = ApmConst.AudioProfiles.NONE; // Add profile value here
            }

            @Override
            public boolean processMessage(Message message) {
                log("Deactivating: Process Message (" + mAudioType + "): "
                        + messageWhatToString(message.what));

                switch(message.what) {
                    case Event.SET_ACTIVE:
                        log("New SHO request while handling previous. Add to queue");
                        removeDeferredMessages(Event.SET_ACTIVE);
                        deferMessage(message);
                        break;

                    case Event.ACTIVE_DEVICE_CHANGE:
                        break;

                    case Event.REMOVE_DEVICE:
                        break;

                    case Event.DEVICE_REMOVED:
                        removeMessages(Event.DEACTIVATE_TIMEOUT);
                        transitionTo(mIdle);
                        break;

                    case Event.DEACTIVATE_TIMEOUT:
                        transitionTo(mPrevState);

                    case Event.STOP_SM:
                        deferMessage(message);
                        break;

                    default:
                        return NOT_HANDLED;
                }
                return HANDLED;
            }
        }

        class Active extends State {
            int ret;
            @Override
            public void enter() {
                synchronized (this) {
                    mState = mActive;
                }
                if(updatePending) {
                    if(mAudioType == AudioType.MEDIA)
                        sendActiveDeviceMediaUpdate(Current);
                    else if(mAudioType == AudioType.VOICE)
                        sendActiveDeviceVoiceUpdate(Current);
                }
                if(txStreamSuspended && mAudioType == AudioType.MEDIA) {
                    mAudioManager.setParameters("A2dpSuspended=false");
                    txStreamSuspended = false;
                } else if (mAudioType == AudioType.VOICE) {
                    lock.lock();
                    voiceHandoffComplete.signal();
                    lock.unlock();
                    Log.d(TAG, "Voice Active: unlock by signal");
                }
            }

            @Override
            public void exit() {
            //2 update dependent profiles
                mPrevState = mActive;
                mPrevActiveDevice = Current.Device;
                VolumeManager mVolumeManager = VolumeManager.get();
                if(mVolumeManager != null) {
                    mVolumeManager.saveVolume(mAudioType);
                }
            }

            @Override
            public boolean processMessage(Message message) {
                log("Active: Process Message (" + mAudioType + "): "
                        + messageWhatToString(message.what));

                switch(message.what) {
                    case Event.SET_ACTIVE:
                        if(mSHOQueue.device == null) {
                            Log.w(TAG, "Invalid request");
                            break;
                        }
                        transitionTo(mActivating);
                        break;

                    case Event.ACTIVE_DEVICE_CHANGE:
                        // might have to handle
                        break;

                    case Event.REMOVE_DEVICE:
                        transitionTo(mDeactivating);
                        break;

                    case Event.DEVICE_REMOVED:
                        //might have to handle
                        break;

                    case Event.STOP_SM:
                        transitionTo(mDeactivating);
                        enabled = false;
                        break;

                    default:
                        return NOT_HANDLED;
                }
                return HANDLED;
            }
        }

        class Gaming extends State {
            int ret;
            @Override
            public void enter() {
                synchronized (this) {
                    mState = mGamingMode;
                }
                if(updatePending) {
                    sendActiveDeviceGamingUpdate(Current);
                }
                if(txStreamSuspended) {
                    mAudioManager.setParameters("A2dpSuspended=false");
                    txStreamSuspended = false;
                }
            }

            @Override
            public void exit() {
            //2 update dependent profiles
                mPrevState = mGamingMode;
                mPrevActiveDevice = Current.Device;
                VolumeManager mVolumeManager = VolumeManager.get();
                if(mVolumeManager != null) {
                    mVolumeManager.saveVolume(mAudioType);
                }
            }

            @Override
            public boolean processMessage(Message message) {
                log("Gaming: Process Message (" + mAudioType + "): "
                        + messageWhatToString(message.what));

                switch(message.what) {
                    case Event.SET_ACTIVE:
                        if(mSHOQueue.device == null) {
                            Log.w(TAG, "Invalid request");
                            break;
                        }
                        if(!mSHOQueue.isUIReq && Current.Device.equals(mSHOQueue.device)) {
                            Log.w(TAG, "Spurious request for same device. Ignore");
                            mSHOQueue.reset();
                            break;
                        }
                        /*MediaAudio mMediaAudio = MediaAudio.get();
                        if(mMediaAudio != null && mMediaAudio.isA2dpPlaying(mSHOQueue.device)) {
                            if(!(mSHOQueue.isBroadcast || mSHOQueue.isRecordingMode)) {
                                Log.w(TAG, "Gaming streaming is on");
                                break;
                            }
                        }*/
                        transitionTo(mActivating);
                        break;

                    case Event.ACTIVE_DEVICE_CHANGE:
                        // might have to handle
                        break;

                    case Event.REMOVE_DEVICE:
                        transitionTo(mDeactivating);
                        break;

                    case Event.DEVICE_REMOVED:
                        //might have to handle
                        break;

                    case Event.STOP_SM:
                        transitionTo(mDeactivating);
                        enabled = false;
                        break;

                    default:
                        return NOT_HANDLED;
                }
                return HANDLED;
            }
        }

        class Broadcasting extends State {
            int ret;
            @Override
            public void enter() {
                synchronized (this) {
                    mState = mBroadcasting;
                }
                if (updatePending) {
                    apmNative.activeDeviceUpdate(Current.Device, Current.Profile, mAudioType);
                    broadcastActiveDeviceChange(Current.Device, AudioType.MEDIA);
                    mAudioManager.avrcpSupportsAbsoluteVolume(Current.Device.getAddress(), false);
                    // Update active device to null in VolumeManager while enter broadcasting state
                    VolumeManager mVolumeManager = VolumeManager.get();
                    if(mVolumeManager != null) {
                        mVolumeManager.onActiveDeviceChange(null,
                                                            ApmConst.AudioFeatures.MEDIA_AUDIO);
                    }
                    int rememberedVolume = 15;
                    mAudioManager.handleBluetoothA2dpActiveDeviceChange(
                            Current.Device, BluetoothProfile.STATE_CONNECTED, BluetoothProfile.A2DP,
                            true, rememberedVolume);
                    updatePending = false;
                }
                if(txStreamSuspended) {
                    mAudioManager.setParameters("A2dpSuspended=false");
                    txStreamSuspended = false;
                }
            }

            @Override
            public void exit() {
                mPrevState = mBroadcasting;
                mPrevActiveDevice = Current.Device;
            }

            @Override
            public boolean processMessage(Message message) {
                log("Broadcasting: Process Message (" + mAudioType + "): "
                        + messageWhatToString(message.what));

                switch(message.what) {
                    case Event.SET_ACTIVE:
                        if(mSHOQueue.isUIReq)
                            transitionTo(mActivating);
                        break;

                    case Event.ACTIVE_DEVICE_CHANGE:
                        break;

                    case Event.REMOVE_DEVICE:
                        if(mSHOQueue.device == null) {
                            transitionTo(mDeactivating);
                        } else {
                            transitionTo(mActivating);
                        }
                        break;

                    case Event.DEVICE_REMOVED:
                        break;

                    case Event.STOP_SM:
                        transitionTo(mDeactivating);
                        enabled = false;
                        break;

                    default:
                        return NOT_HANDLED;
                }
                return HANDLED;
            }
        }

        class Recording extends State {
            int ret;
            @Override
            public void enter() {
                synchronized (this) {
                    mState = mRecordingMode;
                }
                if(updatePending) {
                    sendActiveDeviceRecordingUpdate(Current);
                }
                mRecordingSuspended = false;
            }

            @Override
            public void exit() {
                mPrevState = mRecordingMode;
                mPrevActiveDevice = Current.Device;
                HeadsetService hfpService = HeadsetService.getHeadsetService();

                mAudioManager.handleBluetoothA2dpActiveDeviceChange(
                                        mPrevActiveDevice,
                                        BluetoothProfile.STATE_DISCONNECTED,
                                        BluetoothProfile.A2DP_SINK,
                                        true, -1);
                if(mRecordingSuspended) {
                  mAudioManager.setParameters("A2dpCaptureSuspend=false");
                  mRecordingSuspended = false;
                }
                CallAudio mCallAudio = CallAudio.get();
                boolean isInCall = mCallAudio != null &&
                                   mCallAudio.isVoiceOrCallActive();
                if(isInCall) {
                  Log.d(TAG, " reset txStreamSuspended as call is active" );
                  txStreamSuspended = false;
                }
                VolumeManager mVolumeManager = VolumeManager.get();
                if(mVolumeManager != null) {
                    mVolumeManager.saveVolume(mAudioType);
                }
            }

            @Override
            public boolean processMessage(Message message) {
                log("Recording: Process Message (" + mAudioType + "): "
                        + messageWhatToString(message.what));

                switch(message.what) {
                    case Event.SET_ACTIVE:
                        if (mSHOQueue.device == null) {
                            transitionTo(mDeactivating);
                        } else {
                            transitionTo(mActivating);
                        }
                        break;

                    case Event.ACTIVE_DEVICE_CHANGE:
                        break;

                    case Event.REMOVE_DEVICE:
                        transitionTo(mDeactivating);
                        break;

                    case Event.DEVICE_REMOVED:
                        //might have to handle
                        break;
                    case Event.SUSPEND_RECORDING: {
                        if(mRecordingSuspended) break;
                        mAudioManager.setParameters("A2dpCaptureSuspend=true");
                        mRecordingSuspended = true;
                    } break;

                    case Event.RESUME_RECORDING: {
                        if(!mRecordingSuspended) break;
                        mAudioManager.setParameters("A2dpCaptureSuspend=false");
                        mRecordingSuspended = false;
                    } break;
                    case Event.STOP_SM:
                        transitionTo(mDeactivating);
                        enabled = false;
                        break;

                    default:
                        return NOT_HANDLED;
                }
                return HANDLED;
            }
        }

        void sendActiveDeviceMediaUpdate(DeviceProfileCombo Current) {
            if(Current.Profile == ApmConst.AudioProfiles.HAP_BREDR) {
                if(mPrevActiveDevice != null) {
                    broadcastActiveDeviceChange (null, AudioType.MEDIA );
                    ActiveDeviceManager mDeviceManager = AdapterService.getAdapterService().getActiveDeviceManager();
                    mDeviceManager.onActiveDeviceChange(null, ApmConst.AudioFeatures.MEDIA_AUDIO);
                    mAudioManager.handleBluetoothA2dpActiveDeviceChange(
                                mPrevActiveDevice, BluetoothProfile.STATE_DISCONNECTED,
                                BluetoothProfile.A2DP, true, -1);
                }
                return;
            }
            apmNative.activeDeviceUpdate(Current.Device, Current.Profile, AudioType.MEDIA);
            Log.d(TAG, "sendActiveDeviceMediaUpdate: mPrevActiveDevice: "
                        + mPrevActiveDevice + ", Current.Device: " + Current.Device);

            MediaAudio mMediaAudio = MediaAudio.get();
            mMediaAudio.refreshCurrentCodec(Current.Device);

            broadcastActiveDeviceChange (Current.absoluteDevice, AudioType.MEDIA);
            ActiveDeviceManager mDeviceManager = AdapterService.getAdapterService().getActiveDeviceManager();
            mDeviceManager.onActiveDeviceChange(Current.Device, ApmConst.AudioFeatures.MEDIA_AUDIO);
            if(Current.Profile == ApmConst.AudioProfiles.A2DP) {
                A2dpService mA2dpService = A2dpService.getA2dpService();
                mA2dpService.broadcastActiveCodecConfig();
            }
            //2 Update dependent profiles
            VolumeManager mVolumeManager = VolumeManager.get();
            if(mVolumeManager != null) {
                mVolumeManager.onActiveDeviceChange(Current.Device,
                                                    ApmConst.AudioFeatures.MEDIA_AUDIO);
            }

            McpService mMcpService = McpService.getMcpService();
            if (mMcpService != null) {
                mMcpService.SetActiveDevices(Current.absoluteDevice, Current.Profile);
            }
            int deviceVolume = 7;
            if(mVolumeManager != null) {
                deviceVolume = mVolumeManager.getActiveVolume(ApmConst.AudioFeatures.MEDIA_AUDIO);
            }
            if(mAudioManager != null) {
                mAudioManager.handleBluetoothA2dpActiveDeviceChange(
                        Current.Device, BluetoothProfile.STATE_CONNECTED, BluetoothProfile.A2DP,
                        true, deviceVolume);
            }
            updatePending = false;
        }

        void sendActiveDeviceGamingUpdate(DeviceProfileCombo Current) {
            apmNative.activeDeviceUpdate(Current.Device, Current.Profile, AudioType.MEDIA);

            MediaAudio mMediaAudio = MediaAudio.get();
            mMediaAudio.refreshCurrentCodec(Current.Device);

            broadcastActiveDeviceChange (Current.absoluteDevice, AudioType.MEDIA);
            ActiveDeviceManager mDeviceManager = AdapterService.getAdapterService().getActiveDeviceManager();
            mDeviceManager.onActiveDeviceChange(Current.Device, ApmConst.AudioFeatures.MEDIA_AUDIO);

            //2 Update dependent profiles
            VolumeManager mVolumeManager = VolumeManager.get();
            int deviceVolume = 7;
            if(mVolumeManager != null) {
                mVolumeManager.onActiveDeviceChange(Current.Device,
                                                    ApmConst.AudioFeatures.MEDIA_AUDIO);
                deviceVolume = mVolumeManager.getActiveVolume(ApmConst.AudioFeatures.MEDIA_AUDIO);
            }
            if(mAudioManager != null) {
                mAudioManager.handleBluetoothA2dpActiveDeviceChange(
                        Current.Device, BluetoothProfile.STATE_CONNECTED, BluetoothProfile.A2DP,
                        true, deviceVolume);

                /*Add back channel call here*/
            }
            updatePending = false;
        }

        void sendActiveDeviceVoiceUpdate(DeviceProfileCombo Current) {
            Log.d(TAG, "sendActiveDeviceVoiceUpdate");
            if(Current.Profile == ApmConst.AudioProfiles.HAP_BREDR) {
                if(mPrevActiveDevice != null) {
                    broadcastActiveDeviceChange (null, AudioType.VOICE);
                    ActiveDeviceManager mDeviceManager = AdapterService.getAdapterService().getActiveDeviceManager();
                    mDeviceManager.onActiveDeviceChange(Current.Device, ApmConst.AudioFeatures.CALL_AUDIO);
                }
                return;
            }
            broadcastActiveDeviceChange (Current.absoluteDevice, AudioType.VOICE);
            ActiveDeviceManager mDeviceManager = AdapterService.getAdapterService().getActiveDeviceManager();
            mDeviceManager.onActiveDeviceChange(Current.Device, ApmConst.AudioFeatures.CALL_AUDIO);
            VolumeManager mVolumeManager = VolumeManager.get();
            if(mVolumeManager != null) {
                mVolumeManager.onActiveDeviceChange(Current.Device,
                                                    ApmConst.AudioFeatures.CALL_AUDIO);
            }
            CCService ccService = CCService.getCCService();
            if (ccService != null) {
                ccService.setActiveDevice(Current.absoluteDevice);
            }

            if(mTargetSHO.PlayReq) {
                CallAudio mCallAudio = CallAudio.get();
                mCallAudio.connectAudio();
            }

            updatePending = false;
        }

        void sendActiveDeviceRecordingUpdate(DeviceProfileCombo Current) {
            apmNative.activeDeviceUpdate(Current.Device, Current.Profile, AudioType.MEDIA);

            Log.d(TAG, "sendActiveDeviceRecordingUpdate: mPrevActiveDevice: "
                         + mPrevActiveDevice + ", Current.Device: " + Current.Device);
            MediaAudio mMediaAudio = MediaAudio.get();
            mMediaAudio.refreshCurrentCodec(Current.Device);
            if (mAudioManager != null) {
                mAudioManager.handleBluetoothA2dpActiveDeviceChange(Current.Device,
                        BluetoothProfile.STATE_CONNECTED, BluetoothProfile.A2DP_SINK, false, -1); // TO-Check
            }
            updatePending = false;
        }

        boolean isSameProfile (int p1, int p2, int audioType) {
            if(p1 == p2) {
                return true;
            }

            if(audioType == AudioType.MEDIA) {
                int leMediaMask = ApmConst.AudioProfiles.TMAP_MEDIA |
                                  ApmConst.AudioProfiles.BAP_MEDIA |
                                  ApmConst.AudioProfiles.BAP_RECORDING |
                                  ApmConst.AudioProfiles.BAP_GCP;
                if((leMediaMask & p1) > 0 && (leMediaMask & p2) > 0) {
                    return true;
                }
            } else if(audioType == AudioType.VOICE) {
                int leVoiceMask = ApmConst.AudioProfiles.TMAP_CALL | ApmConst.AudioProfiles.BAP_CALL;
                if((leVoiceMask & p1) > 0 && (leVoiceMask & p2) > 0) {
                    return true;
                }
            }

            return false;
        }
    }

    static class AudioType {
        public static int VOICE = ApmConst.AudioFeatures.CALL_AUDIO;
        public static int MEDIA = ApmConst.AudioFeatures.MEDIA_AUDIO;

        public static int SIZE = 2;
    }

    private class SHOReq {
        BluetoothDevice device;
        boolean PlayReq;
        int retryCount;
        boolean isBroadcast;
        boolean isGamingMode;
        boolean isRecordingMode;
        boolean isUIReq;
        boolean forceStopAudio;

        void copy(SHOReq src) {
            device = src.device;
            PlayReq = src.PlayReq;
            retryCount = src.retryCount;
            isBroadcast = src.isBroadcast;
            isGamingMode = src.isGamingMode;
            isRecordingMode = src.isRecordingMode;
            isUIReq = src.isUIReq;
            forceStopAudio = src.forceStopAudio;
        }

        void reset() {
            device = null;
            PlayReq = false;
            retryCount = 0;
            isBroadcast = false;
            isGamingMode = false;
            isRecordingMode = false;
            isUIReq = false;
            forceStopAudio = false;
        }
    }
}
