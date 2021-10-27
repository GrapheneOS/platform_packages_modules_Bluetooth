/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


package com.android.bluetooth.apm;

import static com.android.bluetooth.Utils.enforceBluetoothPermission;
import static com.android.bluetooth.Utils.enforceBluetoothPrivilegedPermission;

import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothCodecStatus;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.IBluetoothVcp;

import android.os.Binder;
import android.os.HandlerThread;
import android.os.Handler;
import android.os.Message;
import android.os.SystemProperties;
import android.util.Log;

import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.acm.AcmService;

public class StreamAudioService extends ProfileService {
    private static final boolean DBG = true;
    private static final String TAG = "APM: StreamAudioService:";
    public static final int LE_AUDIO_UNICAST = 26;

    public static final String CoordinatedAudioServiceName = "com.android.bluetooth.acm.AcmService";
    public static final int COORDINATED_AUDIO_UNICAST = AcmService.ACM_AUDIO_UNICAST;

    private static StreamAudioService sStreamAudioService;
    private ActiveDeviceManagerService mActiveDeviceManager;
    private MediaAudio mMediaAudio;
    private VolumeManager mVolumeManager;
    private final Object mVolumeManagerLock = new Object();
    @Override
    protected void create() {
        Log.i(TAG, "create()");
    }

    private static final int BAP       = 0x01;
    private static final int GCP       = 0x02;
    private static final int WMCP      = 0x04;
    private static final int VMCP      = 0x08;
    private static final int BAP_CALL  = 0x10;

    private static final int MEDIA_CONTEXT = 1;
    private static final int VOICE_CONTEXT = 2;

    @Override
    protected boolean start() {
        if(sStreamAudioService != null) {
            Log.i(TAG, "StreamAudioService already started");
            return true;
        }
        Log.i(TAG, "start()");

        ApmConst.setLeAudioEnabled(true);
        ApmConstIntf.init();

        setStreamAudioService(this);

        mActiveDeviceManager = ActiveDeviceManagerService.get(this);
        mMediaAudio = MediaAudio.init(this);

        DeviceProfileMap dpm = DeviceProfileMap.getDeviceProfileMapInstance();
        dpm.init(this);
        CallAudio mCallAudio = CallAudio.init(this);
        synchronized (mVolumeManagerLock) {
            mVolumeManager = VolumeManager.init(this);
        }

        Log.i(TAG, "start() complete");
        return true;
    }

    @Override
    protected boolean stop() {
        Log.w(TAG, "stop() called");
        if (sStreamAudioService == null) {
            Log.w(TAG, "stop() called before start()");
            return true;
        }

        if (mActiveDeviceManager != null) {
            mActiveDeviceManager.disable();
            mActiveDeviceManager.cleanup();
        }

        DeviceProfileMap dMap = DeviceProfileMap.getDeviceProfileMapInstance();
        dMap.cleanup();
        return true;
    }

    @Override
    protected void cleanup() {
        Log.i(TAG, "cleanup()");
        synchronized (mVolumeManagerLock) {
            mVolumeManager.cleanup();
            mVolumeManager = null;
        }
        setStreamAudioService(null);
    }

    public boolean connectLeStream(BluetoothDevice device, int profile) {
        AcmService mAcmService = AcmService.getAcmService();
        int mContext = getContext(profile);

        if(mContext == 0) {
            Log.e(TAG, "No valid context for profiles passed");
            return false;
        }
        return mAcmService.connect(device, mContext, getAcmProfileID(profile), MEDIA_CONTEXT);
        //return mAcmService.connect(device, VOICE_CONTEXT, BAP_CALL, VOICE_CONTEXT);
        //return mAcmService.connect(device, MEDIA_CONTEXT, BAP|WMCP, MEDIA_CONTEXT);
    }

    public boolean disconnectLeStream(BluetoothDevice device, boolean callAudio, boolean mediaAudio) {
        AcmService mAcmService = AcmService.getAcmService();
        if(callAudio && mediaAudio)
            return mAcmService.disconnect(device, VOICE_CONTEXT | MEDIA_CONTEXT);
            //return mAcmService.disconnect(device, VOICE_CONTEXT);
            //return mAcmService.disconnect(device, MEDIA_CONTEXT);
        else if(mediaAudio)
            return mAcmService.disconnect(device, MEDIA_CONTEXT);
        else if(callAudio)
            return mAcmService.disconnect(device, VOICE_CONTEXT);

        return false;
    }

    public boolean startStream(BluetoothDevice device) {
        AcmService mAcmService = AcmService.getAcmService();
        return mAcmService.StartStream(device, VOICE_CONTEXT);
    }

    public boolean stopStream(BluetoothDevice device) {
        AcmService mAcmService = AcmService.getAcmService();
        return mAcmService.StopStream(device, VOICE_CONTEXT);
    }

    public int setActiveDevice(BluetoothDevice device, int profile, boolean playReq) {
        AcmService mAcmService = AcmService.getAcmService();
        if (mAcmService == null && device == null) {
            Log.w(TAG, ": device is null, fake success.");
            return mActiveDeviceManager.SHO_SUCCESS;
        }

        if(ApmConst.AudioProfiles.BAP_MEDIA == profile) {
            return mAcmService.setActiveDevice(device, MEDIA_CONTEXT, BAP, playReq);
        } else if(ApmConst.AudioProfiles.BAP_GCP == profile){
            return mAcmService.setActiveDevice(device, MEDIA_CONTEXT, GCP, playReq);
        } else if(ApmConst.AudioProfiles.BAP_RECORDING == profile){
            return mAcmService.setActiveDevice(device, MEDIA_CONTEXT, WMCP, playReq);
        } else {
            return mAcmService.setActiveDevice(device, VOICE_CONTEXT, BAP_CALL, playReq);
            //return mAcmService.setActiveDevice(device, MEDIA_CONTEXT, BAP, playReq);
        }
    }

    public void setCodecConfig(BluetoothDevice device, String codecID, int channelMode) {
        AcmService mAcmService = AcmService.getAcmService();
        mAcmService.ChangeCodecConfigPreference(device, codecID);
    }

    public BluetoothDevice getDeviceGroup(BluetoothDevice device){
        AcmService mAcmService = AcmService.getAcmService();
        return mAcmService.getGroup(device);
    }

    public void onConnectionStateChange(BluetoothDevice device, int state, int audioType, boolean primeDevice) {
        MediaAudio mMediaAudio = MediaAudio.get();
        CallAudio mCallAudio = CallAudio.get();
        int profile = ApmConst.AudioFeatures.MAX_AUDIO_FEATURES;
        if(audioType == ApmConst.AudioFeatures.CALL_AUDIO) {
            mCallAudio.onConnStateChange(device, state, ApmConst.AudioProfiles.BAP_CALL);
        } else if(audioType == ApmConst.AudioFeatures.MEDIA_AUDIO) {
            boolean isCsipDevice = (device != null) &&
                        getDeviceGroup(device).getAddress().contains(ApmConst.groupAddress);
            if(isCsipDevice)
                mMediaAudio.onConnStateChange(device, state, ApmConst.AudioProfiles.BAP_MEDIA, primeDevice);
            else
                mMediaAudio.onConnStateChange(device, state, ApmConst.AudioProfiles.BAP_MEDIA);
        }
    }

    public void onStreamStateChange(BluetoothDevice device, int state, int audioType) {
        MediaAudio mMediaAudio = MediaAudio.get();
        CallAudio mCallAudio = CallAudio.get();
        if(audioType == ApmConst.AudioFeatures.MEDIA_AUDIO)
            mMediaAudio.onStreamStateChange(device, state);
        else if(audioType == ApmConst.AudioFeatures.CALL_AUDIO)
             mCallAudio.onAudioStateChange(device, state);
    }

    public void onActiveDeviceChange(BluetoothDevice device, int audioType) {
        if (mActiveDeviceManager != null)
            mActiveDeviceManager.onActiveDeviceChange(device, audioType);
    }

    public void onMediaCodecConfigChange(BluetoothDevice device, BluetoothCodecStatus codecStatus, int audioType) {
        MediaAudio mMediaAudio = MediaAudio.get();
        mMediaAudio.onCodecConfigChange(device, codecStatus, ApmConst.AudioProfiles.BAP_MEDIA);
    }

    public void onMediaCodecConfigChange(BluetoothDevice device, BluetoothCodecStatus codecStatus, int audioType, boolean updateAudio) {
        MediaAudio mMediaAudio = MediaAudio.get();
        mMediaAudio.onCodecConfigChange(device, codecStatus, ApmConst.AudioProfiles.BAP_MEDIA, updateAudio);
    }

    public void setCallAudioParam(String param) {
        CallAudio mCallAudio = CallAudio.get();
        mCallAudio.setAudioParam(param);
    }

    public void setCallAudioOn(boolean on) {
        CallAudio mCallAudio = CallAudio.get();
        mCallAudio.setBluetoothScoOn(on);
    }

    public int getVcpConnState(BluetoothDevice device) {
        synchronized (mVolumeManagerLock) {
            if (mVolumeManager == null)
                return BluetoothProfile.STATE_DISCONNECTED;
            return mVolumeManager.getConnectionState(device);
        }
    }

    public int getConnectionMode(BluetoothDevice device) {
        synchronized (mVolumeManagerLock) {
            if (mVolumeManager == null)
                return BluetoothProfile.STATE_DISCONNECTED;
            return mVolumeManager.getConnectionMode(device);
        }
    }

    public void setAbsoluteVolume(BluetoothDevice device, int volume) {
        synchronized (mVolumeManagerLock) {
            if (mVolumeManager != null)
                mVolumeManager.updateBroadcastVolume(device, volume);
        }
    }

    public int getAbsoluteVolume(BluetoothDevice device) {
        synchronized (mVolumeManagerLock) {
            if (mVolumeManager == null)
                return 7;
            return mVolumeManager.getBassVolume(device);
        }
    }

    public void setMute(BluetoothDevice device, boolean muteStatus) {
        synchronized (mVolumeManagerLock) {
            if (mVolumeManager != null)
                mVolumeManager.setMute(device, muteStatus);
        }
    }

    public boolean isMute(BluetoothDevice device) {
        synchronized (mVolumeManagerLock) {
            if (mVolumeManager == null)
                return false;
            return mVolumeManager.getMuteStatus(device);
        }
    }

    private int getContext(int profileID) {
        int context = 0;
        if((DeviceProfileMap.getLeMediaProfiles() & profileID) > 0) {
            context = (context|MEDIA_CONTEXT);
        }

        if((DeviceProfileMap.getLeCallProfiles() & profileID) > 0) {
            context = (context|VOICE_CONTEXT);
        }
        return context;
    }

    private int getAcmProfileID (int ProfileID) {
        int AcmProfileID = 0;
        if((ApmConst.AudioProfiles.BAP_MEDIA & ProfileID) == ApmConst.AudioProfiles.BAP_MEDIA)
            AcmProfileID = BAP;
        if((ApmConst.AudioProfiles.BAP_CALL & ProfileID) == ApmConst.AudioProfiles.BAP_CALL)
            AcmProfileID = AcmProfileID | BAP_CALL;
        if((ApmConst.AudioProfiles.BAP_GCP & ProfileID) == ApmConst.AudioProfiles.BAP_GCP)
            AcmProfileID = AcmProfileID | GCP;
        if((ApmConst.AudioProfiles.BAP_RECORDING & ProfileID) == ApmConst.AudioProfiles.BAP_RECORDING)
            AcmProfileID = AcmProfileID | WMCP;
        return AcmProfileID;
    }

    @Override
    protected IProfileServiceBinder initBinder() {
        return new LeAudioUnicastBinder(this);
    }

    private static class LeAudioUnicastBinder extends IBluetoothVcp.Stub implements IProfileServiceBinder {

        StreamAudioService mService;
        LeAudioUnicastBinder(StreamAudioService service) {
            mService = service;
        }

        @Override
        public void cleanup() {
        }

        @Override
        public int getConnectionState(BluetoothDevice device) {
            if(mService == null)
                return BluetoothProfile.STATE_DISCONNECTED;
            return mService.getVcpConnState(device);
        }

        @Override
        public int getConnectionMode(BluetoothDevice device) {
            if(mService != null) {
                return mService.getConnectionMode(device);
            }
            return 0;
        }

        @Override
        public void setAbsoluteVolume(BluetoothDevice device, int volume) {
            if(mService != null) {
                mService.setAbsoluteVolume(device, volume);
            }
        }

        @Override
        public int getAbsoluteVolume(BluetoothDevice device) {
            if(mService == null)
                return 7;
            return mService.getAbsoluteVolume(device);
        }

        @Override
        public void setMute (BluetoothDevice device, boolean enableMute) {
            if(mService != null) {
                mService.setMute(device, enableMute);
            }
        }

        @Override
        public boolean isMute(BluetoothDevice device) {
            if(mService != null) {
                return mService.isMute(device);
            }
            return false;
        }
    }

    public static StreamAudioService getStreamAudioService() {
        return sStreamAudioService;
    }

    private static synchronized void setStreamAudioService(StreamAudioService instance) {
        if (DBG) {
            Log.d(TAG, "setStreamAudioService(): set to: " + instance);
        }
        sStreamAudioService = instance;
    }
}
