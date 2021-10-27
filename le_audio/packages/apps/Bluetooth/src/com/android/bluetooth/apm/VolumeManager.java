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

import android.bluetooth.BleBroadcastAudioScanAssistManager;
import android.bluetooth.BleBroadcastSourceInfo;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothHeadset;
import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.avrcp.Avrcp_ext;
import com.android.bluetooth.acm.AcmService;
import com.android.bluetooth.bc.BCService;
import com.android.bluetooth.hfp.HeadsetService;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.media.AudioManager;
import android.util.Log;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.List;
import java.util.Map;

public class VolumeManager {
    public static final String TAG = "APM: VolumeManager";
    private static VolumeManager mVolumeManager = null;
    private DeviceVolume mMedia;
    private DeviceVolume mCall;
    private DeviceVolume mBroadcast;
    private DeviceProfileMap dpm;
    private MediaAudio mMediaAudio;
    private CallAudio mCallAudio;
    private static Context mContext;
    BroadcastReceiver mVolumeManagerReceiver;
    Map<String, Integer> AbsVolumeSupport;

    public static final String CALL_VOLUME_MAP = "bluetooth_call_volume_map";
    public static final String MEDIA_VOLUME_MAP = "bluetooth_media_volume_map";
    public static final String BROADCAST_VOLUME_MAP = "bluetooth_broadcast_volume_map";
    public final String ACTION_SHUTDOWN = "android.intent.action.ACTION_SHUTDOWN";
    public final String ACTION_POWER_OFF = "android.intent.action.QUICKBOOT_POWEROFF";

    private VolumeManager() {
        mCall = new DeviceVolume(mContext, CALL_VOLUME_MAP);
        mMedia = new DeviceVolume(mContext, MEDIA_VOLUME_MAP);
        mBroadcast = new DeviceVolume(mContext, BROADCAST_VOLUME_MAP);

        dpm = DeviceProfileMap.getDeviceProfileMapInstance();
        mMediaAudio = MediaAudio.get();
        mCallAudio = CallAudio.get();

        AbsVolumeSupport = new ConcurrentHashMap<String, Integer>();

        mVolumeManagerReceiver = new VolumeManagerReceiver();
        IntentFilter filter = new IntentFilter();
        filter.addAction(AudioManager.VOLUME_CHANGED_ACTION);
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        filter.addAction(ACTION_SHUTDOWN);
        filter.addAction(ACTION_POWER_OFF);
        filter.addAction(BleBroadcastAudioScanAssistManager.ACTION_BROADCAST_SOURCE_INFO);
        mContext.registerReceiver(mVolumeManagerReceiver, filter);
    }

    public static VolumeManager init (Context context) {
        mContext = context;

        if(mVolumeManager == null) {
            mVolumeManager = new VolumeManager();
            VolumeManagerIntf.init(mVolumeManager);
        }

        return mVolumeManager;
    }

    public void cleanup() {
        Log.i(TAG, "cleanup");
        handleDeviceShutdown();
        synchronized (mVolumeManager) {
            mCall = null;
            mMedia = null;
            mBroadcast = null;
            mContext.unregisterReceiver(mVolumeManagerReceiver);
            mVolumeManagerReceiver = null;
            AbsVolumeSupport.clear();
            AbsVolumeSupport = null;
            mVolumeManager = null;
        }
    }

    public static VolumeManager get() {
        return mVolumeManager;
    }

    private DeviceVolume VolumeType(int mAudioType) {
        if(ApmConst.AudioFeatures.CALL_AUDIO == mAudioType) {
            return mCall;
        } else if(ApmConst.AudioFeatures.MEDIA_AUDIO == mAudioType) {
            return mMedia;
        } else if(ApmConst.AudioFeatures.BROADCAST_AUDIO == mAudioType) {
            return mBroadcast;
        }
        return null;
    }

    public int getConnectionMode(BluetoothDevice device) {
        AcmService mAcmService = AcmService.getAcmService();
        if(mAcmService == null) {
            return -1;
        }
        return mAcmService.getVcpConnMode(device);
    }

    public void setMediaAbsoluteVolume (Integer volume) {
        if(mMedia.mDevice == null) {
            Log.e (TAG, "setMediaAbsoluteVolume: No Device Active for Media. Ignore");
            return;
        }
        mMedia.updateVolume(volume);

        if(ApmConst.AudioProfiles.AVRCP == mMedia.mProfile) {
            Avrcp_ext mAvrcp = Avrcp_ext.get();
            if(mAvrcp != null) {
                Log.i (TAG, "setMediaAbsoluteVolume: Updating new volume to AVRCP: " + volume);
                mAvrcp.setAbsoluteVolume(volume);
            }
        } else if(ApmConst.AudioProfiles.VCP == mMedia.mProfile) {
            AcmService mAcmService = AcmService.getAcmService();
            if(mAcmService != null) {
                Log.i (TAG, "setMediaAbsoluteVolume: Updating new volume to VCP: " + volume);
                mMedia.updateVolume(volume);
                mAcmService.setAbsoluteVolume(mMedia.mDevice, volume, ApmConst.AudioFeatures.MEDIA_AUDIO);
            }
        }
    }

    public void updateMediaStreamVolume (Integer volume) {
        if(mMedia.mDevice == null) {
            Log.e (TAG, "updateMediaStreamVolume: No Device Active for Media. Ignore");
            return;
        }

        if(mMedia.mSupportAbsoluteVolume) {
            /* Ignore: Will update volume via API call */
            return;
        }
        mMedia.updateVolume(volume);
    }

    public void updateBroadcastVolume (BluetoothDevice device, int volume) {
        int callAudioState = mCallAudio.getAudioState(device);
        boolean isCall = (callAudioState == BluetoothHeadset.STATE_AUDIO_CONNECTING ||
                 callAudioState == BluetoothHeadset.STATE_AUDIO_CONNECTED);
        if (isCall) {
            Log.e(TAG, "Call in progress, ignore volume change");
            return;
        }

        mBroadcast.updateVolume(device, volume);
        AcmService mAcmService = AcmService.getAcmService();
        BluetoothDevice mGroupDevice = mAcmService.getGroup(device);
        mAcmService.setAbsoluteVolume(mGroupDevice, volume, ApmConst.AudioFeatures.BROADCAST_AUDIO);
        mBroadcast.updateVolume(mGroupDevice, volume);
    }

    public void setMute(BluetoothDevice device, boolean muteStatus) {
        AcmService mAcmService = AcmService.getAcmService();
        BluetoothDevice mGroupDevice = mAcmService.getGroup(device);
        mAcmService.setMute(mGroupDevice, muteStatus);
    }

    public void restoreCallVolume (Integer volume) {
        if(mCall.mDevice == null) {
            Log.e (TAG, "restoreCallVolume: No Device Active for Call. Ignore");
            return;
        }

        if(ApmConst.AudioProfiles.HFP == mCall.mProfile) {
            // Ignore restoring call volume for HFP case
            Log.w (TAG, "restoreCallVolume: Ignore restore call volume for HFP");
        } else if(ApmConst.AudioProfiles.VCP == mCall.mProfile) {
            AcmService mAcmService = AcmService.getAcmService();
            if(mAcmService != null) {
                Log.i (TAG, "restoreCallVolume: Updating new volume to VCP: " + volume);
                mCall.updateVolume(volume);
                mAcmService.setAbsoluteVolume(mCall.mDevice, volume, ApmConst.AudioFeatures.CALL_AUDIO);
            }
            // TODO: Restore call volume to MM-Audio also
        }
    }

    public void setCallVolume (Intent intent) {
        if(mCall.mDevice == null) {
            Log.e (TAG, "setCallVolume: No Device Active for Call. Ignore");
            return;
        }

        int volume = intent.getIntExtra(AudioManager.EXTRA_VOLUME_STREAM_VALUE, 0);
        if(ApmConst.AudioProfiles.HFP == mCall.mProfile) {
            Log.i (TAG, "setCallVolume: Updating new volume to HFP: " + volume);
            HeadsetService headsetService = HeadsetService.getHeadsetService();
            headsetService.setIntentScoVolume(intent);
        } else if(ApmConst.AudioProfiles.VCP == mCall.mProfile) {
            Log.i (TAG, "setCallVolume: mCall volume: " + mCall.mVolume + ", volume: " + volume);
            // Avoid updating same call volume after remote volume change
            if (volume == mCall.mVolume) {
                Log.w (TAG, "setCallVolume: Ignore updating same call volume to remote");
                return;
            }
            AcmService mAcmService = AcmService.getAcmService();
            if(mAcmService != null) {
                Log.i (TAG, "setCallVolume: Updating new volume to VCP: " + volume);
                mCall.updateVolume(volume);
                mAcmService.setAbsoluteVolume(mCall.mDevice, volume, ApmConst.AudioFeatures.CALL_AUDIO);
            }
        }
    }

    public int getConnectionState(BluetoothDevice device) {
        AcmService mAcmService = AcmService.getAcmService();
        return mAcmService.getVcpConnState(device);
    }

    public void onConnStateChange(BluetoothDevice device, Integer state, Integer profile) {
        Log.d (TAG, "onConnStateChange: state: " + state + " Profile: " + profile);
        if (device == null) {
            Log.e (TAG, "onConnStateChange: device is null. Ignore");
            return;
        }

        AcmService mAcmService = AcmService.getAcmService();
        BluetoothDevice mGroupDevice;
        if(mAcmService != null) {
            mGroupDevice = mAcmService.getGroup(device);
        } else {
            mGroupDevice = device;
        }

        if (mGroupDevice.equals(mMedia.mDevice)) {
            mMedia.mProfile =
                    dpm.getProfile(mGroupDevice, ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL);
        }
        if (mGroupDevice.equals(mCall.mDevice)) {
            mCall.mProfile =
                    dpm.getProfile(mGroupDevice, ApmConst.AudioFeatures.CALL_VOLUME_CONTROL);
        }

        if (state == BluetoothProfile.STATE_CONNECTED) {
            int audioType = getActiveAudioType(device);
            if (ApmConst.AudioFeatures.MEDIA_AUDIO == audioType && mMedia.mProfile == profile) {
                Log.d (TAG, "onConnStateChange: Media is streaming or active, update media volume");
                setMediaAbsoluteVolume(mMedia.mVolume);
            } else if (ApmConst.AudioFeatures.CALL_AUDIO == audioType &&
                    mCall.mProfile == profile) {
                Log.d (TAG, "onConnStateChange: Call is streaming, update call volume");
                restoreCallVolume(mCall.mVolume);
            } else if (ApmConst.AudioFeatures.BROADCAST_AUDIO == audioType) {
                Log.d (TAG, "onConnStateChange: Broadcast is streaming, update broadcast volume");
                updateBroadcastVolume(device, getBassVolume(device));
            }
        }
    }

    public void onVolumeChange(Integer volume, Integer audioType, Boolean showUI) {
        int flag = showUI ? AudioManager.FLAG_SHOW_UI : 0;
        if(audioType == ApmConst.AudioFeatures.CALL_AUDIO){
            mCall.updateVolume(volume);
            mCallAudio.getAudioManager().setStreamVolume(AudioManager.STREAM_BLUETOOTH_SCO,
                    volume, flag);
        } else if(audioType == ApmConst.AudioFeatures.MEDIA_AUDIO) {
            mMedia.updateVolume(volume);
            mMediaAudio.getAudioManager().setStreamVolume(AudioManager.STREAM_MUSIC, volume,
                    flag | AudioManager.FLAG_BLUETOOTH_ABS_VOLUME);
        }
    }

    public void onVolumeChange(BluetoothDevice device, Integer volume, Integer audioType) {
        if ((VolumeType(audioType) == mCall && device.equals(mCall.mDevice)) ||
            (VolumeType(audioType) == mMedia && device.equals(mMedia.mDevice))) {
            onVolumeChange(volume, audioType, true);
        } else {
            mBroadcast.updateVolume(device, volume);
        }
    }

    public void onMuteStatusChange(BluetoothDevice device, boolean isMute, int audioType) {
    }


    public void onActiveDeviceChange(BluetoothDevice device, int audioType) {
        if(device == null) {
            synchronized(mVolumeManager) {
                if(VolumeType(audioType) != null)
                    VolumeType(audioType).reset();
            }
        } else {
            int mProfile = dpm.getProfile(device, audioType == ApmConst.AudioFeatures.CALL_AUDIO?
                    ApmConst.AudioFeatures.CALL_VOLUME_CONTROL:ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL);
            DeviceVolume mDeviceVolume = VolumeType(audioType);
            mDeviceVolume.updateDevice(device, mProfile);
            Log.i(TAG, "ActiveDeviceChange: device: " + mDeviceVolume.mDevice + ". AudioType: " + audioType);
            if(mDeviceVolume.equals(mMedia)) {
                int mAbsVolSupportProfiles = AbsVolumeSupport.getOrDefault(device.getAddress(), 0);
                boolean isAbsSupported = ((mProfile & mAbsVolSupportProfiles) != 0) ? true : false;
                Log.i(TAG, "isAbsoluteVolumeSupport:  " + isAbsSupported);
                mDeviceVolume.mSupportAbsoluteVolume = isAbsSupported;
                mMediaAudio.getAudioManager().avrcpSupportsAbsoluteVolume (
                        device.getAddress(), isAbsSupported);

                Log.i(TAG, "ActiveDeviceChange: Profile: " + mProfile + ". New Volume: " + mDeviceVolume.mVolume);
                if (!isBroadcastAudioSynced(device) ||
                    (mMediaAudio.isA2dpPlaying(device) && mMediaAudio.getAudioManager().isMusicActive())) {
                    setMediaAbsoluteVolume(mDeviceVolume.mVolume);
                }
            }
        }
    }

    public void updateStreamState(BluetoothDevice device, Integer streamState, Integer audioType) {
        boolean isMusicActive = false;
        if (device == null) {
            Log.e (TAG, "updateStreamState: device is null. Ignore");
            return;
        }
        if (audioType == ApmConst.AudioFeatures.MEDIA_AUDIO &&
            streamState == BluetoothA2dp.STATE_PLAYING) {
            isMusicActive = mMediaAudio.getAudioManager().isMusicActive();
        }
        Log.d(TAG, "updateStreamState, device: " + device + " type: " + audioType
                + " streamState: " + streamState + " isMusicActive: " + isMusicActive);

        AcmService mAcmService = AcmService.getAcmService();
        BluetoothDevice mGroupDevice;
        if(mAcmService != null) {
            mGroupDevice = mAcmService.getGroup(device);
        } else {
            mGroupDevice = device;
        }

        if ((audioType == ApmConst.AudioFeatures.MEDIA_AUDIO &&
                streamState == BluetoothA2dp.STATE_NOT_PLAYING) ||
                (audioType == ApmConst.AudioFeatures.CALL_AUDIO &&
                streamState == BluetoothHeadset.STATE_AUDIO_DISCONNECTED)) {
            if (isBroadcastAudioSynced(device)) {
                handleBroadcastAudioSynced(device);
            }
        } else if (audioType == ApmConst.AudioFeatures.MEDIA_AUDIO &&
                streamState == BluetoothA2dp.STATE_PLAYING && isMusicActive) {
            if (mGroupDevice.equals(mMedia.mDevice)) {
                Log.d(TAG, "Restore volume for A2dp streaming");
                setMediaAbsoluteVolume(mMedia.mVolume);
            }
        } else if (audioType == ApmConst.AudioFeatures.CALL_AUDIO &&
                streamState == BluetoothHeadset.STATE_AUDIO_CONNECTED) {
            if (mGroupDevice.equals(mCall.mDevice)) {
                Log.d(TAG, "Restore volume for call");
                restoreCallVolume(mCall.mVolume);
            }
        }
    }

    public int getActiveAudioType(BluetoothDevice device) {
        int callAudioState = mCallAudio.getAudioState(device);
        boolean isCall = (callAudioState == BluetoothHeadset.STATE_AUDIO_CONNECTING ||
                 callAudioState == BluetoothHeadset.STATE_AUDIO_CONNECTED);
        int audioType = -1;

        if (device == null) {
            Log.e (TAG, "getActiveAudioType: device is null. Ignore");
            return audioType;
        }

        AcmService mAcmService = AcmService.getAcmService();
        BluetoothDevice mGroupDevice;
        if(mAcmService != null) {
            mGroupDevice = mAcmService.getGroup(device);
        } else {
            mGroupDevice = device;
        }

        if (mMediaAudio.isA2dpPlaying(device) &&
                mMediaAudio.getAudioManager().isMusicActive()) {
            if (mGroupDevice.equals(mMedia.mDevice)) {
                Log.d(TAG, "Active Media audio is streaming");
                audioType = ApmConst.AudioFeatures.MEDIA_AUDIO;
            }
        } else if (isCall) {
            if (mGroupDevice.equals(mCall.mDevice)) {
                Log.d(TAG, "Active Call audio is streaming");
                audioType = ApmConst.AudioFeatures.CALL_AUDIO;
            }
        } else if (isBroadcastAudioSynced(device)) {
            Log.d(TAG, "Broadcast audio is streaming");
            audioType = ApmConst.AudioFeatures.BROADCAST_AUDIO;
        } else {
            Log.d(TAG, "None of audio is streaming");
            ActiveDeviceManagerService activeDeviceManager =
                    ActiveDeviceManagerService.get(mContext);
            BluetoothDevice activeDevice =
                    activeDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);
            if (mGroupDevice.equals(mMedia.mDevice) && mGroupDevice.equals(activeDevice)) {
                Log.d(TAG, "Peer is Media active, set for media type by default");
                audioType = ApmConst.AudioFeatures.MEDIA_AUDIO;
            } else {
                Log.d(TAG, "Inactive peer, unknow audio type");
            }
        }

        Log.d(TAG, "getActiveAudioType: ret " + audioType);
        return audioType;
    }

    /*Should be called by AVRCP and VCP after every connection*/
    public void setAbsoluteVolumeSupport(BluetoothDevice device, Boolean isSupported,
            Integer initVol, Integer profile) {
        setAbsoluteVolumeSupport(device, isSupported, profile);
    }

    public void setAbsoluteVolumeSupport(BluetoothDevice device, Boolean isSupported,
            Integer profile) {
        Log.i(TAG, "setAbsoluteVolumeSupport device " + device + " profile " + profile
                + " isSupported " + isSupported);
        if(device == null)
            return;

        int mProfile = dpm.getProfile(device, ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL);
        int mAbsVolSupportProfiles = AbsVolumeSupport.getOrDefault(device.getAddress(), 0);
        if (isSupported) {
            mAbsVolSupportProfiles = mAbsVolSupportProfiles | profile;
        } else {
            mAbsVolSupportProfiles = mAbsVolSupportProfiles & ~profile;
        }

        if(device.equals(mMedia.mDevice)) {
            boolean isAbsSupported = ((mProfile & mAbsVolSupportProfiles) != 0) ? true : false;
            Log.i(TAG, "Update abs volume support:  " + isAbsSupported);
            mMedia.mSupportAbsoluteVolume = isAbsSupported;
            mMediaAudio.getAudioManager().avrcpSupportsAbsoluteVolume (
                    device.getAddress(), isAbsSupported);

            if(mMedia.mProfile == ApmConst.AudioProfiles.NONE) {
                mMedia.mProfile = mProfile;
                Log.i(TAG, "setAbsoluteVolumeSupport: Profile: " + mMedia.mProfile);
            }
        }
        AbsVolumeSupport.put(device.getAddress(), mAbsVolSupportProfiles);
    }

    public void saveVolume(Integer audioType) {
        VolumeType(audioType).saveVolume();
    }

    public int getSavedVolume(BluetoothDevice device, Integer audioType) {
        return VolumeType(audioType).getSavedVolume(device);
    }

    public int getActiveVolume(Integer audioType) {
        return VolumeType(audioType).mVolume;
    }

    public int getBassVolume(BluetoothDevice device) {
        AcmService mAcmService = AcmService.getAcmService();
        BluetoothDevice mGroupDevice = mAcmService.getGroup(device);
        int volume = mBroadcast.getVolume(mGroupDevice);
        Log.i(TAG, "getBassVolume: " + device + " volume: " + volume);
        return volume;
    }

    public boolean getMuteStatus(BluetoothDevice device) {
        AcmService mAcmService = AcmService.getAcmService();
        if(mAcmService == null) {
            return false;
        }
        return mAcmService.isVcpMute(device);
    }

    boolean isBroadcastAudioSynced(BluetoothDevice device) {
        BCService mBCService = BCService.getBCService();
        if (mBCService == null || device == null) return false;
        List<BleBroadcastSourceInfo> srcInfos =
                mBCService.getAllBroadcastSourceInformation(device);
        if (srcInfos == null || srcInfos.size() == 0) {
            Log.e(TAG, "source Infos not available");
            return false;
        }

        for (int i=0; i<srcInfos.size(); i++) {
            if (srcInfos.get(i).getAudioSyncState() ==
                    BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED) {
                Log.d(TAG, "Remote synced audio to broadcast source");
                return true;
            }
        }
        return false;
    }

    void handleBroadcastAudioSynced(BluetoothDevice device) {
        if (device == null) {
            return;
        }

        AcmService mAcmService = AcmService.getAcmService();
        BluetoothDevice mGroupDevice;
        if(mAcmService != null) {
            mGroupDevice = mAcmService.getGroup(device);
        } else {
            mGroupDevice = device;
        }

        int callAudioState = mCallAudio.getAudioState(device);
        boolean isCall = (callAudioState == BluetoothHeadset.STATE_AUDIO_CONNECTING ||
                callAudioState == BluetoothHeadset.STATE_AUDIO_CONNECTED);

        if (mGroupDevice.equals(mMedia.mDevice) && mMediaAudio.isA2dpPlaying(device)) {
            Log.d (TAG, "Active media device and streaming, not restore broadcast volume");
        } else if (mGroupDevice.equals(mCall.mDevice) && isCall) {
            Log.d (TAG, "Active call device and in call, not restore broadcast volume");
        } else {
            Log.d (TAG, "Restore broadcast volume while remote synced audio");
            updateBroadcastVolume(device, getBassVolume(device));
        }
    }

    void handleDeviceUnbond(BluetoothDevice device) {
        if(device == mCall.mDevice) {
            mCall.reset();
        }
        if(device == mMedia.mDevice) {
            mMedia.reset();
        }

        mCall.removeDevice(device);
        mMedia.removeDevice(device);
        mBroadcast.removeDevice(device);
    }

    void handleDeviceShutdown() {
        Log.i(TAG, "handleDeviceShutdown Save Volume start");
        if(mCall.mDevice != null) {
            mCall.saveVolume();
            mCall.reset();
        }
        if(mMedia.mDevice != null) {
            mMedia.saveVolume();
            mMedia.reset();
        }
        mBroadcast.saveVolume();
        Log.i(TAG, "handleDeviceShutdown Save Volume end");
    }

    class DeviceVolume {
        BluetoothDevice mDevice;
        int mVolume;
        int mProfile;
        boolean mSupportAbsoluteVolume;
        Map<String, Integer> mBassVolMap;

        Context mContext;
        private String mAudioTypeStr;
        public static final int SAFE_VOL = 7;
        public String mVolumeMap;

        DeviceVolume(Context context, String map) {
            this.reset();
            mContext = context;
            mVolumeMap = map;
            mSupportAbsoluteVolume = false;

            if(map == "bluetooth_call_volume_map") {
                 mAudioTypeStr = "Call";
            }
            else if(map == "bluetooth_media_volume_map") {
                mAudioTypeStr = "Media";
            }
            else {
                mAudioTypeStr = "Broadcast";
                mBassVolMap = new ConcurrentHashMap<String, Integer>();
            }

            Map<String, ?> allKeys = getVolumeMap().getAll();
            SharedPreferences.Editor pref = getVolumeMap().edit();
            for (Map.Entry<String, ?> entry : allKeys.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();
                BluetoothDevice d = BluetoothAdapter.getDefaultAdapter().getRemoteDevice(key);

                if (value instanceof Integer && d.getBondState() == BluetoothDevice.BOND_BONDED) {
                    if (mAudioTypeStr.equals("Broadcast")) {
                        mBassVolMap.put(key, (Integer) value);
                        Log.w(TAG, "address " + key + " from the broadcast volume map volume :" + value);
                    }
                } else {
                    Log.w(TAG, "Removing " + key + " from the " + mAudioTypeStr + " volume map");
                    pref.remove(key);
                }
            }
            pref.apply();
        }

        void updateDevice (BluetoothDevice device, int profile) {
            mDevice = device;
            mProfile = profile;

            mVolume = getSavedVolume(device);
            Log.i (TAG, "New " + mAudioTypeStr + " device: " + mDevice + " Vol: " + mVolume);
        }

        int getSavedVolume (BluetoothDevice device) {
            int mSavedVolume;
            SharedPreferences pref = getVolumeMap();
            mSavedVolume = pref.getInt(device.getAddress(), SAFE_VOL);
            return mSavedVolume;
        }

        void updateVolume (int volume) {
            mVolume = volume;
        }

        void updateVolume (BluetoothDevice device, int volume) {
            if(mAudioTypeStr.equals("Broadcast")) {
                Log.i(TAG, "updateVolume, device " + device + " volume: " + volume);
                mBassVolMap.put(device.getAddress(), volume);
            }
        }
        int getVolume(BluetoothDevice device) {
            if(device == null) {
                Log.e (TAG, "Null Device passed");
                return 7;
            }
            if(mAudioTypeStr.equals("Broadcast")) {
                if(mBassVolMap.containsKey(device.getAddress())) {
                    return mBassVolMap.getOrDefault(device.getAddress(), 7);
                } else {
                    int mSavedVolume = getSavedVolume(device);
                    mBassVolMap.put(device.getAddress(), mSavedVolume);
                    Log.i(TAG, "get saved volume, device " + device + " volume: " + mSavedVolume);
                    return mSavedVolume;
                }
            }
            return 7;
        }
        private SharedPreferences getVolumeMap() {
            return mContext.getSharedPreferences(mVolumeMap, Context.MODE_PRIVATE);
        }

        public void saveVolume() {
            if(mAudioTypeStr.equals("Broadcast")) {
                saveBroadcastVolume();
                return;
            }

            if(mDevice == null) {
                Log.e (TAG, "saveVolume: No Device Active for " + mAudioTypeStr + ". Ignore");
                return;
            }

            SharedPreferences.Editor pref = getVolumeMap().edit();
            pref.putInt(mDevice.getAddress(), mVolume);
            pref.apply();
            Log.i (TAG, "Saved " + mAudioTypeStr + " Volume: " + mVolume + " for device: " + mDevice);
        }

        public void saveBroadcastVolume() {
            SharedPreferences.Editor pref = getVolumeMap().edit();
            for(Map.Entry<String, Integer> itr : mBassVolMap.entrySet()) {
                pref.putInt(itr.getKey(), itr.getValue());
            }
            pref.apply();
        }

        public void saveVolume(BluetoothDevice device) {
            if(device == null) {
                Log.e (TAG, "Null Device passed");
                return;
            }
            if(mAudioTypeStr.equals("Broadcast")) {
                int mVol = mBassVolMap.getOrDefault(device.getAddress(), 7);
                SharedPreferences.Editor pref = getVolumeMap().edit();
                pref.putInt(device.getAddress(), mVol);
                pref.apply();
            }
        }

        void removeDevice(BluetoothDevice device) {
            if(mAudioTypeStr.equals("Broadcast")) {
                Log.i (TAG, "Remove device " + device + " from broadcast volume map ");
                mBassVolMap.remove(device.getAddress());
            }
            SharedPreferences.Editor pref = getVolumeMap().edit();
            pref.remove(device.getAddress());
            pref.apply();
        }

        void reset () {
            Log.i (TAG, "Reset " + mAudioTypeStr + " Device: " + mDevice);
            mDevice = null;
            mVolume = SAFE_VOL;
            mProfile = ApmConst.AudioProfiles.NONE;
        }
    }

    private class VolumeManagerReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if(action == null) 
                return;

            switch(action) {
                case AudioManager.VOLUME_CHANGED_ACTION:
                    int streamType = intent.getIntExtra(AudioManager.EXTRA_VOLUME_STREAM_TYPE, -1);
                    int volumeValue = intent.getIntExtra(AudioManager.EXTRA_VOLUME_STREAM_VALUE, 0);
                    if(streamType == AudioManager.STREAM_BLUETOOTH_SCO) {
                        setCallVolume(intent);
                    } else {
                        updateMediaStreamVolume(volumeValue);
                    }
                    break;

                case BluetoothDevice.ACTION_BOND_STATE_CHANGED:
                    int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE,
                            BluetoothDevice.ERROR);
                    BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if(device == null)
                        return;

                    if(state == BluetoothDevice.BOND_NONE) {
                        handleDeviceUnbond(device);
                    }
                    break;

                case BleBroadcastAudioScanAssistManager.ACTION_BROADCAST_SOURCE_INFO:
                    BleBroadcastSourceInfo sourceInfo = intent.getParcelableExtra(
                                      BleBroadcastSourceInfo.EXTRA_SOURCE_INFO);
                    device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);

                    if (device == null || sourceInfo == null) {
                        Log.w (TAG, "Bluetooth Device or Source info is null");
                        break;
                    }

                    if (sourceInfo.getAudioSyncState() ==
                            BleBroadcastSourceInfo.BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED) {
                        handleBroadcastAudioSynced(device);
                    }
                    break;

                case ACTION_SHUTDOWN:
                case ACTION_POWER_OFF:
                    handleDeviceShutdown();
                    break;
            }
        }
    }
}
