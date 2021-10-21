/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 **************************************************************************/

package com.android.bluetooth.apm;

import static android.Manifest.permission.BLUETOOTH_CONNECT;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothCodecConfig;
import android.bluetooth.BluetoothCodecStatus;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import com.android.bluetooth.Utils;
import android.bluetooth.BluetoothUuid;
import android.bluetooth.IBluetoothA2dp;

import com.android.bluetooth.btservice.AdapterService;
import com.android.bluetooth.btservice.ActiveDeviceManager;
import com.android.bluetooth.btservice.ProfileService;
import com.android.bluetooth.a2dp.A2dpService;
import com.android.bluetooth.apm.ActiveDeviceManagerService;
import com.android.bluetooth.apm.ApmConst;
import com.android.bluetooth.broadcast.BroadcastService;
import com.android.bluetooth.acm.AcmService;
import android.content.Context;
import android.content.Intent;
import android.content.BroadcastReceiver;
import android.content.IntentFilter;
import android.media.AudioManager;
import android.util.Log;
import android.util.StatsLog;
import com.android.bluetooth.hfp.HeadsetService;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import android.os.Handler;
import android.os.Message;
import android.os.SystemClock;
import android.os.SystemProperties;

public class MediaAudio {
    private static MediaAudio sMediaAudio;
    private AdapterService mAdapterService;
//    private BapBroadcastService mBapBroadcastService;
    private ActiveDeviceManagerService mActiveDeviceManager;
    private Context mContext;
    BapBroadcastManager mBapBroadcastManager;
    Map<String, MediaDevice> mMediaDevices;

    final ArrayList <String> supported_codec = new ArrayList<String>( List.of(
        "LC3"
    ));

    private BroadcastReceiver mCodecConfigReceiver;
    private BroadcastReceiver mQosConfigReceiver;
    public static final String BLUETOOTH_PERM = android.Manifest.permission.BLUETOOTH;
    public static final String BLUETOOTH_PRIVILEGED =
            android.Manifest.permission.BLUETOOTH_PRIVILEGED;
    public static final String BLUETOOTH_ADMIN_PERM = android.Manifest.permission.BLUETOOTH_ADMIN;
    public static final String ACTION_UPDATE_CODEC_CONFIG =
                "qti.intent.bluetooth.action.UPDATE_CODEC_CONFIG";
    public static final String CODEC_ID =
                "qti.bluetooth.extra.CODEC_ID";
    public static final String CODEC_CONFIG =
                "qti.bluetooth.extra.CODEC_CONFIG";
    public static final String CHANNEL_MODE =
                "qti.bluetooth.extra.CHANNEL_MODE";
    public static final String ACTION_UPDATE_QOS_CONFIG =
                "qti.intent.bluetooth.action.UPDATE_QOS_CONFIG";
    public static final String QOS_CONFIG =
                "qti.bluetooth.extra.QOS_CONFIG";
    private static final int MAX_DEVICES = 200;
    public static final String TAG = "APM: MediaAudio";
    public static final boolean DBG = true;

    private static final long AUDIO_RECORDING_MASK = 0x00030000;
    private static final long AUDIO_RECORDING_OFF = 0x00010000;
    private static final long AUDIO_RECORDING_ON = 0x00020000;

    private static final long GAMING_OFF = 0x00001000;
    private static final long GAMING_ON = 0x00002000;
    private static final long GAMING_MODE_MASK = 0x00007000;

    private static boolean mIsRecordingEnabled;

    private AudioManager mAudioManager;

    private MediaAudio(Context context) {
        Log.i(TAG, "initialization");

        mContext = context;
        mMediaDevices = new ConcurrentHashMap<String, MediaDevice>();
        mAudioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            Objects.requireNonNull(mAudioManager,
                               "AudioManager cannot be null when A2dpService starts");

        mAdapterService = AdapterService.getAdapterService();
        mActiveDeviceManager = ActiveDeviceManagerService.get();

        mBapBroadcastManager = new BapBroadcastManager();

        IntentFilter codecFilter = new IntentFilter();
        codecFilter.addAction(ACTION_UPDATE_CODEC_CONFIG);
        mCodecConfigReceiver = new LeCodecConfig();
        context.registerReceiver(mCodecConfigReceiver, codecFilter);

        IntentFilter qosFilter = new IntentFilter();
        qosFilter.addAction(ACTION_UPDATE_QOS_CONFIG);
        mQosConfigReceiver = new QosConfigReceiver();
        context.registerReceiver(mQosConfigReceiver, qosFilter);

        mIsRecordingEnabled =
            SystemProperties.getBoolean("persist.vendor.service.bt.recording_supported", false);

        //2 Setup Codec Config here
    }

    public static MediaAudio init(Context context) {
        if(sMediaAudio == null) {
            sMediaAudio = new MediaAudio(context);
            MediaAudioIntf.init(sMediaAudio);
        }
        return sMediaAudio;
    }

    public static MediaAudio get() {
        return sMediaAudio;
    }

    public boolean connect(BluetoothDevice device) {
        return connect (device, false, false);
    }

    public boolean connect(BluetoothDevice device, Boolean allProfile) {
        return connect (device, allProfile, false);
    }

    public boolean autoConnect(BluetoothDevice device) {
        Log.e(TAG, "autoConnect: " + device);
        return connect(device, false, true);
    }

    private boolean connect(BluetoothDevice device, boolean allProfile, boolean autoConnect) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");

        Log.e(TAG, "connect: " + device + " allProfile: " + allProfile +
                                          " autoConnect: " + autoConnect);
        if (getConnectionPolicy(device) == BluetoothProfile.CONNECTION_POLICY_FORBIDDEN) {
            Log.e(TAG, "Cannot connect to " + device + " : CONNECTION_POLICY_FORBIDDEN");
            return false;
        }

        DeviceProfileMap dMap = DeviceProfileMap.getDeviceProfileMapInstance();
        if (dMap == null)
            return false;

        int peer_supported_profiles = dMap.getAllSupportedProfile(device);
        boolean is_peer_support_recording =
                ((peer_supported_profiles & ApmConst.AudioProfiles.BAP_RECORDING) != 0);
        int profileID = dMap.getSupportedProfile(device, ApmConst.AudioFeatures.MEDIA_AUDIO);
        if (profileID == ApmConst.AudioProfiles.NONE) {
            Log.e(TAG, "Can Not connect to " + device + ". Device does not support media service.");
            return false;
        }

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        if(mMediaDevice == null) {
            if(mMediaDevices.size() >= MAX_DEVICES)
                return false;
            mMediaDevice = new MediaDevice(device, profileID);
            mMediaDevices.put(device.getAddress(), mMediaDevice);
        } else if(mMediaDevice.deviceConnStatus != BluetoothProfile.STATE_DISCONNECTED) {
            Log.i(TAG, "Device already connected");
            return false;
        }

        if((ApmConst.AudioProfiles.A2DP & profileID) == ApmConst.AudioProfiles.A2DP) {
            A2dpService service = A2dpService.getA2dpService();
            if(service != null) {
                service.connectA2dp(device);
            }
        }

        BluetoothDevice groupDevice = device;
        StreamAudioService mStreamService = StreamAudioService.getStreamAudioService();

        if(mStreamService != null &&
                (ApmConst.AudioProfiles.BAP_MEDIA & profileID) == ApmConst.AudioProfiles.BAP_MEDIA) {
            int defaultMediaProfile = ApmConst.AudioProfiles.BAP_MEDIA;

            /* handle common conect of call and media audio */
            if(autoConnect) {
                groupDevice = mStreamService.getDeviceGroup(device);
                Log.i(TAG, "Auto Connect Request. Connecting group: " + groupDevice);
            }

            /*int defaultMusicProfile = dMap.getProfile(device, ApmConst.AudioFeatures.MEDIA_AUDIO);
            if((ApmConst.AudioProfiles.A2DP & defaultMusicProfile) == ApmConst.AudioProfiles.A2DP) {
                Log.i(TAG, "A2DP is default profile for Music, configure BAP for Gaming");
                defaultMediaProfile = ApmConst.AudioProfiles.BAP_GCP;
            }*/

            if(mIsRecordingEnabled) {
                Log.i(TAG, "Add Recording profile to LE connect request");
                defaultMediaProfile = defaultMediaProfile | ApmConst.AudioProfiles.BAP_RECORDING;
            }

            if(allProfile) {
                int callProfileID = dMap.getSupportedProfile(device, ApmConst.AudioFeatures.CALL_AUDIO);
                if((callProfileID & ApmConst.AudioProfiles.BAP_CALL) == ApmConst.AudioProfiles.BAP_CALL) {
                    Log.i(TAG, "Add BAP_CALL to LE connect request");
                    mStreamService.connectLeStream(groupDevice,
                        defaultMediaProfile | ApmConst.AudioProfiles.BAP_CALL);
                } else {
                    mStreamService.connectLeStream(groupDevice, defaultMediaProfile);
                }
            } else {
                mStreamService.connectLeStream(groupDevice, defaultMediaProfile);
            }
        }
        return true;
    }

    public boolean disconnect(BluetoothDevice device) {
        return disconnect(device, false);
    }

    public boolean disconnect(BluetoothDevice device, Boolean allProfile) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH ADMIN permission");
        Log.i(TAG, "Disconnect: " + device);
        MediaDevice mMediaDevice = null;

        if(device == null)
            return false;

        mMediaDevice = mMediaDevices.get(device.getAddress());
        if(mMediaDevice == null) {
            Log.e(TAG, "Ignore: Device " + device + " not present in list");
            return false;
        }

        if (mMediaDevice.profileConnStatus[MediaDevice.A2DP_STREAM] != BluetoothProfile.STATE_DISCONNECTED) {
            A2dpService service = A2dpService.getA2dpService();
            if(service != null) {
                service.disconnectA2dp(device);
            }
        }
        if (mMediaDevice.profileConnStatus[MediaDevice.LE_STREAM] != BluetoothProfile.STATE_DISCONNECTED) {
            StreamAudioService service = StreamAudioService.getStreamAudioService();
            if(service != null) {
                DeviceProfileMap dMap = DeviceProfileMap.getDeviceProfileMapInstance();
                if (!dMap.isProfileConnected(device, ApmConst.AudioProfiles.BAP_CALL)) {
                    Log.d(TAG,"BAP_CALL not connected");
                    allProfile = false;
                }
                service.disconnectLeStream(device, allProfile, true);
            }
        }

        return true;
    }

    public List<BluetoothDevice> getConnectedDevices() {
        Log.i(TAG, "getConnectedDevices: ");
        if(mMediaDevices.size() == 0) {
            return new ArrayList<>(0);
        }

        List<BluetoothDevice> connectedDevices = new ArrayList<>();
        for(MediaDevice mMediaDevice : mMediaDevices.values()) {
            if(mMediaDevice.deviceConnStatus == BluetoothProfile.STATE_CONNECTED) {
                connectedDevices.add(mMediaDevice.mDevice);
            }
        }
        return connectedDevices;
    }

    public List<BluetoothDevice> getDevicesMatchingConnectionStates(Integer[] states) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");

        Log.i(TAG, "getDevicesMatchingConnectionStates: ");
        List<BluetoothDevice> devices = new ArrayList<>();
        if (states == null) {
            return devices;
        }

        BluetoothDevice [] bondedDevices = null;
        bondedDevices = mAdapterService.getBondedDevices();
        if(bondedDevices == null) {
            return devices;
        }

        for (BluetoothDevice device : bondedDevices) {
            MediaDevice mMediaDevice;
            int state = BluetoothProfile.STATE_DISCONNECTED;

            DeviceProfileMap dMap = DeviceProfileMap.getDeviceProfileMapInstance();
            if(dMap == null) {
                return new ArrayList<>(0);
            }
            if(dMap.getProfile(device, ApmConst.AudioFeatures.MEDIA_AUDIO) == ApmConst.AudioProfiles.NONE) {
                continue;
            }

            mMediaDevice = mMediaDevices.get(device.getAddress());
            if(mMediaDevice != null)
                state = mMediaDevice.deviceConnStatus;

            for(int s: states) {
                if(s == state) {
                    devices.add(device);
                    break;
                }
            }
        }
        return devices;
    }

    public int getConnectionState(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");

        if(device == null)
            return BluetoothProfile.STATE_DISCONNECTED;

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        if(mMediaDevice != null)
            return mMediaDevice.deviceConnStatus;

        return BluetoothProfile.STATE_DISCONNECTED;
    }

    public int getPriority(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        if(mAdapterService != null) {
            return mAdapterService.getDatabase()
                .getProfileConnectionPolicy(device, BluetoothProfile.A2DP);
        }
        return BluetoothProfile.PRIORITY_UNDEFINED;
    }

    public boolean isA2dpPlaying(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");

        if(device == null)
            return false;

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        if(mMediaDevice != null) {
            Log.i(TAG, "isA2dpPlaying: " + mMediaDevice.streamStatus);
            return (mMediaDevice.streamStatus == BluetoothA2dp.STATE_PLAYING);
        }

        return false;
    }

    public BluetoothCodecStatus getCodecStatus(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");

        Log.i(TAG, "getCodecStatus: for device: " + device);
        if(device == null)
            return null;

        if (mBapBroadcastManager.isBapBroadcastActive()) {
            return mBapBroadcastManager.getCodecStatus();
        }

        ActiveDeviceManagerService mActiveDeviceManager = ActiveDeviceManagerService.get();
        int profile = mActiveDeviceManager.getActiveProfile(ApmConst.AudioFeatures.MEDIA_AUDIO);
        if(profile != ApmConst.AudioProfiles.NONE && profile != ApmConst.AudioProfiles.A2DP) {
            StreamAudioService service = StreamAudioService.getStreamAudioService();
            if(service != null) {
                device = service.getDeviceGroup(device);
            }
        }

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        Log.i(TAG, "getCodecStatus: for mMediaDevice: " + mMediaDevice);
        if(mMediaDevice == null)
            return null;

        Log.i(TAG, "getCodecStatus: " + mMediaDevice.mCodecStatus);
        return mMediaDevice.mCodecStatus;
    }

    public void setCodecConfigPreference(BluetoothDevice mDevice,
                                             BluetoothCodecConfig codecConfig) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        BluetoothDevice device = mDevice;

        Log.i(TAG, "setCodecConfigPreference: " + codecConfig);
        if(device == null) {
            if(mActiveDeviceManager != null) {
                device = mActiveDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);
            }
        }
        if(device == null)
            return;

        if (codecConfig == null) {
            Log.e(TAG, "setCodecConfigPreference: Codec config can't be null");
            return;
        }
        long cs4 = codecConfig.getCodecSpecific4();

        if (mActiveDeviceManager.getActiveProfile(ApmConst.AudioFeatures.MEDIA_AUDIO) ==
                                                      ApmConst.AudioProfiles.BROADCAST_LE) {
            AcmService mAcmService = AcmService.getAcmService();
            BluetoothDevice mPrevDevice = mActiveDeviceManager.getQueuedDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);
            if (mPrevDevice != null && mAcmService != null) {
                if ((cs4 & AUDIO_RECORDING_MASK) == AUDIO_RECORDING_ON) {
                    if (mAcmService.getConnectionState(mPrevDevice) == BluetoothProfile.STATE_CONNECTED) {
                        device = mPrevDevice;
                        Log.d(TAG,"Recording request, switch device to " + device);
                    } else {
                        Log.d(TAG,"Not DUMO device, ignore recording request");
                        return;
                    }
                }
            } else if ((cs4 & GAMING_MODE_MASK) == GAMING_ON) {
                Log.d(TAG, "Ignore gaming mode request when broadcast is active");
                return;
            }
        }

        DeviceProfileMap dMap = DeviceProfileMap.getDeviceProfileMapInstance();
        int supported_prfiles = dMap.getAllSupportedProfile(device);

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        boolean peer_supports_recording =
                ((supported_prfiles & ApmConst.AudioProfiles.BAP_RECORDING) != 0);

        int profileIndex = mMediaDevice.getProfileIndex(ApmConst.AudioProfiles.BAP_MEDIA);
        int profileIndexA2dp = mMediaDevice.getProfileIndex(ApmConst.AudioProfiles.A2DP);
        boolean is_peer_connected_for_recording =
                              (mMediaDevice.profileConnStatus[profileIndex] ==
                               BluetoothProfile.STATE_CONNECTED);
        boolean is_peer_connected_for_a2dp = (mMediaDevice.profileConnStatus[profileIndexA2dp] ==
                               BluetoothProfile.STATE_CONNECTED);
        Log.i(TAG, "is_peer_connected_for_recording: " + is_peer_connected_for_recording +
                   ", is_peer_connected_for_a2dp: " + is_peer_connected_for_a2dp);
        CallAudio mCallAudio = CallAudio.get();
        boolean isInCall = mCallAudio != null && mCallAudio.isVoiceOrCallActive();
        // TODO : check the FM related rx activity
        if (mActiveDeviceManager != null &&
            peer_supports_recording && mIsRecordingEnabled &&
            is_peer_connected_for_recording && is_peer_connected_for_a2dp) {
            if ((cs4 & AUDIO_RECORDING_MASK) == AUDIO_RECORDING_ON) {
                if(!isInCall &&
                   !mActiveDeviceManager.isRecordingActive(device)) {
                  mActiveDeviceManager.enableRecording(device);
                }

            } else if ((cs4 & AUDIO_RECORDING_MASK) == AUDIO_RECORDING_OFF) {
                if(mActiveDeviceManager.isRecordingActive(device)) {
                  mActiveDeviceManager.disableRecording(device);
                }
            }
        }

        boolean isBapConnected = (mMediaDevice.profileConnStatus[mMediaDevice.LE_STREAM]
                 == BluetoothProfile.STATE_CONNECTED);

        if(isBapConnected) {
            long mGamingStatus = (cs4 & GAMING_MODE_MASK);
            if((mGamingStatus & GAMING_ON) > 0) {
                Log.w(TAG, "Turning On Gaming Mode");
                mActiveDeviceManager.enableGaming(device);
                return;
            } else if((mGamingStatus & GAMING_OFF) > 0) {
                Log.w(TAG, "Turning Off Gaming Mode");
                mActiveDeviceManager.disableGaming(device);
                return;
            }
        }

        int profileID = dMap.getProfile(device, ApmConst.AudioFeatures.MEDIA_AUDIO);

        if(ApmConst.AudioProfiles.A2DP == profileID) {
            if(codecConfig.getCodecType() ==
                  BluetoothCodecConfig.SOURCE_CODEC_TYPE_LC3) {
              return;
            }
            A2dpService service = A2dpService.getA2dpService();
            if(service != null) {
                service.setCodecConfigPreferenceA2dp(device, codecConfig);
                return;
            }
        }/* else if(ApmConst.AudioProfiles.BAP == profileID) { // once implemented
            LeStreamService service = LeStreamService.getLeStreamService();
            if(service != null) {
                service.setCodecConfigPreferenceLeStream(device, codecConfig);
                return;
            }
        }*/

    }

    public void enableOptionalCodecs(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        Log.i(TAG, "enableOptionalCodecs: ");

        BluetoothCodecStatus mCodecStatus = null;

        if (device == null) {
            if(mActiveDeviceManager != null) {
                device = mActiveDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);
            }
        }
        if (device == null) {
            Log.e(TAG, "enableOptionalCodecs: Invalid device");
            return;
        }

        if (getSupportsOptionalCodecs(device) != BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED) {
            Log.e(TAG, "enableOptionalCodecs: No optional codecs");
            return;
        }

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());

        A2dpService service = A2dpService.getA2dpService();
        if(service != null) {
            int profileIndex = mMediaDevice.getProfileIndex(ApmConst.AudioProfiles.A2DP);
            mCodecStatus = mMediaDevice.mProfileCodecStatus[profileIndex];
            if(mCodecStatus != null) {
                service.enableOptionalCodecsA2dp(device, mCodecStatus.getCodecConfig());
            }
        }
        // 2 Should implement common codec handling when
        //vendor codecs is introduced in LE Audio
    }

    public void disableOptionalCodecs(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_PERM, "Need BLUETOOTH permission");
        Log.i(TAG, "disableOptionalCodecs: ");
        BluetoothCodecStatus mCodecStatus = null;
        if (device == null) {
            if(mActiveDeviceManager != null) {
                device = mActiveDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);
            }
        }
        if (device == null) {
            Log.e(TAG, "disableOptionalCodecs: Invalid device");
            return;
        }

        if (getSupportsOptionalCodecs(device) != BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED) {
            Log.e(TAG, "disableOptionalCodecs: No optional codecs");
            return;
        }

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());

        A2dpService service = A2dpService.getA2dpService();
        if(service != null) {
            int profileIndex = mMediaDevice.getProfileIndex(ApmConst.AudioProfiles.A2DP);
            mCodecStatus = mMediaDevice.mProfileCodecStatus[profileIndex];
            if(mCodecStatus != null) {
                service.disableOptionalCodecsA2dp(device, mCodecStatus.getCodecConfig());
            }
        }
        // 2 Should implement common codec handling when
        //vendor codecs is introduced in LE Audio
    }

    public int getSupportsOptionalCodecs(BluetoothDevice device) {
        if(mAdapterService != null)
            return mAdapterService.getDatabase().getA2dpSupportsOptionalCodecs(device);
        return BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED;
    }

    public int supportsOptionalCodecs(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        if(mAdapterService.isTwsPlusDevice(device)) {
             Log.w(TAG, "Disable optional codec support for TWS+ device");
             return BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED;
        }
        return getSupportsOptionalCodecs(device);
    }

    public int getOptionalCodecsEnabled(BluetoothDevice device) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        if(mAdapterService != null)
            return mAdapterService.getDatabase().getA2dpOptionalCodecsEnabled(device);
        return BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN;
    }

    public void setOptionalCodecsEnabled(BluetoothDevice device, Integer value) {
        Log.i(TAG, "setOptionalCodecsEnabled: " + value);
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_ADMIN_PERM, "Need BLUETOOTH_ADMIN permission");
        if (value != BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN
                && value != BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED
                && value != BluetoothA2dp.OPTIONAL_CODECS_PREF_ENABLED) {
            Log.w(TAG, "Unexpected value passed to setOptionalCodecsEnabled:" + value);
            return;
        }

        if(mAdapterService != null)
            mAdapterService.getDatabase().setA2dpOptionalCodecsEnabled(device, value);
    }

    public int getConnectionPolicy(BluetoothDevice device) {
        if(mAdapterService != null)
            return mAdapterService.getDatabase()
                .getProfileConnectionPolicy(device, BluetoothProfile.A2DP);
        return BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
    }

    public boolean setConnectionPolicy(BluetoothDevice device, Integer connectionPolicy) {
        mContext.enforceCallingOrSelfPermission(BLUETOOTH_PRIVILEGED,
                "Need BLUETOOTH_PRIVILEGED permission");
        if (DBG) {
            Log.d(TAG, "Saved connectionPolicy " + device + " = " + connectionPolicy);
        }
        boolean setSuccessfully;
        setSuccessfully = mAdapterService.getDatabase()
                .setProfileConnectionPolicy(device, BluetoothProfile.A2DP, connectionPolicy);

        if (setSuccessfully && connectionPolicy == BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
            connect(device);
        } else if (setSuccessfully
                && connectionPolicy == BluetoothProfile.CONNECTION_POLICY_FORBIDDEN) {
            disconnect(device);
        }
        return setSuccessfully;
    }

    public boolean setSilenceMode(BluetoothDevice device, Boolean silence) {
        if (DBG) {
            Log.d(TAG, "setSilenceMode(" + device + "): " + silence);
        }
        BluetoothDevice mActiveDevice = mActiveDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);
        if (silence && Objects.equals(mActiveDevice, device)) {
            mActiveDeviceManager.removeActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO, true);
        } else if (!silence && null ==
                mActiveDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO)) {
            // Set the device as the active device if currently no active device.
            mActiveDeviceManager.setActiveDevice(device, ApmConst.AudioFeatures.MEDIA_AUDIO, false);
        }
        return true;
    }

    public void onConnStateChange(BluetoothDevice device, Integer state, Integer profile) {
        Log.d(TAG, "onConnStateChange: profile: " + profile + " state: " + state + " for device " + device);
        if(device == null)
            return;
        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());

        if(mMediaDevice == null) {
            if(state == BluetoothProfile.STATE_DISCONNECTED)
                return;
            if(mMediaDevices.size() >= MAX_DEVICES) {
                return;
            }
            mMediaDevice = new MediaDevice(device, profile, state);
            mMediaDevices.put(device.getAddress(), mMediaDevice);
            broadcastConnStateChange(device, BluetoothProfile.STATE_DISCONNECTED, state);
            return;
        }

        int profileIndex = mMediaDevice.getProfileIndex(profile);
        int prevState = mMediaDevice.deviceConnStatus;
        if(mMediaDevice.profileConnStatus[profileIndex] == state) {
            Log.w(TAG, "Profile already in state: " + state + ". Return");
            return;
        }
        mMediaDevice.profileConnStatus[profileIndex] = state;

        if(state == BluetoothProfile.STATE_CONNECTED) {
            DeviceProfileMap dMap = DeviceProfileMap.getDeviceProfileMapInstance();
            dMap.profileConnectionUpdate(device, ApmConst.AudioFeatures.MEDIA_AUDIO, profile, true);
            refreshCurrentCodec(device);
        } else if(state == BluetoothProfile.STATE_DISCONNECTED) {
            DeviceProfileMap dMap = DeviceProfileMap.getDeviceProfileMapInstance();
            dMap.profileConnectionUpdate(device, ApmConst.AudioFeatures.MEDIA_AUDIO, profile, false);
        }

        int otherProfileConnectionState = mMediaDevice.profileConnStatus[(profileIndex+1)%2];
        Log.w(TAG, " otherProfileConnectionState: " + otherProfileConnectionState);

        switch(otherProfileConnectionState) {
        /*Send Broadcast based on state of other profile*/
            case BluetoothProfile.STATE_DISCONNECTED:
                broadcastConnStateChange(device, prevState, state);
                mMediaDevice.deviceConnStatus = state;
                break;
            case BluetoothProfile.STATE_CONNECTING:
                if(state == BluetoothProfile.STATE_CONNECTED) {
                    broadcastConnStateChange(device, prevState, state);
                    mMediaDevice.deviceConnStatus = state;
                }
                break;
            case BluetoothProfile.STATE_DISCONNECTING:
                if(state == BluetoothProfile.STATE_CONNECTING ||
                        state == BluetoothProfile.STATE_CONNECTED) {
                    broadcastConnStateChange(device, prevState, state);
                    mMediaDevice.deviceConnStatus = state;
                }
                break;
            case BluetoothProfile.STATE_CONNECTED:
                ActiveDeviceManagerService mActiveDeviceManager =
                        ActiveDeviceManagerService.get();
                if(mActiveDeviceManager == null) {
                    break;
                }

                BluetoothDevice mActiveDevice = mActiveDeviceManager
                            .getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);

                if((state == BluetoothProfile.STATE_CONNECTED) ||
                            (state == BluetoothProfile.STATE_DISCONNECTED &&
                            device.equals(mActiveDevice))) {
                    Log.w(TAG, "onConnStateChange: Trigger Media handoff for Device: " + device);
                    mActiveDeviceManager.setActiveDevice(device,
                                              ApmConst.AudioFeatures.MEDIA_AUDIO);
                }
                break;
        }

        if (profileIndex == mMediaDevice.LE_STREAM &&
             state == BluetoothProfile.STATE_DISCONNECTED) {
            mMediaDevice.mProfileCodecStatus[profileIndex] = null;
        }
    }

    public void onConnStateChange(BluetoothDevice device, int state, int profile, boolean isFirstMember) {
        Log.w(TAG, "onConnStateChange: state:" + state + " for device " + device + " new group: " + isFirstMember);
        if((state == BluetoothProfile.STATE_CONNECTED || state == BluetoothProfile.STATE_CONNECTING)
                        && isFirstMember) {
            StreamAudioService mStreamAudioService = StreamAudioService.getStreamAudioService();
            BluetoothDevice groupDevice = mStreamAudioService.getDeviceGroup(device);
            if(groupDevice != null) {
                MediaDevice mMediaDevice = mMediaDevices.get(groupDevice.getAddress());
                if(mMediaDevice == null) {
                    mMediaDevice = new MediaDevice(groupDevice, profile, BluetoothProfile.STATE_CONNECTED);
                    mMediaDevices.put(groupDevice.getAddress(), mMediaDevice);
                } else {
                    int profileIndex = mMediaDevice.getProfileIndex(profile);
                    mMediaDevice.profileConnStatus[profileIndex] = BluetoothProfile.STATE_CONNECTED;
                    mMediaDevice.deviceConnStatus = state;
                }
            }
        } else if(isFirstMember && (state == BluetoothProfile.STATE_DISCONNECTING ||
                        state == BluetoothProfile.STATE_DISCONNECTED)) {
            StreamAudioService mStreamAudioService = StreamAudioService.getStreamAudioService();
            BluetoothDevice groupDevice = mStreamAudioService.getDeviceGroup(device);
            MediaDevice mMediaDevice = mMediaDevices.get(groupDevice.getAddress());
            int prevState = BluetoothProfile.STATE_CONNECTED;
            Log.w(TAG, "onConnStateChange: mMediaDevice: " + mMediaDevice);
            if(mMediaDevice != null) {
                prevState = mMediaDevice.deviceConnStatus;
                int profileIndex = mMediaDevice.getProfileIndex(profile);
                mMediaDevice.profileConnStatus[profileIndex] = state;
                mMediaDevice.deviceConnStatus = state;
                Log.w(TAG, "onConnStateChange: device: " + groupDevice + " state = " +  mMediaDevice.deviceConnStatus);
            }
            ActiveDeviceManager mDeviceManager = AdapterService.getAdapterService().getActiveDeviceManager();
            mDeviceManager.onDeviceConnStateChange(groupDevice, state, prevState,
                            ApmConst.AudioFeatures.MEDIA_AUDIO);
        }
        onConnStateChange(device, state, profile);
    }

    public void onStreamStateChange(BluetoothDevice device, Integer streamStatus) {
        int prevStatus;
        if(device == null)
            return;
        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        if(mMediaDevice == null) {
            return;
        }

        if(mMediaDevice.streamStatus == streamStatus)
            return;

        prevStatus = mMediaDevice.streamStatus;
        mMediaDevice.streamStatus = streamStatus;
        Log.d(TAG, "onStreamStateChange update to volume manager");
        VolumeManager mVolumeManager = VolumeManager.get();
        mVolumeManager.updateStreamState(device, streamStatus, ApmConst.AudioFeatures.MEDIA_AUDIO);
        broadcastStreamState(device, prevStatus, streamStatus);
    }

    protected BluetoothCodecStatus convergeCodecConfig(MediaDevice mMediaDevice) {
        BluetoothCodecStatus A2dpCodecStatus = mMediaDevice.mProfileCodecStatus[MediaDevice.A2DP_STREAM];
        BluetoothCodecStatus BapCodecStatus = mMediaDevice.mProfileCodecStatus[MediaDevice.LE_STREAM];
        BluetoothCodecStatus mCodecStatus = null;

        if(A2dpCodecStatus == null ||
           mMediaDevice.profileConnStatus[MediaDevice.A2DP_STREAM] !=
                                       BluetoothProfile.STATE_CONNECTED) {
            return BapCodecStatus;
        }

        if(BapCodecStatus == null ||
           mMediaDevice.profileConnStatus[MediaDevice.LE_STREAM] !=
                                       BluetoothProfile.STATE_CONNECTED) {
            return A2dpCodecStatus;
        }

        ActiveDeviceManagerService mActiveDeviceManager = ActiveDeviceManagerService.get();
        int mActiveProfile = mActiveDeviceManager.getActiveProfile(ApmConst.AudioFeatures.MEDIA_AUDIO);
        int mActiveProfileIndex = mMediaDevice.getProfileIndex(mActiveProfile);
        BluetoothCodecConfig mCodecConfig = mMediaDevice.mProfileCodecStatus[mActiveProfileIndex].getCodecConfig();

        Log.d(TAG, "convergeCodecConfig: mActiveProfile: "
                   + mActiveProfile + ", mActiveProfileIndex: " +  mActiveProfileIndex);

        BluetoothCodecConfig[] mCodecsLocalCapabilities = new BluetoothCodecConfig[
                            A2dpCodecStatus.getCodecsLocalCapabilities().length +
                            BapCodecStatus.getCodecsLocalCapabilities().length];
        System.arraycopy(A2dpCodecStatus.getCodecsLocalCapabilities(), 0, mCodecsLocalCapabilities, 0,
                         A2dpCodecStatus.getCodecsLocalCapabilities().length);
        System.arraycopy(BapCodecStatus.getCodecsLocalCapabilities(), 0, mCodecsLocalCapabilities,
                         A2dpCodecStatus.getCodecsLocalCapabilities().length,
                         BapCodecStatus.getCodecsLocalCapabilities().length);

        BluetoothCodecConfig[] mCodecsSelectableCapabilities = new BluetoothCodecConfig[
                            A2dpCodecStatus.getCodecsSelectableCapabilities().length +
                            BapCodecStatus.getCodecsSelectableCapabilities().length];
        System.arraycopy(A2dpCodecStatus.getCodecsSelectableCapabilities(), 0, mCodecsSelectableCapabilities, 0,
                         A2dpCodecStatus.getCodecsSelectableCapabilities().length);
        System.arraycopy(BapCodecStatus.getCodecsSelectableCapabilities(), 0, mCodecsSelectableCapabilities,
                         A2dpCodecStatus.getCodecsSelectableCapabilities().length,
                         BapCodecStatus.getCodecsSelectableCapabilities().length);

        mCodecStatus = new BluetoothCodecStatus(mCodecConfig,
                mCodecsLocalCapabilities, mCodecsSelectableCapabilities);
        return mCodecStatus;
    }

    public void onCodecConfigChange(BluetoothDevice device, BluetoothCodecStatus mCodecStatus, Integer profile) {
        onCodecConfigChange(device, mCodecStatus, profile, true);
    }

    protected void refreshCurrentCodec(BluetoothDevice device) {
        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        if(mMediaDevice == null) {
            return;
        }

        mMediaDevice.mCodecStatus = convergeCodecConfig(mMediaDevice);

        Log.d(TAG, "refreshCurrentCodec: " + device + ", " + mMediaDevice.mCodecStatus);

        broadcastCodecStatus(device, mMediaDevice.mCodecStatus);
    }

    public void onCodecConfigChange(BluetoothDevice device,
            BluetoothCodecStatus codecStatus, Integer profile, Boolean updateAudio) {
        Log.w(TAG, "onCodecConfigChange: for profile:" + profile + " for device "
                + device + " update audio: " + updateAudio + " with status " + codecStatus);
        if(device == null || codecStatus == null)
            return;

        MediaDevice mMediaDevice = mMediaDevices.get(device.getAddress());
        BluetoothCodecStatus prevCodecStatus = null;
        //BapBroadcastService mBapBroadcastService = BapBroadcastService.getBapBroadcastService();
        if (mMediaDevice == null && profile == ApmConst.AudioProfiles.BROADCAST_LE) {
            Log.d(TAG,"LE Broadcast codec change");
        } else if(mMediaDevice == null) {
            Log.e(TAG, "No entry in Device Profile map for device: " + device);
            return;
        }
        if (mMediaDevice != null) {
            int profileIndex = mMediaDevice.getProfileIndex(profile);
            Log.d(TAG, "profileIndex: " + profileIndex);

            if(codecStatus.equals(mMediaDevice.mProfileCodecStatus[profileIndex])) {
                Log.w(TAG, "onCodecConfigChange: Codec already updated for the device and profile");
                return;
            }

            mMediaDevice.mProfileCodecStatus[profileIndex] = codecStatus;
            prevCodecStatus = mMediaDevice.mCodecStatus;

            /* Check the codec status for alternate Media profile for this device */
            if(mMediaDevice.mProfileCodecStatus[(profileIndex+1)%2] != null) {
                mMediaDevice.mCodecStatus = convergeCodecConfig(mMediaDevice);
            } else {
                mMediaDevice.mCodecStatus = codecStatus;
            }

            Log.w(TAG, "BroadCasting codecstatus " + mMediaDevice.mCodecStatus +
                                                              " for device: " + device);
            broadcastCodecStatus(device, mMediaDevice.mCodecStatus);
        }

        if(prevCodecStatus != null && mMediaDevice != null) {
            if (prevCodecStatus.getCodecConfig().equals(mMediaDevice.mCodecStatus.getCodecConfig())) {
                Log.d(TAG, "Previous and current codec config are same. Return");
                return;
            }
        }

        ActiveDeviceManagerService mActiveDeviceManager = ActiveDeviceManagerService.get();
        if(mActiveDeviceManager != null && (!mActiveDeviceManager.isStableState(ApmConst.AudioFeatures.MEDIA_AUDIO))) {
            Log.d(TAG, "SHO under progress. MM Audio will be updated after SHO completes");
            return;
        }

        if(device.equals(mActiveDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO)) && updateAudio) {
            VolumeManager mVolumeManager = VolumeManager.get();
            int currentVolume = mVolumeManager.getActiveVolume(ApmConst.AudioFeatures.MEDIA_AUDIO);
            if (profile == ApmConst.AudioProfiles.BROADCAST_LE)
                currentVolume = 15;
            if (mAudioManager != null) {
                BluetoothDevice groupDevice = device;
                if(profile == ApmConst.AudioProfiles.BAP_MEDIA) {
                    StreamAudioService mStreamAudioService = StreamAudioService.getStreamAudioService();
                    groupDevice = mStreamAudioService.getDeviceGroup(device);
                }
                Log.d(TAG, "onCodecConfigChange Calling handleBluetoothA2dpActiveDeviceChange");
                mAudioManager.handleBluetoothA2dpActiveDeviceChange(groupDevice,
                        BluetoothProfile.STATE_CONNECTED, BluetoothProfile.A2DP,
                        true, currentVolume);
            }
        }
    }

    private void broadcastConnStateChange(BluetoothDevice device, int prevState, int newState) {
      A2dpService mA2dpService = A2dpService.getA2dpService();
      if (mA2dpService != null) {
        Log.d(TAG, "Broadcast Conn State Change: " + prevState + "->" + newState + " for device " + device);
        Intent intent = new Intent(BluetoothA2dp.ACTION_CONNECTION_STATE_CHANGED);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevState);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, newState);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mA2dpService.sendBroadcast(intent, BLUETOOTH_CONNECT,
             Utils.getTempAllowlistBroadcastOptions());
      }
    }

    private void broadcastStreamState(BluetoothDevice device, int prevStatus, int streamStatus) {
      A2dpService mA2dpService = A2dpService.getA2dpService();
      if (mA2dpService != null) {
        Intent intent = new Intent(BluetoothA2dp.ACTION_PLAYING_STATE_CHANGED);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.putExtra(BluetoothProfile.EXTRA_PREVIOUS_STATE, prevStatus);
        intent.putExtra(BluetoothProfile.EXTRA_STATE, streamStatus);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        mA2dpService.sendBroadcast(intent, BLUETOOTH_CONNECT,
             Utils.getTempAllowlistBroadcastOptions());
      }
    }

    private void broadcastCodecStatus (BluetoothDevice device, BluetoothCodecStatus mCodecStatus) {
      A2dpService mA2dpService = A2dpService.getA2dpService();
      if (mA2dpService != null) {
        Intent intent = new Intent(BluetoothA2dp.ACTION_CODEC_CONFIG_CHANGED);
        intent.putExtra(BluetoothCodecStatus.EXTRA_CODEC_STATUS, mCodecStatus);
        intent.putExtra(BluetoothDevice.EXTRA_DEVICE, device);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT
                        | Intent.FLAG_RECEIVER_INCLUDE_BACKGROUND);
        mA2dpService.sendBroadcast(intent, BLUETOOTH_CONNECT,
             Utils.getTempAllowlistBroadcastOptions());
      }
    }

    public boolean isValidCodec (String mCodec) {
        return supported_codec.contains(mCodec);
    }

    public AudioManager getAudioManager() {
        return mAudioManager;
    }

    class MediaDevice {
        BluetoothDevice mDevice;
        int[] profileConnStatus = new int[2];
        int deviceConnStatus;
        int streamStatus;
        private BluetoothCodecStatus mCodecStatus;
        private BluetoothCodecStatus[] mProfileCodecStatus = new BluetoothCodecStatus[2];

        public static final int A2DP_STREAM = 0;
        public static final int LE_STREAM = 1;

        MediaDevice(BluetoothDevice device, int profile, int state) {
            profileConnStatus[A2DP_STREAM] = BluetoothProfile.STATE_DISCONNECTED;
            profileConnStatus[LE_STREAM] = BluetoothProfile.STATE_DISCONNECTED;
            mDevice = device;
            if((profile & ApmConst.AudioProfiles.A2DP) != ApmConst.AudioProfiles.NONE) {
                profileConnStatus[A2DP_STREAM] = state;
            }
            if((profile & (ApmConst.AudioProfiles.TMAP_MEDIA | ApmConst.AudioProfiles.BAP_MEDIA)) !=
                    ApmConst.AudioProfiles.NONE) {
                profileConnStatus[LE_STREAM] = state;
            }
            deviceConnStatus = state;
            streamStatus = BluetoothA2dp.STATE_NOT_PLAYING;
        }

        MediaDevice(BluetoothDevice device, int profile) {
            this(device, profile, BluetoothProfile.STATE_DISCONNECTED);
        }

        public int getProfileIndex(int profile) {
            if(profile == ApmConst.AudioProfiles.A2DP)
                return A2DP_STREAM;
            else
                return LE_STREAM;
        }
    }

    private class LeCodecConfig extends BroadcastReceiver {
        /*am broadcast -a qti.intent.bluetooth.action.UPDATE_CODEC_CONFIG --es
            qti.bluetooth.extra.CODEC_ID "LC3" --es qti.bluetooth.extra.CODEC_CONFIG "<ID>"*/

        ArrayList <String> supported_codec_config = new ArrayList<String>( List.of(
        /* config ID      Sampling Freq    Octets/Frame  */
            "8_1",  /*          8               26       */
            "8_2",  /*          8               30       */
            "16_1", /*          16              30       */
            "16_2", /*          16              40       */
            "24_1", /*          24              45       */
            "24_2", /*          24              60       */
            "32_1", /*          32              60       */
            "32_2", /*          32              80       */
            "441_1",/*          44.1            98       */
            "441_2",/*          44.1            130      */
            "48_1", /*          48              75       */
            "48_2", /*          48              100      */
            "48_3", /*          48              90       */
            "48_4", /*          48              120      */
            "48_5", /*          48              117      */
            "48_6", /*          48              155      */
            "GCP_TX",
            "GCP_TX_RX"
        ));

        Map <String, Integer> channel_mode = Map.of(
            "NONE", 0,
            "MONO", 1,
            "STEREO", 2
        );

        @Override
        public void onReceive(Context context, Intent intent) {
            if (!ACTION_UPDATE_CODEC_CONFIG.equals(intent.getAction())) {
                return;
            }
            String mCodecId = intent.getStringExtra(CODEC_ID);
            if(mCodecId == null || !isValidCodec(mCodecId)) {
                Log.w(TAG, "Invalid Codec " + mCodecId);
                return;
            }
            String mCodecConfig = intent.getStringExtra(CODEC_CONFIG);
            if(mCodecConfig == null || !isValidCodecConfig(mCodecConfig)) {
                Log.w(TAG, "Invalid Codec Config " + mCodecConfig);
                return;
            }

            int mChannelMode = BluetoothCodecConfig.CHANNEL_MODE_NONE;
            String chMode = intent.getStringExtra(CHANNEL_MODE);
            if(chMode != null && channel_mode.containsKey(chMode)) {
                mChannelMode = channel_mode.get(chMode);
            }

            ActiveDeviceManagerService mActiveDeviceManager
                = ActiveDeviceManagerService.get();
            int profile = mActiveDeviceManager.getActiveProfile(ApmConst.AudioFeatures.MEDIA_AUDIO);
            if(profile == ApmConst.AudioProfiles.BROADCAST_LE) {
                /*Update Broadcast module here*/
                mBapBroadcastManager.setCodecPreference(mCodecConfig, mChannelMode);
            } else if (profile == ApmConst.AudioProfiles.BAP_MEDIA) {
                BluetoothDevice device = mActiveDeviceManager.getActiveDevice(ApmConst.AudioFeatures.MEDIA_AUDIO);
                StreamAudioService service = StreamAudioService.getStreamAudioService();
                service.setCodecConfig(device, mCodecConfig, mChannelMode);
            }
            Log.i(TAG, "Codec Config Request: Codec Name: " + mCodecId + " Config ID: "
                    + mCodecConfig + " mChannelMode: " + mChannelMode + " for profile: " + profile);
        }

        boolean isValidCodecConfig (String mCodecConfig) {
            return supported_codec_config.contains(mCodecConfig);
        }
    }

    private class QosConfigReceiver extends BroadcastReceiver {
        /*am broadcast -a qti.intent.bluetooth.action.UPDATE_QOS_CONFIG --es
            qti.bluetooth.extra.CODEC_ID "LC3" --es qti.bluetooth.extra.QOS_CONFIG "<ID>"*/
        boolean enable = false;

        ArrayList <String> supported_Qos_config = new ArrayList<String>( List.of(
            "8_1_1",
            "8_2_1",
            "16_1_1",
            "16_2_1",
            "24_1_1",
            "24_2_1",
            "32_1_1",
            "32_2_1",
            "441_1_1",
            "441_2_1",
            "48_1_1",
            "48_2_1",
            "48_3_1",
            "48_4_1",
            "48_5_1",
            "48_6_1",

            "8_1_2",
            "8_2_2",
            "16_1_2",
            "16_2_2",
            "24_1_2",
            "24_2_2",
            "32_1_2",
            "32_2_2",
            "441_1_2",
            "441_2_2",
            "48_1_2",
            "48_2_2",
            "48_3_2",
            "48_4_2",
            "48_5_2",
            "48_6_2"
        ));

        @Override
        public void onReceive(Context context, Intent intent) {
            if(!enable)
                return;
            if (!ACTION_UPDATE_QOS_CONFIG.equals(intent.getAction())) {
                return;
            }

            String mCodecId = intent.getStringExtra(CODEC_ID);
            if(mCodecId == null || !isValidCodec(mCodecId)) {
                Log.w(TAG, "Invalid Codec " + mCodecId);
                return;
            }
            String mQosConfig = intent.getStringExtra(QOS_CONFIG);
            if(mQosConfig == null || !isValidQosConfig(mQosConfig)) {
                Log.w(TAG, "Invalid QosConfig " + mQosConfig);
                return;
            }

            ActiveDeviceManagerService mActiveDeviceManager
                = ActiveDeviceManagerService.get();
            int profile = mActiveDeviceManager.getActiveProfile(ApmConst.AudioFeatures.MEDIA_AUDIO);
            if(profile == ApmConst.AudioProfiles.BROADCAST_LE) {
                /*Update Broadcast module here*/
            } else if (profile == ApmConst.AudioProfiles.BAP_MEDIA) {
                /*Update ACM here*/
            }
            Log.i(TAG, "New Qos Config ID: " + mQosConfig + " for profile: " + profile);
        }

        boolean isValidQosConfig(String mQosConfig) {
            return supported_Qos_config.contains(mQosConfig);
        }
    }

    class BapBroadcastManager {
        void setCodecPreference(String codecConfig, int channelMode) {
            BroadcastService mBroadcastService = BroadcastService.getBroadcastService();
            if(mBroadcastService != null) {
                mBroadcastService.setCodecPreference(codecConfig, channelMode);
            }
        }

        BluetoothCodecStatus getCodecStatus() {
            BroadcastService mBroadcastService = BroadcastService.getBroadcastService();
            if(mBroadcastService != null) {
                return mBroadcastService.getCodecStatus();
            }
            return null;
        }

        boolean isBapBroadcastActive() {
            BroadcastService mBroadcastService = BroadcastService.getBroadcastService();
            if(mBroadcastService != null) {
                return mBroadcastService.isBroadcastActive();
            }
            return false;
        }
    }
}

