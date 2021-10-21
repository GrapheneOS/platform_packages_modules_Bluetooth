/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
*****************************************************************************/

package com.android.bluetooth.apm;

import android.content.SharedPreferences;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.content.IntentFilter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothUuid;
import android.os.ParcelUuid;
import android.os.Parcelable;
import android.os.SystemProperties;
import android.util.Log;
import android.content.Context;
import com.android.internal.util.ArrayUtils;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import java.util.ArrayList;
import java.lang.Integer;
import java.lang.Boolean;
import java.util.Objects;

public class DeviceProfileMap {

    Map<BluetoothDevice, Integer> mSupportedProfileMap = new HashMap();
    Map<BluetoothDevice, int []> mActiveProfileMap = new HashMap();
    Map<BluetoothDevice, Integer> mConnectedProfileMap = new HashMap();
    private Context mContext;
    private static DeviceProfileMap DPMSingleInstance = null;
    public static int [] mPreferredProfileList = new int[ApmConst.AudioFeatures.MAX_AUDIO_FEATURES];
    public static final String SUPPORTED_PROFILE_MAP = "bluetooth_supported_profile_map";
    public final String ACTION_SHUTDOWN = "android.intent.action.ACTION_SHUTDOWN";
    public final String ACTION_POWER_OFF = "android.intent.action.QUICKBOOT_POWEROFF";
    private final Object mLock = new Object();

    private static final int LeMediaProfiles = ApmConst.AudioProfiles.BAP_MEDIA
                                             | ApmConst.AudioProfiles.TMAP_MEDIA
                                             | ApmConst.AudioProfiles.BAP_GCP
                                             | ApmConst.AudioProfiles.BAP_RECORDING;

    private static final int LeCallProfiles = ApmConst.AudioProfiles.BAP_CALL
                                             | ApmConst.AudioProfiles.TMAP_CALL;

    // private constructor restricted to this class itself
    private DeviceProfileMap() {
        Log.w(LOGTAG, "DeviceProfileMap object creation");
    }

    // static method to create instance of Singleton class
    public static DeviceProfileMap getDeviceProfileMapInstance() {
            if (DPMSingleInstance == null) {
            DPMSingleInstance = new DeviceProfileMap();
            DeviceProfileMapIntf.init(DPMSingleInstance);
        }
        return DPMSingleInstance;
    }

    private static final String LOGTAG = "DeviceProfileMap";
    private SharedPreferences getSupportedProfileMap() {
         return mContext.getSharedPreferences(SUPPORTED_PROFILE_MAP, Context.MODE_PRIVATE);
    }

    /**
     * Initialize the device profile map
     */
    public synchronized boolean init(Context context) {
        Log.d(LOGTAG, "init: ");
        // populate the supported profile list.
        mContext = context;
        Map<String, ?> allKeys = getSupportedProfileMap().getAll();
        SharedPreferences.Editor mSupportedProfileMapEditor = getSupportedProfileMap().edit();

        for (Map.Entry<String, ?> entry : allKeys.entrySet()) {
             String key = entry.getKey();
             Object value = entry.getValue();
             BluetoothDevice mBluetoothDevice = BluetoothAdapter.getDefaultAdapter().
                                                      getRemoteDevice(key);
             if (value instanceof Integer && mBluetoothDevice.getBondState()
                                            == BluetoothDevice.BOND_BONDED) {
                 mSupportedProfileMap.put(mBluetoothDevice, (Integer) value);
                 Log.d(LOGTAG, "address " + key + " from the Supported Profile Map: " + value);
             } else {
                 Log.d(LOGTAG, "Removing " + key + " from the Supported Profile map");
                 mSupportedProfileMapEditor.remove(key);
             }
        }
        mSupportedProfileMapEditor.apply();
        //intialize the preferred profile list
        int mPreferredProfileVal =
                    SystemProperties.getInt("persist.vendor.qcom.bluetooth.default_profiles", 0);
        Log.d(LOGTAG, "init: Preferred Profile = " + mPreferredProfileVal);
        int mfeature = 0;
        while (mfeature < ApmConst.AudioFeatures.MAX_AUDIO_FEATURES) {
            switch(mfeature) {
                case ApmConst.AudioFeatures.CALL_AUDIO:
                    /* default preferred profile for call */
                    mPreferredProfileList[mfeature] = ApmConst.AudioProfiles.HFP;
                    if((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.TMAP_CALL) != 0) {
                        mPreferredProfileList[mfeature] = ApmConst.AudioProfiles.TMAP_CALL;
                    } else if((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.BAP_CALL) != 0) {
                        mPreferredProfileList[mfeature] = ApmConst.AudioProfiles.BAP_CALL;
                    }
                    break;
                case ApmConst.AudioFeatures.MEDIA_AUDIO:
                    mPreferredProfileList[mfeature] = ApmConst.AudioProfiles.A2DP;
                    if((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.TMAP_MEDIA) != 0) {
                        mPreferredProfileList[mfeature] = ApmConst.AudioProfiles.TMAP_MEDIA;
                    } else if((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.BAP_RECORDING) != 0) {
                        mPreferredProfileList[mfeature] = ApmConst.AudioProfiles.BAP_RECORDING;
                    } else if((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.BAP_MEDIA) != 0) {
                        mPreferredProfileList[mfeature] = ApmConst.AudioProfiles.BAP_MEDIA;
                    }
                    break;
                case ApmConst.AudioFeatures.CALL_CONTROL:
                    mPreferredProfileList[mfeature] = ((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.CCP) != 0) ?
                                    ApmConst.AudioProfiles.CCP : ApmConst.AudioProfiles.HFP;
                    break;
                 case ApmConst.AudioFeatures.MEDIA_CONTROL:
                    mPreferredProfileList[mfeature] = ((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.AVRCP) != 0) ?
                                    ApmConst.AudioProfiles.AVRCP : ApmConst.AudioProfiles.MCP;
                    break;
                case ApmConst.AudioFeatures.CALL_VOLUME_CONTROL:
                    mPreferredProfileList[mfeature] = ((mPreferredProfileVal &
                                    (ApmConst.AudioProfiles.BAP_CALL | ApmConst.AudioProfiles.TMAP_CALL)) != 0) ?
                                    ApmConst.AudioProfiles.VCP : ApmConst.AudioProfiles.HFP;
                    break;
                case ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL:
                    mPreferredProfileList[mfeature] = ((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.AVRCP) != 0) ?
                                    ApmConst.AudioProfiles.AVRCP : ApmConst.AudioProfiles.VCP;
                    break;
                case ApmConst.AudioFeatures.HEARING_AID:
                    mPreferredProfileList[mfeature] = ((mPreferredProfileVal &
                                    ApmConst.AudioProfiles.HAP_BREDR) != 0) ?
                                    ApmConst.AudioProfiles.HAP_BREDR : ApmConst.AudioProfiles.HAP_LE;
                    break;
                case ApmConst.AudioFeatures.BROADCAST_AUDIO:
                    mPreferredProfileList[mfeature] = ((mPreferredProfileVal &
                           ApmConst.AudioProfiles.BROADCAST_BREDR) != 0) ?
                           ApmConst.AudioProfiles.BROADCAST_BREDR : ApmConst.AudioProfiles.BROADCAST_LE;
                    break;
                default :
                    break;
                }
                Log.w(LOGTAG, "init: Preferred Profile = " + mPreferredProfileList[mfeature] +
                                                       " for audio feature " + mfeature);
                mfeature++;
        }

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_UUID);
        filter.addAction(ACTION_SHUTDOWN);
        filter.addAction(ACTION_POWER_OFF);
        mContext.registerReceiver(mDeviceProfileMapReceiver, filter);

        return true;
    }

    private final BroadcastReceiver mDeviceProfileMapReceiver = new BroadcastReceiver() {
        @Override
         public void onReceive(Context context, Intent intent) {
             String action = intent.getAction();
             if (action == null) {
                 Log.w(LOGTAG, "mDeviceProfileMapReceiver, action is null");
                 return;
             }
             switch (action) {
                case BluetoothDevice.ACTION_UUID: {
                     BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                     Parcelable[] uuids = intent.getParcelableArrayExtra(BluetoothDevice.EXTRA_UUID);
                     handleDeviceUuidEvent(device, uuids);
                     break;
                }
                case ACTION_SHUTDOWN:
                case ACTION_POWER_OFF:
                    handleDeviceShutdown();
                    break;
                default:
                     Log.w(LOGTAG, "Unknown action " + action);
             }
         }
    };

     private void handleDeviceUuidEvent(BluetoothDevice device, Parcelable[] uuids) {
         Log.d(LOGTAG, "UUIDs found, device: " + device);
         if (uuids != null) {
             ParcelUuid[] uuidsToSend = new ParcelUuid[uuids.length];
             for (int i = 0; i < uuidsToSend.length; i++) {
                 uuidsToSend[i] = (ParcelUuid) uuids[i];
                 Log.d(LOGTAG,"index=" + i + "uuid=" + uuidsToSend[i]);
             }
             checkIfProfileSupported(device, uuidsToSend);
         }
     }

    private void checkIfProfileSupported(BluetoothDevice device, ParcelUuid[] remoteDeviceUuids) {
        ParcelUuid ADV_AUDIO_T_MEDIA =
            ParcelUuid.fromString("00006AD0-0000-1000-8000-00805F9B34FB");

        ParcelUuid HEARINGAID_ADV_AUDIO =
            ParcelUuid.fromString("00006AD2-0000-1000-8000-00805F9B34FB");

        ParcelUuid ADV_AUDIO_P_MEDIA =
            ParcelUuid.fromString("00006AD1-0000-1000-8000-00805F9B34FB");

        ParcelUuid ADV_AUDIO_P_VOICE =
            ParcelUuid.fromString("00006AD4-0000-1000-8000-00805F9B34FB");

        ParcelUuid ADV_AUDIO_T_VOICE =
            ParcelUuid.fromString("00006AD5-0000-1000-8000-00805F9B34FB");

        ParcelUuid ADV_AUDIO_G_MEDIA =
            ParcelUuid.fromString("12994B7E-6d47-4215-8C9E-AAE9A1095BA3");

        ParcelUuid ADV_AUDIO_W_RECORDING =
            ParcelUuid.fromString("2587DB3C-CE70-4FC9-935F-777AB4188FD7");

        if (ArrayUtils.contains(remoteDeviceUuids, BluetoothUuid.HFP)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.HFP);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, BluetoothUuid.A2DP_SINK)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.A2DP);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, BluetoothUuid.HEARING_AID)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.HAP_BREDR);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, BluetoothUuid.AVRCP_CONTROLLER)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.AVRCP);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, ADV_AUDIO_T_MEDIA)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.TMAP_MEDIA);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, ADV_AUDIO_T_VOICE)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.TMAP_CALL);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, ADV_AUDIO_P_MEDIA)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.BAP_MEDIA);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, ADV_AUDIO_P_VOICE)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.BAP_CALL);
        }
        if (ArrayUtils.contains(remoteDeviceUuids, ADV_AUDIO_W_RECORDING)) {
            updateSupportedProfileMap(device, ApmConst.AudioProfiles.BAP_RECORDING);
        }
    }

    private void updateSupportedProfileMap(BluetoothDevice device, int mProfile) {
        synchronized (mLock) {
            int mSupportedProfileBitMap = 0;
            if(!mSupportedProfileMap.containsKey(device)) {
                //device is not added in supported map, add to it
                Log.d(LOGTAG, "updateSupportedProfileMap: device " + device +
                                 "is not added in supported map, add it");
                mSupportedProfileMap.put(device, mSupportedProfileBitMap);
            } else {
                mSupportedProfileBitMap = mSupportedProfileMap.get(device);
            }
            Log.d(LOGTAG, "updateSupportedProfileMap: device " + device + " for profile "
                    + mProfile + " mSupportedProfileBitMap " + mSupportedProfileBitMap);
            mSupportedProfileBitMap = mSupportedProfileBitMap | mProfile;
            mSupportedProfileMap.put(device, mSupportedProfileBitMap);
            Log.d(LOGTAG, "updateSupportedProfileMap: device " + device + " for profile "
                    + mProfile + " mSupportedProfileBitMap " + mSupportedProfileBitMap);
        }
    }

    public int getAllSupportedProfile(BluetoothDevice device) {
        int mSupportedProfileBitMap = 0;
        synchronized (mLock) {
            if(!mSupportedProfileMap.containsKey(device)) {
                Log.d(LOGTAG, "No Supported Profile found for the device " + device);
            } else {
                mSupportedProfileBitMap = mSupportedProfileMap.get(device);
            }
            Log.d(LOGTAG, "getAllSupportedProfile: Supported Profile for the device "
                + device + " mSupportedProfileBitMap " + Integer.toHexString(mSupportedProfileBitMap));
        }
        return mSupportedProfileBitMap;
    }

    public int getProfile(BluetoothDevice device, Integer mAudioFeature) {
        int profileMap = getSupportedProfile(device, mAudioFeature);
        int preferredProfile = profileMap;
        int [] mAciveProfileArray = mActiveProfileMap.get(device);

        if(profileMap == ApmConst.AudioProfiles.NONE)
            return ApmConst.AudioProfiles.NONE;

        switch(mAudioFeature) {
            case ApmConst.AudioFeatures.CALL_AUDIO:
                int mActiveProfileForCallAudio = mAciveProfileArray[mAudioFeature];
                if(mActiveProfileForCallAudio != ApmConst.AudioProfiles.NONE) {
                    //active profile is set
                    preferredProfile = mActiveProfileForCallAudio;
                    return preferredProfile;
                }

                if(profileMap == ApmConst.AudioProfiles.HAP_BREDR ||
                        profileMap == ApmConst.AudioProfiles.HAP_LE) {
                    preferredProfile = profileMap;
                    return preferredProfile;
                }

                int mHFP = profileMap & ApmConst.AudioProfiles.HFP;
                int mLeCall = profileMap & ApmConst.AudioProfiles.TMAP_CALL;
                if(mLeCall == ApmConst.AudioProfiles.NONE)
                    mLeCall = profileMap & ApmConst.AudioProfiles.BAP_CALL;

                if(mHFP != ApmConst.AudioProfiles.NONE &&
                        mLeCall != ApmConst.AudioProfiles.NONE) {
                    preferredProfile = mPreferredProfileList[mAudioFeature];
                } else if(mHFP != ApmConst.AudioProfiles.NONE) {
                    preferredProfile = mHFP;
                } else {
                    preferredProfile = mLeCall;
                }

                Log.d(LOGTAG, "getProfile: device " + device + " preferredProfile: "
                    + preferredProfile + " for CALL_AUDIO");
                break;

            case ApmConst.AudioFeatures.MEDIA_AUDIO:
                int mActiveProfileForMediaAudio = mAciveProfileArray[mAudioFeature];
                if(mActiveProfileForMediaAudio != ApmConst.AudioProfiles.NONE) {
                    //active profile is set
                    preferredProfile = mActiveProfileForMediaAudio;
                    Log.d(LOGTAG, "getProfile: device " + device + " Active Profile: "
                            + preferredProfile + " for MEDIA_AUDIO");
                    return preferredProfile;
                }

                if(profileMap == ApmConst.AudioProfiles.HAP_BREDR ||
                        profileMap == ApmConst.AudioProfiles.HAP_LE) {
                    preferredProfile = profileMap;
                    return preferredProfile;
                }

                int mA2dp = profileMap & ApmConst.AudioProfiles.A2DP;
                int mLeMedia = profileMap & ApmConst.AudioProfiles.TMAP_MEDIA;
                if(mLeMedia == ApmConst.AudioProfiles.NONE)
                    mLeMedia = profileMap & ApmConst.AudioProfiles.BAP_MEDIA;

                if(mA2dp != ApmConst.AudioProfiles.NONE &&
                        mLeMedia != ApmConst.AudioProfiles.NONE) {
                    preferredProfile = mPreferredProfileList[mAudioFeature];
                } else if(mA2dp != ApmConst.AudioProfiles.NONE) {
                    preferredProfile = mA2dp;
                } else {
                    if((preferredProfile & ApmConst.AudioProfiles.BAP_RECORDING)
                                != ApmConst.AudioProfiles.NONE)
                        preferredProfile = mPreferredProfileList[mAudioFeature];
                    else
                        preferredProfile = mLeMedia;
                }

                Log.d(LOGTAG, "getProfile: device " + device + " preferredProfile: "
                    + preferredProfile + " for MEDIA_AUDIO");
                break;
        }
        return preferredProfile;
    }

    public int getSupportedProfile(BluetoothDevice device, Integer mAudioFeature) {
        int [] mAciveProfileArray;

        Log.d(LOGTAG, "getSupportedProfile: for the device " + device + " AudioFeature " + mAudioFeature);
        if(!mActiveProfileMap.containsKey(device)) {
            // intialize the active profile but map for the device
            Log.d(LOGTAG, "getSupportedProfile: intialize the active profile map for the device " + device);
            mAciveProfileArray = new int[ApmConst.AudioFeatures.MAX_AUDIO_FEATURES];
            Arrays.fill(mAciveProfileArray, ApmConst.AudioProfiles.NONE);
            mActiveProfileMap.put(device, mAciveProfileArray);
        } else {
            mAciveProfileArray = mActiveProfileMap.get(device);
        }
        //get the supprted profile list
        int mSupportedProfileBitMap = 0;
        if(!mSupportedProfileMap.containsKey(device)) {
            //device is not added in supported map, add to it
            Log.d(LOGTAG, "getSupportedProfile: device " + device + " is not added in supported map, add it");
            mSupportedProfileMap.put(device, mSupportedProfileBitMap);
        } else {
            mSupportedProfileBitMap = mSupportedProfileMap.get(device);
        }
        Log.d(LOGTAG, "getSupportedProfile: supported Profiles for the device " + device
            + " val = " + Integer.toHexString(mSupportedProfileBitMap));

        switch(mAudioFeature) {
            case ApmConst.AudioFeatures.CALL_AUDIO:
            {
                int mIsHapBREDRSupported = mSupportedProfileBitMap & ApmConst.AudioProfiles.HAP_BREDR;
                int mIsHapLESupported = mSupportedProfileBitMap & ApmConst.AudioProfiles.HAP_LE;

                if(mIsHapBREDRSupported != ApmConst.AudioProfiles.NONE) {
                    return ApmConst.AudioProfiles.HAP_BREDR;
                } else if (mIsHapLESupported != ApmConst.AudioProfiles.NONE) {
                    return ApmConst.AudioProfiles.HAP_LE;
                }

                int mCallAudioProfile = mSupportedProfileBitMap & ( ApmConst.AudioProfiles.HFP
                                | ApmConst.AudioProfiles.BAP_CALL
                                | ApmConst.AudioProfiles.TMAP_CALL);

                Log.d(LOGTAG, "getSupportedProfile: device " + device + " supports: "
                    + mCallAudioProfile + " for CALL_AUDIO");

                return mCallAudioProfile;
            }

            case ApmConst.AudioFeatures.MEDIA_AUDIO:
            {
                int mIsHapBREDRSupported = mSupportedProfileBitMap & ApmConst.AudioProfiles.HAP_BREDR;
                int mIsHapLESupported = mSupportedProfileBitMap & ApmConst.AudioProfiles.HAP_LE;

                if(mIsHapBREDRSupported != ApmConst.AudioProfiles.NONE) {
                    return ApmConst.AudioProfiles.HAP_BREDR;
                } else if (mIsHapLESupported != ApmConst.AudioProfiles.NONE) {
                    return ApmConst.AudioProfiles.HAP_LE;
                }

                int mMediaAudioProfile = mSupportedProfileBitMap & ( ApmConst.AudioProfiles.A2DP
                                | ApmConst.AudioProfiles.BAP_MEDIA
                                | ApmConst.AudioProfiles.TMAP_MEDIA
                                | ApmConst.AudioProfiles.BAP_RECORDING);

                Log.d(LOGTAG, "getSupportedProfile: device " + device + " supports: "
                    + mMediaAudioProfile + " for MEDIA_AUDIO");

                return mMediaAudioProfile;
            }
            case ApmConst.AudioFeatures.MEDIA_CONTROL:
            {
                int mActiveProfileForMediaControl = mAciveProfileArray
                                        [ApmConst.AudioFeatures.MEDIA_CONTROL];
                Log.d(LOGTAG, "getSupportedProfile: device " + device + " ActiveProfile For MediaControl " +
                        mActiveProfileForMediaControl);
                return mActiveProfileForMediaControl;
            }
            case ApmConst.AudioFeatures.CALL_CONTROL:
            {
                int mActiveProfileForCallControl = mAciveProfileArray
                                            [ApmConst.AudioFeatures.CALL_CONTROL];
                Log.d(LOGTAG, "getSupportedProfile: device " + device + " ActiveProfile For Call Control " +
                     mActiveProfileForCallControl);
                return mActiveProfileForCallControl;
            }
            case ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL:
            {
                int mActiveProfileForMediaVolControl = mAciveProfileArray
                                          [ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL];
                    Log.d(LOGTAG, "getSupportedProfile: device " + device +
                      " ActiveProfile For Media Volume Control " + mActiveProfileForMediaVolControl);

                    return mActiveProfileForMediaVolControl;
            }
            case ApmConst.AudioFeatures.CALL_VOLUME_CONTROL:
            {
                int mActiveProfileForCallVolControl = mAciveProfileArray
                                          [ApmConst.AudioFeatures.CALL_VOLUME_CONTROL];
                Log.d(LOGTAG, "getSupportedProfile: device " + device +
                       " ActiveProfile For call Volume Control " + mActiveProfileForCallVolControl);

                return mActiveProfileForCallVolControl;

            }
            case ApmConst.AudioFeatures.BROADCAST_AUDIO:
            {
                int mActiveProfileForBroadCastAudio = mAciveProfileArray
                                           [ApmConst.AudioFeatures.BROADCAST_AUDIO];
                if(mActiveProfileForBroadCastAudio != ApmConst.AudioProfiles.NONE) {
                    //active profile is set
                    return mActiveProfileForBroadCastAudio;
                }

                int mIsBroadCastBREDRSupported = mSupportedProfileBitMap &
                                              ApmConst.AudioProfiles.BROADCAST_BREDR;
                int mIsBroadCastLESupported =
                         mSupportedProfileBitMap & ApmConst.AudioProfiles.BROADCAST_LE;
                Log.d(LOGTAG, "getSupportedProfile: device " + device + " mIsBroadCastBREDRSupported "
                    + mIsBroadCastBREDRSupported + " mIsBroadCastLESupported "
                                                    + mIsBroadCastLESupported);

                if((mIsBroadCastBREDRSupported != 0) && (mIsBroadCastLESupported != 0)) {
                    return mPreferredProfileList[ApmConst.AudioFeatures.BROADCAST_AUDIO];
                } else if (mIsBroadCastBREDRSupported != 0) {
                    return ApmConst.AudioProfiles.BROADCAST_BREDR;
                } else if(mIsBroadCastLESupported != 0) {
                    return ApmConst.AudioProfiles.BROADCAST_LE;
                }
                break;
            }
            case ApmConst.AudioFeatures.HEARING_AID:
            {
                int mActiveProfileForHearingAid = mAciveProfileArray
                                               [ApmConst.AudioFeatures.HEARING_AID];
                if(mActiveProfileForHearingAid != ApmConst.AudioProfiles.NONE) {
                    //active profile is set
                    return mActiveProfileForHearingAid;
                }

                int mIsHAPBREDRSupported = mSupportedProfileBitMap & ApmConst.AudioProfiles.HAP_BREDR;
                int mIsHAPLESupported = mSupportedProfileBitMap & ApmConst.AudioProfiles.HAP_LE;
                Log.d(LOGTAG, "getSupportedProfile: device " + device + " mIsHAPBREDRSupported "
                    + mIsHAPBREDRSupported + " mIsHAPLESupported " + mIsHAPLESupported);

                if((mIsHAPBREDRSupported != 0) && (mIsHAPLESupported !=0)) {
                    return mPreferredProfileList[ApmConst.AudioFeatures.HEARING_AID];
                } else if (mIsHAPBREDRSupported != 0) {
                    return ApmConst.AudioProfiles.HAP_BREDR;
                } else if(mIsHAPLESupported != 0) {
                    return ApmConst.AudioProfiles.HAP_LE;
                }
                break;
            }
            default :
            {
                Log.w(LOGTAG, "getSupportedProfile: no profile supported for" +
                                 mAudioFeature + " device " + device);
                return ApmConst.AudioProfiles.NONE;
            }
        }
        return ApmConst.AudioProfiles.NONE;
    }

    public void profileDescoveryUpdate (BluetoothDevice device, Integer mAudioProfile) {
        int mSupportedProfileBitMap = 0;
        if(mSupportedProfileMap.containsKey(device)) {
            mSupportedProfileBitMap = mSupportedProfileMap.get(device);
        }

        mSupportedProfileBitMap = mSupportedProfileBitMap | mAudioProfile;
        mSupportedProfileMap.put(device, mSupportedProfileBitMap);
    }

    public void profileConnectionUpdate(BluetoothDevice device, Integer mAudioFeature,
           Integer mAudioProfile, Boolean mProfileStatus) {
        int mSupportedProfileBitMap = 0;
        int mConnectedProfileBitMap = 0;
        int [] mAciveProfileArray;

        Log.d(LOGTAG, "profileConnectionUpdate: device : " + device + " AudioProfile "
                + mAudioProfile + " ProfileStatus " + mProfileStatus);

        synchronized (mLock) {
            // get the Connected profile list
            if(mConnectedProfileMap.containsKey(device)) {
                mConnectedProfileBitMap = mConnectedProfileMap.get(device);
            }

            // get the Supported profile list
            if(mSupportedProfileMap.containsKey(device)) {
                mSupportedProfileBitMap = mSupportedProfileMap.get(device);
            }

            if(!mActiveProfileMap.containsKey(device)) {
                // intialize the active profile but map for the device
                Log.d(LOGTAG, "profileConnectionUpdate: intialize the active " +
                              " profile map for the device " + device);
                mAciveProfileArray = new int[ApmConst.AudioFeatures.MAX_AUDIO_FEATURES];
                Arrays.fill(mAciveProfileArray, ApmConst.AudioProfiles.NONE);
                mActiveProfileMap.put(device, mAciveProfileArray);
            } else {
                mAciveProfileArray = mActiveProfileMap.get(device);
            }
            // update the Audio profile connection in list
            if (mProfileStatus) {
                mSupportedProfileBitMap = mSupportedProfileBitMap | mAudioProfile;
                mConnectedProfileBitMap = mConnectedProfileBitMap | mAudioProfile;

                //update the active profile list
                if(mAciveProfileArray[mAudioFeature] == ApmConst.AudioProfiles.NONE) {
                    mAciveProfileArray[mAudioFeature] = mAudioProfile;
                } else if(mAciveProfileArray[mAudioFeature] != mAudioProfile) {
                // diffrent profile connected for the same mAudioFeature need to update the active list.
                    int mPreferredProfile = mPreferredProfileList[mAudioFeature];
                    Log.d(LOGTAG, "profileConnectionUpdate: PreferredProfile for audio feature " +
                          mAudioFeature + " is " + mPreferredProfile + " device " + device);
                    if((mPreferredProfile != ApmConst.AudioProfiles.NONE)
                                         && (mConnectedProfileBitMap & mPreferredProfile) != 0) {
                        mAciveProfileArray[mAudioFeature] = mPreferredProfile;
                    }
                }
            } else {
                mConnectedProfileBitMap = mConnectedProfileBitMap & ~mAudioProfile;
                // profile disconnect for active profile
                if(mAciveProfileArray[mAudioFeature] == mAudioProfile) {
                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                    // do we need to update the active profile with other connected profile for that audio feature.
                    switch(mAudioFeature) {
                        case ApmConst.AudioFeatures.CALL_AUDIO:
                            if(mAudioProfile == ApmConst.AudioProfiles.HFP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.TMAP_CALL) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.TMAP_CALL;
                                } else if ((mConnectedProfileBitMap & ApmConst.AudioProfiles.BAP_CALL) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.BAP_CALL;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            } else if (mAudioProfile == ApmConst.AudioProfiles.TMAP_CALL
                                    || mAudioProfile == ApmConst.AudioProfiles.BAP_CALL) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.HFP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.HFP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            }
                            break;
                        case ApmConst.AudioFeatures.MEDIA_AUDIO:
                            if(mAudioProfile == ApmConst.AudioProfiles.A2DP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.TMAP_MEDIA) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.TMAP_MEDIA;
                                } else if ((mConnectedProfileBitMap & ApmConst.AudioProfiles.BAP_MEDIA) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.BAP_MEDIA;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            } else if (mAudioProfile == ApmConst.AudioProfiles.TMAP_MEDIA
                                    || mAudioProfile == ApmConst.AudioProfiles.BAP_MEDIA) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.A2DP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.A2DP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            }
                            break;
                        case ApmConst.AudioFeatures.CALL_CONTROL:
                            if(mAudioProfile == ApmConst.AudioProfiles.HFP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.CCP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.CCP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            } else if (mAudioProfile == ApmConst.AudioProfiles.CCP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.HFP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.HFP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            }
                            break;
                        case ApmConst.AudioFeatures.MEDIA_CONTROL:
                            if(mAudioProfile == ApmConst.AudioProfiles.AVRCP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.MCP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.MCP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            } else if (mAudioProfile == ApmConst.AudioProfiles.MCP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.AVRCP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.AVRCP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            }
                            break;
                        case ApmConst.AudioFeatures.MEDIA_VOLUME_CONTROL:
                            if(mAudioProfile == ApmConst.AudioProfiles.AVRCP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.VCP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.VCP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            } else if (mAudioProfile == ApmConst.AudioProfiles.VCP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.AVRCP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.AVRCP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            }
                            break;
                        case ApmConst.AudioFeatures.CALL_VOLUME_CONTROL:
                            if(mAudioProfile == ApmConst.AudioProfiles.HFP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.VCP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.VCP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            } else if (mAudioProfile == ApmConst.AudioProfiles.VCP) {
                                if((mConnectedProfileBitMap & ApmConst.AudioProfiles.HFP) > 0) {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.HFP;
                                } else {
                                    mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                                }
                            }
                            break;
                        default:
                            mAciveProfileArray[mAudioFeature] = ApmConst.AudioProfiles.NONE;
                    }
                }
            }

            mActiveProfileMap.put(device, mAciveProfileArray);
            Log.d(LOGTAG, "profileConnectionUpdate: supported Profiles for the device " + device
                                    + " val " + Integer.toHexString(mSupportedProfileBitMap));
            Log.d(LOGTAG, "profileConnectionUpdate: connected Profiles for the device " + device
                                    + " val " + Integer.toHexString(mConnectedProfileBitMap));

            mConnectedProfileMap.put(device, mConnectedProfileBitMap);
            mSupportedProfileMap.put(device, mSupportedProfileBitMap);
        }
    }

    public boolean isProfileConnected(BluetoothDevice device, Integer mAudioProfile) {
        if (device == null) return false;
        int mConnectedProfileBitMap = mConnectedProfileMap.get(device);
        Log.d(LOGTAG, "isProfileConnected: device: " + device
               + " mAudioProfile: " + mAudioProfile + " mConnectedProfileMap: " + mConnectedProfileBitMap);

        return ((mConnectedProfileBitMap & mAudioProfile) == mAudioProfile);
    }

    public void setActiveProfile(BluetoothDevice device, Integer mAudioFeature, Integer mAudioProfile) {
        int [] mAciveProfileArray;
        Log.d(LOGTAG, "setActiveProfile: device : " + device + " AudioProfile "
            + mAudioProfile + " AudioFeature " + mAudioFeature);
        synchronized (mLock) {
            if(!mActiveProfileMap.containsKey(device)) {
                Log.d(LOGTAG, "setActiveProfile: intialize the active profile map for the device "
                       + device);
                mAciveProfileArray = new int[ApmConst.AudioFeatures.MAX_AUDIO_FEATURES];
                Arrays.fill(mAciveProfileArray, ApmConst.AudioProfiles.NONE);
                mActiveProfileMap.put(device, mAciveProfileArray);
            } else {
                mAciveProfileArray = mActiveProfileMap.get(device);
            }
            mAciveProfileArray[mAudioFeature] = mAudioProfile;
            mActiveProfileMap.put(device, mAciveProfileArray);
        }
    }

    static int getLeMediaProfiles() {
        return LeMediaProfiles;
    }

    static int getLeCallProfiles() {
        return LeCallProfiles;
    }

    public synchronized void handleDeviceShutdown() {
        Log.d(LOGTAG, "handleDeviceShutdown: started");

        //store the supported profiles for the bonded devices
        SharedPreferences.Editor pref = getSupportedProfileMap().edit();
        for (BluetoothDevice mBluetoothDevice : mSupportedProfileMap.keySet()) {
            int mSupportedProfilesVal = mSupportedProfileMap.get(mBluetoothDevice);
            Log.d(LOGTAG, "cleanup: supported Profiles for the device " + mBluetoothDevice
                                   + " val = " + Integer.toHexString(mSupportedProfilesVal));
            if(mBluetoothDevice.getBondState() == BluetoothDevice.BOND_BONDED) {
                pref.putInt(mBluetoothDevice.getAddress(), mSupportedProfilesVal);
            }
        }
        pref.apply();
        mSupportedProfileMap.clear();
        mActiveProfileMap.clear();
        mConnectedProfileMap.clear();

        Log.d(LOGTAG, "handleDeviceShutdown: Done");
    }

    public synchronized void cleanup () {
        if(DPMSingleInstance == null) {
            Log.w(LOGTAG, "cleanup called without initialization, Returning");
            return;
        }

        Log.d(LOGTAG, "cleanup: started");

        //store the supported profiles for the bonded devices
        SharedPreferences.Editor pref = getSupportedProfileMap().edit();
        for (BluetoothDevice mBluetoothDevice : mSupportedProfileMap.keySet()) {
            int mSupportedProfilesVal = mSupportedProfileMap.get(mBluetoothDevice);
            Log.d(LOGTAG, "cleanup: supported Profiles for the device " + mBluetoothDevice
                                   + " val = " + Integer.toHexString(mSupportedProfilesVal));
            if(mBluetoothDevice.getBondState() == BluetoothDevice.BOND_BONDED) {
                pref.putInt(mBluetoothDevice.getAddress(), mSupportedProfilesVal);
            }
        }
        pref.apply();
        mSupportedProfileMap.clear();
        mActiveProfileMap.clear();
        mConnectedProfileMap.clear();
        DPMSingleInstance = null;
        mContext.unregisterReceiver(mDeviceProfileMapReceiver);

        Log.d(LOGTAG, "cleanup: Done");
    }
}
