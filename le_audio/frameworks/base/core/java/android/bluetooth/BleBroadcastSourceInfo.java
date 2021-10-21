 /*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 */
package android.bluetooth;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.IBluetoothGatt;
import android.bluetooth.IBluetoothManager;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Retention;
import android.annotation.IntDef;
import android.compat.annotation.UnsupportedAppUsage;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;
import java.util.Objects;
import android.util.Log;
import java.util.List;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.HashMap;

/**
 * This class provides methods to get various information of Broadcast
 * source information stored in remote. Users can call get/set methods
 * enquire the required information
 *
 * <p>This also acts as general data structure for updating the Broadcast
 * source information
 * This class is used to input the User provided data for below operations
 * {@link BleBroadcastAudioScanAssistManager#addBroadcastSource},
 * {@link BleBroadcastAudioScanAssistManager#updateBroadcastSource} and
 * {@link BleBroadcastAudioScanAssistManager#setBroadcastCode}
 *
 * <p>This is also used to pack all Broadcast source information as part of {@link #ACTION_BROADCAST_RECEIVER_STATE}
 * Intent. User can retrive the {@link BleBroadcastSourceInfo} using {@link BleBroadcastSourceInfo#EXTRA_RECEIVER_STATE}
 * extra field
 * @hide
 */
public final class BleBroadcastSourceInfo implements Parcelable {

    private static final String TAG = "BleBroadcastSourceInfo";
    private static final boolean BASS_DBG = Log.isLoggable(TAG, Log.VERBOSE);

    /** @hide
     * @deprecated
     */
    @Deprecated
    @IntDef(prefix = "BROADCAST_ASSIST_ADDRESS_TYPE_", value = {
           BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC,
           BROADCAST_ASSIST_ADDRESS_TYPE_RANDOM
    })
    @Retention(RetentionPolicy.SOURCE)
    public @interface BroadcastAssistAddressType {}

    /**
     * Address Type of the LE Broadcast Audio Source Device
     * Specifies whether LE Broadcast Audio Source device using public OR
     * random address for the LE Audio broadcasts
     *
     * @deprecated
     */
    @Deprecated
    public static final int BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC = 0;
    /**
     * Address Type of the LE Broadcast Audio Source Device
     * Specifies whether LE Broadcast Audio Source device using public OR
     * random address for the LE Audio broadcasts
     *
     * @deprecated
     */
    @Deprecated
    public static final int BROADCAST_ASSIST_ADDRESS_TYPE_RANDOM = 1;
     /**
     * Address Type of the LE Broadcast Audio Source Device
     * Specifies whether LE Broadcast Audio Source device using public PR
     * random address for the LE Audio broadcasts
     *
     * @deprecated
     */
    @Deprecated
    public static final int BROADCAST_ASSIST_ADDRESS_TYPE_INVALID = 0xFFFF;

    /** @hide */
    @IntDef(prefix = "BROADCAST_ASSIST_PA_SYNC_STATE_", value = {
           BROADCAST_ASSIST_PA_SYNC_STATE_IDLE,
           BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ,
           BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC,
           BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL,
           BROADCAST_ASSIST_PA_SYNC_STATE_NO_PAST
    })
    @Retention(RetentionPolicy.SOURCE)
    public @interface BroadcastAssistMetadataSyncState {}

    /**
     * Meta data Sync State
     * Broadcast receiver sync state w.r.t PA. State IDLE specifies that broadcast
     * receiver is not able to sync the Metada/PA
     */
    public static final int BROADCAST_ASSIST_PA_SYNC_STATE_IDLE = 0;
    /**
     * Meta data Sync State
     * Broadcast receiver sync state w.r.t PA. State SYNCINFO REQ specifies that broadcast
     * receiver requesting for SYNCINFO from the Scan Offloader to synchronie
     * to Metadata/PA
     */
    public static final int BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ = 1;
    /**
     * Meta data Sync State
     * Broadcast receiver sync state w.r.t PA. State INSYNC specifies that broadcast
     * receiver in sync with to Metadata/PA.
     */
    public static final int BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC = 2;
    /**
     * Meta data Sync State
     * Broadcast receiver sync state w.r.t PA. State INSYNC specifies that broadcast
     * receiver is failed to sync with Metadata/PA.
     */
    public static final int BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL = 3;
    /**
     * Meta data Sync State
     * Broadcast receiver sync state w.r.t PA. State SYNC NOPAST denotes that broadcast
     * receiver needs PAST procedure to sync with Metadata.
     */
    public static final int BROADCAST_ASSIST_PA_SYNC_STATE_NO_PAST = 4;
    /**
     * Meta data Sync State
     * Broadcast receiver sync state w.r.t PA. State SYNC NOPAST denotes that broadcast
     * receiver needs PAST procedure to sync with Metadata.
     */
    public static final int BROADCAST_ASSIST_PA_SYNC_STATE_INVALID = 0xFFFF;

    /** @hide */
    @IntDef(prefix = "BROADCAST_ASSIST_AUDIO_SYNC_STATE_", value = {
           BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED,
           BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED
    })
    @Retention(RetentionPolicy.SOURCE)
    public @interface BroadcastAssistAudioSyncState {}

    /**
     * Broadcast Audio stream Sync State
     * Broadcast receiver sync state w.r.t Broadcast Audio stream BIS. denotes
     * receiver is not synchronized to LE Audio BIS
     */
    public static final int BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED = 0;
    /**
     * Broadcast Audio stream Sync State
     * Broadcast receiver sync state w.r.t Broadcast Audio stream BIS. denotes
     * receiver is not synchronized to LE Audio BIS
     */
    public static final int BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED = 1;
    /**
     * Broadcast Audio stream Sync State
     * Broadcast receiver sync state w.r.t Broadcast Audio stream BIS. denotes
     * receiver is not synchronized to LE Audio BIS
     */
    public static final int BROADCAST_ASSIST_AUDIO_SYNC_STATE_INVALID = 0xFFFF;


    /** @hide */
    @IntDef(prefix = "BROADCAST_ASSIST_ENC_STATE_", value = {
           BROADCAST_ASSIST_ENC_STATE_UNENCRYPTED,
           BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED,
           BROADCAST_ASSIST_ENC_STATE_DECRYPTING
    })
    @Retention(RetentionPolicy.SOURCE)
    public @interface BroadcastAssistEncryptionState {}
   /**
    * Encryption Status at the LE Audio broadcast receiver side
    * UNENCRYPTED denoted that broadcast receiver is in sync with an uncrypted
    * broadcasted audio
    */
    public static final int BROADCAST_ASSIST_ENC_STATE_UNENCRYPTED = 0;
   /**
    * Encryption Status at the LE Audio broadcast receiver side
    * PIN_NEEDED denote that the Broadcast receiver needs broadcast PIN
    * to sync and listen to Broadcasted Audio
    */
    public static final int BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED = 1;
   /**
     * Encryption Status at the LE Audio broadcast receiver side
     * state DECRYPTING denote that the Broadcast receiver is able to decrypt
     * and listen to the Broadcasted Audio
     */
    public static final int BROADCAST_ASSIST_ENC_STATE_DECRYPTING = 2;
   /**
     * Encryption Status at the LE Audio broadcast receiver side
     * state BADCODE denote that the Broadcast receiver has got bad code
     * and not able decrypt
     * Incorrect code that Scan delegator tried to decrypt can be retrieved from
     *
     */
    public static final int BROADCAST_ASSIST_ENC_STATE_BADCODE = 3;
   /**
     * Encryption Status at the LE Audio broadcast receiver side
     * state DECRYPTING denote that the Broadcast receiver is able to decrypt
     * and listen to the Broadcasted Audio
     */
    public static final int BROADCAST_ASSIST_ENC_STATE_INVALID = 0xFFFF;

    /*
     * Invalid Broadcast source Information Id
     */
    public static final byte BROADCAST_ASSIST_INVALID_SOURCE_ID = (byte)0x00;
    /*
     * Invalid Broadcaster Identifier of the given Broadcast Source
     */
    public static final int BROADCASTER_ID_INVALID = 0xFFFF;
    /**
     * Used as an int extra field in {@link BleBroadcastAudioScanAssistManager#ACTION_BROADCAST_RECEIVER_STATE}
     * intent notifys the Broadcast Source Information to Application layer
     *
     * <p> Source Info object can be extracted using this extra field at Application layer
     *
     * This is used to read the {@link BleBroadcastSourceInfo } parcelable object
     * @hide
     */
    public static final String EXTRA_SOURCE_INFO = "android.bluetooth.device.extra.SOURCE_INFO";
    /**
     * Used as an int extra field in {@link BleBroadcastAudioScanAssistManager#ACTION_BROADCAST_RECEIVER_STATE}
     * intent Broadcast Source Information to Application layer
     *
     * <p> Index of the Source Info object can be extracted using this extra field at Application layer
     *
     * This is used to read the {@link BleBroadcastSourceInfo } parcelable object
     * @hide
     */
    public static final String EXTRA_SOURCE_INFO_INDEX = "android.bluetooth.device.extra.SOURCE_INFO_INDEX";
    /**
     * Used as an int extra field in {@link BleBroadcastAudioScanAssistManager#ACTION_BROADCAST_RECEIVER_STATE}
     * intent notifys the Broadcast Source Information to Application layer
     *
     * <p> Maximm number of the Broadcast Source Information that given broadcast receiver can hold, can be extracted using
     * this extra field at Application layer
     *
     * @hide
     */
    public static final String EXTRA_MAX_NUM_SOURCE_INFOS = "android.bluetooth.device.extra.MAX_NUM_SOURCE_INFOS";
    private byte mSourceId;
    private @BroadcastAssistAddressType int mSourceAddressType;
    private BluetoothDevice mSourceDevice;
    private byte mSourceAdvSid;
    private int mBroadcasterId;
    private @BroadcastAssistMetadataSyncState int mMetaDataSyncState;
    private @BroadcastAssistAudioSyncState int mAudioSyncState;
    private Map<Integer, Integer> mAudioBisIndexList = new HashMap <Integer, Integer>();
    private @BroadcastAssistEncryptionState int mEncyptionStatus;
    private Map<Integer, byte[]> mMetadataList = new HashMap<Integer, byte[]>();
    private String mBroadcastCode;
    private byte[] mBadBroadcastCode;
    private byte mNumSubGroups;
    private static final int BIS_NO_PREF = 0xFFFFFFFF;
    private static final int BROADCAST_CODE_SIZE = 16;

    /**
     * Constructor to create an Empty object of {@link BleBroadcastSourceInfo } with given source Id,
     * which contains, Broadcast reciever state information for Broadcast Assistant Usecases.
     *
     * This is mainly used to represent the Empty Broadcast source entries
     *
     *  @param sourceId Source Id for this broadcast source info object
     *
     *  @deprecated
     *  @hide
     */
    @Deprecated
    public BleBroadcastSourceInfo (byte sourceId) {
       mSourceId = sourceId;
       mMetaDataSyncState = BROADCAST_ASSIST_PA_SYNC_STATE_INVALID;
       mAudioSyncState = BROADCAST_ASSIST_AUDIO_SYNC_STATE_INVALID;
       mSourceAddressType = BROADCAST_ASSIST_ADDRESS_TYPE_INVALID;
       mSourceDevice = null;
       mSourceAdvSid = (byte)0x00;
       mEncyptionStatus = BROADCAST_ASSIST_ENC_STATE_INVALID;
       mBroadcastCode = null;
       mBadBroadcastCode = null;
       mNumSubGroups = 0;
       mBroadcasterId = BROADCASTER_ID_INVALID;
    }
    /**
     * Constructor to create an object of {@link BleBroadcastSourceInfo } which contains
     * Broadcast reciever state information for Broadcast Assistant Usecases.
     * This is  mainly used for input purpose of {@link BleBroadcastAudioScanAssistManager#addBroadcastSource}
     * operation
     *
     *  @param audioSource BluetoothDevice object whcih is selected as Broadcast source
     *  @param advSid advertising Sid of the Broadcast source device for which reciever synchronized with.
     *  @param addressType type of address. This can be be one of {@link #BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC} or
     *                                              {@link #BROADCAST_ASSIST_ADDRESS_TYPE_RANDOM}
     *  @param metadataSyncState sync status of metadata at the receiver side from this Broadcast source. This can
     *                           be one of {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IDLE}, {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ},
     *                           {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC},
     *                           {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL} OR  {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_NO_PAST}
     *  @param audioSyncState Audio sync status of metadata at the receiver side from this broadcast source. This can be
     *                        one of {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED} OR
     *                        {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED}
     *  @param audioBisIndex Audio BIS index for what Broadcast reciever synchronized with
     *  @param metadataLength Length of the  metadata field
     *  @prama metadata metadata information about the type Broadcast information being synchronized at receiver side
     *
     *
     *  @hide
     */
    /*package*/ BleBroadcastSourceInfo (BluetoothDevice audioSource,
                            byte advSid,
                            @BroadcastAssistAddressType int addressType,
                            @BroadcastAssistMetadataSyncState int metadataSyncstate,
                            @BroadcastAssistAudioSyncState int audioSyncstate,
                            List<BleBroadcastSourceChannel> selectedBISIndicies
                            ) {
       mMetaDataSyncState =  metadataSyncstate;
       mAudioSyncState = audioSyncstate;
       mSourceAddressType = addressType;
       mSourceDevice = audioSource;
       mSourceAdvSid = advSid;
       mBroadcasterId = BROADCASTER_ID_INVALID;
       if (selectedBISIndicies == null) {
           BASS_Debug(TAG, "selectedBISIndiciesList is null");
       } else {
           for (int i=0; i<selectedBISIndicies.size(); i++) {
             if (selectedBISIndicies.get(i).getStatus() == true) {
                  Integer audioBisIndex = 0;
                 int subGroupId = selectedBISIndicies.get(i).getSubGroupId();
                 if (mAudioBisIndexList.containsKey(subGroupId)) {
                     audioBisIndex = mAudioBisIndexList.get(subGroupId);
                 }
                 audioBisIndex = audioBisIndex | (1<<selectedBISIndicies.get(i).getIndex());
                 BASS_Debug(TAG, "index" + selectedBISIndicies.get(i).getIndex() + "is set");
                 mAudioBisIndexList.put(subGroupId, audioBisIndex);
             }
           }
       }

       //not valid info
       mSourceId = BROADCAST_ASSIST_INVALID_SOURCE_ID;
       mEncyptionStatus = BROADCAST_ASSIST_ENC_STATE_INVALID;
       mBroadcastCode = null;
       mBadBroadcastCode = null;
       mNumSubGroups = 0;
    }

    /**
     * Constructor override  to create an object of {@link BleBroadcastSourceInfo } which contains
     * Broadcast reciever state information for Broadcast Assistant Usecases.
     *
     * This is mainly used for output purpose to create an object from the receiver state information
     * read from the remote BASS server. This will be packed and broadcasted as an Intent using
     * {@link #ACTION_BROADCAST_RECEIVER_STATE}
     *
     *  @param audioSource BluetoothDevice object whcih is selected as Broadcast source
     *  @param sourceId Source Id for this broadcast source info object
     *  @param advSid advertising Sid of the Broadcast source device for which reciever synchronized with
     *  @param addressType type of address. This can be be one of {@link #BLE_ASSIST_ADDRESS_TYPE_PUBLIC} or
     *                                              {@link #BLE_ASSIST_ADDRESS_TYPE_RANDOM}
     *  @param metadataSyncState sync status of metadata at the receiver side from this Broadcast source. This can
     *                           be one of {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IDLE}, {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ},
     *                           {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC},
     *                           {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL} OR  {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_NO_PAST}
     *  @param audioSyncState Audio sync status of metadata at the receiver side from this broadcast source. This can be
     *                        one of {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED} OR
     *                        {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED}
     *  @param encryptionStatus Encryotion state at Broadcast receiver. This can be one of {@link #BROADCAST_ASSIST_ENC_STATE_UNENCRYPTED},
                                {@link #BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED} OR {@link #BROADCAST_ASSIST_ENC_STATE_DECRYPTING}
     *  @param audioBisIndex Audio BIS index for what Broadcast reciever synchronized with
     *  @param metadataLength Length of the  metadata field
     *  @prama metadata metadata information about the type Broadcast information being synchronized at receiver side
     *
     *
     *  @deprecated
     *  @hide
     */
    @Deprecated
    public BleBroadcastSourceInfo (BluetoothDevice audioSource,
                            byte sourceId,
                            byte advSid,
                            int broadcasterId,
                            @BroadcastAssistAddressType int addressType,
                            @BroadcastAssistMetadataSyncState int metadataSyncstate,
                            @BroadcastAssistEncryptionState int encryptionStatus,
                            byte[] badCode,
                            byte numSubGroups,
                            @BroadcastAssistAudioSyncState int audioSyncstate,
                            Map<Integer, List<BleBroadcastSourceChannel>> selectedBISIndiciesList,
                            Map<Integer, byte[]> metadataList
                            ) {
       mSourceId = sourceId;
       mSourceAddressType = addressType;
       mSourceDevice = audioSource;
       mSourceAdvSid = advSid;
       mBroadcasterId = broadcasterId;
       mMetaDataSyncState =  metadataSyncstate;
       mAudioSyncState = audioSyncstate;
       mEncyptionStatus = encryptionStatus;
       if (badCode != null) {
           mBadBroadcastCode = new byte[BROADCAST_CODE_SIZE];
           System.arraycopy(badCode, 0, mBadBroadcastCode, 0, mBadBroadcastCode.length);
       }
       mNumSubGroups = numSubGroups;
       int audioBisIndex = 0;
       if (selectedBISIndiciesList != null) {
           for (Map.Entry<Integer, List<BleBroadcastSourceChannel>> entry : selectedBISIndiciesList.entrySet()) {
               List<BleBroadcastSourceChannel> selectedBISIndicies = entry.getValue();
                  if (selectedBISIndicies == null) {
                   //do nothing
                   BASS_Debug(TAG, "selectedBISIndiciesList is null");
                  } else {
                      for (int i=0; i<selectedBISIndicies.size(); i++) {
                          if (selectedBISIndicies.get(i).getStatus() == true) {
                           audioBisIndex = audioBisIndex | (1<<selectedBISIndicies.get(i).getIndex());
                              BASS_Debug(TAG, "index" + selectedBISIndicies.get(i).getIndex() + "is set");
                          }
                      }
                  }
               BASS_Debug(TAG, "subGroupId:" + entry.getKey() + "audioBisIndex" + audioBisIndex);
               mAudioBisIndexList.put(entry.getKey(), audioBisIndex);
           }
       }
       if (metadataList != null) {
           for (Map.Entry<Integer, byte[]> entry : metadataList.entrySet()) {
               byte[] metadata = entry.getValue();
               if (metadata != null && metadata.length != 0) {
                   byte[] mD = new byte[metadata.length];
                   System.arraycopy(metadata, 0, mD, 0, metadata.length);
               }
               mMetadataList.put(entry.getKey(), metadata);
               }
           }
    }

    /**
     * Constructor override  to create an object of {@link BleBroadcastSourceInfo } which contains
     * Broadcast reciever state information for Broadcast Assistant Usecases.
     *
     * This is mainly used for output purpose to create an object from the receiver state information
     * read from the remote BASS server. This will be packed and broadcasted as an Intent using
     * {@link #ACTION_BROADCAST_RECEIVER_STATE}
     *
     *  @param audioSource BluetoothDevice object whcih is selected as Broadcast source
     *  @param advSid advertising Sid of the Broadcast source device for which reciever synchronized with
     *  @param addressType type of address. This can be be one of {@link #BLE_ASSIST_ADDRESS_TYPE_PUBLIC} or
     *                                              {@link #BLE_ASSIST_ADDRESS_TYPE_RANDOM}
     *  @param metadataSyncState sync status of metadata at the receiver side from this Broadcast source. This can
     *                           be one of {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IDLE}, {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ},
     *                           {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC},
     *                           {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL} OR  {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_NO_PAST}
     *  @param audioSyncState Audio sync status of metadata at the receiver side from this broadcast source. This can be
     *                        one of {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED} OR
     *                        {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED}
     *  @param encryptionStatus Encryotion state at Broadcast receiver. This can be one of {@link #BROADCAST_ASSIST_ENC_STATE_UNENCRYPTED},
     *                          {@link #BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED} OR {@link #BROADCAST_ASSIST_ENC_STATE_DECRYPTING}
     *  @param audioBisIndex Audio BIS index for what Broadcast reciever synchronized with
     *  @param metadataLength Length of the  metadata field
     *  @prama metadata metadata information about the type Broadcast information being synchronized at receiver side
     *  @param broadcastCode Numeric Character String maximum of 16 characters in length, which serves as broadcast PIN code
     *
     *  @hide
     */
    /*package*/ BleBroadcastSourceInfo (BluetoothDevice device,
                            byte sourceId,
                            byte advSid,
                            @BroadcastAssistAddressType int addressType,
                            @BroadcastAssistMetadataSyncState int metadataSyncstate,
                            @BroadcastAssistAudioSyncState int audioSyncstate,
                            List<BleBroadcastSourceChannel> selectedBISIndicies,
                            @BroadcastAssistEncryptionState int encryptionStatus,
                            String broadcastCode) {
       mSourceId = sourceId;
       mMetaDataSyncState =  metadataSyncstate;
       mAudioSyncState = audioSyncstate;
       mEncyptionStatus = encryptionStatus;
       mSourceAddressType = addressType;
       mSourceDevice = device;
       mSourceAdvSid = advSid;
       mBroadcasterId = BROADCASTER_ID_INVALID;
       if (selectedBISIndicies == null) {
           BASS_Debug(TAG, "selectedBISIndiciesList is null");
       } else {
           for (int i=0; i<selectedBISIndicies.size(); i++) {
             if (selectedBISIndicies.get(i).getStatus() == true) {
                  Integer audioBisIndex = 0;
                 int subGroupId = selectedBISIndicies.get(i).getSubGroupId();
                 if (mAudioBisIndexList.containsKey(subGroupId)) {
                     audioBisIndex = mAudioBisIndexList.get(subGroupId);
                 }
                 audioBisIndex = audioBisIndex | (1<<selectedBISIndicies.get(i).getIndex());
                 BASS_Debug(TAG, "index" + selectedBISIndicies.get(i).getIndex() + "is set");
                 BASS_Debug(TAG, "audioBisIndex" + audioBisIndex);
                 mAudioBisIndexList.put(subGroupId, audioBisIndex);
             }
           }

       }
       /*if (metadata != null && metadata.length != 0) {
           mMetadata = new byte[metadata.length];
           System.arraycopy(metadata, 0, mMetadata, 0, metadata.length);
       }*/
       mBroadcastCode = broadcastCode;
       mBadBroadcastCode = null;
       mNumSubGroups = 0;
    }

    /*package*/ BleBroadcastSourceInfo (BluetoothDevice device,
                                byte sourceId,
                                byte advSid,
                                int broadcasterId,
                                @BroadcastAssistAddressType int addressType,
                                @BroadcastAssistMetadataSyncState int metadataSyncstate,
                                @BroadcastAssistAudioSyncState int audioSyncstate,
                                @BroadcastAssistEncryptionState int encryptionStatus,
                                String broadcastCode,
                                byte[] badCode,
                                byte numSubGroups,
                                Map<Integer, Integer> bisIndiciesList,
                                Map<Integer, byte[]> metadataList
                                ) {
           mSourceId = sourceId;
           mMetaDataSyncState =  metadataSyncstate;
           mAudioSyncState = audioSyncstate;
           mEncyptionStatus = encryptionStatus;
           mSourceAddressType = addressType;
           mSourceDevice = device;
           mSourceAdvSid = advSid;
           mBroadcasterId = broadcasterId;
           mBroadcastCode = broadcastCode;
           if (badCode != null && badCode.length != 0) {
               mBadBroadcastCode= new byte[badCode.length];
               System.arraycopy(badCode, 0, mBadBroadcastCode, 0, badCode.length);
           }
           mNumSubGroups = numSubGroups;
           mAudioBisIndexList = new HashMap<Integer, Integer> (bisIndiciesList);
           mMetadataList = new HashMap<Integer, byte[]> (metadataList);
        }

    @Override
    public boolean equals(Object o) {
        if (o instanceof BleBroadcastSourceInfo) {
            BleBroadcastSourceInfo other = (BleBroadcastSourceInfo) o;
            BASS_Debug(TAG, "other>>  " + o.toString());
            BASS_Debug(TAG, "local>>  " + toString());
            return (other.mSourceId == mSourceId
                    && other.mMetaDataSyncState == mMetaDataSyncState
                    && other.mAudioSyncState == mAudioSyncState
                    && other.mSourceAddressType == mSourceAddressType
                    && other.mSourceDevice == mSourceDevice
                    && other.mSourceAdvSid == mSourceAdvSid
                    && other.mEncyptionStatus == mEncyptionStatus
                    && other.mBroadcastCode == mBroadcastCode
                    && other.mBroadcasterId == mBroadcasterId
                    );
        }
        return false;
    }

    public boolean isEmptyEntry()  {
        boolean ret = false;
        if (mMetaDataSyncState == (int)BROADCAST_ASSIST_PA_SYNC_STATE_INVALID &&
            mAudioSyncState == (int)BROADCAST_ASSIST_AUDIO_SYNC_STATE_INVALID &&
            mSourceAddressType == (int)BROADCAST_ASSIST_ADDRESS_TYPE_INVALID &&
            mSourceDevice == null &&
            mSourceAdvSid == (byte)0 &&
            mEncyptionStatus == (int)BROADCAST_ASSIST_ENC_STATE_INVALID
            ) {
                ret = true;
            }
        BASS_Debug(TAG, "isEmptyEntry returns: " + ret);
        return ret;
    }

    public boolean matches(BleBroadcastSourceInfo srcInfo) {
        boolean ret = false;
        if (srcInfo == null) {
            ret = false;
        } else {
            if (mSourceDevice == null) {
                if (mSourceAdvSid == srcInfo.getAdvertisingSid() &&
                   mSourceAddressType == srcInfo.getAdvAddressType()) {
                      ret = true;
                }
            } else {
                if (mSourceDevice.equals(srcInfo.getSourceDevice()) &&
                   mSourceAdvSid == srcInfo.getAdvertisingSid() &&
                   mSourceAddressType == srcInfo.getAdvAddressType() &&
                   mBroadcasterId == srcInfo.getBroadcasterId()) {
                      ret = true;
                }
            }
        }
        BASS_Debug(TAG, "matches returns: " + ret);
        return ret;
    }

    @Override
    public int hashCode() {
        return Objects.hash(mSourceId, mMetaDataSyncState, mAudioSyncState,
                mSourceAddressType, mSourceDevice, mSourceAdvSid,
                mEncyptionStatus, mBroadcastCode);
    }

    @Override
    public int describeContents() {
        return 0;
    }
    @Override
    public String toString() {
        return "{BleBroadcastSourceInfo : mSourceId" + mSourceId
               + " sourceDevice: " + mSourceDevice
               + " addressType: " + mSourceAddressType
               + " mSourceAdvSid:" + mSourceAdvSid
               + " mMetaDataSyncState:" + mMetaDataSyncState
               + " mAudioSyncState" + mAudioSyncState
               + " mEncyptionStatus" + mEncyptionStatus
               + " mBadBroadcastCode" + mBadBroadcastCode
               + " mNumSubGroups" + mNumSubGroups
               + " mBroadcastCode" + mBroadcastCode
               + " mAudioBisIndexList" + mAudioBisIndexList
               + " mMetadataList" + mMetadataList
               + " mBroadcasterId" + mBroadcasterId
               + "}";
    }

    /**
     * Gets the Source Id of the BleBroadcastSourceInfo Object
     *
     * @return byte representing the Source Id of the Broadcast Source Info Object
     *          {@link #BROADCAST_ASSIST_INVALID_SOURCE_ID} in case if this field is not valid
     * @hide
     */
    public byte getSourceId () {
        return mSourceId;
    }

    /**
     * Sets the Source Id of the BleBroadcastSourceInfo Object
     *
     * @param byte source Id for the BleBroadcastSourceInfo Object
     *
     * @hide
     */
    public void setSourceId (byte sourceId) {
        mSourceId = sourceId;
    }

    /**
     * Sets the Broadcast source device for the BleBroadcastSourceInfo Object
     *
     * @param BluetoothDevice which need to be set as Broadcast source device
     * @hide
     */
    public void setSourceDevice(BluetoothDevice sourceDevice) {
        mSourceDevice = sourceDevice;
    }

    /**
     * Gets the Broadcast source Device object from the BleBroadcastSourceInfo Object
     *
     * @return BluetoothDevice object for Broadcast source device
     * @hide
     */
    public BluetoothDevice getSourceDevice () {
        return mSourceDevice;
    }

    /**
     * Sets the address type of the Broadcast source advertisement for the BleBroadcastSourceInfo Object
     *
     * @param byte addressType, this can be one of {@link #BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC} OR {@link #BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC}
     * @hide
     */
     public void setAdvAddressType(int addressType) {
        mSourceAddressType = addressType;
    }

    /**
     * Gets the address type of the Broadcast source advertisement for the BleBroadcastSourceInfo Object
     *
     * @return byte addressType, this can be one of {@link #BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC} OR {@link #BROADCAST_ASSIST_ADDRESS_TYPE_PUBLIC}
     * @hide
     *
     * @deprecated
     */
    @UnsupportedAppUsage
    @Deprecated
    public int getAdvAddressType () {
        return mSourceAddressType;
    }

    /**
     * Sets the advertising Sid of the Broadcast source advertisement for the BleBroadcastSourceInfo Object
     *
     * @param byte advertising Sid value
     * @hide
     */
    public void setAdvertisingSid(byte advSid) {
        mSourceAdvSid = advSid;
    }

    /**
     * Gets the advertising Sid of the Broadcast source advertisement for the BleBroadcastSourceInfo Object
     *
     * @return byte advertising Sid value
     * @hide
     */
    public byte getAdvertisingSid () {
        return mSourceAdvSid;
    }

    /**
     * Gets the Broadcast Id of the Broadcast source of the BleBroadcastSourceInfo Object
     *
     * @return int broadcast source Identifier
     * @hide
     */
    public int getBroadcasterId () {
        return mBroadcasterId;
    }

    /**
     * Sets the Metadata sync status at the Broadcast receiver side for the BleBroadcastSourceInfo Object
     *
     * @param BroadcastAssistMetadataSyncState representing the state of Meta data sync status. this can be one of
     *                       {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IDLE}, {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ},
     *                       {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC},
     *                       {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL} OR  {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_NO_PAST}
     *
     * @hide
     */
    /*package*/ void setMetadataSyncState(@BroadcastAssistMetadataSyncState int metadataSyncState) {
        mMetaDataSyncState = metadataSyncState;
    }

    /**
     * Gets the Metadata sync status at the Broadcast receiver side from the BleBroadcastSourceInfo Object
     *
     * @return BroadcastAssistMetadataSyncState representing the state of Meta data sync status. this can be one of
     *                       {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IDLE}, {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNCINFO_REQ},
     *                       {@link #BROADCAST_ASSIST_PA_SYNC_STATE_IN_SYNC},
     *                       {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_FAIL} OR  {@link #BROADCAST_ASSIST_PA_SYNC_STATE_SYNC_NO_PAST}
     *
     * @hide
     */
    public  @BroadcastAssistMetadataSyncState int getMetadataSyncState () {
        return mMetaDataSyncState;
    }

    /**
     * Sets the Audio sync status at the Broadcast receiver side for the BleBroadcastSourceInfo Object
     *
     * @param BroadcastAssistAudioSyncState representing the state of Meta data sync status. this can be one of
     *                         {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED} OR
     *                        {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED}
     *
     * @hide
     */
    /*package*/ void setAudioSyncState(@BroadcastAssistAudioSyncState int audioSyncState) {
        mAudioSyncState = audioSyncState;
    }

    /**
     * Gets the Audio sync status at the Broadcast receiver side from the BleBroadcastSourceInfo Object
     *
     * @return BroadcastAssistAudioSyncState representing the state of Meta data sync status. this can be one of
     *                           {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_NOT_SYNCHRONIZED} OR
     *                           {@link #BROADCAST_ASSIST_AUDIO_SYNC_STATE_SYNCHRONIZED}   *
     * @hide
     */
    public @BroadcastAssistAudioSyncState int getAudioSyncState () {
        return mAudioSyncState;
    }

    /**
     * Sets the Encryption status at the Broadcast receiver side for the BleBroadcastSourceInfo Object
     *
     * @param BroadcastAssistEncryptionState  representing the state of Meta data sync status. This can be one of
     *                           {@link #BROADCAST_ASSIST_ENC_STATE_UNENCRYPTED},
     *                           {@link #BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED}, {@link #BROADCAST_ASSIST_ENC_STATE_DECRYPTING}
     *                           Or {@link #BROADCAST_ASSIST_ENC_STATE_BADCODE}
     * @hide
     */
    /*package*/ void setEncryptionStatus(@BroadcastAssistEncryptionState int encryptionStatus) {
        mEncyptionStatus = encryptionStatus;
    }

    /**
     * Gets the Audio sync status at the Broadcast receiver side from the BleBroadcastSourceInfo Object
     *
     * @return BroadcastAssistEncryptionState  representing the state of Meta data sync status. This can be one of
     *                           {@link #BROADCAST_ASSIST_ENC_STATE_UNENCRYPTED},
     *                           {@link #BROADCAST_ASSIST_ENC_STATE_PIN_NEEDED} ,{@link #BROADCAST_ASSIST_ENC_STATE_DECRYPTING}
     *                           Or {@link #BROADCAST_ASSIST_ENC_STATE_BADCODE}
     * @hide
     */
    public @BroadcastAssistEncryptionState int getEncryptionStatus () {
        return mEncyptionStatus;
    }

    /**
     * Gets the Incorrect Broadcast code with which Scan delegator try
     * decrypt the Broadcast audio and failed
     *
     * This code is valid only if {@link #getEncryptionStatus} returns
     * {@link #BROADCAST_ASSIST_ENC_STATE_BADCODE}
     *
     * @param byte[] byte array containing bad broadcast value
     *               null if the current Encryptetion status is
     *                     not {@link #BROADCAST_ASSIST_ENC_STATE_BADCODE}
     *
     * @hide
     */
    public byte[] getBadBroadcastCode () {
        return mBadBroadcastCode;
    }

    /**
     * Gets the number of subgroups of the BleBroadcastSourceInfo Object
     *
     * @return byte number of subgroups
     * @hide
     *
     * @deprecated
     */
    @UnsupportedAppUsage
    @Deprecated
    public byte getNumberOfSubGroups () {
        return mNumSubGroups;
    }

    /**
     * Sets the Audio Broadcast channels to which receiver need to be synchronized with,
     * for BleBroadcastSourceInfo Object
     *
     *
     * @param int audioBis Index to which reciever need to be synchronized with
     * @hide
     */
    /*package*/ void setBroadcastChannelsSyncStatus(List<BleBroadcastSourceChannel> selectedBISIndicies) {
        if (selectedBISIndicies == null) {
            //set No preference
            BASS_Debug(TAG, "selectedBISIndiciesList is null");
            return;
        }
        for (int i=0; i<selectedBISIndicies.size(); i++) {
          if (selectedBISIndicies.get(i).getStatus() == true) {
              Integer audioBisIndex = 0;
              int subGroupId = selectedBISIndicies.get(i).getSubGroupId();
              if (mAudioBisIndexList.containsKey(subGroupId)) {
                 audioBisIndex = mAudioBisIndexList.get(subGroupId);
              }
              audioBisIndex = audioBisIndex | (1<<selectedBISIndicies.get(i).getIndex());
              BASS_Debug(TAG, "index" + selectedBISIndicies.get(i).getIndex() + "is set");
              mAudioBisIndexList.put(subGroupId, audioBisIndex);
          }
        }

    }
    /**
     * Gets the Broadcast channels index and the sync status from BleBroadcastSourceInfo Object
     * This maps the various broadcast source indicies and sync status of them
     *
     * @param int audio BIS index from the BleBroadcastSourceInfo object
     * @hide
     */
    public List<BleBroadcastSourceChannel> getBroadcastChannelsSyncStatus () {
        List<BleBroadcastSourceChannel> bcastIndicies = new ArrayList<BleBroadcastSourceChannel>();
        for (int i=0; i<mNumSubGroups; i++) {
            int bisIndexValue = mAudioBisIndexList.get(i);
            int index =0;
            while (bisIndexValue != 0) {
                if ((bisIndexValue&0x01) == 0x01) {
                    BleBroadcastSourceChannel bI =
                        new BleBroadcastSourceChannel(index, String.valueOf(index), true, i, mMetadataList.get(i));
                    bcastIndicies.add(bI);
                }
                bisIndexValue = bisIndexValue>>1;
                index++;
            }
        }

        BASS_Debug(TAG, "returning Bisindicies:" + bcastIndicies);
        return bcastIndicies;
    }

    @UnsupportedAppUsage
    @Deprecated
    public Map<Integer, Integer> getBisIndexList() {
        return mAudioBisIndexList;
    }

    /*package*/ void setBroadcastCode(String broadcastCode) {
        mBroadcastCode = broadcastCode;
    }

    @UnsupportedAppUsage
    @Deprecated
    public void setBroadcasterId(int broadcasterId) {
        mBroadcasterId = broadcasterId;
    }

    /**
     * Gets the broadcastCode value from BleBroadcastSourceInfo Object
     *
     * @param String broadcast code from the BleBroadcastSourceInfo object
     * @hide
     *
     * @deprecated
     */
    @UnsupportedAppUsage
    @Deprecated
    public String getBroadcastCode () {
        return mBroadcastCode;
    }

    private void writeMapToParcel(Parcel dest, Map<Integer, Integer> bisIndexList) {
        dest.writeInt(bisIndexList.size());
        for (Map.Entry<Integer, Integer> entry : bisIndexList.entrySet()) {
            dest.writeInt(entry.getKey());
            dest.writeInt(entry.getValue());
        }
    }

    private static void readMapFromParcel(Parcel in, Map<Integer, Integer> bisIndexList) {
        int size = in.readInt();

        for (int i = 0; i < size; i++) {
            Integer key = in.readInt();
            Integer value = in.readInt();
            bisIndexList.put(key, value);
        }
    }

    private void writeMetadataListToParcel(Parcel dest, Map<Integer, byte[]> metadataList) {
        dest.writeInt(metadataList.size());
        for (Map.Entry<Integer, byte[]> entry : metadataList.entrySet()) {
            dest.writeInt(entry.getKey());
            byte[] metadata = entry.getValue();
            if (metadata != null) {
                dest.writeInt(metadata.length);
                dest.writeByteArray(metadata);
            }
        }
    }

    private static void readMetadataListFromParcel(Parcel in, Map<Integer, byte[]> metadataList) {
        int size = in.readInt();

        for (int i = 0; i < size; i++) {
            Integer key = in.readInt();
            Integer metaDataLen = in.readInt();
            byte[] metadata = null;
            if (metaDataLen != 0) {
                metadata = new byte[metaDataLen];
                in.readByteArray(metadata);
            }
            metadataList.put(key, metadata);
        }
    }

    public static final @android.annotation.NonNull Parcelable.Creator<BleBroadcastSourceInfo> CREATOR =
            new Parcelable.Creator<BleBroadcastSourceInfo>() {
                public BleBroadcastSourceInfo createFromParcel(Parcel in) {

                    BASS_Debug(TAG, "createFromParcel>");
                    final byte sourceId = in.readByte();
                    final int sourceAddressType = in.readInt();
                    final BluetoothDevice sourceDevice = in.readTypedObject(
                             BluetoothDevice.CREATOR);
                    final byte sourceAdvSid = in.readByte();
                    final int broadcastId = in.readInt();
                    BASS_Debug(TAG, "broadcastId" + broadcastId);
                    final int metaDataSyncState = in.readInt();
                    final int audioSyncState = in.readInt();
                    BASS_Debug(TAG, "audioSyncState" + audioSyncState);
                    final int encyptionStatus = in.readInt();
                    final int badBroadcastLen = in.readInt();
                    byte[] badBroadcastCode = null;
                    if (badBroadcastLen > 0) {
                        badBroadcastCode = new byte[badBroadcastLen];
                        in.readByteArray(badBroadcastCode);
                    }
                    final byte numSubGroups = in.readByte();
                    final String broadcastCode = in.readString();
                    Map<Integer,Integer> bisIndexList = new HashMap <Integer, Integer>();
                    readMapFromParcel(in, bisIndexList);
                    Map<Integer,byte[]> metadataList = new HashMap <Integer, byte[]>();
                    readMetadataListFromParcel(in, metadataList);

                    BleBroadcastSourceInfo srcInfo = new BleBroadcastSourceInfo(sourceDevice, sourceId, sourceAdvSid, broadcastId,
                            sourceAddressType, metaDataSyncState,audioSyncState,
                            encyptionStatus, broadcastCode, badBroadcastCode, numSubGroups, bisIndexList, metadataList);
                    BASS_Debug(TAG, "createFromParcel:" + srcInfo);
                    return srcInfo;
                }

                public BleBroadcastSourceInfo[] newArray(int size) {
                    return new BleBroadcastSourceInfo[size];
                }
            };

    @Override
    public void writeToParcel(Parcel out, int flags) {
        BASS_Debug(TAG, "writeToParcel>");
        out.writeByte(mSourceId);
        out.writeInt(mSourceAddressType);
        out.writeTypedObject(mSourceDevice, 0);
        out.writeByte(mSourceAdvSid);
        out.writeInt(mBroadcasterId);
        out.writeInt(mMetaDataSyncState);
        out.writeInt(mAudioSyncState);
        out.writeInt(mEncyptionStatus);
        if (mBadBroadcastCode != null) {
            out.writeInt(mBadBroadcastCode.length);
            out.writeByteArray(mBadBroadcastCode);
        } else {
            //write ZERO to parcel to say no badBroadcastcode
            out.writeInt(0);
        }
        out.writeByte(mNumSubGroups);
        out.writeString(mBroadcastCode);
        writeMapToParcel(out, mAudioBisIndexList);
        writeMetadataListToParcel(out, mMetadataList);
        BASS_Debug(TAG, "writeToParcel:" + toString());
    }

    static void BASS_Debug(String TAG, String msg) {
        if (BASS_DBG) {
           Log.d(TAG, msg);
        }
    }

};

