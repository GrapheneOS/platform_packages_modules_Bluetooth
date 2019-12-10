/*
 * Copyright 2019 The Android Open Source Project
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

package com.android.bluetooth.btservice.storage;

import android.bluetooth.BluetoothA2dp;
import android.bluetooth.BluetoothA2dp.OptionalCodecsPreferenceStatus;
import android.bluetooth.BluetoothA2dp.OptionalCodecsSupportStatus;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothProtoEnums;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.provider.Settings;
import android.util.Log;
import android.util.StatsLog;

import com.android.bluetooth.Utils;
import com.android.bluetooth.btservice.AdapterService;
import com.android.internal.annotations.VisibleForTesting;

import com.google.common.collect.EvictingQueue;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * The active device manager is responsible to handle a Room database
 * for Bluetooth persistent data.
 */
public class DatabaseManager {
    private static final String TAG = "BluetoothDatabase";

    private AdapterService mAdapterService = null;
    private HandlerThread mHandlerThread = null;
    private Handler mHandler = null;
    private MetadataDatabase mDatabase = null;
    private boolean mMigratedFromSettingsGlobal = false;

    @VisibleForTesting
    final Map<String, Metadata> mMetadataCache = new HashMap<>();
    private final Semaphore mSemaphore = new Semaphore(1);
    private static final int METADATA_CHANGED_LOG_MAX_SIZE = 20;
    private final EvictingQueue<String> mMetadataChangedLog;

    private static final int LOAD_DATABASE_TIMEOUT = 500; // milliseconds
    private static final int MSG_LOAD_DATABASE = 0;
    private static final int MSG_UPDATE_DATABASE = 1;
    private static final int MSG_DELETE_DATABASE = 2;
    private static final int MSG_CLEAR_DATABASE = 100;
    private static final String LOCAL_STORAGE = "LocalStorage";

    private static final String
            LEGACY_BTSNOOP_DEFAULT_MODE = "bluetooth_btsnoop_default_mode";
    private static final String
            LEGACY_HEADSET_PRIORITY_PREFIX = "bluetooth_headset_priority_";
    private static final String
            LEGACY_A2DP_SINK_PRIORITY_PREFIX = "bluetooth_a2dp_sink_priority_";
    private static final String
            LEGACY_A2DP_SRC_PRIORITY_PREFIX = "bluetooth_a2dp_src_priority_";
    private static final String LEGACY_A2DP_SUPPORTS_OPTIONAL_CODECS_PREFIX =
            "bluetooth_a2dp_supports_optional_codecs_";
    private static final String LEGACY_A2DP_OPTIONAL_CODECS_ENABLED_PREFIX =
            "bluetooth_a2dp_optional_codecs_enabled_";
    private static final String
            LEGACY_INPUT_DEVICE_PRIORITY_PREFIX = "bluetooth_input_device_priority_";
    private static final String
            LEGACY_MAP_PRIORITY_PREFIX = "bluetooth_map_priority_";
    private static final String
            LEGACY_MAP_CLIENT_PRIORITY_PREFIX = "bluetooth_map_client_priority_";
    private static final String
            LEGACY_PBAP_CLIENT_PRIORITY_PREFIX = "bluetooth_pbap_client_priority_";
    private static final String
            LEGACY_SAP_PRIORITY_PREFIX = "bluetooth_sap_priority_";
    private static final String
            LEGACY_PAN_PRIORITY_PREFIX = "bluetooth_pan_priority_";
    private static final String
            LEGACY_HEARING_AID_PRIORITY_PREFIX = "bluetooth_hearing_aid_priority_";

    /**
     * Constructor of the DatabaseManager
     */
    public DatabaseManager(AdapterService service) {
        mAdapterService = service;
        mMetadataChangedLog = EvictingQueue.create(METADATA_CHANGED_LOG_MAX_SIZE);
    }

    class DatabaseHandler extends Handler {
        DatabaseHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MSG_LOAD_DATABASE: {
                    synchronized (mDatabase) {
                        List<Metadata> list;
                        try {
                            list = mDatabase.load();
                        } catch (IllegalStateException e) {
                            Log.e(TAG, "Unable to open database: " + e);
                            mDatabase = MetadataDatabase
                                    .createDatabaseWithoutMigration(mAdapterService);
                            list = mDatabase.load();
                        }
                        cacheMetadata(list);
                    }
                    break;
                }
                case MSG_UPDATE_DATABASE: {
                    Metadata data = (Metadata) msg.obj;
                    synchronized (mDatabase) {
                        mDatabase.insert(data);
                    }
                    break;
                }
                case MSG_DELETE_DATABASE: {
                    String address = (String) msg.obj;
                    synchronized (mDatabase) {
                        mDatabase.delete(address);
                    }
                    break;
                }
                case MSG_CLEAR_DATABASE: {
                    synchronized (mDatabase) {
                        mDatabase.deleteAll();
                    }
                    break;
                }
            }
        }
    }

    private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) {
                Log.e(TAG, "Received intent with null action");
                return;
            }
            switch (action) {
                case BluetoothDevice.ACTION_BOND_STATE_CHANGED: {
                    int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE,
                            BluetoothDevice.ERROR);
                    BluetoothDevice device =
                            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    Objects.requireNonNull(device,
                            "ACTION_BOND_STATE_CHANGED with no EXTRA_DEVICE");
                    bondStateChanged(device, state);
                    break;
                }
                case BluetoothAdapter.ACTION_STATE_CHANGED: {
                    int state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE,
                            BluetoothAdapter.STATE_OFF);
                    if (!mMigratedFromSettingsGlobal
                            && state == BluetoothAdapter.STATE_TURNING_ON) {
                        migrateSettingsGlobal();
                    }
                    break;
                }
            }
        }
    };

    void bondStateChanged(BluetoothDevice device, int state) {
        synchronized (mMetadataCache) {
            String address = device.getAddress();
            if (state != BluetoothDevice.BOND_NONE) {
                if (mMetadataCache.containsKey(address)) {
                    return;
                }
                createMetadata(address);
            } else {
                Metadata metadata = mMetadataCache.get(address);
                if (metadata != null) {
                    mMetadataCache.remove(address);
                    deleteDatabase(metadata);
                }
            }
        }
    }

    boolean isValidMetaKey(int key) {
        switch (key) {
            case BluetoothDevice.METADATA_MANUFACTURER_NAME:
            case BluetoothDevice.METADATA_MODEL_NAME:
            case BluetoothDevice.METADATA_SOFTWARE_VERSION:
            case BluetoothDevice.METADATA_HARDWARE_VERSION:
            case BluetoothDevice.METADATA_COMPANION_APP:
            case BluetoothDevice.METADATA_MAIN_ICON:
            case BluetoothDevice.METADATA_IS_UNTETHERED_HEADSET:
            case BluetoothDevice.METADATA_UNTETHERED_LEFT_ICON:
            case BluetoothDevice.METADATA_UNTETHERED_RIGHT_ICON:
            case BluetoothDevice.METADATA_UNTETHERED_CASE_ICON:
            case BluetoothDevice.METADATA_UNTETHERED_LEFT_BATTERY:
            case BluetoothDevice.METADATA_UNTETHERED_RIGHT_BATTERY:
            case BluetoothDevice.METADATA_UNTETHERED_CASE_BATTERY:
            case BluetoothDevice.METADATA_UNTETHERED_LEFT_CHARGING:
            case BluetoothDevice.METADATA_UNTETHERED_RIGHT_CHARGING:
            case BluetoothDevice.METADATA_UNTETHERED_CASE_CHARGING:
            case BluetoothDevice.METADATA_ENHANCED_SETTINGS_UI_URI:
                return true;
        }
        Log.w(TAG, "Invalid metadata key " + key);
        return false;
    }

    /**
     * Set customized metadata to database with requested key
     */
    @VisibleForTesting
    public boolean setCustomMeta(BluetoothDevice device, int key, byte[] newValue) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "setCustomMeta: device is null");
                return false;
            }
            if (!isValidMetaKey(key)) {
                Log.e(TAG, "setCustomMeta: meta key invalid " + key);
                return false;
            }

            String address = device.getAddress();
            if (!mMetadataCache.containsKey(address)) {
                createMetadata(address);
            }
            Metadata data = mMetadataCache.get(address);
            byte[] oldValue = data.getCustomizedMeta(key);
            if (oldValue != null && Arrays.equals(oldValue, newValue)) {
                Log.v(TAG, "setCustomMeta: metadata not changed.");
                return true;
            }
            logManufacturerInfo(device, key, newValue);
            logMetadataChange(address, "setCustomMeta key=" + key);
            data.setCustomizedMeta(key, newValue);

            updateDatabase(data);
            mAdapterService.metadataChanged(address, key, newValue);
            return true;
        }
    }

    /**
     * Get customized metadata from database with requested key
     */
    @VisibleForTesting
    public byte[] getCustomMeta(BluetoothDevice device, int key) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "getCustomMeta: device is null");
                return null;
            }
            if (!isValidMetaKey(key)) {
                Log.e(TAG, "getCustomMeta: meta key invalid " + key);
                return null;
            }

            String address = device.getAddress();

            if (!mMetadataCache.containsKey(address)) {
                Log.d(TAG, "getCustomMeta: device " + address + " is not in cache");
                return null;
            }

            Metadata data = mMetadataCache.get(address);
            return data.getCustomizedMeta(key);
        }
    }

    /**
     * Set the device profile connection policy
     *
     * @param device {@link BluetoothDevice} wish to set
     * @param profile The Bluetooth profile; one of {@link BluetoothProfile#HEADSET},
     * {@link BluetoothProfile#HEADSET_CLIENT}, {@link BluetoothProfile#A2DP},
     * {@link BluetoothProfile#A2DP_SINK}, {@link BluetoothProfile#HID_HOST},
     * {@link BluetoothProfile#PAN}, {@link BluetoothProfile#PBAP},
     * {@link BluetoothProfile#PBAP_CLIENT}, {@link BluetoothProfile#MAP},
     * {@link BluetoothProfile#MAP_CLIENT}, {@link BluetoothProfile#SAP},
     * {@link BluetoothProfile#HEARING_AID}
     * @param newConnectionPolicy the connectionPolicy to set; one of
     * {@link BluetoothProfile.CONNECTION_POLICY_UNKNOWN},
     * {@link BluetoothProfile.CONNECTION_POLICY_FORBIDDEN},
     * {@link BluetoothProfile.CONNECTION_POLICY_ALLOWED}
     */
    @VisibleForTesting
    public boolean setProfileConnectionPolicy(BluetoothDevice device, int profile,
            int newConnectionPolicy) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "setProfileConnectionPolicy: device is null");
                return false;
            }

            if (newConnectionPolicy != BluetoothProfile.CONNECTION_POLICY_UNKNOWN
                    && newConnectionPolicy != BluetoothProfile.CONNECTION_POLICY_FORBIDDEN
                    && newConnectionPolicy != BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                Log.e(TAG, "setProfileConnectionPolicy: invalid connection policy "
                        + newConnectionPolicy);
                return false;
            }

            String address = device.getAddress();
            if (!mMetadataCache.containsKey(address)) {
                if (newConnectionPolicy == BluetoothProfile.CONNECTION_POLICY_UNKNOWN) {
                    return true;
                }
                createMetadata(address);
            }
            Metadata data = mMetadataCache.get(address);
            int oldConnectionPolicy = data.getProfileConnectionPolicy(profile);
            if (oldConnectionPolicy == newConnectionPolicy) {
                Log.v(TAG, "setProfileConnectionPolicy connection policy not changed.");
                return true;
            }
            String profileStr = BluetoothProfile.getProfileName(profile);
            logMetadataChange(address, profileStr + " connection policy changed: "
                    + ": " + oldConnectionPolicy + " -> " + newConnectionPolicy);

            data.setProfileConnectionPolicy(profile, newConnectionPolicy);
            updateDatabase(data);
            return true;
        }
    }

    /**
     * Get the device profile connection policy
     *
     * @param device {@link BluetoothDevice} wish to get
     * @param profile The Bluetooth profile; one of {@link BluetoothProfile#HEADSET},
     * {@link BluetoothProfile#HEADSET_CLIENT}, {@link BluetoothProfile#A2DP},
     * {@link BluetoothProfile#A2DP_SINK}, {@link BluetoothProfile#HID_HOST},
     * {@link BluetoothProfile#PAN}, {@link BluetoothProfile#PBAP},
     * {@link BluetoothProfile#PBAP_CLIENT}, {@link BluetoothProfile#MAP},
     * {@link BluetoothProfile#MAP_CLIENT}, {@link BluetoothProfile#SAP},
     * {@link BluetoothProfile#HEARING_AID}
     * @return the profile connection policy of the device; one of
     * {@link BluetoothProfile.CONNECTION_POLICY_UNKNOWN},
     * {@link BluetoothProfile.CONNECTION_POLICY_FORBIDDEN},
     * {@link BluetoothProfile.CONNECTION_POLICY_ALLOWED}
     */
    @VisibleForTesting
    public int getProfileConnectionPolicy(BluetoothDevice device, int profile) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "getProfileConnectionPolicy: device is null");
                return BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
            }

            String address = device.getAddress();

            if (!mMetadataCache.containsKey(address)) {
                Log.d(TAG, "getProfileConnectionPolicy: device " + address + " is not in cache");
                return BluetoothProfile.CONNECTION_POLICY_UNKNOWN;
            }

            Metadata data = mMetadataCache.get(address);
            int connectionPolicy = data.getProfileConnectionPolicy(profile);

            // If result is PRIORITY_AUTO_CONNECT, return as CONNECTION_POLICY_ALLOWED
            if (connectionPolicy > BluetoothProfile.CONNECTION_POLICY_ALLOWED) {
                setProfileConnectionPolicy(device, profile,
                        BluetoothProfile.CONNECTION_POLICY_ALLOWED);
                connectionPolicy = BluetoothProfile.CONNECTION_POLICY_ALLOWED;
            }

            Log.v(TAG, "getProfileConnectionPolicy: " + address + ", profile=" + profile
                    + ", connectionPolicy = " + connectionPolicy);
            return connectionPolicy;
        }
    }

    /**
     * Set the A2DP optional coedc support value
     *
     * @param device {@link BluetoothDevice} wish to set
     * @param newValue the new A2DP optional coedc support value, one of
     * {@link BluetoothA2dp#OPTIONAL_CODECS_SUPPORT_UNKNOWN},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_NOT_SUPPORTED},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_SUPPORTED}
     */
    @VisibleForTesting
    public void setA2dpSupportsOptionalCodecs(BluetoothDevice device, int newValue) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "setA2dpOptionalCodec: device is null");
                return;
            }
            if (newValue != BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN
                    && newValue != BluetoothA2dp.OPTIONAL_CODECS_NOT_SUPPORTED
                    && newValue != BluetoothA2dp.OPTIONAL_CODECS_SUPPORTED) {
                Log.e(TAG, "setA2dpSupportsOptionalCodecs: invalid value " + newValue);
                return;
            }

            String address = device.getAddress();

            if (!mMetadataCache.containsKey(address)) {
                return;
            }
            Metadata data = mMetadataCache.get(address);
            int oldValue = data.a2dpSupportsOptionalCodecs;
            if (oldValue == newValue) {
                return;
            }
            logMetadataChange(address, "Supports optional codec changed: "
                    + oldValue + " -> " + newValue);

            data.a2dpSupportsOptionalCodecs = newValue;
            updateDatabase(data);
        }
    }

    /**
     * Get the A2DP optional coedc support value
     *
     * @param device {@link BluetoothDevice} wish to get
     * @return the A2DP optional coedc support value, one of
     * {@link BluetoothA2dp#OPTIONAL_CODECS_SUPPORT_UNKNOWN},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_NOT_SUPPORTED},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_SUPPORTED},
     */
    @VisibleForTesting
    @OptionalCodecsSupportStatus
    public int getA2dpSupportsOptionalCodecs(BluetoothDevice device) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "setA2dpOptionalCodec: device is null");
                return BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN;
            }

            String address = device.getAddress();

            if (!mMetadataCache.containsKey(address)) {
                Log.d(TAG, "getA2dpOptionalCodec: device " + address + " is not in cache");
                return BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN;
            }

            Metadata data = mMetadataCache.get(address);
            return data.a2dpSupportsOptionalCodecs;
        }
    }

    /**
     * Set the A2DP optional coedc enabled value
     *
     * @param device {@link BluetoothDevice} wish to set
     * @param newValue the new A2DP optional coedc enabled value, one of
     * {@link BluetoothA2dp#OPTIONAL_CODECS_PREF_UNKNOWN},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_PREF_DISABLED},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_PREF_ENABLED}
     */
    @VisibleForTesting
    public void setA2dpOptionalCodecsEnabled(BluetoothDevice device, int newValue) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "setA2dpOptionalCodecEnabled: device is null");
                return;
            }
            if (newValue != BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN
                    && newValue != BluetoothA2dp.OPTIONAL_CODECS_PREF_DISABLED
                    && newValue != BluetoothA2dp.OPTIONAL_CODECS_PREF_ENABLED) {
                Log.e(TAG, "setA2dpOptionalCodecsEnabled: invalid value " + newValue);
                return;
            }

            String address = device.getAddress();

            if (!mMetadataCache.containsKey(address)) {
                return;
            }
            Metadata data = mMetadataCache.get(address);
            int oldValue = data.a2dpOptionalCodecsEnabled;
            if (oldValue == newValue) {
                return;
            }
            logMetadataChange(address, "Enable optional codec changed: "
                    + oldValue + " -> " + newValue);

            data.a2dpOptionalCodecsEnabled = newValue;
            updateDatabase(data);
        }
    }

    /**
     * Get the A2DP optional coedc enabled value
     *
     * @param device {@link BluetoothDevice} wish to get
     * @return the A2DP optional coedc enabled value, one of
     * {@link BluetoothA2dp#OPTIONAL_CODECS_PREF_UNKNOWN},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_PREF_DISABLED},
     * {@link BluetoothA2dp#OPTIONAL_CODECS_PREF_ENABLED}
     */
    @VisibleForTesting
    @OptionalCodecsPreferenceStatus
    public int getA2dpOptionalCodecsEnabled(BluetoothDevice device) {
        synchronized (mMetadataCache) {
            if (device == null) {
                Log.e(TAG, "getA2dpOptionalCodecEnabled: device is null");
                return BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN;
            }

            String address = device.getAddress();

            if (!mMetadataCache.containsKey(address)) {
                Log.d(TAG, "getA2dpOptionalCodecEnabled: device " + address + " is not in cache");
                return BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN;
            }

            Metadata data = mMetadataCache.get(address);
            return data.a2dpOptionalCodecsEnabled;
        }
    }

    /**
     * Get the {@link Looper} for the handler thread. This is used in testing and helper
     * objects
     *
     * @return {@link Looper} for the handler thread
     */
    @VisibleForTesting
    public Looper getHandlerLooper() {
        if (mHandlerThread == null) {
            return null;
        }
        return mHandlerThread.getLooper();
    }

    /**
     * Start and initialize the DatabaseManager
     *
     * @param database the Bluetooth storage {@link MetadataDatabase}
     */
    public void start(MetadataDatabase database) {
        Log.d(TAG, "start()");
        if (mAdapterService == null) {
            Log.e(TAG, "stat failed, mAdapterService is null.");
            return;
        }

        if (database == null) {
            Log.e(TAG, "stat failed, database is null.");
            return;
        }

        mDatabase = database;

        mHandlerThread = new HandlerThread("BluetoothDatabaseManager");
        mHandlerThread.start();
        mHandler = new DatabaseHandler(mHandlerThread.getLooper());

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        filter.addAction(BluetoothAdapter.ACTION_STATE_CHANGED);
        mAdapterService.registerReceiver(mReceiver, filter);

        loadDatabase();
    }

    String getDatabaseAbsolutePath() {
        //TODO backup database when Bluetooth turn off and FOTA?
        return mAdapterService.getDatabasePath(MetadataDatabase.DATABASE_NAME)
                .getAbsolutePath();
    }

    /**
     * Clear all persistence data in database
     */
    public void factoryReset() {
        Log.w(TAG, "factoryReset");
        Message message = mHandler.obtainMessage(MSG_CLEAR_DATABASE);
        mHandler.sendMessage(message);
    }

    /**
     * Close and de-init the DatabaseManager
     */
    public void cleanup() {
        removeUnusedMetadata();
        mAdapterService.unregisterReceiver(mReceiver);
        if (mHandlerThread != null) {
            mHandlerThread.quit();
            mHandlerThread = null;
        }
        mMetadataCache.clear();
    }

    void createMetadata(String address) {
        Metadata data = new Metadata(address);
        mMetadataCache.put(address, data);
        updateDatabase(data);
        logMetadataChange(address, "Metadata created");
    }

    @VisibleForTesting
    void removeUnusedMetadata() {
        BluetoothDevice[] bondedDevices = mAdapterService.getBondedDevices();
        synchronized (mMetadataCache) {
            mMetadataCache.forEach((address, metadata) -> {
                if (!address.equals(LOCAL_STORAGE)
                        && !Arrays.asList(bondedDevices).stream().anyMatch(device ->
                        address.equals(device.getAddress()))) {
                    List<Integer> list = metadata.getChangedCustomizedMeta();
                    for (int key : list) {
                        mAdapterService.metadataChanged(address, key, null);
                    }
                    Log.i(TAG, "remove unpaired device from database " + address);
                    deleteDatabase(mMetadataCache.get(address));
                }
            });
        }
    }

    void cacheMetadata(List<Metadata> list) {
        synchronized (mMetadataCache) {
            Log.i(TAG, "cacheMetadata");
            // Unlock the main thread.
            mSemaphore.release();

            if (!isMigrated(list)) {
                // Wait for data migrate from Settings Global
                mMigratedFromSettingsGlobal = false;
                return;
            }
            mMigratedFromSettingsGlobal = true;
            for (Metadata data : list) {
                String address = data.getAddress();
                Log.v(TAG, "cacheMetadata: found device " + address);
                mMetadataCache.put(address, data);
            }
            Log.i(TAG, "cacheMetadata: Database is ready");
        }
    }

    boolean isMigrated(List<Metadata> list) {
        for (Metadata data : list) {
            String address = data.getAddress();
            if (address.equals(LOCAL_STORAGE) && data.migrated) {
                return true;
            }
        }
        return false;
    }

    void migrateSettingsGlobal() {
        Log.i(TAG, "migrateSettingGlobal");

        BluetoothDevice[] bondedDevices = mAdapterService.getBondedDevices();
        ContentResolver contentResolver = mAdapterService.getContentResolver();

        for (BluetoothDevice device : bondedDevices) {
            int a2dpConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyA2dpSinkPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int a2dpSinkConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyA2dpSrcPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int hearingaidConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyHearingAidPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int headsetConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyHeadsetPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int headsetClientConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyHeadsetPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int hidHostConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyHidHostPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int mapConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyMapPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int mapClientConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyMapClientPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int panConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyPanPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int pbapConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyPbapClientPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int pbapClientConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacyPbapClientPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int sapConnectionPolicy = Settings.Global.getInt(contentResolver,
                    getLegacySapPriorityKey(device.getAddress()),
                    BluetoothProfile.CONNECTION_POLICY_UNKNOWN);
            int a2dpSupportsOptionalCodec = Settings.Global.getInt(contentResolver,
                    getLegacyA2dpSupportsOptionalCodecsKey(device.getAddress()),
                    BluetoothA2dp.OPTIONAL_CODECS_SUPPORT_UNKNOWN);
            int a2dpOptionalCodecEnabled = Settings.Global.getInt(contentResolver,
                    getLegacyA2dpOptionalCodecsEnabledKey(device.getAddress()),
                    BluetoothA2dp.OPTIONAL_CODECS_PREF_UNKNOWN);

            String address = device.getAddress();
            Metadata data = new Metadata(address);
            data.setProfileConnectionPolicy(BluetoothProfile.A2DP, a2dpConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.A2DP_SINK, a2dpSinkConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.HEADSET, headsetConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.HEADSET_CLIENT,
                    headsetClientConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.HID_HOST, hidHostConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.PAN, panConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.PBAP, pbapConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.PBAP_CLIENT,
                    pbapClientConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.MAP, mapConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.MAP_CLIENT, mapClientConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.SAP, sapConnectionPolicy);
            data.setProfileConnectionPolicy(BluetoothProfile.HEARING_AID,
                    hearingaidConnectionPolicy);
            data.a2dpSupportsOptionalCodecs = a2dpSupportsOptionalCodec;
            data.a2dpOptionalCodecsEnabled = a2dpOptionalCodecEnabled;
            mMetadataCache.put(address, data);
            updateDatabase(data);
        }

        // Mark database migrated from Settings Global
        Metadata localData = new Metadata(LOCAL_STORAGE);
        localData.migrated = true;
        mMetadataCache.put(LOCAL_STORAGE, localData);
        updateDatabase(localData);

        // Reload database after migration is completed
        loadDatabase();

    }

    /**
     * Get the key that retrieves a bluetooth headset's priority.
     */
    private static String getLegacyHeadsetPriorityKey(String address) {
        return LEGACY_HEADSET_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth a2dp sink's priority.
     */
    private static String getLegacyA2dpSinkPriorityKey(String address) {
        return LEGACY_A2DP_SINK_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth a2dp src's priority.
     */
    private static String getLegacyA2dpSrcPriorityKey(String address) {
        return LEGACY_A2DP_SRC_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth a2dp device's ability to support optional codecs.
     */
    private static String getLegacyA2dpSupportsOptionalCodecsKey(String address) {
        return LEGACY_A2DP_SUPPORTS_OPTIONAL_CODECS_PREFIX
                + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves whether a bluetooth a2dp device should have optional codecs
     * enabled.
     */
    private static String getLegacyA2dpOptionalCodecsEnabledKey(String address) {
        return LEGACY_A2DP_OPTIONAL_CODECS_ENABLED_PREFIX
                + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth Input Device's priority.
     */
    private static String getLegacyHidHostPriorityKey(String address) {
        return LEGACY_INPUT_DEVICE_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth pan client priority.
     */
    private static String getLegacyPanPriorityKey(String address) {
        return LEGACY_PAN_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth hearing aid priority.
     */
    private static String getLegacyHearingAidPriorityKey(String address) {
        return LEGACY_HEARING_AID_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth map priority.
     */
    private static String getLegacyMapPriorityKey(String address) {
        return LEGACY_MAP_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth map client priority.
     */
    private static String getLegacyMapClientPriorityKey(String address) {
        return LEGACY_MAP_CLIENT_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth pbap client priority.
     */
    private static String getLegacyPbapClientPriorityKey(String address) {
        return LEGACY_PBAP_CLIENT_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    /**
     * Get the key that retrieves a bluetooth sap priority.
     */
    private static String getLegacySapPriorityKey(String address) {
        return LEGACY_SAP_PRIORITY_PREFIX + address.toUpperCase(Locale.ROOT);
    }

    private void loadDatabase() {
        Log.d(TAG, "Load Database");
        Message message = mHandler.obtainMessage(MSG_LOAD_DATABASE);
        mHandler.sendMessage(message);
        try {
            // Lock the thread until handler thread finish loading database.
            mSemaphore.tryAcquire(LOAD_DATABASE_TIMEOUT, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Log.e(TAG, "loadDatabase: semaphore acquire failed");
        }
    }

    private void updateDatabase(Metadata data) {
        if (data.getAddress() == null) {
            Log.e(TAG, "updateDatabase: address is null");
            return;
        }
        Log.d(TAG, "updateDatabase " + data.getAddress());
        Message message = mHandler.obtainMessage(MSG_UPDATE_DATABASE);
        message.obj = data;
        mHandler.sendMessage(message);
    }

    private void deleteDatabase(Metadata data) {
        String address = data.getAddress();
        if (address == null) {
            Log.e(TAG, "deleteDatabase: address is null");
            return;
        }
        logMetadataChange(address, "Metadata deleted");
        Message message = mHandler.obtainMessage(MSG_DELETE_DATABASE);
        message.obj = data.getAddress();
        mHandler.sendMessage(message);
    }

    private void logManufacturerInfo(BluetoothDevice device, int key, byte[] bytesValue) {
        String callingApp = mAdapterService.getPackageManager().getNameForUid(
                Binder.getCallingUid());
        String manufacturerName = "";
        String modelName = "";
        String hardwareVersion = "";
        String softwareVersion = "";
        String value = Utils.byteArrayToUtf8String(bytesValue);
        switch (key) {
            case BluetoothDevice.METADATA_MANUFACTURER_NAME:
                manufacturerName = value;
                break;
            case BluetoothDevice.METADATA_MODEL_NAME:
                modelName = value;
                break;
            case BluetoothDevice.METADATA_HARDWARE_VERSION:
                hardwareVersion = value;
                break;
            case BluetoothDevice.METADATA_SOFTWARE_VERSION:
                softwareVersion = value;
                break;
            default:
                // Do not log anything if metadata doesn't fall into above categories
                return;
        }
        StatsLog.write(StatsLog.BLUETOOTH_DEVICE_INFO_REPORTED,
                mAdapterService.obfuscateAddress(device),
                BluetoothProtoEnums.DEVICE_INFO_EXTERNAL, callingApp, manufacturerName, modelName,
                hardwareVersion, softwareVersion);
    }

    private void logMetadataChange(String address, String log) {
        String time = Utils.getLocalTimeString();
        String uidPid = Utils.getUidPidString();
        mMetadataChangedLog.add(time + " (" + uidPid + ") " + address + " " + log);
    }

    /**
     * Dump database info to a PrintWriter
     *
     * @param writer the PrintWriter to write log
     */
    public void dump(PrintWriter writer) {
        writer.println("\nBluetoothDatabase:");
        writer.println("  Metadata Changes:");
        for (String log : mMetadataChangedLog) {
            writer.println("    " + log);
        }
        writer.println("\nMetadata:");
        for (HashMap.Entry<String, Metadata> entry : mMetadataCache.entrySet()) {
            if (entry.getKey().equals(LOCAL_STORAGE)) {
                // No need to dump local storage
                continue;
            }
            writer.println("    " + entry.getValue());
        }
    }
}
