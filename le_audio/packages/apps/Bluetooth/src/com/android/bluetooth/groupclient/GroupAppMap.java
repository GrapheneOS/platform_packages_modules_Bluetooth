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

package com.android.bluetooth.groupclient;

import android.bluetooth.IBluetoothGroupCallback;
import android.bluetooth.BluetoothGroupCallback;

import android.os.Binder;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.util.Log;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

/* This class keeps track of registered GroupClient applications and
 * managing callbacks to be given to appropriate app or module */

public class GroupAppMap {

    private static final String TAG = "BluetoothGroupAppMap";

    class GroupClientApp {
        /* The UUID of the application */
        public UUID uuid;

        /* The id of the application */
        public int appId;

        /* flag to determine if Bluetooth module has registered. */
        public boolean isLocal;

        /* Callbacks to be given to application */
        public IBluetoothGroupCallback appCb;

        /* Callbacks to be given to registered Bluetooth modules*/
        public BluetoothGroupCallback  mCallback;

        public boolean isRegistered;

        /** Death receipient */
        private IBinder.DeathRecipient mDeathRecipient;

        GroupClientApp(UUID uuid, boolean isLocal, IBluetoothGroupCallback appCb,
                BluetoothGroupCallback  localCallbacks) {
            this.uuid = uuid;
            this.isLocal = isLocal;
            this.appCb = appCb;
            this.mCallback = localCallbacks;
            this.isRegistered = true;
            appUuids.add(uuid);
        }

        /**
         * To link death recipient
         */
        void linkToDeath(IBinder.DeathRecipient deathRecipient) {
            try {
                IBinder binder = ((IInterface) appCb).asBinder();
                binder.linkToDeath(deathRecipient, 0);
                mDeathRecipient = deathRecipient;
            } catch (RemoteException e) {
                Log.e(TAG, "Unable to link deathRecipient for appId: " + appId);
            }
        }

    }

    List<GroupClientApp> mApps = Collections.synchronizedList(new ArrayList<GroupClientApp>());

    ArrayList<UUID> appUuids = new ArrayList<UUID>();

    /**
     * Add an entry to the application list.
     */
    GroupClientApp add(UUID uuid, boolean isLocal, IBluetoothGroupCallback appCb,
            BluetoothGroupCallback  localCallback) {
        synchronized (mApps) {
            GroupClientApp app = new GroupClientApp(uuid, isLocal, appCb, localCallback);
            mApps.add(app);
            return app;
        }
    }

    /**
     * Remove the entry for a given UUID
     */
    void remove(UUID uuid) {
        synchronized (mApps) {
            Iterator<GroupClientApp> i = mApps.iterator();
            while (i.hasNext()) {
                GroupClientApp entry = i.next();
                if (entry.uuid.equals(uuid)) {
                    entry.isRegistered = false;
                    i.remove();
                    break;
                }
            }
        }
    }

    /**
     * Remove the entry for a given application ID.
     */
    void remove(int appId) {
        synchronized (mApps) {
            Iterator<GroupClientApp> i = mApps.iterator();
            while (i.hasNext()) {
                GroupClientApp entry = i.next();
                if (entry.appId == appId) {
                    entry.isRegistered = false;
                    i.remove();
                    break;
                }
            }
        }
    }

    /**
     * Get GroupClient application by UUID.
     */
    GroupClientApp getByUuid(UUID uuid) {
        synchronized (mApps) {
            Iterator<GroupClientApp> i = mApps.iterator();
            while (i.hasNext()) {
                GroupClientApp entry = i.next();
                if (entry.uuid.equals(uuid)) {
                    return entry;
                }
            }
        }
        Log.e(TAG, "App not found for UUID " + uuid);
        return null;
    }

    /**
     * Get a GroupClient application by appId.
     */
    GroupClientApp getById(int appId) {
        synchronized (mApps) {
            Iterator<GroupClientApp> i = mApps.iterator();
            while (i.hasNext()) {
                GroupClientApp entry = i.next();
                if (entry.appId == appId) {
                    return entry;
                }
            }
        }
        Log.e(TAG, "GroupClient App not found for appId " + appId);
        return null;
    }
}
