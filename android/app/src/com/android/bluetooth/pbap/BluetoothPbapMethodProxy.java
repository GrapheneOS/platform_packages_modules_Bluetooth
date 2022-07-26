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

package com.android.bluetooth.pbap;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

import com.android.bluetooth.Utils;
import com.android.internal.annotations.VisibleForTesting;
import com.android.obex.HeaderSet;

import java.io.IOException;

/**
 * Proxy class for method calls to help with unit testing
 */
public class BluetoothPbapMethodProxy {
    private static final String TAG = BluetoothPbapMethodProxy.class.getSimpleName();
    private static BluetoothPbapMethodProxy sInstance;
    private static final Object INSTANCE_LOCK = new Object();

    private BluetoothPbapMethodProxy() {}

    /**
     * Get the singleton instance of proxy
     *
     * @return the singleton instance, guaranteed not null
     */
    public static BluetoothPbapMethodProxy getInstance() {
        synchronized (INSTANCE_LOCK) {
            if (sInstance == null) {
                sInstance = new BluetoothPbapMethodProxy();
            }
        }
        return sInstance;
    }

    /**
     * Allow unit tests to substitute BluetoothPbapMethodCallProxy with a test instance
     *
     * @param proxy a test instance of the BluetoothPbapMethodCallProxy
     */
    @VisibleForTesting
    public static void setInstanceForTesting(BluetoothPbapMethodProxy proxy) {
        Utils.enforceInstrumentationTestMode();
        synchronized (INSTANCE_LOCK) {
            Log.d(TAG, "setInstanceForTesting(), set to " + proxy);
            sInstance = proxy;
        }
    }

    /**
     * Proxies {@link ContentResolver#query(Uri, String[], String, String[], String)}.
     */
    public Cursor contentResolverQuery(ContentResolver contentResolver, final Uri contentUri,
            final String[] projection, final String selection, final String[] selectionArgs,
            final String sortOrder) {
        return contentResolver.query(contentUri, projection, selection, selectionArgs, sortOrder);
    }

    /**
     * Proxies {@link HeaderSet#getHeader}.
     */
    public Object getHeader(HeaderSet headerSet, int headerId) throws IOException {
        return headerSet.getHeader(headerId);
    }

    /**
     * Proxies {@link Context#getSystemService(Class)}.
     */
    public <T> T getSystemService(Context context, Class<T> serviceClass) {
        return context.getSystemService(serviceClass);
    }
}
