/*
 * Copyright (C) 2011 The Android Open Source Project
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

package com.android.settings.bluetooth;

import android.app.settings.SettingsEnums;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.DialogInterface;
import android.provider.Settings;
import android.util.Log;
import android.widget.Toast;
import android.text.InputType;
import android.view.View;

import androidx.annotation.VisibleForTesting;
import androidx.appcompat.app.AlertDialog;

import com.android.settings.R;
import com.android.settings.overlay.FeatureFactory;
import com.android.settingslib.bluetooth.BluetoothUtils;
import com.android.settingslib.bluetooth.BluetoothUtils.ErrorListener;
import com.android.settingslib.bluetooth.LocalBluetoothManager;
import com.android.settingslib.bluetooth.LocalBluetoothManager.BluetoothManagerCallback;
import android.bluetooth.BluetoothAdapter;

/**
 * BroadcastScanAssistanceUtils is a helper class that contains constants for various
 * Android resource IDs, debug logging flags, and static methods
 * for creating BASS dialogs.
 */
public final class BroadcastScanAssistanceUtils {

    private static final String TAG = "BroadcastScanAsssitanceBroadcastScanAssistanceUtils";
    static final boolean BASS_DBG = Log.isLoggable(TAG, Log.VERBOSE);

    private BroadcastScanAssistanceUtils() {
    }

    static void debug(String TAG, String msg) {
        if (BASS_DBG) {
           Log.d(TAG, msg);
        }
    }

    static boolean isLocalDevice(BluetoothDevice dev) {
        boolean ret = false;
        if (dev != null) {
              BluetoothAdapter btAdapter = BluetoothAdapter.getDefaultAdapter();
              ret = btAdapter.getAddress().equals(dev.getAddress());
        }
        Log.d(TAG, "isLocalBroadcastSource returns" +ret);
        return ret;
    }

    static AlertDialog showScanAssistError(Context context, String name, int messageResId,
                  DialogInterface.OnClickListener okListener) {
        return showScanAssistError(context, name, messageResId, Utils.getLocalBtManager(context), okListener);
    }

    private static AlertDialog showScanAssistError(Context context, String name, int messageResId,
            LocalBluetoothManager manager, DialogInterface.OnClickListener okListener) {
        String message = context.getString(messageResId, name);
        Context activity = manager.getForegroundActivity();
        AlertDialog dialog = null;
        if (manager.isForegroundActivity()) {
            try {
               dialog = new AlertDialog.Builder(activity)
                        .setTitle(R.string.bluetooth_error_title)
                        .setMessage(message)
                        .setPositiveButton(android.R.string.ok, okListener)
                        .show();
            } catch (Exception e) {
                Log.e(TAG, "Cannot show error dialog.", e);
                return null;
            }
            return dialog;
        } else {
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
            return dialog;
        }
    }
    // Create (or recycle existing) and show disconnect dialog.
    static AlertDialog showScanAssistDetailsDialog(Context context,
            AlertDialog dialog,
            DialogInterface.OnClickListener addSourceListener,
            DialogInterface.OnClickListener cancelAddSourceListener,
            CharSequence title, CharSequence message,
            View customView
            ) {
        if (dialog == null) {
            dialog = new AlertDialog.Builder(context)
                    .setPositiveButton(android.R.string.ok, addSourceListener)
                    .setNegativeButton(android.R.string.cancel, cancelAddSourceListener)
                    .setView(customView)
                    .create();
        } else {
            if (dialog.isShowing()) {
                dialog.dismiss();
            }
            // use disconnectListener for the correct profile(s)
            //CharSequence okText = context.getText(android.R.string.ok);
            //dialog.setButton(DialogInterface.BUTTON_POSITIVE,
            //        okText, addSourceListener);
        }
        dialog.setTitle(title);
        dialog.setMessage(message);
        dialog.show();
        return dialog;
    }

    static AlertDialog showAssistanceGroupOptionsDialog(Context context,
            AlertDialog dialog,
            DialogInterface.OnClickListener groupOpListener,
            DialogInterface.OnClickListener singleDevListener,
            CharSequence title, CharSequence message) {
        if (dialog == null) {
            Log.d(TAG, "showAssistanceGroupOptionsDialog creation");
            dialog = new AlertDialog.Builder(context)
                    .setPositiveButton(R.string.yes, groupOpListener)
                    .setNegativeButton(R.string.no, singleDevListener)
                    .create();
        } else {
            if (dialog.isShowing()) {
                dialog.dismiss();
            }
            // use disconnectListener for the correct profile(s)
            //CharSequence okText = context.getText(android.R.string.yes);
            //dialog.setButton(DialogInterface.BUTTON_POSITIVE,
            //        okText, groupOpListener);
        }
        dialog.setTitle(title);
        dialog.setMessage(message);
        dialog.show();
        return dialog;
    }
}
