/*
 * Copyright 2023 The Android Open Source Project
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

package com.android.bluetooth.airplane;

import static java.util.Objects.requireNonNull;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.net.Uri;
import android.os.IBinder;
import android.provider.Settings;
import android.service.notification.StatusBarNotification;
import android.util.Log;
import android.util.Pair;

import com.android.bluetooth.R;
import com.android.internal.messages.SystemMessageProto.SystemMessage;

import java.util.Map;

public class NotificationHelperService extends Service {
    private static final String TAG = NotificationHelperService.class.getSimpleName();

    // Keeps track of whether wifi and bt remains on notification was shown
    private static final String APM_WIFI_BT_NOTIFICATION = "apm_wifi_bt_notification";
    // Keeps track of whether bt remains on notification was shown
    private static final String APM_BT_NOTIFICATION = "apm_bt_notification";
    // Keeps track of whether user enabling bt notification was shown
    private static final String APM_BT_ENABLED_NOTIFICATION = "apm_bt_enabled_notification";

    private static final String NOTIFICATION_TAG = "com.android.bluetooth";
    private static final String APM_NOTIFICATION_CHANNEL = "apm_notification_channel";
    private static final String APM_NOTIFICATION_GROUP = "apm_notification_group";

    private static final Map<String, Pair<Integer /* titleId */, Integer /* messageId */>>
            NOTIFICATION_MAP =
                    Map.of(
                            APM_WIFI_BT_NOTIFICATION,
                            Pair.create(
                                    R.string.bluetooth_and_wifi_stays_on_title,
                                    R.string.bluetooth_and_wifi_stays_on_message),
                            APM_BT_NOTIFICATION,
                            Pair.create(
                                    R.string.bluetooth_stays_on_title,
                                    R.string.bluetooth_stays_on_message),
                            APM_BT_ENABLED_NOTIFICATION,
                            Pair.create(
                                    R.string.bluetooth_enabled_apm_title,
                                    R.string.bluetooth_enabled_apm_message));

    @Override
    public IBinder onBind(Intent intent) {
        return null; // This is not a bound service
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        sendAirplaneModeNotification(
                intent.getStringExtra("android.bluetooth.airplane.extra.NOTIFICATION_STATE"));
        return Service.START_NOT_STICKY;
    }

    private void sendAirplaneModeNotification(String notificationState) {
        String logHeader = "sendAirplaneModeNotification(" + notificationState + "): ";
        Pair<Integer, Integer> notificationContent = NOTIFICATION_MAP.get(notificationState);
        if (notificationContent == null) {
            Log.e(TAG, logHeader + "unknown action");
            return;
        }

        if (!isFirstTimeNotification(notificationState)) {
            Log.d(TAG, logHeader + "already displayed");
            return;
        }
        Settings.Secure.putInt(getContentResolver(), notificationState, 1);

        Log.d(TAG, logHeader + "sending");

        NotificationManager notificationManager =
                requireNonNull(getSystemService(NotificationManager.class));
        for (StatusBarNotification notification : notificationManager.getActiveNotifications()) {
            if (NOTIFICATION_TAG.equals(notification.getTag())) {
                notificationManager.cancel(NOTIFICATION_TAG, notification.getId());
            }
        }

        notificationManager.createNotificationChannel(
                new NotificationChannel(
                        APM_NOTIFICATION_CHANNEL,
                        APM_NOTIFICATION_GROUP,
                        NotificationManager.IMPORTANCE_HIGH));

        String title = getString(notificationContent.first);
        String message = getString(notificationContent.second);
        String helpLinkUrl = getString(R.string.config_apmLearnMoreLink);

        notificationManager.notify(
                NOTIFICATION_TAG,
                SystemMessage.ID.NOTE_BT_APM_NOTIFICATION_VALUE,
                new Notification.Builder(this, APM_NOTIFICATION_CHANNEL)
                        .setAutoCancel(true)
                        .setLocalOnly(true)
                        .setContentTitle(title)
                        .setContentText(message)
                        .setContentIntent(
                                PendingIntent.getActivity(
                                        this,
                                        PendingIntent.FLAG_UPDATE_CURRENT,
                                        new Intent(Intent.ACTION_VIEW)
                                                .setData(Uri.parse(helpLinkUrl))
                                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                        PendingIntent.FLAG_IMMUTABLE))
                        .setVisibility(Notification.VISIBILITY_PUBLIC)
                        .setStyle(new Notification.BigTextStyle().bigText(message))
                        .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                        .build());
    }

    /** Return whether the notification has been shown */
    private boolean isFirstTimeNotification(String name) {
        return Settings.Secure.getInt(getContentResolver(), name, 0) == 0;
    }
}
