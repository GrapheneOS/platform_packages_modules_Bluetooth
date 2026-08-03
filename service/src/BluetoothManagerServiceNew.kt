/*
 * Copyright (C) 2026 The Android Open Source Project
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

package com.android.server.bluetooth

import android.Manifest.permission.BLUETOOTH_CONNECT
import android.app.BroadcastOptions
import android.bluetooth.IBluetoothManager.ACTION_LOCAL_NAME_CHANGED
import android.bluetooth.IBluetoothManager.EXTRA_LOCAL_NAME
import android.bluetooth.IBluetoothManagerCallback
import android.bluetooth.State
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.Looper
import android.os.PowerExemptionManager.REASON_BLUETOOTH_BROADCAST
import android.os.PowerExemptionManager.TEMPORARY_ALLOW_LIST_TYPE_FOREGROUND_SERVICE_ALLOWED
import android.os.RemoteCallbackList
import android.os.SystemProperties
import android.os.UserHandle
import android.provider.Settings.Global
import android.provider.Settings.Secure
import com.android.bluetooth.util.truncateUtf8String
import com.android.server.bluetooth.airplane.AirplaneModeController
import java.io.FileDescriptor
import java.io.PrintWriter
import kotlin.text.Regex
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

// Must match android.provider.Settings.Secure.BLUETOOTH_NAME but cannot depend on the variable
const val BLUETOOTH_NAME = "bluetooth_name"

// Must match android.provider.Settings.Secure.BLUETOOTH_ADDRESS but cannot depend on the variable
const val BLUETOOTH_ADDRESS = "bluetooth_address"

// Regex used for address matching: XX:XX:XX:XX:XX:XX
private const val HEX_PAIR = "[0-9A-F]{2}"
private val ADDRESS_PATTERN = Regex("^($HEX_PAIR:){5}$HEX_PAIR$")

@kotlin.time.ExperimentalTime
class BluetoothManagerServiceNew(
    private val context: Context,
    private val looper: Looper,
    private val userHandle: UserHandle,
    private val bluetoothComponent: BluetoothComponent,
    private var isBootCompleted: Boolean,
) {
    private val contentResolver = context.contentResolver
    private val state = BluetoothAdapterState()
    private val airplaneController: AirplaneModeController
    private val autoOn: AutoOn? // Null when config doesn't allow

    private var localAddress = readLocalAddress()
    private var localName = validateLocalName(Secure.getString(contentResolver, BLUETOOTH_NAME))
    private val callbacks = RemoteCallbackList<IBluetoothManagerCallback>()

    init {
        airplaneController =
            AirplaneModeController(
                context,
                state,
                this::onAirplaneModeChanged,
                this::sendToggleNotification,
                TimeSource.Monotonic,
            )

        autoOn =
            if (SystemProperties.getBoolean("bluetooth.server.automatic_turn_on", false)) {
                AutoOn(
                    looper,
                    context,
                    userHandle,
                    state,
                    this::enableFromAutoOn,
                    airplaneController,
                )
            } else null

        Log.i(
            TAG,
            "Starting for user $userHandle (boot completed=$isBootCompleted) Name=$localName AutoOnEnabled=${autoOn != null}",
        )
    }

    fun shutdown() {
        Log.i(TAG, "Shutting down for user $userHandle")
    }

    suspend fun awaitShutdown() {
        // TODO wait for completion
    }

    fun onRestrictionChange() {
        Log.i(TAG, "onRestrictionChange")
    }

    /** Send Intent to the Notification Service in the Bluetooth app */
    fun sendToggleNotification(reason: String) {
        val targetComponent =
            ComponentName(
                bluetoothComponent.packageName,
                "com.android.bluetooth.notification.NotificationHelperService",
            )

        context.startService(
            Intent().apply {
                setAction("android.bluetooth.notification.action.SEND_TOGGLE_NOTIFICATION")
                setComponent(targetComponent)
                putExtra("android.bluetooth.notification.extra.NOTIFICATION_REASON", reason)
            }
        )
    }

    fun onAirplaneModeChanged(isAirplaneModeOn: Boolean) {
        Log.i(TAG, "onAirplaneModeChanged($isAirplaneModeOn)")
    }

    fun onSatelliteModeChanged(isSatelliteModeOn: Boolean) {
        Log.i(TAG, "onSatelliteModeChanged($isSatelliteModeOn)")
    }

    fun onBootCompleted() {
        Log.i(TAG, "onBootCompleted")
        isBootCompleted = true
    }

    fun onBleScanDisabled() {
        Log.i(TAG, "onBleScanDisabled")
    }

    fun onSettingsRestored(enabled: Boolean) {
        Log.i(TAG, "onSettingsRestored(enabled=$enabled)")
    }

    // API Delegate methods
    fun getState(): Int = state.get()

    fun waitForState(state: Int): Boolean = false

    // TODO Flags.systemServerMigrateBmsToKotlin() -> move to oneway binder without return value
    fun registerAdapter(callback: IBluetoothManagerCallback): IBinder? {
        callbacks.register(callback)
        // TODO when adapter is implemented:
        // if (adapter is bound) {
        //     callback.onBluetoothServiceUp(adapterBinder)
        // }
        // TODO implement global broadcast using new API:
        // callbacks.broadcast { it.onBluetoothServiceUp(adapterBinder) }
        return null
    }

    fun unregisterAdapter(callback: IBluetoothManagerCallback) {
        callbacks.unregister(callback)
    }

    fun getAddress() = localAddress

    private fun readLocalAddress() =
        Secure.getString(contentResolver, BLUETOOTH_ADDRESS)?.takeIf { it.matches(ADDRESS_PATTERN) }

    private fun persistentStorageForLocalAddress(address: String) {
        Secure.putString(contentResolver, BLUETOOTH_ADDRESS, address)
        Log.v(TAG, "Local address updated: ${Log.address(localAddress)} -> ${Log.address(address)}")
        localAddress = address
    }

    fun getName() = localName

    fun setName(name: String?) {
        val validatedName = validateLocalName(name)
        if (validatedName == localName) {
            return
        }
        if (!state.oneOf(State.OFF)) {
            throw NotImplementedError("setName when Bluetooth is ON") // TODO
        }
        persistentStorageForLocalName(validatedName)
    }

    private fun validateLocalName(_name: String?): String {
        var name = _name
        if (name.isNullOrEmpty()) {
            name = SystemProperties.get("bluetooth.device.default_name")
        }
        if (name.isNullOrEmpty()) {
            name = Global.getString(contentResolver, Global.DEVICE_NAME)
        }
        if (name.isNullOrEmpty()) {
            name = SystemProperties.get("ro.product.model")
        }
        if (name.isNullOrEmpty()) {
            name = "Android"
        }
        // The Bluetooth Device Name can be up to 248 bytes (see [Vol 2] Part C, Section 4.3.5).
        return name.truncateUtf8String(248)
    }

    private fun persistentStorageForLocalName(name: String) {
        Secure.putString(contentResolver, BLUETOOTH_NAME, name)
        val intent =
            Intent(ACTION_LOCAL_NAME_CHANGED)
                .putExtra(EXTRA_LOCAL_NAME, name)
                .addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT)
        val userManager = context.getSystemService(android.os.UserManager::class.java)!!
        for (user in userManager.getEnabledProfiles()) {
            context.sendBroadcastAsUser(
                intent,
                user,
                BLUETOOTH_CONNECT,
                getTempAllowlistBroadcastOptions(),
            )
        }
        Log.v(TAG, "Local name updated: $localName -> $name")
        localName = name
    }

    fun isBleScanAvailable(): Boolean = false

    fun enable(reason: Int, packageName: String): Boolean = false

    fun enableBle(packageName: String, token: IBinder): Boolean = false

    fun enableNoAutoConnect(packageName: String): Boolean = false

    fun enableFromAutoOn() {
        throw NotImplementedError("enableFromAutoOn") // TODO
        // if (!BluetoothRestriction.isBluetoothAllowed()) {
        //     Log.d(TAG, "Bluetooth is not allowed, preventing AutoOn")
        //     return
        // }
        // sendToggleNotification("auto_on_bt_enabled_notification")
        // enable(ENABLE_DISABLE_REASON_AUTO_ON, mContext.packageName)
    }

    fun disable(packageName: String, persist: Boolean): Boolean = false

    fun disableBle(packageName: String, token: IBinder): Boolean = false

    fun factoryReset(): Boolean = false

    fun isAutoOnSupported() = autoOn?.isSupported() ?: false

    fun isAutoOnEnabled() =
        checkNotNull(autoOn) { "AutoOn is not supported in current config" }.isEnabled()

    fun setAutoOnEnabled(status: Boolean) =
        checkNotNull(autoOn) { "AutoOn is not supported in current config" }.setEnabled(status)

    fun dump(fd: FileDescriptor?, writer: PrintWriter?, args: Array<String?>?) {
        writer?.println("$TAG for $userHandle")
    }

    companion object {
        private const val TAG = "BluetoothManagerServiceNew"

        fun getTempAllowlistBroadcastOptions() =
            BroadcastOptions.makeBasic()
                .apply {
                    setTemporaryAppAllowlist(
                        10.seconds.inWholeMilliseconds,
                        TEMPORARY_ALLOW_LIST_TYPE_FOREGROUND_SERVICE_ALLOWED,
                        REASON_BLUETOOTH_BROADCAST,
                        "",
                    )
                }
                .toBundle()
    }
}
