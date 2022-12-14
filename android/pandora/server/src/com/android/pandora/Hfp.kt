/*
 * Copyright (C) 2022 The Android Open Source Project
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

package com.android.pandora

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothHeadset
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.IBinder
import android.telecom.CallAudioState
import android.telecom.InCallService
import android.telecom.TelecomManager
import com.google.protobuf.Empty
import io.grpc.stub.StreamObserver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.shareIn
import pandora.HFPGrpc.HFPImplBase
import pandora.HfpProto.*

private const val TAG = "PandoraHfp"

@kotlinx.coroutines.ExperimentalCoroutinesApi
class Hfp(val context: Context) : HFPImplBase() {
  private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default)
  private val flow: Flow<Intent>

  private val bluetoothManager = context.getSystemService(BluetoothManager::class.java)!!
  private val telecomManager = context.getSystemService(TelecomManager::class.java)!!
  private val bluetoothAdapter = bluetoothManager.adapter

  private val bluetoothHfp = getProfileProxy<BluetoothHeadset>(context, BluetoothProfile.HEADSET)

  companion object {
    @SuppressLint("StaticFieldLeak")
    private lateinit var inCallService: InCallService
  }

  init {

    val intentFilter = IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED)
    flow = intentFlow(context, intentFilter).shareIn(scope, SharingStarted.Eagerly)

    // kill any existing call
    telecomManager.endCall()
  }

  fun deinit() {
    // kill any existing call
    telecomManager.endCall()

    bluetoothAdapter.closeProfileProxy(BluetoothProfile.HEADSET, bluetoothHfp)
    scope.cancel()
  }

  class PandoraInCallService : InCallService() {
    override fun onBind(intent: Intent?): IBinder? {
      inCallService = this
      return super.onBind(intent)
    }
  }

  override fun enableSlc(request: EnableSlcRequest, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
      val device = request.connection.toBluetoothDevice(bluetoothAdapter)

      bluetoothHfp.setConnectionPolicy(device, BluetoothProfile.CONNECTION_POLICY_ALLOWED)

      Empty.getDefaultInstance()
    }
  }

  override fun disableSlc(request: DisableSlcRequest, responseObserver: StreamObserver<Empty>) {
    grpcUnary<Empty>(scope, responseObserver) {
      val device = request.connection.toBluetoothDevice(bluetoothAdapter)

      bluetoothHfp.setConnectionPolicy(device, BluetoothProfile.CONNECTION_POLICY_FORBIDDEN)

      Empty.getDefaultInstance()
    }
  }

  override fun setBatteryLevel(
    request: SetBatteryLevelRequest,
    responseObserver: StreamObserver<Empty>,
  ) {
    grpcUnary<Empty>(scope, responseObserver) {
      val action = "android.intent.action.BATTERY_CHANGED"
      shell("am broadcast -a $action --ei level ${request.batteryPercentage} --ei scale 100")
      Empty.getDefaultInstance()
    }
  }

  override fun declineCall(
    request: DeclineCallRequest,
    responseObserver: StreamObserver<DeclineCallResponse>,
  ) {
    grpcUnary(scope, responseObserver) {
      telecomManager.endCall()
      DeclineCallResponse.getDefaultInstance()
    }
  }

  override fun setAudioPath(
    request: SetAudioPathRequest,
    responseObserver: StreamObserver<SetAudioPathResponse>,
  ) {
    grpcUnary(scope, responseObserver) {
      when (request.audioPath!!) {
        AudioPath.AUDIO_PATH_UNKNOWN,
        AudioPath.UNRECOGNIZED -> {}
        AudioPath.AUDIO_PATH_HANDSFREE -> {
          check(bluetoothHfp.getActiveDevice() != null)
          inCallService.setAudioRoute(CallAudioState.ROUTE_BLUETOOTH)
        }
        AudioPath.AUDIO_PATH_SPEAKERS -> inCallService.setAudioRoute(CallAudioState.ROUTE_SPEAKER)
      }
      SetAudioPathResponse.getDefaultInstance()
    }
  }
}
