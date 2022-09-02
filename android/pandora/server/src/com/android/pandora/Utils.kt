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

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.MacAddress
import com.google.protobuf.ByteString
import io.grpc.stub.StreamObserver
import java.util.concurrent.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.trySendBlocking
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import pandora.HostProto.Connection

/**
 * Creates a cold flow of intents based on an intent filter. If used multiple times in a same class,
 * this flow should be transformed into a shared flow.
 *
 * @param context context on which to register the broadcast receiver.
 * @param intentFilter intent filter.
 * @return cold flow.
 */
@kotlinx.coroutines.ExperimentalCoroutinesApi
fun intentFlow(context: Context, intentFilter: IntentFilter) = callbackFlow {
  val broadcastReceiver: BroadcastReceiver =
    object : BroadcastReceiver() {
      override fun onReceive(context: Context, intent: Intent) {
        trySendBlocking(intent)
      }
    }
  context.registerReceiver(broadcastReceiver, intentFilter)

  awaitClose { context.unregisterReceiver(broadcastReceiver) }
}

/**
 * Creates a gRPC coroutine in a given coroutine scope which executes a given suspended function
 * returning a gRPC response and sends it on a given gRPC stream observer.
 *
 * @param T the type of gRPC response.
 * @param scope coroutine scope used to run the coroutine.
 * @param responseObserver the gRPC stream observer on which to send the response.
 * @param timeout the duration in seconds after which the coroutine is automatically cancelled and
 * returns a timeout error. Default: 60s.
 * @param block the suspended function to execute to get the response.
 * @return reference to the coroutine as a Job.
 *
 * Example usage:
 * ```
 * override fun grpcMethod(
 *   request: TypeOfRequest,
 *   responseObserver: StreamObserver<TypeOfResponse> {
 *     grpcUnary(scope, responseObserver) {
 *       block
 *     }
 *   }
 * }
 * ```
 */
@kotlinx.coroutines.ExperimentalCoroutinesApi
fun <T> grpcUnary(
  scope: CoroutineScope,
  responseObserver: StreamObserver<T>,
  timeout: Long = 60,
  block: suspend CoroutineScope.() -> T
): Job {
  return scope.launch {
    try {
      val response = withTimeout(timeout * 1000, block)
      responseObserver.onNext(response)
      responseObserver.onCompleted()
    } catch (e: Throwable) {
      e.printStackTrace()
      responseObserver.onError(e)
    }
  }
}

/**
 * Creates a gRPC coroutine in a given coroutine scope which executes a given suspended function
 * taking in a Flow of gRPC requests and returning a Flow of gRPC responses and sends it on a given
 * gRPC stream observer.
 *
 * @param T the type of gRPC response.
 * @param scope coroutine scope used to run the coroutine.
 * @param responseObserver the gRPC stream observer on which to send the response.
 * @param block the suspended function transforming the request Flow to the response Flow.
 * @return a StreamObserver for the incoming requests.
 *
 * Example usage:
 * ```
 * override fun grpcMethod(
 *   request: TypeOfRequest,
 *   responseObserver: StreamObserver<TypeOfResponse> {
 *     grpcBidirectionalStream(scope, responseObserver) {
 *       block
 *     }
 *   }
 * }
 * ```
 */
@kotlinx.coroutines.ExperimentalCoroutinesApi
fun <T, U> grpcBidirectionalStream(
  scope: CoroutineScope,
  responseObserver: StreamObserver<U>,
  block: CoroutineScope.(Flow<T>) -> Flow<U>
): StreamObserver<T> {

  val inputFlow = MutableSharedFlow<T>(extraBufferCapacity = 8)
  val outputFlow = scope.block(inputFlow.asSharedFlow())

  val job =
    outputFlow
      .onEach { responseObserver.onNext(it) }
      .onCompletion { error ->
        if (error == null) {
          responseObserver.onCompleted()
        }
      }
      .catch {
        it.printStackTrace()
        responseObserver.onError(it)
      }
      .launchIn(scope)

  return object : StreamObserver<T> {
    override fun onNext(req: T) {
      // Note: this should be made a blocking call, and the handler should run in a separate thread
      // so we get flow control - but for now we can live with this
      if (!inputFlow.tryEmit(req)) {
        job.cancel(CancellationException("too many incoming requests, buffer exceeded"))
        responseObserver.onError(
          CancellationException("too many incoming requests, buffer exceeded")
        )
      }
    }

    override fun onCompleted() {
      job.cancel()
    }

    override fun onError(e: Throwable) {
      job.cancel()
      e.printStackTrace()
    }
  }
}

/**
 * Synchronous method to get a Bluetooth profile proxy.
 *
 * @param T the type of profile proxy (e.g. BluetoothA2dp)
 * @param context context
 * @param bluetoothAdapter local Bluetooth adapter
 * @param profile identifier of the Bluetooth profile (e.g. BluetoothProfile#A2DP)
 * @return T the desired profile proxy
 */
@Suppress("UNCHECKED_CAST")
@kotlinx.coroutines.ExperimentalCoroutinesApi
fun <T> getProfileProxy(context: Context, profile: Int): T {
  var proxy: BluetoothProfile?
  runBlocking {
    val bluetoothManager = context.getSystemService(BluetoothManager::class.java)!!
    val bluetoothAdapter = bluetoothManager.adapter

    val flow = callbackFlow {
      val serviceListener =
        object : BluetoothProfile.ServiceListener {
          override fun onServiceConnected(profile: Int, proxy: BluetoothProfile) {
            trySendBlocking(proxy)
          }
          override fun onServiceDisconnected(profile: Int) {}
        }

      bluetoothAdapter.getProfileProxy(context, serviceListener, profile)

      awaitClose {}
    }
    proxy = withTimeoutOrNull(5_000) { flow.first() }
  }
  return proxy!! as T
}

fun Intent.getBluetoothDeviceExtra(): BluetoothDevice =
  this.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)

fun ByteString.decodeToString(): String =
  MacAddress.fromBytes(this.toByteArray()).toString().uppercase()

fun ByteString.toBluetoothDevice(adapter: BluetoothAdapter): BluetoothDevice =
  adapter.getRemoteDevice(this.decodeToString())

fun Connection.toBluetoothDevice(adapter: BluetoothAdapter): BluetoothDevice =
  adapter.getRemoteDevice(this.cookie.toByteArray().decodeToString())

fun String.toByteArray(): ByteArray = MacAddress.fromString(this).toByteArray()

fun BluetoothDevice.toByteArray(): ByteArray = this.address.toByteArray()
