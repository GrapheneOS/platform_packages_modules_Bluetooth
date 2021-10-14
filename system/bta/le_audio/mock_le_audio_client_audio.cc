/*
 * Copyright 2020 HIMSA II K/S - www.himsa.com.
 * Represented by EHIMA - www.ehima.com
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

#include "mock_le_audio_client_audio.h"

#include <base/logging.h>

/* Source mock */
static MockLeAudioClientAudioSource* source_instance = nullptr;
void MockLeAudioClientAudioSource::SetMockInstanceForTesting(
    MockLeAudioClientAudioSource* mock) {
  source_instance = mock;
}

bool LeAudioClientAudioSource::Start(
    const LeAudioCodecConfiguration& codecConfiguration,
    LeAudioClientAudioSinkReceiver* audioReceiver) {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSource interface not set!";
  return source_instance->Start(codecConfiguration, audioReceiver);
}

void LeAudioClientAudioSource::Stop() {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSource interface not set!";
  source_instance->Stop();
}

// FIXME: This is wrong! we will return a different class object - not even in
// inheritance hierarchy
const void* LeAudioClientAudioSource::Acquire() {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSource interface not set!";
  return source_instance->Acquire();
}

void LeAudioClientAudioSource::Release(const void* inst) {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSource interface not set!";
  source_instance->Release(inst);
}

void LeAudioClientAudioSource::ConfirmStreamingRequest() {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSink interface not set!";
  source_instance->ConfirmStreamingRequest();
}

void LeAudioClientAudioSource::CancelStreamingRequest() {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSink interface not set!";
  source_instance->CancelStreamingRequest();
}

void LeAudioClientAudioSource::UpdateRemoteDelay(uint16_t delay) {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSource interface not set!";
  source_instance->UpdateRemoteDelay(delay);
}

void LeAudioClientAudioSource::DebugDump(int fd) {
  LOG_ASSERT(source_instance)
      << "Mock LeAudioClientAudioSource interface not set!";
  source_instance->DebugDump(fd);
}

/* Sink mock */
static MockLeAudioClientAudioSink* sink_instance = nullptr;
void MockLeAudioClientAudioSink::SetMockInstanceForTesting(
    MockLeAudioClientAudioSink* mock) {
  sink_instance = mock;
}

bool LeAudioClientAudioSink::Start(
    const LeAudioCodecConfiguration& codecConfiguration,
    LeAudioClientAudioSourceReceiver* audioReceiver) {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  return sink_instance->Start(codecConfiguration, audioReceiver);
}

void LeAudioClientAudioSink::Stop() {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  sink_instance->Stop();
}

// FIXME: This is wrong! we will return a different class object - not even in
// inheritance hierarchy
const void* LeAudioClientAudioSink::Acquire() {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  return sink_instance->Acquire();
}

void LeAudioClientAudioSink::Release(const void* inst) {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  sink_instance->Release(inst);
}

void LeAudioClientAudioSink::UpdateRemoteDelay(uint16_t delay) {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  sink_instance->UpdateRemoteDelay(delay);
}

void LeAudioClientAudioSink::DebugDump(int fd) {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  sink_instance->DebugDump(fd);
}

size_t LeAudioClientAudioSink::SendData(uint8_t* data, uint16_t size) {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  return sink_instance->SendData(data, size);
}

void LeAudioClientAudioSink::ConfirmStreamingRequest() {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  sink_instance->ConfirmStreamingRequest();
}

void LeAudioClientAudioSink::CancelStreamingRequest() {
  LOG_ASSERT(sink_instance) << "Mock LeAudioClientAudioSink interface not set!";
  sink_instance->CancelStreamingRequest();
}
