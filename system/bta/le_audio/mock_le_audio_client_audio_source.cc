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

#include "mock_le_audio_client_audio_source.h"

static MockLeAudioClientAudioSource* instance;
void MockLeAudioClientAudioSource::SetMockInstanceForTesting(
    MockLeAudioClientAudioSource* mock) {
  instance = mock;
}

bool LeAudioClientAudioSource::Start(
    const LeAudioCodecConfiguration& codecConfiguration,
    LeAudioClientAudioSinkReceiver* audioReceiver, uint16_t remote_delay_ms) {
  return instance->Start(codecConfiguration, audioReceiver, remote_delay_ms);
}

void LeAudioClientAudioSource::Stop() { instance->Stop(); }

// FIXME: This is wrong! we will return a different class object - not even in
// inheritance hierarchy
const void* LeAudioClientAudioSource::Acquire() { return instance->Acquire(); }

void LeAudioClientAudioSource::Release(const void* inst) {
  instance->Release(inst);
}

void LeAudioClientAudioSource::ConfirmStreamingRequest() {
  instance->ConfirmStreamingRequest();
}

void LeAudioClientAudioSource::CancelStreamingRequest() {
  instance->CancelStreamingRequest();
}

void LeAudioClientAudioSource::DebugDump(int fd) { instance->DebugDump(fd); }
