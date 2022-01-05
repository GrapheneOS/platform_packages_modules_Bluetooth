/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mock_codec_manager.h"

MockCodecManager* mock_codec_manager_pimpl_;
MockCodecManager* MockCodecManager::GetInstance() {
  le_audio::CodecManager::GetInstance();
  return mock_codec_manager_pimpl_;
}

namespace le_audio {

struct CodecManager::impl : public MockCodecManager {
 public:
  impl() = default;
  ~impl() = default;
};

CodecManager::CodecManager() {}

types::CodecLocation CodecManager::GetCodecLocation() const {
  if (!pimpl_) return types::CodecLocation::HOST;
  return pimpl_->GetCodecLocation();
}

void CodecManager::UpdateActiveAudioConfig(
    const stream_configuration& stream_conf, uint16_t delay) {
  if (pimpl_) return pimpl_->UpdateActiveAudioConfig(stream_conf, delay);
}

void CodecManager::Start() {
  // It is needed here as CodecManager which is a singleton creates it, but in
  // this mock we want to destroy and recreate the mock on each test case.
  if (!pimpl_) {
    pimpl_ = std::make_unique<impl>();
  }

  mock_codec_manager_pimpl_ = pimpl_.get();
  pimpl_->Start();
}

void CodecManager::Stop() {
  // It is needed here as CodecManager which is a singleton creates it, but in
  // this mock we want to destroy and recreate the mock on each test case.
  if (pimpl_) {
    pimpl_->Stop();
    pimpl_.reset();
  }

  mock_codec_manager_pimpl_ = nullptr;
}

// CodecManager::~CodecManager() = default;

}  // namespace le_audio
