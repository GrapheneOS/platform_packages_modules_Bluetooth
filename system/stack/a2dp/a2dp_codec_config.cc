/*
 * Copyright (C) 2016 The Android Open Source Project
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

/**
 * A2DP Codecs Configuration
 */

#define LOG_TAG "a2dp_codec"

#include "a2dp_codec_api.h"

#include <base/logging.h>

#include "a2dp_sbc.h"
#include "a2dp_vendor.h"
#include "a2dp_vendor_aptx.h"
#include "a2dp_vendor_aptx_hd.h"
#include "osi/include/log.h"

/* The Media Type offset within the codec info byte array */
#define A2DP_MEDIA_TYPE_OFFSET 1

A2dpCodecConfig::A2dpCodecConfig(btav_a2dp_codec_index_t codec_index,
                                 const std::string& name)
    : codec_index_(codec_index), name_(name) {
  setDefaultCodecPriority();

  memset(&codec_config_, 0, sizeof(codec_config_));
  codec_config_.codec_type = codec_index_;

  memset(&codec_capability_, 0, sizeof(codec_capability_));
  codec_capability_.codec_type = codec_index_;

  memset(&codec_user_config_, 0, sizeof(codec_user_config_));
  codec_user_config_.codec_type = codec_index_;

  memset(&codec_audio_config_, 0, sizeof(codec_audio_config_));
  codec_audio_config_.codec_type = codec_index_;

  memset(ota_codec_config_, 0, sizeof(ota_codec_config_));
  memset(ota_codec_peer_capability_, 0, sizeof(ota_codec_peer_capability_));
  memset(ota_codec_peer_config_, 0, sizeof(ota_codec_peer_config_));
}

A2dpCodecConfig::~A2dpCodecConfig() {}

void A2dpCodecConfig::setCodecPriority(
    btav_a2dp_codec_priority_t codec_priority) {
  if (codec_priority == 0) {
    // Compute the default codec priority
    setDefaultCodecPriority();
  } else {
    codec_priority_ = codec_priority;
  }
}

void A2dpCodecConfig::setDefaultCodecPriority() {
  // Compute the default codec priority
  codec_priority_ = 1000 * codec_index_ + 1;
}

A2dpCodecConfig* A2dpCodecConfig::createCodec(
    btav_a2dp_codec_index_t codec_index) {
  LOG_DEBUG(LOG_TAG, "%s: codec %s", __func__, A2DP_CodecIndexStr(codec_index));

  A2dpCodecConfig* codec_config = nullptr;
  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
      codec_config = new A2dpCodecConfigSbc();
      break;
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
      codec_config = new A2dpCodecConfigSbcSink();
      break;
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX:
      codec_config = new A2dpCodecConfigAptx();
      break;
    case BTAV_A2DP_CODEC_INDEX_SOURCE_APTX_HD:
      codec_config = new A2dpCodecConfigAptxHd();
      break;
    case BTAV_A2DP_CODEC_INDEX_MAX:
      break;
  }

  if (codec_config != nullptr) {
    if (!codec_config->init()) {
      delete codec_config;
      codec_config = nullptr;
    }
  }

  return codec_config;
}

bool A2dpCodecConfig::isValid() const { return true; }

bool A2dpCodecConfig::copyOutOtaCodecConfig(uint8_t* p_codec_info) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  // TODO: We should use a mechanism to verify codec config,
  // not codec capability.
  if (!A2DP_IsSourceCodecValid(ota_codec_config_)) {
    return false;
  }
  memcpy(p_codec_info, ota_codec_config_, sizeof(ota_codec_config_));
  return true;
}

btav_a2dp_codec_config_t A2dpCodecConfig::getCodecConfig() {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  // TODO: We should check whether the codec config is valid
  return codec_config_;
}

btav_a2dp_codec_config_t A2dpCodecConfig::getCodecCapability() {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  // TODO: We should check whether the codec capability is valid
  return codec_capability_;
}

btav_a2dp_codec_config_t A2dpCodecConfig::getCodecUserConfig() {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  return codec_user_config_;
}

btav_a2dp_codec_config_t A2dpCodecConfig::getCodecAudioConfig() {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  return codec_audio_config_;
}

uint8_t A2dpCodecConfig::getAudioBitsPerSample() {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  switch (codec_config_.bits_per_sample) {
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_16:
      return 16;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_24:
      return 24;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_32:
      return 32;
    case BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE:
      break;
  }
  return 0;
}

bool A2dpCodecConfig::isCodecConfigEmpty(
    const btav_a2dp_codec_config_t& codec_config) {
  return (
      (codec_config.codec_priority == 0) &&
      (codec_config.sample_rate == BTAV_A2DP_CODEC_SAMPLE_RATE_NONE) &&
      (codec_config.bits_per_sample == BTAV_A2DP_CODEC_BITS_PER_SAMPLE_NONE) &&
      (codec_config.channel_mode == BTAV_A2DP_CODEC_CHANNEL_MODE_NONE) &&
      (codec_config.codec_specific_1 == 0) &&
      (codec_config.codec_specific_2 == 0) &&
      (codec_config.codec_specific_3 == 0) &&
      (codec_config.codec_specific_4 == 0));
}

bool A2dpCodecConfig::setCodecUserConfig(
    const btav_a2dp_codec_config_t& codec_user_config,
    const btav_a2dp_codec_config_t& codec_audio_config,
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
    const uint8_t* p_peer_codec_info, bool is_capability,
    uint8_t* p_result_codec_config, bool* p_restart_input,
    bool* p_restart_output, bool* p_config_updated) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);
  *p_restart_input = false;
  *p_restart_output = false;
  *p_config_updated = false;

  // Save copies of the current codec config, and the OTA codec config, so they
  // can be compared for changes.
  btav_a2dp_codec_config_t saved_codec_config = getCodecConfig();
  uint8_t saved_ota_codec_config[AVDT_CODEC_SIZE];
  memcpy(saved_ota_codec_config, ota_codec_config_, sizeof(ota_codec_config_));

  btav_a2dp_codec_config_t saved_codec_user_config = codec_user_config_;
  codec_user_config_ = codec_user_config;
  btav_a2dp_codec_config_t saved_codec_audio_config = codec_audio_config_;
  codec_audio_config_ = codec_audio_config;
  bool success =
      setCodecConfig(p_peer_codec_info, is_capability, p_result_codec_config);
  if (!success) {
    // Restore the local copy of the user and audio config
    codec_user_config_ = saved_codec_user_config;
    codec_audio_config_ = saved_codec_audio_config;
    return false;
  }

  //
  // The input (audio data) should be restarted if the audio format has changed
  //
  btav_a2dp_codec_config_t new_codec_config = getCodecConfig();
  if ((saved_codec_config.sample_rate != new_codec_config.sample_rate) ||
      (saved_codec_config.bits_per_sample !=
       new_codec_config.bits_per_sample) ||
      (saved_codec_config.channel_mode != new_codec_config.channel_mode)) {
    *p_restart_input = true;
  }

  //
  // The output (the connection) should be restarted if OTA codec config
  // has changed.
  //
  if (!A2DP_CodecEquals(saved_ota_codec_config, p_result_codec_config)) {
    *p_restart_output = true;
  }

  bool encoder_restart_input = *p_restart_input;
  bool encoder_restart_output = *p_restart_output;
  bool encoder_config_updated = *p_config_updated;
  if (updateEncoderUserConfig(p_peer_params, &encoder_restart_input,
                              &encoder_restart_output,
                              &encoder_config_updated)) {
    if (encoder_restart_input) *p_restart_input = true;
    if (encoder_restart_output) *p_restart_output = true;
    if (encoder_config_updated) *p_config_updated = true;
  }
  if (*p_restart_input || *p_restart_output) *p_config_updated = true;

  return true;
}

//
// Compares two codecs |lhs| and |rhs| based on their priority.
// Returns true if |lhs| has higher priority (larger priority value).
// If |lhs| and |rhs| have same priority, the unique codec index is used
// as a tie-breaker: larger codec index value means higher priority.
//
static bool compare_codec_priority(const A2dpCodecConfig* lhs,
                                   const A2dpCodecConfig* rhs) {
  if (lhs->codecPriority() > rhs->codecPriority()) return true;
  if (lhs->codecPriority() < rhs->codecPriority()) return false;
  return (lhs->codecIndex() > rhs->codecIndex());
}

A2dpCodecs::A2dpCodecs() : current_codec_config_(nullptr) {}

A2dpCodecs::~A2dpCodecs() {
  std::unique_lock<std::recursive_mutex> lock(codec_mutex_);
  for (const auto& iter : indexed_codecs_) {
    delete iter.second;
  }
  lock.unlock();
}

bool A2dpCodecs::init() {
  LOG_DEBUG(LOG_TAG, "%s", __func__);
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  for (int i = BTAV_A2DP_CODEC_INDEX_MIN; i < BTAV_A2DP_CODEC_INDEX_MAX; i++) {
    btav_a2dp_codec_index_t codec_index =
        static_cast<btav_a2dp_codec_index_t>(i);
    A2dpCodecConfig* codec_config = A2dpCodecConfig::createCodec(codec_index);
    if (codec_config == nullptr) continue;

    indexed_codecs_.insert(std::make_pair(codec_index, codec_config));

    if (codec_index < BTAV_A2DP_CODEC_INDEX_SOURCE_MAX) {
      ordered_source_codecs_.push_back(codec_config);
      ordered_source_codecs_.sort(compare_codec_priority);
    } else {
      ordered_sink_codecs_.push_back(codec_config);
      ordered_sink_codecs_.sort(compare_codec_priority);
    }
  }

  if (ordered_source_codecs_.empty()) {
    LOG_ERROR(LOG_TAG, "%s: no Source codecs were initialized", __func__);
  } else {
    for (auto iter : ordered_source_codecs_) {
      LOG_INFO(LOG_TAG, "%s: initialized Source codec %s", __func__,
               iter->name().c_str());
    }
  }
  if (ordered_sink_codecs_.empty()) {
    LOG_ERROR(LOG_TAG, "%s: no Sink codecs were initialized", __func__);
  } else {
    for (auto iter : ordered_sink_codecs_) {
      LOG_INFO(LOG_TAG, "%s: initialized Sink codec %s", __func__,
               iter->name().c_str());
    }
  }

  return (!ordered_source_codecs_.empty() && !ordered_sink_codecs_.empty());
}

A2dpCodecConfig* A2dpCodecs::findSourceCodecConfig(
    const uint8_t* p_codec_info) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);
  btav_a2dp_codec_index_t codec_index = A2DP_SourceCodecIndex(p_codec_info);
  if (codec_index == BTAV_A2DP_CODEC_INDEX_MAX) return nullptr;

  auto iter = indexed_codecs_.find(codec_index);
  if (iter == indexed_codecs_.end()) return nullptr;
  return iter->second;
}

bool A2dpCodecs::setCodecConfig(const uint8_t* p_peer_codec_info,
                                bool is_capability,
                                uint8_t* p_result_codec_config) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);
  A2dpCodecConfig* a2dp_codec_config = findSourceCodecConfig(p_peer_codec_info);
  if (a2dp_codec_config == nullptr) return false;
  if (!a2dp_codec_config->setCodecConfig(p_peer_codec_info, is_capability,
                                         p_result_codec_config)) {
    return false;
  }
  current_codec_config_ = a2dp_codec_config;
  return true;
}

bool A2dpCodecs::setCodecUserConfig(
    const btav_a2dp_codec_config_t& codec_user_config,
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
    const uint8_t* p_peer_sink_capabilities, uint8_t* p_result_codec_config,
    bool* p_restart_input, bool* p_restart_output, bool* p_config_updated) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);
  btav_a2dp_codec_config_t codec_audio_config;
  A2dpCodecConfig* a2dp_codec_config = nullptr;
  A2dpCodecConfig* last_codec_config = current_codec_config_;
  *p_restart_input = false;
  *p_restart_output = false;
  *p_config_updated = false;

  if (codec_user_config.codec_type < BTAV_A2DP_CODEC_INDEX_MAX) {
    auto iter = indexed_codecs_.find(codec_user_config.codec_type);
    if (iter == indexed_codecs_.end()) goto fail;
    a2dp_codec_config = iter->second;
  } else {
    // Update the default codec
    a2dp_codec_config = current_codec_config_;
  }
  if (a2dp_codec_config == nullptr) goto fail;
  current_codec_config_ = a2dp_codec_config;

  // Reuse the existing codec audio config
  codec_audio_config = a2dp_codec_config->getCodecAudioConfig();
  if (!a2dp_codec_config->setCodecUserConfig(
          codec_user_config, codec_audio_config, p_peer_params,
          p_peer_sink_capabilities, true, p_result_codec_config,
          p_restart_input, p_restart_output, p_config_updated)) {
    goto fail;
  }
  CHECK(current_codec_config_ != nullptr);

  // If the codec has changed because of priority, update the priorities
  // and restart the connection
  do {
    btav_a2dp_codec_priority_t old_priority =
        a2dp_codec_config->codecPriority();
    btav_a2dp_codec_priority_t new_priority = codec_user_config.codec_priority;
    if (old_priority == new_priority) break;  // No change in priority
    *p_config_updated = true;
    a2dp_codec_config->setCodecPriority(new_priority);
    // Get the actual (recomputed) priority
    new_priority = a2dp_codec_config->codecPriority();
    if (old_priority > new_priority) {
      // The priority has become lower. If this was the previous codec, restart
      // the connection to re-elect a new codec.
      if (a2dp_codec_config == last_codec_config) {
        *p_restart_output = true;
      }
      break;
    }
    // The priority has become higher. If this was not the previous codec,
    // and the new priority is higher than the current codec, restart the
    // connection to re-elect a new codec.
    if ((a2dp_codec_config == last_codec_config) ||
        (last_codec_config == nullptr)) {
      break;
    }
    if (new_priority < last_codec_config->codecPriority()) break;
    last_codec_config->setDefaultCodecPriority();
    *p_restart_output = true;

  } while (false);
  ordered_source_codecs_.sort(compare_codec_priority);

  if (*p_restart_input || *p_restart_output) *p_config_updated = true;

  return true;

fail:
  current_codec_config_ = last_codec_config;
  return false;
}

bool A2dpCodecs::setCodecAudioConfig(
    const btav_a2dp_codec_config_t& codec_audio_config,
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
    const uint8_t* p_peer_sink_capabilities, uint8_t* p_result_codec_config,
    bool* p_restart_output, bool* p_config_updated) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);
  btav_a2dp_codec_config_t codec_user_config;
  A2dpCodecConfig* a2dp_codec_config = current_codec_config_;
  *p_restart_output = false;
  *p_config_updated = false;

  if (a2dp_codec_config == nullptr) return false;

  // Reuse the existing codec user config
  codec_user_config = a2dp_codec_config->getCodecUserConfig();
  bool restart_input = false;  // Flag ignored - input was just restarted
  if (!a2dp_codec_config->setCodecUserConfig(
          codec_user_config, codec_audio_config, p_peer_params,
          p_peer_sink_capabilities, true, p_result_codec_config, &restart_input,
          p_restart_output, p_config_updated)) {
    return false;
  }

  return true;
}

bool A2dpCodecs::setCodecOtaConfig(
    const uint8_t* p_ota_codec_config,
    const tA2DP_ENCODER_INIT_PEER_PARAMS* p_peer_params,
    uint8_t* p_result_codec_config, bool* p_restart_input,
    bool* p_restart_output, bool* p_config_updated) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);
  btav_a2dp_codec_index_t codec_type;
  btav_a2dp_codec_config_t codec_user_config;
  btav_a2dp_codec_config_t codec_audio_config;
  A2dpCodecConfig* a2dp_codec_config = nullptr;
  A2dpCodecConfig* last_codec_config = current_codec_config_;
  *p_restart_input = false;
  *p_restart_output = false;
  *p_config_updated = false;

  // Check whether the current codec config is explicitly configured by
  // user configuration. If yes, then the OTA codec configuration is ignored.
  if (current_codec_config_ != nullptr) {
    codec_user_config = current_codec_config_->getCodecUserConfig();
    if (!A2dpCodecConfig::isCodecConfigEmpty(codec_user_config)) {
      LOG_WARN(LOG_TAG,
               "%s: ignoring peer OTA configuration for codec %s: "
               "existing user configuration for current codec %s",
               __func__, A2DP_CodecName(p_ota_codec_config),
               current_codec_config_->name().c_str());
      goto fail;
    }
  }

  // Check whether the codec config for the same codec is explicitly configured
  // by user configuration. If yes, then the OTA codec configuration is
  // ignored.
  codec_type = A2DP_SourceCodecIndex(p_ota_codec_config);
  if (codec_type == BTAV_A2DP_CODEC_INDEX_MAX) {
    LOG_WARN(LOG_TAG,
             "%s: ignoring peer OTA codec configuration: "
             "invalid codec",
             __func__);
    goto fail;  // Invalid codec
  } else {
    auto iter = indexed_codecs_.find(codec_type);
    if (iter == indexed_codecs_.end()) {
      LOG_WARN(LOG_TAG,
               "%s: cannot find codec configuration for peer OTA codec %s",
               __func__, A2DP_CodecName(p_ota_codec_config));
      goto fail;
    }
    a2dp_codec_config = iter->second;
  }
  if (a2dp_codec_config == nullptr) goto fail;
  codec_user_config = a2dp_codec_config->getCodecUserConfig();
  if (!A2dpCodecConfig::isCodecConfigEmpty(codec_user_config)) {
    LOG_WARN(LOG_TAG,
             "%s: ignoring peer OTA configuration for codec %s: "
             "existing user configuration for same codec",
             __func__, A2DP_CodecName(p_ota_codec_config));
    goto fail;
  }
  current_codec_config_ = a2dp_codec_config;

  // Reuse the existing codec user config and codec audio config
  codec_audio_config = a2dp_codec_config->getCodecAudioConfig();
  if (!a2dp_codec_config->setCodecUserConfig(
          codec_user_config, codec_audio_config, p_peer_params,
          p_ota_codec_config, false, p_result_codec_config, p_restart_input,
          p_restart_output, p_config_updated)) {
    LOG_WARN(LOG_TAG,
             "%s: cannot set codec configuration for peer OTA codec %s",
             __func__, A2DP_CodecName(p_ota_codec_config));
    goto fail;
  }
  CHECK(current_codec_config_ != nullptr);

  if (*p_restart_input || *p_restart_output) *p_config_updated = true;

  return true;

fail:
  current_codec_config_ = last_codec_config;
  return false;
}

bool A2dpCodecs::getCodecConfigAndCapabilities(
    btav_a2dp_codec_config_t* p_codec_config,
    std::vector<btav_a2dp_codec_config_t>* p_codec_capabilities) {
  std::lock_guard<std::recursive_mutex> lock(codec_mutex_);

  if (current_codec_config_ != nullptr) {
    *p_codec_config = current_codec_config_->getCodecConfig();
  } else {
    btav_a2dp_codec_config_t codec_config;
    memset(&codec_config, 0, sizeof(codec_config));
    *p_codec_config = codec_config;
  }

  std::vector<btav_a2dp_codec_config_t> codec_capabilities;
  for (auto codec : orderedSourceCodecs()) {
    codec_capabilities.push_back(codec->getCodecCapability());
  }
  *p_codec_capabilities = codec_capabilities;

  return true;
}

tA2DP_CODEC_TYPE A2DP_GetCodecType(const uint8_t* p_codec_info) {
  return (tA2DP_CODEC_TYPE)(p_codec_info[AVDT_CODEC_TYPE_INDEX]);
}

bool A2DP_IsSourceCodecValid(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_IsSourceCodecValidSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_IsVendorSourceCodecValid(p_codec_info);
    default:
      break;
  }

  return false;
}

bool A2DP_IsSinkCodecValid(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_IsSinkCodecValidSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_IsVendorSinkCodecValid(p_codec_info);
    default:
      break;
  }

  return false;
}

bool A2DP_IsPeerSourceCodecValid(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_IsPeerSourceCodecValidSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_IsVendorPeerSourceCodecValid(p_codec_info);
    default:
      break;
  }

  return false;
}

bool A2DP_IsPeerSinkCodecValid(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_IsPeerSinkCodecValidSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_IsVendorPeerSinkCodecValid(p_codec_info);
    default:
      break;
  }

  return false;
}

bool A2DP_IsSinkCodecSupported(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_IsSinkCodecSupportedSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_IsVendorSinkCodecSupported(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return false;
}

bool A2DP_IsPeerSourceCodecSupported(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_IsPeerSourceCodecSupportedSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_IsVendorPeerSourceCodecSupported(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return false;
}

void A2DP_InitDefaultCodec(uint8_t* p_codec_info) {
  A2DP_InitDefaultCodecSbc(p_codec_info);
}

tA2DP_STATUS A2DP_BuildSrc2SinkConfig(const uint8_t* p_src_cap,
                                      uint8_t* p_pref_cfg) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_src_cap);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_BuildSrc2SinkConfigSbc(p_src_cap, p_pref_cfg);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorBuildSrc2SinkConfig(p_src_cap, p_pref_cfg);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return A2DP_NS_CODEC_TYPE;
}

bool A2DP_UsesRtpHeader(bool content_protection_enabled,
                        const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  if (codec_type != A2DP_MEDIA_CT_NON_A2DP) return true;

  return A2DP_VendorUsesRtpHeader(content_protection_enabled, p_codec_info);
}

uint8_t A2DP_GetMediaType(const uint8_t* p_codec_info) {
  uint8_t media_type = (p_codec_info[A2DP_MEDIA_TYPE_OFFSET] >> 4) & 0x0f;
  return media_type;
}

const char* A2DP_CodecName(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_CodecNameSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorCodecName(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return "UNKNOWN CODEC";
}

bool A2DP_CodecTypeEquals(const uint8_t* p_codec_info_a,
                          const uint8_t* p_codec_info_b) {
  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if (codec_type_a != codec_type_b) return false;

  switch (codec_type_a) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_CodecTypeEqualsSbc(p_codec_info_a, p_codec_info_b);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorCodecTypeEquals(p_codec_info_a, p_codec_info_b);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type_a);
  return false;
}

bool A2DP_CodecEquals(const uint8_t* p_codec_info_a,
                      const uint8_t* p_codec_info_b) {
  tA2DP_CODEC_TYPE codec_type_a = A2DP_GetCodecType(p_codec_info_a);
  tA2DP_CODEC_TYPE codec_type_b = A2DP_GetCodecType(p_codec_info_b);

  if (codec_type_a != codec_type_b) return false;

  switch (codec_type_a) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_CodecEqualsSbc(p_codec_info_a, p_codec_info_b);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorCodecEquals(p_codec_info_a, p_codec_info_b);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type_a);
  return false;
}

int A2DP_GetTrackSampleRate(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_GetTrackSampleRateSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorGetTrackSampleRate(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return -1;
}

int A2DP_GetTrackBitsPerSample(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_GetTrackBitsPerSampleSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorGetTrackBitsPerSample(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return -1;
}

int A2DP_GetTrackChannelCount(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_GetTrackChannelCountSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorGetTrackChannelCount(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return -1;
}

int A2DP_GetSinkTrackChannelType(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_GetSinkTrackChannelTypeSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorGetSinkTrackChannelType(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return -1;
}

int A2DP_GetSinkFramesCountToProcess(uint64_t time_interval_ms,
                                     const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_GetSinkFramesCountToProcessSbc(time_interval_ms,
                                                 p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorGetSinkFramesCountToProcess(time_interval_ms,
                                                    p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return -1;
}

bool A2DP_GetPacketTimestamp(const uint8_t* p_codec_info, const uint8_t* p_data,
                             uint32_t* p_timestamp) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_GetPacketTimestampSbc(p_codec_info, p_data, p_timestamp);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorGetPacketTimestamp(p_codec_info, p_data, p_timestamp);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return false;
}

bool A2DP_BuildCodecHeader(const uint8_t* p_codec_info, BT_HDR* p_buf,
                           uint16_t frames_per_packet) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_BuildCodecHeaderSbc(p_codec_info, p_buf, frames_per_packet);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorBuildCodecHeader(p_codec_info, p_buf,
                                         frames_per_packet);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return false;
}

const tA2DP_ENCODER_INTERFACE* A2DP_GetEncoderInterface(
    const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_GetEncoderInterfaceSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorGetEncoderInterface(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return NULL;
}

bool A2DP_AdjustCodec(uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_AdjustCodecSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorAdjustCodec(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return false;
}

btav_a2dp_codec_index_t A2DP_SourceCodecIndex(const uint8_t* p_codec_info) {
  tA2DP_CODEC_TYPE codec_type = A2DP_GetCodecType(p_codec_info);

  LOG_VERBOSE(LOG_TAG, "%s: codec_type = 0x%x", __func__, codec_type);

  switch (codec_type) {
    case A2DP_MEDIA_CT_SBC:
      return A2DP_SourceCodecIndexSbc(p_codec_info);
    case A2DP_MEDIA_CT_NON_A2DP:
      return A2DP_VendorSourceCodecIndex(p_codec_info);
    default:
      break;
  }

  LOG_ERROR(LOG_TAG, "%s: unsupported codec type 0x%x", __func__, codec_type);
  return BTAV_A2DP_CODEC_INDEX_MAX;
}

const char* A2DP_CodecIndexStr(btav_a2dp_codec_index_t codec_index) {
  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
      return A2DP_CodecIndexStrSbc();
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
      return A2DP_CodecIndexStrSbcSink();
    default:
      break;
  }

  if (codec_index < BTAV_A2DP_CODEC_INDEX_MAX)
    return A2DP_VendorCodecIndexStr(codec_index);

  return "UNKNOWN CODEC INDEX";
}

bool A2DP_InitCodecConfig(btav_a2dp_codec_index_t codec_index,
                          tAVDT_CFG* p_cfg) {
  LOG_VERBOSE(LOG_TAG, "%s: codec %s", __func__,
              A2DP_CodecIndexStr(codec_index));

  /* Default: no content protection info */
  p_cfg->num_protect = 0;
  p_cfg->protect_info[0] = 0;

  switch (codec_index) {
    case BTAV_A2DP_CODEC_INDEX_SOURCE_SBC:
      return A2DP_InitCodecConfigSbc(p_cfg);
    case BTAV_A2DP_CODEC_INDEX_SINK_SBC:
      return A2DP_InitCodecConfigSbcSink(p_cfg);
    default:
      break;
  }

  if (codec_index < BTAV_A2DP_CODEC_INDEX_MAX)
    return A2DP_VendorInitCodecConfig(codec_index, p_cfg);

  return false;
}
