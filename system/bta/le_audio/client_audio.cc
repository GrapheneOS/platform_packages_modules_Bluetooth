/******************************************************************************
 *
 * Copyright 2019 HIMSA II K/S - www.himsa.com. Represented by EHIMA -
 * www.ehima.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************/

#include "client_audio.h"

#include "audio_hal_interface/le_audio_software.h"
#include "btu.h"
#include "common/repeating_timer.h"
#include "common/time_util.h"
#include "osi/include/wakelock.h"

using bluetooth::audio::le_audio::LeAudioClientInterface;

namespace {
LeAudioCodecConfiguration source_codec_config;
bluetooth::common::RepeatingTimer audio_timer;
LeAudioClientInterface* leAudioClientInterface = nullptr;
LeAudioClientInterface::Sink* sinkClientInterface = nullptr;
LeAudioClientInterface::Source* sourceClientInterface = nullptr;
LeAudioClientAudioSinkReceiver* localAudioSinkReceiver = nullptr;
LeAudioClientAudioSourceReceiver* localAudioSourceReceiver = nullptr;

enum {
  HAL_UNINITIALIZED,
  HAL_STOPPED,
  HAL_STARTED,
} le_audio_sink_hal_state,
    le_audio_source_hal_state;

struct AudioHalStats {
  size_t media_read_total_underflow_bytes;
  size_t media_read_total_underflow_count;
  uint64_t media_read_last_underflow_us;

  AudioHalStats() { Reset(); }

  void Reset() {
    media_read_total_underflow_bytes = 0;
    media_read_total_underflow_count = 0;
    media_read_last_underflow_us = 0;
  }
};

AudioHalStats stats;

bool le_audio_sink_on_resume_req(bool start_media_task);
bool le_audio_sink_on_suspend_req();

void send_audio_data() {
  uint32_t bytes_per_tick =
      (source_codec_config.num_channels * source_codec_config.sample_rate *
       source_codec_config.data_interval_us / 1000 *
       (source_codec_config.bits_per_sample / 8)) /
      1000;

  std::vector<uint8_t> data(bytes_per_tick);

  uint32_t bytes_read = 0;
  if (sinkClientInterface != nullptr) {
    bytes_read = sinkClientInterface->Read(data.data(), bytes_per_tick);
  } else {
    LOG(ERROR) << __func__ << ", no LE Audio sink client interface - aborting.";
    return;
  }

  // LOG(INFO) << __func__ << ", bytes_read: " << static_cast<int>(bytes_read)
  //          << ", bytes_per_tick: " << static_cast<int>(bytes_per_tick);

  if (bytes_read < bytes_per_tick) {
    stats.media_read_total_underflow_bytes += bytes_per_tick - bytes_read;
    stats.media_read_total_underflow_count++;
    stats.media_read_last_underflow_us =
        bluetooth::common::time_get_os_boottime_us();
  }

  if (localAudioSinkReceiver != nullptr) {
    localAudioSinkReceiver->OnAudioDataReady(data);
  }
}

void start_audio_ticks() {
  wakelock_acquire();
  audio_timer.SchedulePeriodic(
      get_main_thread()->GetWeakPtr(), FROM_HERE, base::Bind(&send_audio_data),
      base::TimeDelta::FromMicroseconds(source_codec_config.data_interval_us));
}

void stop_audio_ticks() {
  audio_timer.CancelAndWait();
  wakelock_release();
}

bool le_audio_sink_on_resume_req(bool start_media_task) {
  if (localAudioSinkReceiver != nullptr) {
    // Call OnAudioResume and block till it returns.
    std::promise<void> do_resume_promise;
    std::future<void> do_resume_future = do_resume_promise.get_future();
    bt_status_t status = do_in_main_thread(
        FROM_HERE,
        base::BindOnce(&LeAudioClientAudioSinkReceiver::OnAudioResume,
                       base::Unretained(localAudioSinkReceiver),
                       std::move(do_resume_promise)));
    if (status == BT_STATUS_SUCCESS) {
      do_resume_future.wait();
    } else {
      LOG(ERROR) << __func__
                 << ": LE_AUDIO_CTRL_CMD_START: do_in_main_thread err="
                 << status;
      return false;
    }
  } else {
    LOG(ERROR) << __func__
               << ": LE_AUDIO_CTRL_CMD_START: audio sink receiver not started";
    return false;
  }

  return true;
}

bool le_audio_source_on_resume_req(bool start_media_task) {
  if (localAudioSourceReceiver != nullptr) {
    // Call OnAudioResume and block till it returns.
    std::promise<void> do_resume_promise;
    std::future<void> do_resume_future = do_resume_promise.get_future();
    bt_status_t status = do_in_main_thread(
        FROM_HERE,
        base::BindOnce(&LeAudioClientAudioSourceReceiver::OnAudioResume,
                       base::Unretained(localAudioSourceReceiver),
                       std::move(do_resume_promise)));
    if (status == BT_STATUS_SUCCESS) {
      do_resume_future.wait();
    } else {
      LOG(ERROR) << __func__
                 << ": LE_AUDIO_CTRL_CMD_START: do_in_main_thread err="
                 << status;
      return false;
    }
  } else {
    LOG(ERROR)
        << __func__
        << ": LE_AUDIO_CTRL_CMD_START: audio source receiver not started";
    return false;
  }

  return true;
}

bool le_audio_sink_on_suspend_req() {
  stop_audio_ticks();
  if (localAudioSinkReceiver != nullptr) {
    // Call OnAudioSuspend and block till it returns.
    std::promise<void> do_suspend_promise;
    std::future<void> do_suspend_future = do_suspend_promise.get_future();
    bt_status_t status = do_in_main_thread(
        FROM_HERE,
        base::BindOnce(&LeAudioClientAudioSinkReceiver::OnAudioSuspend,
                       base::Unretained(localAudioSinkReceiver),
                       std::move(do_suspend_promise)));
    if (status == BT_STATUS_SUCCESS) {
      do_suspend_future.wait();
      return true;
    } else {
      LOG(ERROR) << __func__
                 << ": LE_AUDIO_CTRL_CMD_SUSPEND: do_in_main_thread err="
                 << status;
    }
  } else {
    LOG(ERROR) << __func__
               << ": LE_AUDIO_CTRL_CMD_SUSPEND: audio receiver not started";
  }
  return false;
}

bool le_audio_source_on_suspend_req() {
  if (localAudioSourceReceiver != nullptr) {
    // Call OnAudioSuspend and block till it returns.
    std::promise<void> do_suspend_promise;
    std::future<void> do_suspend_future = do_suspend_promise.get_future();
    bt_status_t status = do_in_main_thread(
        FROM_HERE,
        base::BindOnce(&LeAudioClientAudioSourceReceiver::OnAudioSuspend,
                       base::Unretained(localAudioSourceReceiver),
                       std::move(do_suspend_promise)));
    if (status == BT_STATUS_SUCCESS) {
      do_suspend_future.wait();
      return true;
    } else {
      LOG(ERROR) << __func__
                 << ": LE_AUDIO_CTRL_CMD_SUSPEND: do_in_main_thread err="
                 << status;
    }
  } else {
    LOG(ERROR) << __func__
               << ": LE_AUDIO_CTRL_CMD_SUSPEND: audio receiver not started";
  }
  return false;
}

bool le_audio_sink_on_metadata_update_req(audio_usage_t usage,
                                          audio_content_type_t content_type) {
  if (localAudioSinkReceiver == nullptr) {
    LOG(ERROR) << __func__ << ", audio receiver not started";
    return false;
  }

  // Call OnAudioSuspend and block till it returns.
  std::promise<void> do_update_metadata_promise;
  std::future<void> do_update_metadata_future =
      do_update_metadata_promise.get_future();
  bt_status_t status = do_in_main_thread(
      FROM_HERE,
      base::BindOnce(&LeAudioClientAudioSinkReceiver::OnAudioMetadataUpdate,
                     base::Unretained(localAudioSinkReceiver),
                     std::move(do_update_metadata_promise), usage,
                     content_type));

  if (status == BT_STATUS_SUCCESS) {
    do_update_metadata_future.wait();
    return true;
  }

  LOG(ERROR) << __func__ << ", do_in_main_thread err=" << status;

  return false;
}

}  // namespace

bool LeAudioClientAudioSource::Start(
    const LeAudioCodecConfiguration& codec_configuration,
    LeAudioClientAudioSinkReceiver* audioReceiver) {
  LOG(INFO) << __func__;

  if (!sinkClientInterface) {
    LOG(ERROR) << "sinkClientInterface is not Acquired!";
    return false;
  }

  if (le_audio_sink_hal_state == HAL_STARTED) {
    LOG(ERROR) << "LE audio device HAL is already in use!";
    return false;
  }

  LOG(INFO) << __func__ << ": Le Audio Source Open, bits per sample: "
            << int{codec_configuration.bits_per_sample}
            << ", num channels: " << int{codec_configuration.num_channels}
            << ", sample rate: " << codec_configuration.sample_rate
            << ", data interval: " << codec_configuration.data_interval_us;

  stats.Reset();

  /* Global config for periodic audio data */
  source_codec_config = codec_configuration;
  LeAudioClientInterface::PcmParameters pcmParameters = {
      .data_interval_us = codec_configuration.data_interval_us,
      .sample_rate = codec_configuration.sample_rate,
      .bits_per_sample = codec_configuration.bits_per_sample,
      .channels_count = codec_configuration.num_channels};

  sinkClientInterface->SetPcmParameters(pcmParameters);
  sinkClientInterface->StartSession();

  localAudioSinkReceiver = audioReceiver;
  le_audio_sink_hal_state = HAL_STARTED;

  return true;
}

void LeAudioClientAudioSource::Stop() {
  LOG(INFO) << __func__;
  if (!sinkClientInterface) {
    LOG(ERROR) << __func__ << " sinkClientInterface stopped";
    return;
  }

  if (le_audio_sink_hal_state != HAL_STARTED) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  LOG(INFO) << __func__ << ": Le Audio Source Close";

  sinkClientInterface->StopSession();
  le_audio_sink_hal_state = HAL_STOPPED;
  localAudioSinkReceiver = nullptr;

  stop_audio_ticks();
}

const void* LeAudioClientAudioSource::Acquire() {
  LOG(INFO) << __func__;
  if (sinkClientInterface != nullptr) {
    LOG(WARNING) << __func__ << ", Sink client interface already initialized";
    return nullptr;
  }

  /* Get pointer to singleton LE audio client interface */
  if (leAudioClientInterface == nullptr) {
    leAudioClientInterface = LeAudioClientInterface::Get();

    if (leAudioClientInterface == nullptr) {
      LOG(ERROR) << __func__ << ", can't get LE audio client interface";
      return nullptr;
    }
  }

  auto sink_stream_cb = bluetooth::audio::le_audio::StreamCallbacks{
      .on_resume_ = le_audio_sink_on_resume_req,
      .on_suspend_ = le_audio_sink_on_suspend_req,
      .on_metadata_update_ = le_audio_sink_on_metadata_update_req,
  };

  sinkClientInterface =
      leAudioClientInterface->GetSink(sink_stream_cb, get_main_thread());

  if (sinkClientInterface == nullptr) {
    LOG(ERROR) << __func__ << ", can't get LE audio sink client interface";
    return nullptr;
  }

  le_audio_sink_hal_state = HAL_STOPPED;
  return sinkClientInterface;
}

void LeAudioClientAudioSource::Release(const void* instance) {
  LOG(INFO) << __func__;
  if (sinkClientInterface != instance) {
    LOG(WARNING) << "Trying to release not own session";
    return;
  }

  if (le_audio_sink_hal_state == HAL_UNINITIALIZED) {
    LOG(WARNING) << "LE audio device HAL is not running.";
    return;
  }

  sinkClientInterface->Cleanup();
  leAudioClientInterface->ReleaseSink(sinkClientInterface);
  le_audio_sink_hal_state = HAL_UNINITIALIZED;
  sinkClientInterface = nullptr;
}

void LeAudioClientAudioSource::ConfirmStreamingRequest() {
  LOG(INFO) << __func__;
  if ((sinkClientInterface == nullptr) ||
      (le_audio_sink_hal_state != HAL_STARTED)) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  sinkClientInterface->ConfirmStreamingRequest();
  LOG(INFO) << __func__ << ", start_audio_ticks";
  start_audio_ticks();
}

void LeAudioClientAudioSource::CancelStreamingRequest() {
  LOG(INFO) << __func__;
  if ((sinkClientInterface == nullptr) ||
      (le_audio_sink_hal_state != HAL_STARTED)) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  sinkClientInterface->CancelStreamingRequest();
}

void LeAudioClientAudioSource::UpdateRemoteDelay(uint16_t remote_delay_ms) {
  LOG(INFO) << __func__;
  if ((sinkClientInterface == nullptr) ||
      (le_audio_sink_hal_state != HAL_STARTED)) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  sinkClientInterface->SetRemoteDelay(remote_delay_ms);
}

void LeAudioClientAudioSource::DebugDump(int fd) {
  uint64_t now_us = bluetooth::common::time_get_os_boottime_us();
  std::stringstream stream;
  stream << "  Le Audio Audio HAL:"
         << "\n    Counts (underflow)                                      : "
         << stats.media_read_total_underflow_count
         << "\n    Bytes (underflow)                                       : "
         << stats.media_read_total_underflow_bytes
         << "\n    Last update time ago in ms (underflow)                  : "
         << (stats.media_read_last_underflow_us > 0
                 ? (unsigned long long)(now_us -
                                        stats.media_read_last_underflow_us) /
                       1000
                 : 0)
         << std::endl;
  dprintf(fd, "%s", stream.str().c_str());
}

bool LeAudioClientAudioSink::Start(
    const LeAudioCodecConfiguration& codec_configuration,
    LeAudioClientAudioSourceReceiver* audioReceiver) {
  LOG(INFO) << __func__;
  if (!sourceClientInterface) {
    LOG(ERROR) << "sourceClientInterface is not Acquired!";
    return false;
  }

  if (le_audio_source_hal_state == HAL_STARTED) {
    LOG(ERROR) << "LE audio device HAL is already in use!";
    return false;
  }

  LOG(INFO) << __func__ << ": Le Audio Sink Open, bit rate: "
            << codec_configuration.bits_per_sample
            << ", num channels: " << int{codec_configuration.num_channels}
            << ", sample rate: " << codec_configuration.sample_rate
            << ", data interval: " << codec_configuration.data_interval_us;

  LeAudioClientInterface::PcmParameters pcmParameters = {
      .data_interval_us = codec_configuration.data_interval_us,
      .sample_rate = codec_configuration.sample_rate,
      .bits_per_sample = codec_configuration.bits_per_sample,
      .channels_count = codec_configuration.num_channels};

  sourceClientInterface->SetPcmParameters(pcmParameters);
  sourceClientInterface->StartSession();

  localAudioSourceReceiver = audioReceiver;
  le_audio_source_hal_state = HAL_STARTED;
  return true;
}

void LeAudioClientAudioSink::Stop() {
  LOG(INFO) << __func__;
  if (!sourceClientInterface) {
    LOG(ERROR) << __func__ << " sourceClientInterface stopped";
    return;
  }

  if (le_audio_source_hal_state != HAL_STARTED) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  LOG(INFO) << __func__ << ": Le Audio Sink Close";

  sourceClientInterface->StopSession();
  le_audio_source_hal_state = HAL_STOPPED;
  localAudioSourceReceiver = nullptr;
}

const void* LeAudioClientAudioSink::Acquire() {
  LOG(INFO) << __func__;
  if (sourceClientInterface != nullptr) {
    LOG(WARNING) << __func__ << ", Source client interface already initialized";
    return nullptr;
  }

  /* Get pointer to singleton LE audio client interface */
  if (leAudioClientInterface == nullptr) {
    leAudioClientInterface = LeAudioClientInterface::Get();

    if (leAudioClientInterface == nullptr) {
      LOG(ERROR) << __func__ << ", can't get LE audio client interface";
      return nullptr;
    }
  }

  auto source_stream_cb = bluetooth::audio::le_audio::StreamCallbacks{
      .on_resume_ = le_audio_source_on_resume_req,
      .on_suspend_ = le_audio_source_on_suspend_req,
  };

  sourceClientInterface =
      leAudioClientInterface->GetSource(source_stream_cb, get_main_thread());

  if (sourceClientInterface == nullptr) {
    LOG(ERROR) << __func__ << ", can't get LE audio source client interface";
    return nullptr;
  }

  le_audio_source_hal_state = HAL_STOPPED;
  return sourceClientInterface;
}

void LeAudioClientAudioSink::Release(const void* instance) {
  LOG(INFO) << __func__;
  if (sourceClientInterface != instance) {
    LOG(WARNING) << "Trying to release not own session";
    return;
  }

  if (le_audio_source_hal_state == HAL_UNINITIALIZED) {
    LOG(WARNING) << ", LE audio device source HAL is not running.";
    return;
  }

  sourceClientInterface->Cleanup();
  leAudioClientInterface->ReleaseSource(sourceClientInterface);
  le_audio_source_hal_state = HAL_UNINITIALIZED;
  sourceClientInterface = nullptr;
}

size_t LeAudioClientAudioSink::SendData(uint8_t* data, uint16_t size) {
  size_t bytes_written;
  if (!sourceClientInterface) {
    LOG(ERROR) << "sourceClientInterface not initialized!";
    return 0;
  }

  if (le_audio_source_hal_state != HAL_STARTED) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return 0;
  }

  /* TODO: What to do if not all data is written ? */
  bytes_written = sourceClientInterface->Write(data, size);
  if (bytes_written != size)
    LOG(ERROR) << ", Not all data is written to source HAL. bytes written: "
               << static_cast<int>(bytes_written)
               << ", total: " << static_cast<int>(size);

  return bytes_written;
}

void LeAudioClientAudioSink::ConfirmStreamingRequest() {
  LOG(INFO) << __func__;
  if ((sourceClientInterface == nullptr) ||
      (le_audio_source_hal_state != HAL_STARTED)) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  sourceClientInterface->ConfirmStreamingRequest();
}

void LeAudioClientAudioSink::CancelStreamingRequest() {
  LOG(INFO) << __func__;
  if ((sourceClientInterface == nullptr) ||
      (le_audio_source_hal_state != HAL_STARTED)) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  sourceClientInterface->CancelStreamingRequest();
}

void LeAudioClientAudioSink::UpdateRemoteDelay(uint16_t remote_delay_ms) {
  if ((sourceClientInterface == nullptr) ||
      (le_audio_source_hal_state != HAL_STARTED)) {
    LOG(ERROR) << "LE audio device HAL was not started!";
    return;
  }

  sourceClientInterface->SetRemoteDelay(remote_delay_ms);
}

void LeAudioClientAudioSink::DebugDump(int fd) {
  /* TODO: Add some statistic for source client interface */
}
