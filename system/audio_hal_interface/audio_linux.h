/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <stddef.h>

/* maximum audio device address length */
#define AUDIO_DEVICE_MAX_ADDRESS_LEN 32

typedef enum {
  AUDIO_SOURCE_DEFAULT = 0,
  AUDIO_SOURCE_MIC = 1,
  AUDIO_SOURCE_VOICE_UPLINK = 2,
  AUDIO_SOURCE_VOICE_DOWNLINK = 3,
  AUDIO_SOURCE_VOICE_CALL = 4,
  AUDIO_SOURCE_CAMCORDER = 5,
  AUDIO_SOURCE_VOICE_RECOGNITION = 6,
  AUDIO_SOURCE_VOICE_COMMUNICATION = 7,
  AUDIO_SOURCE_REMOTE_SUBMIX = 8,
  AUDIO_SOURCE_UNPROCESSED = 9,
  AUDIO_SOURCE_VOICE_PERFORMANCE = 10,
  AUDIO_SOURCE_ECHO_REFERENCE = 1997,
  AUDIO_SOURCE_FM_TUNER = 1998,
  AUDIO_SOURCE_HOTWORD = 1999,
  AUDIO_SOURCE_INVALID = -1,
} audio_source_t;

typedef enum {
  AUDIO_CONTENT_TYPE_UNKNOWN = 0u,
  AUDIO_CONTENT_TYPE_SPEECH = 1u,
  AUDIO_CONTENT_TYPE_MUSIC = 2u,
  AUDIO_CONTENT_TYPE_MOVIE = 3u,
  AUDIO_CONTENT_TYPE_SONIFICATION = 4u,
} audio_content_type_t;

typedef enum {
  AUDIO_USAGE_UNKNOWN = 0,
  AUDIO_USAGE_MEDIA = 1,
  AUDIO_USAGE_VOICE_COMMUNICATION = 2,
  AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING = 3,
  AUDIO_USAGE_ALARM = 4,
  AUDIO_USAGE_NOTIFICATION = 5,
  AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE = 6,
  AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST = 7,
  AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT = 8,
  AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED = 9,
  AUDIO_USAGE_NOTIFICATION_EVENT = 10,
  AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY = 11,
  AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE = 12,
  AUDIO_USAGE_ASSISTANCE_SONIFICATION = 13,
  AUDIO_USAGE_GAME = 14,
  AUDIO_USAGE_VIRTUAL_SOURCE = 15,
  AUDIO_USAGE_ASSISTANT = 16,
  AUDIO_USAGE_CALL_ASSISTANT = 17,
  AUDIO_USAGE_EMERGENCY = 1000,
  AUDIO_USAGE_SAFETY = 1001,
  AUDIO_USAGE_VEHICLE_STATUS = 1002,
  AUDIO_USAGE_ANNOUNCEMENT = 1003,
} audio_usage_t;

typedef enum {
  AUDIO_DEVICE_DEFAULT = 0,
} audio_devices_t;

/** Metadata of a playback track for an in stream. */
typedef struct playback_track_metadata {
  audio_usage_t usage;
  audio_content_type_t content_type;
  float gain;  // Normalized linear volume. 0=silence, 1=0dbfs...
} playback_track_metadata_t;

/** Metadata of a record track for an out stream. */
typedef struct record_track_metadata {
  audio_source_t source;
  float gain;  // Normalized linear volume. 0=silence, 1=0dbfs...
               // For record tracks originating from a software patch, the
               // dest_device fields provide information about the downstream
               // device.
  audio_devices_t dest_device;
  char dest_device_address[AUDIO_DEVICE_MAX_ADDRESS_LEN];
} record_track_metadata_t;

typedef struct source_metadata {
  size_t track_count;
  /** Array of metadata of each track connected to this source. */
  struct playback_track_metadata* tracks;
} source_metadata_t;

typedef struct sink_metadata {
  size_t track_count;
  /** Array of metadata of each track connected to this sink. */
  struct record_track_metadata* tracks;
} sink_metadata_t;
