/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/******************************************************************************
 *
 *  Copyright (C) 2014 Google, Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#define LOG_TAG "bt_btif_bap_config"

#include "btif_bap_config.h"
#include <base/strings/string_split.h>

#include <base/logging.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <string>

#include <mutex>

#include "bt_types.h"
#include "btcore/include/module.h"
#include "btif_api.h"
#include "btif_common.h"
#include "btif_util.h"
#include "osi/include/alarm.h"
#include "osi/include/allocator.h"
#include "osi/include/compat.h"
#include "osi/include/config.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"
#include "osi/include/properties.h"
#include "btif_bap_codec_utils.h"

#define BT_CONFIG_SOURCE_TAG_NUM 1010001

#define INFO_SECTION "Info"
#define FILE_TIMESTAMP "TimeCreated"
#define FILE_SOURCE "FileSource"
#define TIME_STRING_LENGTH sizeof("YYYY-MM-DD HH:MM:SS")
#define INDEX_FREE      (0x00)
#define INDEX_OCCUPIED  (0x01)
#define MAX_INDEX       (255)
#define MAX_INDEX_LEN   (0x04)
#define MAX_SECTION_LEN  (255)

using bluetooth::bap::pacs::CodecSampleRate;

static const char* TIME_STRING_FORMAT = "%Y-%m-%d %H:%M:%S";

// TODO(armansito): Find a better way than searching by a hardcoded path.
#if defined(OS_GENERIC)
static const char* CONFIG_FILE_PATH = "bap_config.conf";
static const char* CONFIG_BACKUP_PATH = "bap_config.bak";
#else   // !defined(OS_GENERIC)
static const char* CONFIG_FILE_PATH = "/data/misc/bluedroid/bap_config.conf";
static const char* CONFIG_BACKUP_PATH = "/data/misc/bluedroid/bap_config.bak";
#endif  // defined(OS_GENERIC)
static const period_ms_t CONFIG_SETTLE_PERIOD_MS = 3000;

static void timer_config_save_cb(void* data);
static void btif_bap_config_write(uint16_t event, char* p_param);
static bool is_factory_reset(void);
static void delete_config_files(void);
static void btif_bap_config_remove_restricted(config_t* config);
static config_t* btif_bap_config_open(const char* filename);

static enum ConfigSource {
  NOT_LOADED,
  ORIGINAL,
  BACKUP,
  NEW_FILE,
  RESET
} btif_bap_config_source = NOT_LOADED;

//static int btif_bap_config_devices_loaded = -1;
static char btif_bap_config_time_created[TIME_STRING_LENGTH];

static config_t* config;
static std::recursive_mutex config_lock;  // protects operations on |config|.
static alarm_t* config_timer;

#define BAP_DIRECTION_KEY              "Direction"
#define BAP_CODEC_TYPE_KEY             "CodecType"

#define BAP_RECORD_TYPE_KEY            "RecordType"
#define BAP_RECORD_TYPE_CAPA            "Capability"
#define BAP_RECORD_TYPE_CONF           "Configuration"

#define BAP_SAMP_FREQS_KEY             "SamplingRate"
#define BAP_CONTEXT_TYPE_KEY           "ContextType"

#define BAP_SUPP_FRM_DURATIONS_KEY     "SupFrameDurations"
#define BAP_SUP_MIN_OCTS_PER_FRAME_KEY "SupMinOctsPerFrame"
#define BAP_SUP_MAX_OCTS_PER_FRAME_KEY "SupMaxOctsPerFrame"
#define BAP_MAX_SUP_CODEC_FRAMES_PER_SDU "SupMaxFramesPerSDU"
#define BAP_LC3Q_SUP_KEY               "LC3QSupport"
#define BAP_LC3Q_VER_KEY               "LC3QVersion"

#define BAP_CONF_FRAME_DUR_KEY         "ConfiguredFrameDur"
#define BAP_CONF_OCTS_PER_FRAME_KEY    "ConfiguredOctsPerFrame"
#define BAP_LC3_FRAMES_PER_SDU_KEY     "Lc3FramesPerSDU"
#define BAP_CHNL_ALLOCATION_KEY        "ChannelAllocation"

#define BAP_SRC_LOCATIONS_KEY          "SrcLocation"
#define BAP_SINK_LOCATIONS_KEY         "SinkLocation"
#define BAP_SUP_AUDIO_CONTEXTS_KEY     "SupAudioContexts"

// Module lifecycle functions
static future_t* init(void) {
  std::unique_lock<std::recursive_mutex> lock(config_lock);

  if (is_factory_reset()) delete_config_files();

  std::string file_source;

  config = btif_bap_config_open(CONFIG_FILE_PATH);
  btif_bap_config_source = ORIGINAL;
  if (!config) {
    LOG_WARN(LOG_TAG, "%s unable to load config file: %s; using backup.",
             __func__, CONFIG_FILE_PATH);
    config = btif_bap_config_open(CONFIG_BACKUP_PATH);
    btif_bap_config_source = BACKUP;
    file_source = "Backup";
  }

  if (!config) {
    LOG_ERROR(LOG_TAG,
              "%s unable to transcode legacy file; creating empty config.",
              __func__);
    config = config_new_empty();
    btif_bap_config_source = NEW_FILE;
    file_source = "Empty";
  }

  if (!config) {
    LOG_ERROR(LOG_TAG, "%s unable to allocate a config object.", __func__);
    goto error;
  }

  if (!file_source.empty())
    config_set_string(config, INFO_SECTION, FILE_SOURCE, file_source.c_str());

  // Cleanup temporary pairings if we have left guest mode
  if (!is_restricted_mode()) btif_bap_config_remove_restricted(config);

  // Read or set config file creation timestamp
  const char* time_str;
  time_str = config_get_string(config, INFO_SECTION, FILE_TIMESTAMP, NULL);
  if (time_str != NULL) {
    strlcpy(btif_bap_config_time_created, time_str, TIME_STRING_LENGTH);
  } else {
    time_t current_time = time(NULL);
    struct tm* time_created = localtime(&current_time);
    if (time_created) {
      if (strftime(btif_bap_config_time_created, TIME_STRING_LENGTH,
                   TIME_STRING_FORMAT, time_created)) {
        config_set_string(config, INFO_SECTION, FILE_TIMESTAMP,
                          btif_bap_config_time_created);
      }
    }
  }
  // TODO(sharvil): use a non-wake alarm for this once we have
  // API support for it. There's no need to wake the system to
  // write back to disk.
  config_timer = alarm_new("btif_bap.config");
  if (!config_timer) {
    LOG_ERROR(LOG_TAG, "%s unable to create alarm.", __func__);
    goto error;
  }

  LOG_EVENT_INT(BT_CONFIG_SOURCE_TAG_NUM, btif_bap_config_source);

  return future_new_immediate(FUTURE_SUCCESS);

error:
  alarm_free(config_timer);
  if (config != NULL)
    config_free(config);
  config_timer = NULL;
  config = NULL;
  btif_bap_config_source = NOT_LOADED;
  return future_new_immediate(FUTURE_FAIL);
}

static config_t* btif_bap_config_open(const char* filename) {
  config_t* config = config_new(filename);
  if (!config) return NULL;

  return config;
}

static void btif_bap_config_save(void) {
  CHECK(config != NULL);
  CHECK(config_timer != NULL);

  if (config_timer == NULL) {
    LOG(WARNING) << __func__ << "config_timer is null";
    return;
  }
  alarm_set(config_timer, CONFIG_SETTLE_PERIOD_MS, timer_config_save_cb, NULL);
}

static void btif_bap_config_flush(void) {
  CHECK(config != NULL);
  CHECK(config_timer != NULL);

  alarm_cancel(config_timer);
  btif_bap_config_write(0, NULL);
}

bool btif_bap_config_clear(void) {
  CHECK(config != NULL);
  CHECK(config_timer != NULL);

  alarm_cancel(config_timer);

  std::unique_lock<std::recursive_mutex> lock(config_lock);
  if (config != NULL)
    config_free(config);

  config = config_new_empty();
  if (config == NULL) return false;

  bool ret = config_save(config, CONFIG_FILE_PATH);
  btif_bap_config_source = RESET;
  return ret;
}

static future_t* shut_down(void) {
  btif_bap_config_flush();
  return future_new_immediate(FUTURE_SUCCESS);
}

static future_t* clean_up(void) {
  btif_bap_config_flush();

  alarm_free(config_timer);
  config_timer = NULL;

  std::unique_lock<std::recursive_mutex> lock(config_lock);
  config_free(config);
  config = NULL;
  return future_new_immediate(FUTURE_SUCCESS);
}

EXPORT_SYMBOL module_t btif_bap_config_module = {.name = BTIF_BAP_CONFIG_MODULE,
                                             .init = init,
                                             .start_up = NULL,
                                             .shut_down = shut_down,
                                             .clean_up = clean_up};

static void timer_config_save_cb(UNUSED_ATTR void* data) {
  // Moving file I/O to btif context instead of timer callback because
  // it usually takes a lot of time to be completed, introducing
  // delays during A2DP playback causing blips or choppiness.
  btif_transfer_context(btif_bap_config_write, 0, NULL, 0, NULL);
}

static void btif_bap_config_write(UNUSED_ATTR uint16_t event,
                              UNUSED_ATTR char* p_param) {
  CHECK(config != NULL);
  CHECK(config_timer != NULL);

  std::unique_lock<std::recursive_mutex> lock(config_lock);
  rename(CONFIG_FILE_PATH, CONFIG_BACKUP_PATH);
  if (config == NULL) {
    LOG(WARNING) << __func__ << "config is null";
    return;
  }
  config_t* config_paired = config_new_clone(config);

  if (config_paired != NULL) {
    //btif_bap_config_remove_unpaired(config_paired);
    config_save(config_paired, CONFIG_FILE_PATH);
    config_free(config_paired);
  }
}

static void btif_bap_config_remove_restricted(config_t* config) {
  CHECK(config != NULL);

  if (config == NULL) {
    LOG(WARNING) << __func__ << "config is null";
    return;
  }
  const config_section_node_t* snode = config_section_begin(config);
  for(; snode != config_section_end(config);
             snode = config_section_next(snode)) {
    const char* section = config_section_name(snode);
    // first check the address
    if (config_has_key(config, section, "Restricted")) {
      config_remove_section(config, section);
    }
  }
}

static bool is_factory_reset(void) {
  char factory_reset[PROPERTY_VALUE_MAX] = {0};
  osi_property_get("persist.bluetooth.factoryreset", factory_reset, "false");
  return strncmp(factory_reset, "true", 4) == 0;
}

static void delete_config_files(void) {
  remove(CONFIG_FILE_PATH);
  remove(CONFIG_BACKUP_PATH);
  osi_property_set("persist.bluetooth.factoryreset", "false");
}

static bool btif_bap_get_section_index(const std::string &section,
                                       uint16_t *index) {
  char *temp = nullptr;
  if (section.length() != 20) return false;

  std::vector<std::string> byte_tokens =
              base::SplitString(section, ":", base::TRIM_WHITESPACE,
              base::SPLIT_WANT_ALL);

  LOG(WARNING) << __func__ << ": LC# codec ";
  if (byte_tokens.size() != 7) return false;

  // get the last nibble
  const auto& token = byte_tokens[6];

  if (token.length() != 2) return false;

  *index = strtol(token.c_str(), &temp, 16);

  if (*temp != '\0') return false;

  return true;
}

static bool btif_bap_get_free_section_id(const RawAddress& bd_addr,
                                         char *section) {
  uint16_t i = 0;
  uint8_t index_status[MAX_INDEX] = {0};
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();

  // reserve the first index for sink, src, locations
  index_status[0] = INDEX_OCCUPIED;

  const config_section_node_t* snode = config_section_begin(config);
  for(; snode != config_section_end(config);
           snode = config_section_next(snode)) {
    const char* section = config_section_name(snode);
    uint16_t index;

    // first check the address
    if(!strcasestr(section, bdstr)) {
      continue;
    }

    if(btif_bap_get_section_index(section, &index)) {
      index_status[index] = INDEX_OCCUPIED;
    }
  }

  // find the unused index
  for(i = 0; i < MAX_INDEX; i++) {
    if(index_status[i] == INDEX_FREE) break;
  }

  if(i != MAX_INDEX) {
    char index_str[MAX_INDEX_LEN];
    // form the section entry ( bd address plus index)
    snprintf(index_str, sizeof(index_str), ":%02x", i);
    strlcpy(section, bdstr, MAX_SECTION_LEN);
    strlcat(section, index_str, MAX_SECTION_LEN);
    return true;
  } else {
    return false;
  }
}

static bool btif_bap_find_sections(const RawAddress& bd_addr,
                            btif_bap_record_type_t rec_type,
                            uint16_t context_type,
                            CodecDirection direction,
                            CodecConfig *record,
                            std::vector<char *> *sections) {
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();
  const config_section_node_t* snode = config_section_begin(config);
  for(; snode != config_section_end(config);
             snode = config_section_next(snode)) {
    const char *section = config_section_name(snode);
    // first check the address
    if(!strcasestr(section, bdstr)) {
      continue;
    }

    // next check the record type
    const char* value_str = config_get_string(config, section,
                                          BAP_RECORD_TYPE_KEY, NULL);
    if(value_str == nullptr ||
      ((rec_type == REC_TYPE_CAPABILITY &&
       strcasecmp(value_str, BAP_RECORD_TYPE_CAPA)) ||
       (rec_type == REC_TYPE_CONFIGURATION &&
       strcasecmp(value_str, BAP_RECORD_TYPE_CONF)))) {
      continue;
    }

    // next check the record type
    uint16_t context = config_get_uint16(config, section,
                                         BAP_CONTEXT_TYPE_KEY, 0XFFFF);
    LOG(WARNING) << __func__ << ": context " << context
                             << ": context_type " << context_type;
    if(context != context_type) {
      continue;
    }

    // next check the direction
    value_str = config_get_string(config, section,
                                          BAP_DIRECTION_KEY, NULL);
    if(value_str == nullptr ||
      ((direction == CodecDirection::CODEC_DIR_SRC &&
        strcasecmp(value_str, "SRC")) ||
       (direction == CodecDirection::CODEC_DIR_SINK &&
        strcasecmp(value_str, "SINK")))) {
      continue;
    }

    if(record == nullptr) {
      sections->push_back((char*) section);
    } else {
      // next check codec type
      value_str = config_get_string(config, section,
                                    BAP_CODEC_TYPE_KEY, NULL);

      if(value_str == nullptr ||
        (record->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3 &&
         strcasecmp(value_str, "LC3"))) {
        continue;
      }

      // next check the freqency
      uint16_t value = config_get_uint16(config, section,
                                         BAP_SAMP_FREQS_KEY, 0);
      if(value == static_cast<uint16_t> (record->sample_rate)) {
        sections->push_back((char*) section);
      }
    }
  }

  if(sections->size()) {
    return true;
  } else {
    return false;
  }
}

static bool btif_bap_update_LC3_codec_info(char *section, CodecConfig *record,
                                           btif_bap_record_type_t rec_type) {
  if(section == nullptr || record == nullptr) {
    return false;
  }

  if(rec_type == REC_TYPE_CAPABILITY) {

    config_set_string(config, section, BAP_RECORD_TYPE_KEY,
                      BAP_RECORD_TYPE_CAPA);

    if(record->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3) {
      config_set_string(config, section, BAP_CODEC_TYPE_KEY, "LC3");
    }
    // update freqs
    config_set_uint16(config, section, BAP_SAMP_FREQS_KEY ,
                     static_cast<uint16_t>(record->sample_rate));

    // update chnl count
    config_set_uint16(config, section, BAP_CHNL_ALLOCATION_KEY,
                   static_cast<uint16_t> (record->channel_mode));

    // update supp frames
    config_set_uint16(config, section, BAP_SUPP_FRM_DURATIONS_KEY ,
        static_cast<uint16_t> (GetCapaSupFrameDurations(record)));

    // update chnl supp min octs per frame
    config_set_uint16(config, section, BAP_SUP_MIN_OCTS_PER_FRAME_KEY ,
        static_cast<uint16_t> (GetCapaSupOctsPerFrame(record) &
                               0xFFFF));

    // update chnl supp max octs per frame
    config_set_uint16(config, section, BAP_SUP_MAX_OCTS_PER_FRAME_KEY,
        static_cast<uint16_t> ((GetCapaSupOctsPerFrame(record) &
                                0xFFFF0000) >> 16));

    // update max supp codec frames per sdu
    config_set_uint16(config, section, BAP_MAX_SUP_CODEC_FRAMES_PER_SDU,
        static_cast<uint16_t> (GetCapaMaxSupLc3Frames(record)));

    // update LC3Q support
    if (GetCapaVendorMetaDataLc3QPref(record)) {
      config_set_string(config, section, BAP_LC3Q_SUP_KEY, "true");
    } else {
      config_set_string(config, section, BAP_LC3Q_SUP_KEY, "false");
    }

    // update LC3Q Version
    config_set_uint16(config, section, BAP_LC3Q_VER_KEY,
        static_cast<uint16_t> (GetCapaVendorMetaDataLc3QVer(record)));
  } else {

    config_set_string(config, section, BAP_RECORD_TYPE_KEY,
                                      BAP_RECORD_TYPE_CONF);

    if(record->codec_type == CodecIndex::CODEC_INDEX_SOURCE_LC3) {
      config_set_string(config, section, BAP_CODEC_TYPE_KEY, "LC3");
    }

    // update freqs
    config_set_uint16(config, section, BAP_SAMP_FREQS_KEY ,
                     static_cast<uint16_t>(record->sample_rate));

    // update chnl count
    config_set_uint16(config, section, BAP_CHNL_ALLOCATION_KEY,
                   static_cast<uint16_t> (record->channel_mode));

    // update configured frame duration
    config_set_uint16(config, section, BAP_CONF_FRAME_DUR_KEY,
        static_cast<uint16_t> (GetFrameDuration(record)));

    // update configured octs per frame
    config_set_uint16(config, section, BAP_CONF_OCTS_PER_FRAME_KEY,
        static_cast<uint16_t> (GetOctsPerFrame(record)));

    // update LC3 frames per SDU
    config_set_uint16(config, section, BAP_LC3_FRAMES_PER_SDU_KEY,
      static_cast<uint16_t> (GetLc3BlocksPerSdu(record)));
  }

  if (is_restricted_mode()) {
    LOG(WARNING) << __func__ << ": records will be removed if unrestricted";
    config_set_uint16(config, section, "Restricted", 1);
  }

  return true;
}

bool btif_bap_add_record(const RawAddress& bd_addr,
                         btif_bap_record_type_t rec_type,
                         uint16_t context_type,
                         CodecDirection direction,
                         CodecConfig *record) {
  // first check if same record already exists
  std::unique_lock<std::recursive_mutex> lock(config_lock);
  std::vector<char *> sections;

  if(btif_bap_find_sections(bd_addr, rec_type, context_type,
                            direction, record, &sections)) {
    for (auto it = sections.begin();
                         it != sections.end(); it++) {
      btif_bap_update_LC3_codec_info((*it), record , rec_type);
    }
  } else {
    LOG(WARNING) << __func__ << ": section not found";
    char section[MAX_SECTION_LEN];
    btif_bap_get_free_section_id(bd_addr, section);

    config_set_uint16(config, section, BAP_CONTEXT_TYPE_KEY, context_type);

    if(direction == CodecDirection::CODEC_DIR_SRC) {
      config_set_string(config, section, BAP_DIRECTION_KEY, "SRC");
    } else {
      config_set_string(config, section, BAP_DIRECTION_KEY, "SINK");
    }
    btif_bap_update_LC3_codec_info(section, record , rec_type);
  }
  btif_bap_config_save();
  return true;
}

bool btif_bap_remove_record(const RawAddress& bd_addr,
                            btif_bap_record_type_t rec_type,
                            uint16_t context_type,
                            CodecDirection direction,
                            CodecConfig *record) {
  // first check if same record exists
  // if exists remove the record by complete section
  std::unique_lock<std::recursive_mutex> lock(config_lock);
  bool record_removed = false;
  std::vector<char *> sections;

  if(btif_bap_find_sections(bd_addr, rec_type, context_type,
                            direction, record, &sections)) {
    for (auto it = sections.begin();
                         it != sections.end(); it++) {
      config_remove_section(config, (*it));
    }
    record_removed = true;
    btif_bap_config_flush();
  }
  return record_removed;
}

bool btif_bap_remove_record_by_context(const RawAddress& bd_addr,
                                       btif_bap_record_type_t rec_type,
                                       uint16_t context_type,
                                       CodecDirection direction) {
  // first check if same record exists
  // if exists remove the record by complete section
  std::unique_lock<std::recursive_mutex> lock(config_lock);
  bool record_removed = false;
  std::vector<char *> sections;

  if(btif_bap_find_sections(bd_addr, rec_type, context_type,
                            direction, nullptr, &sections)) {
    for (auto it = sections.begin();
                         it != sections.end(); it++) {
      config_remove_section(config, (*it));
    }
    record_removed = true;
    btif_bap_config_flush();
  }
  return record_removed;
}

bool btif_bap_remove_all_records(const RawAddress& bd_addr) {
  // loop through the file if any record is found delete it
  std::unique_lock<std::recursive_mutex> lock(config_lock);
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();
  bool record_removed = false;
  const config_section_node_t* snode = config_section_begin(config);
  for(; snode != config_section_end(config);
             snode = config_section_next(snode)) {
    const char* section = config_section_name(snode);
    // first check the address
    if(strcasestr(section, bdstr)) {
      record_removed = true;
      config_remove_section(config, section);
    }
  }
  btif_bap_config_flush();
  return record_removed;
}

bool btif_bap_get_records(const RawAddress& bd_addr,
                          btif_bap_record_type_t rec_type,
                          uint16_t context_type,
                          CodecDirection direction,
                          std::vector<CodecConfig> *pac_records) {
  std::unique_lock<std::recursive_mutex> lock(config_lock);
  std::vector<char *> sections;

  if(btif_bap_find_sections(bd_addr, rec_type, context_type,
                            direction, nullptr, &sections)) {
    for (auto it = sections.begin();
                         it != sections.end(); it++) {
      CodecConfig record;
      memset(&record, 0, sizeof(record));

      if(config_has_key(config, (*it), BAP_SAMP_FREQS_KEY)) {
        record.sample_rate = static_cast<CodecSampleRate>
                                (config_get_uint16(config, (*it),
                                              BAP_SAMP_FREQS_KEY,
                                              0x00));
      }

      if (config_has_key(config, (*it), BAP_LC3Q_SUP_KEY)) {
        bool lc3q_sup = false;
        const char* is_lc3q_sup = config_get_string(config, (*it),
                                                BAP_LC3Q_SUP_KEY,
                                                "");
        if(!strcmp(is_lc3q_sup, "true")) {
           lc3q_sup = true;
        }
        LOG(WARNING) << __func__ << ": lc3q_sup: " << lc3q_sup;
        if (lc3q_sup) {
          UpdateCapaVendorMetaDataLc3QPref(&record, lc3q_sup);
        }
      }

      if(config_has_key(config, (*it), BAP_LC3Q_VER_KEY)) {
        uint16_t lc3q_ver = config_get_uint16(config, (*it),
                                                BAP_LC3Q_VER_KEY,
                                                0x00);
        LOG(WARNING) << __func__ << ": lc3q_ver: " << lc3q_ver;
        UpdateCapaVendorMetaDataLc3QVer(&record, lc3q_ver);
      }

      record.codec_type = CodecIndex::CODEC_INDEX_SOURCE_LC3;
      if(rec_type == REC_TYPE_CAPABILITY) {

        if(config_has_key(config, (*it), BAP_SUPP_FRM_DURATIONS_KEY)) {
          uint16_t supp_frames = config_get_uint16(config, (*it),
                                                BAP_SUPP_FRM_DURATIONS_KEY,
                                                0x00);
          UpdateCapaSupFrameDurations(&record, supp_frames);
        }

        // update chnl supp octs per frame
        if(config_has_key(config, (*it), BAP_SUP_MIN_OCTS_PER_FRAME_KEY) &&
           config_has_key(config, (*it), BAP_SUP_MAX_OCTS_PER_FRAME_KEY)) {
          uint16_t sup_min_octs = config_get_uint16(config, (*it),
                                           BAP_SUP_MIN_OCTS_PER_FRAME_KEY,
                                           0x00);
          uint16_t sup_max_octs =  config_get_uint16(config, (*it),
                                           BAP_SUP_MAX_OCTS_PER_FRAME_KEY,
                                           0x00);
          UpdateCapaSupOctsPerFrame(&record, sup_min_octs | sup_max_octs << 16);
        }

        // update max supp codec frames per sdu
        if(config_has_key(config, (*it), BAP_MAX_SUP_CODEC_FRAMES_PER_SDU)) {
          uint16_t max_sup_codec_frames_per_sdu = config_get_uint16(config, (*it),
                                           BAP_MAX_SUP_CODEC_FRAMES_PER_SDU,
                                           0x00);
          UpdateCapaMaxSupLc3Frames(&record, max_sup_codec_frames_per_sdu);
        }

        // update preferred context type.
        if(config_has_key(config, (*it), BAP_CONTEXT_TYPE_KEY)) {
          uint16_t context_type = config_get_uint16(config, (*it),
                                           BAP_CONTEXT_TYPE_KEY,
                                           0x00);
          UpdateCapaPreferredContexts(&record, context_type);
        }
      } else {

        if(config_has_key(config, (*it), BAP_CONF_FRAME_DUR_KEY)) {
          uint16_t conf_frames = config_get_uint16(config, (*it),
                                                BAP_CONF_FRAME_DUR_KEY,
                                                0x00);
          UpdateFrameDuration(&record, conf_frames);
        }

        if(config_has_key(config, (*it), BAP_CONF_OCTS_PER_FRAME_KEY)) {
          uint16_t conf_octs_per_frame = config_get_uint16(config, (*it),
                                                BAP_CONF_OCTS_PER_FRAME_KEY,
                                                0x00);
          UpdateOctsPerFrame(&record, conf_octs_per_frame);
        }

        if(config_has_key(config, (*it), BAP_LC3_FRAMES_PER_SDU_KEY)) {
          uint16_t lc3_frms_per_sdu = config_get_uint16(config, (*it),
                                                BAP_LC3_FRAMES_PER_SDU_KEY,
                                                0x00);
          UpdateLc3BlocksPerSdu(&record, lc3_frms_per_sdu);
        }
      }
      pac_records->push_back(record);
    }
  }

  if(pac_records->size()) {
    return true;
  } else {
    return false;
  }
}

bool btif_bap_add_audio_loc(const RawAddress& bd_addr,
                             CodecDirection direction, uint32_t audio_loc) {
  // first check if same already exists
  // if exists update the same entry
  // audio location will always be stored @ 0th index
  // form the section entry ( bd address plus index)
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();
  char section[MAX_SECTION_LEN];
  char index[MAX_INDEX_LEN];
  snprintf(index, sizeof(index), ":%02x", 0);
  strlcpy(section, bdstr, sizeof(section));
  strlcat(section, index, sizeof(section));
  if(direction == CodecDirection::CODEC_DIR_SRC) {
    config_set_int(config, section, BAP_SRC_LOCATIONS_KEY, audio_loc);
  } else {
    config_set_int(config, section, BAP_SINK_LOCATIONS_KEY, audio_loc);
  }
  btif_bap_config_save();
  return true;
}

bool btif_bap_rem_audio_loc(const RawAddress& bd_addr,
                             CodecDirection direction) {
  // first check if same record already exists
  // if exists remove the record by complete section
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();
  char section[MAX_SECTION_LEN];
  char index[MAX_INDEX_LEN];
  snprintf(index, sizeof(index), ":%02x", 0);
  strlcpy(section, bdstr, sizeof(section));
  strlcat(section, index, sizeof(section));
  if(direction == CodecDirection::CODEC_DIR_SRC) {
    config_remove_key(config, section, "BAP_SRC_LOCATIONS_KEY");
  } else {
    config_remove_key(config, section, "BAP_SINK_LOCATIONS_KEY");
  }
  btif_bap_config_flush();
  return true;
}

bool btif_bap_add_supp_contexts(const RawAddress& bd_addr,
                                  uint32_t supp_contexts) {
  // first check if same already exists
  // if exists update the same entry
  // supp contexts will always be stored @ 0th index
  // form the section entry ( bd address plus index)
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();
  char section[MAX_SECTION_LEN];
  char index[MAX_INDEX_LEN];
  snprintf(index, sizeof(index), ":%02x", 0);
  strlcpy(section, bdstr, sizeof(section));
  strlcat(section, index, sizeof(section));
  LOG(WARNING) << __func__ << " supp_contexts "  << supp_contexts;
  config_set_uint64(config, section,
                    BAP_SUP_AUDIO_CONTEXTS_KEY, supp_contexts);
  btif_bap_config_save();
  return true;
}

bool btif_bap_get_supp_contexts(const RawAddress& bd_addr,
                                 uint32_t *supp_contexts) {
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();
  char section[MAX_SECTION_LEN];
  char index[MAX_INDEX_LEN];
  snprintf(index, sizeof(index), ":%02x", 0);
  strlcpy(section, bdstr, sizeof(section));
  strlcat(section, index, sizeof(section));
  *supp_contexts = config_get_uint64(config, section,
                                     BAP_SUP_AUDIO_CONTEXTS_KEY, 0);
  return true;
}

bool btif_bap_rem_supp_contexts(const RawAddress& bd_addr) {
  std::string addrstr = bd_addr.ToString();
  const char* bdstr = addrstr.c_str();
  char section[MAX_SECTION_LEN];
  char index[MAX_INDEX_LEN];
  snprintf(index, sizeof(index), ":%02x", 0);
  strlcpy(section, bdstr, sizeof(section));
  strlcat(section, index, sizeof(section));
  config_remove_key(config, section, BAP_SUP_AUDIO_CONTEXTS_KEY);
  btif_bap_config_flush();
  return true;
}
