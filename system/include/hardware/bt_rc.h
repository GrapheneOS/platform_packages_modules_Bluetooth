/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef ANDROID_INCLUDE_BT_RC_H
#define ANDROID_INCLUDE_BT_RC_H

#include <bluetooth/types/address.h>

#include "bt_status.h"

__BEGIN_DECLS

/* Change this macro to use multiple RC */
#define BT_RC_NUM_APP 6

/* Macros */
#define BTRC_MAX_ATTR_STR_LEN (1 << 16)
#define BTRC_UID_SIZE 8
#define BTRC_MAX_APP_SETTINGS 8
#define BTRC_MAX_FOLDER_DEPTH 4
#define BTRC_MAX_APP_ATTR_SIZE 16
#define BTRC_MAX_ELEM_ATTR_SIZE 8
#define BTRC_FEATURE_BIT_MASK_SIZE 16

/* Macros for valid scopes in get_folder_items */
#define BTRC_SCOPE_PLAYER_LIST 0x00 /* Media Player List */
#define BTRC_SCOPE_FILE_SYSTEM 0x01 /* Virtual File System */
#define BTRC_SCOPE_SEARCH 0x02      /* Search */
#define BTRC_SCOPE_NOW_PLAYING 0x03 /* Now Playing */

/* Macros for supported character encoding */
#define BTRC_CHARSET_ID_UTF8 0x006A

/* Macros for item types */
#define BTRC_ITEM_PLAYER 0x01 /* Media Player */
#define BTRC_ITEM_FOLDER 0x02 /* Folder */
#define BTRC_ITEM_MEDIA 0x03  /* Media File */

/* Macros for media attribute IDs */
#define BTRC_MEDIA_ATTR_ID_INVALID -1
#define BTRC_MEDIA_ATTR_ID_TITLE 0x00000001
#define BTRC_MEDIA_ATTR_ID_ARTIST 0x00000002
#define BTRC_MEDIA_ATTR_ID_ALBUM 0x00000003
#define BTRC_MEDIA_ATTR_ID_TRACK_NUM 0x00000004
#define BTRC_MEDIA_ATTR_ID_NUM_TRACKS 0x00000005
#define BTRC_MEDIA_ATTR_ID_GENRE 0x00000006
#define BTRC_MEDIA_ATTR_ID_PLAYING_TIME 0x00000007 /* in miliseconds */
#define BTRC_MEDIA_ATTR_ID_COVER_ARTWORK_HANDLE 0x00000008

/* Macros for folder types */
#define BTRC_FOLDER_TYPE_MIXED 0x00
#define BTRC_FOLDER_TYPE_TITLES 0x01
#define BTRC_FOLDER_TYPE_ALBUMS 0x02
#define BTRC_FOLDER_TYPE_ARTISTS 0x03
#define BTRC_FOLDER_TYPE_GENRES 0x04
#define BTRC_FOLDER_TYPE_PLAYLISTS 0x05
#define BTRC_FOLDER_TYPE_YEARS 0x06

/* Macros for media types */
#define BTRC_MEDIA_TYPE_AUDIO 0x00 /* audio */
#define BTRC_MEDIA_TYPE_VIDEO 0x01 /* video */

/* Macros for num attributes */
#define BTRC_NUM_ATTR_NONE 0xFF /* No attributes required */
#define BTRC_NUM_ATTR_ALL 0X00  /* All attributes required */

#define BTRC_HANDLE_NONE 0xFF

typedef uint8_t btrc_uid_t[BTRC_UID_SIZE];

typedef enum {
  BTRC_CONNECTION_STATE_DISCONNECTED = 0,
  BTRC_CONNECTION_STATE_CONNECTED
} btrc_connection_state_t;

typedef enum {
  BTRC_FEAT_NONE = 0x00,            /* AVRCP 1.0 */
  BTRC_FEAT_METADATA = 0x01,        /* AVRCP 1.3 */
  BTRC_FEAT_ABSOLUTE_VOLUME = 0x02, /* Supports TG role and volume sync */
  BTRC_FEAT_BROWSE = 0x04,          /* AVRCP 1.4 and up, with Browsing support */
  BTRC_FEAT_COVER_ARTWORK = 0x8,    /* AVRCP 1.6 and up, Cover Art */
} btrc_remote_features_t;

typedef enum {
  BTRC_PLAYSTATE_STOPPED = 0x00,  /* Stopped */
  BTRC_PLAYSTATE_PLAYING = 0x01,  /* Playing */
  BTRC_PLAYSTATE_PAUSED = 0x02,   /* Paused  */
  BTRC_PLAYSTATE_FWD_SEEK = 0x03, /* Fwd Seek*/
  BTRC_PLAYSTATE_REV_SEEK = 0x04, /* Rev Seek*/
  BTRC_PLAYSTATE_ERROR = 0xFF,    /* Error   */
} btrc_play_status_t;

typedef enum {
  BTRC_EVT_PLAY_STATUS_CHANGED = 0x01,
  BTRC_EVT_TRACK_CHANGE = 0x02,
  BTRC_EVT_TRACK_REACHED_END = 0x03,
  BTRC_EVT_TRACK_REACHED_START = 0x04,
  BTRC_EVT_PLAY_POS_CHANGED = 0x05,
  BTRC_EVT_APP_SETTINGS_CHANGED = 0x08,
  BTRC_EVT_NOW_PLAYING_CONTENT_CHANGED = 0x09,
  BTRC_EVT_AVAL_PLAYER_CHANGE = 0x0a,
  BTRC_EVT_ADDR_PLAYER_CHANGE = 0x0b,
  BTRC_EVT_UIDS_CHANGED = 0x0c,
  BTRC_EVT_VOL_CHANGED = 0x0d,
} btrc_event_id_t;

typedef enum {
  BTRC_NOTIFICATION_TYPE_INTERIM = 0,
  BTRC_NOTIFICATION_TYPE_CHANGED = 1,
} btrc_notification_type_t;

typedef enum {
  BTRC_PLAYER_ATTR_EQUALIZER = 0x01,
  BTRC_PLAYER_ATTR_REPEAT = 0x02,
  BTRC_PLAYER_ATTR_SHUFFLE = 0x03,
  BTRC_PLAYER_ATTR_SCAN = 0x04,
} btrc_player_attr_t;

typedef enum {
  BTRC_MEDIA_ATTR_TITLE = 0x01,
  BTRC_MEDIA_ATTR_ARTIST = 0x02,
  BTRC_MEDIA_ATTR_ALBUM = 0x03,
  BTRC_MEDIA_ATTR_TRACK_NUM = 0x04,
  BTRC_MEDIA_ATTR_NUM_TRACKS = 0x05,
  BTRC_MEDIA_ATTR_GENRE = 0x06,
  BTRC_MEDIA_ATTR_PLAYING_TIME = 0x07,
} btrc_media_attr_t;

typedef enum {
  BTRC_PLAYER_VAL_OFF_REPEAT = 0x01,
  BTRC_PLAYER_VAL_SINGLE_REPEAT = 0x02,
  BTRC_PLAYER_VAL_ALL_REPEAT = 0x03,
  BTRC_PLAYER_VAL_GROUP_REPEAT = 0x04
} btrc_player_repeat_val_t;

typedef enum {
  BTRC_PLAYER_VAL_OFF_SHUFFLE = 0x01,
  BTRC_PLAYER_VAL_ALL_SHUFFLE = 0x02,
  BTRC_PLAYER_VAL_GROUP_SHUFFLE = 0x03
} btrc_player_shuffle_val_t;

typedef enum {
  BTRC_STS_BAD_CMD = 0x00,        /* Invalid command */
  BTRC_STS_BAD_PARAM = 0x01,      /* Invalid parameter */
  BTRC_STS_NOT_FOUND = 0x02,      /* Specified parameter is wrong or not found */
  BTRC_STS_INTERNAL_ERR = 0x03,   /* Internal Error */
  BTRC_STS_NO_ERROR = 0x04,       /* Operation Success */
  BTRC_STS_UID_CHANGED = 0x05,    /* UIDs changed */
  BTRC_STS_RESERVED = 0x06,       /* Reserved */
  BTRC_STS_INV_DIRN = 0x07,       /* Invalid direction */
  BTRC_STS_INV_DIRECTORY = 0x08,  /* Invalid directory */
  BTRC_STS_INV_ITEM = 0x09,       /* Invalid Item */
  BTRC_STS_INV_SCOPE = 0x0a,      /* Invalid scope */
  BTRC_STS_INV_RANGE = 0x0b,      /* Invalid range */
  BTRC_STS_DIRECTORY = 0x0c,      /* UID is a directory */
  BTRC_STS_MEDIA_IN_USE = 0x0d,   /* Media in use */
  BTRC_STS_PLAY_LIST_FULL = 0x0e, /* Playing list full */
  BTRC_STS_SRCH_NOT_SPRTD = 0x0f, /* Search not supported */
  BTRC_STS_SRCH_IN_PROG = 0x10,   /* Search in progress */
  BTRC_STS_INV_PLAYER = 0x11,     /* Invalid player */
  BTRC_STS_PLAY_NOT_BROW = 0x12,  /* Player not browsable */
  BTRC_STS_PLAY_NOT_ADDR = 0x13,  /* Player not addressed */
  BTRC_STS_INV_RESULTS = 0x14,    /* Invalid results */
  BTRC_STS_NO_AVBL_PLAY = 0x15,   /* No available players */
  BTRC_STS_ADDR_PLAY_CHGD = 0x16, /* Addressed player changed */
} btrc_status_t;

typedef struct {
  uint8_t num_attr;
  uint8_t attr_ids[BTRC_MAX_APP_SETTINGS];
  uint8_t attr_values[BTRC_MAX_APP_SETTINGS];
} btrc_player_settings_t;

typedef struct {
  uint8_t val;
  uint16_t charset_id;
  uint16_t str_len;
  uint8_t* p_str;
} btrc_player_app_ext_attr_val_t;

typedef struct {
  uint8_t attr_id;
  uint16_t charset_id;
  uint16_t str_len;
  uint8_t* p_str;
  uint8_t num_val;
  btrc_player_app_ext_attr_val_t ext_attr_val[BTRC_MAX_APP_ATTR_SIZE];
} btrc_player_app_ext_attr_t;

typedef struct {
  uint8_t attr_id;
  uint8_t num_val;
  uint8_t attr_val[BTRC_MAX_APP_ATTR_SIZE];
} btrc_player_app_attr_t;

typedef struct {
  uint32_t attr_id;
  uint8_t text[BTRC_MAX_ATTR_STR_LEN];
} btrc_element_attr_val_t;

typedef struct {
  uint16_t player_id;
  uint8_t major_type;
  uint32_t sub_type;
  uint8_t play_status;
  uint8_t features[BTRC_FEATURE_BIT_MASK_SIZE];
  uint16_t charset_id;
  uint8_t name[BTRC_MAX_ATTR_STR_LEN];
} btrc_item_player_t;

typedef struct {
  uint8_t uid[BTRC_UID_SIZE];
  uint8_t type;
  uint8_t playable;
  uint16_t charset_id;
  uint8_t name[BTRC_MAX_ATTR_STR_LEN];
} btrc_item_folder_t;

typedef struct {
  uint8_t uid[BTRC_UID_SIZE];
  uint8_t type;
  uint16_t charset_id;
  uint8_t name[BTRC_MAX_ATTR_STR_LEN];
  int num_attrs;
  btrc_element_attr_val_t* p_attrs;
} btrc_item_media_t;

typedef struct {
  uint8_t item_type;
  union {
    btrc_item_player_t player;
    btrc_item_folder_t folder;
    btrc_item_media_t media;
  };
} btrc_folder_items_t;

typedef void (*btrc_passthrough_rsp_callback)(const RawAddress& bd_addr, int id, int key_state);

typedef void (*btrc_groupnavigation_rsp_callback)(int id, int key_state);

typedef void (*btrc_connection_state_callback)(const RawAddress& bd_addr,
                                               btrc_connection_state_t rc_state,
                                               btrc_connection_state_t br_state);

typedef void (*btrc_ctrl_getrcfeatures_callback)(const RawAddress& bd_addr, int features);

typedef void (*btrc_ctrl_setabsvol_cmd_callback)(const RawAddress& bd_addr, uint8_t abs_vol,
                                                 uint8_t label);

typedef void (*btrc_ctrl_registernotification_abs_vol_callback)(const RawAddress& bd_addr,
                                                                uint8_t label);

typedef void (*btrc_ctrl_setplayerapplicationsetting_rsp_callback)(const RawAddress& bd_addr,
                                                                   uint8_t accepted);

typedef void (*btrc_ctrl_playerapplicationsetting_callback)(const RawAddress& bd_addr,
                                                            uint8_t num_attr,
                                                            btrc_player_app_attr_t* app_attrs);

typedef void (*btrc_ctrl_playerapplicationsetting_changed_callback)(
        const RawAddress& bd_addr, const btrc_player_settings_t& vals);

typedef void (*btrc_ctrl_track_changed_callback)(const RawAddress& bd_addr, uint8_t num_attr,
                                                 btrc_element_attr_val_t* p_attrs);

typedef void (*btrc_ctrl_play_position_changed_callback)(const RawAddress& bd_addr,
                                                         uint32_t song_len, uint32_t song_pos);

typedef void (*btrc_ctrl_play_status_changed_callback)(const RawAddress& bd_addr,
                                                       btrc_play_status_t play_status);

typedef void (*btrc_ctrl_get_folder_items_callback)(const RawAddress& bd_addr, btrc_status_t status,
                                                    const btrc_folder_items_t* folder_items,
                                                    uint8_t count);

typedef void (*btrc_ctrl_change_path_callback)(const RawAddress& bd_addr, uint32_t count);

typedef void (*btrc_ctrl_set_browsed_player_callback)(const RawAddress& bd_addr, uint8_t num_items,
                                                      uint8_t depth);
typedef void (*btrc_ctrl_set_addressed_player_callback)(const RawAddress& bd_addr, uint8_t status);
typedef void (*btrc_ctrl_addressed_player_changed_callback)(const RawAddress& bd_addr, uint16_t id);
typedef void (*btrc_ctrl_now_playing_contents_changed_callback)(const RawAddress& bd_addr);
typedef void (*btrc_ctrl_available_player_changed_callback)(const RawAddress& bd_addr);

typedef void (*btrc_ctrl_get_cover_art_psm_callback)(const RawAddress& bd_addr, const uint16_t psm);

/** BT-RC Controller callback structure. */
typedef struct {
  /** set to sizeof(BtRcCallbacks) */
  size_t size;
  btrc_passthrough_rsp_callback passthrough_rsp_cb;
  btrc_groupnavigation_rsp_callback groupnavigation_rsp_cb;
  btrc_connection_state_callback connection_state_cb;
  btrc_ctrl_getrcfeatures_callback getrcfeatures_cb;
  btrc_ctrl_setplayerapplicationsetting_rsp_callback setplayerappsetting_rsp_cb;
  btrc_ctrl_playerapplicationsetting_callback playerapplicationsetting_cb;
  btrc_ctrl_playerapplicationsetting_changed_callback playerapplicationsetting_changed_cb;
  btrc_ctrl_setabsvol_cmd_callback setabsvol_cmd_cb;
  btrc_ctrl_registernotification_abs_vol_callback registernotification_absvol_cb;
  btrc_ctrl_track_changed_callback track_changed_cb;
  btrc_ctrl_play_position_changed_callback play_position_changed_cb;
  btrc_ctrl_play_status_changed_callback play_status_changed_cb;
  btrc_ctrl_get_folder_items_callback get_folder_items_cb;
  btrc_ctrl_change_path_callback change_folder_path_cb;
  btrc_ctrl_set_browsed_player_callback set_browsed_player_cb;
  btrc_ctrl_set_addressed_player_callback set_addressed_player_cb;
  btrc_ctrl_addressed_player_changed_callback addressed_player_changed_cb;
  btrc_ctrl_now_playing_contents_changed_callback now_playing_contents_changed_cb;
  btrc_ctrl_available_player_changed_callback available_player_changed_cb;
  btrc_ctrl_get_cover_art_psm_callback get_cover_art_psm_cb;
} btrc_ctrl_callbacks_t;

/** Represents the standard BT-RC AVRCP Controller interface. */
typedef struct {
  /** set to sizeof(BtRcInterface) */
  size_t size;
  /**
   * Register the BtRc callbacks
   */
  BtStatus (*init)(btrc_ctrl_callbacks_t* callbacks);

  /** send pass through command to target */
  BtStatus (*send_pass_through_cmd)(const RawAddress& bd_addr, uint8_t key_code, uint8_t key_state);

  /** send group navigation command to target */
  BtStatus (*send_group_navigation_cmd)(const RawAddress& bd_addr, uint8_t key_code,
                                        uint8_t key_state);

  /** send command to set player application setting attributes to target */
  BtStatus (*set_player_app_setting_cmd)(const RawAddress& bd_addr, uint8_t num_attrib,
                                         uint8_t* attrib_ids, uint8_t* attrib_vals);

  /** send command to play a particular item */
  BtStatus (*play_item_cmd)(const RawAddress& bd_addr, uint8_t scope, uint8_t* uid,
                            uint16_t uid_counter);

  /** get the current track's media metadata */
  BtStatus (*get_current_metadata_cmd)(const RawAddress& bd_addr);

  /** get the playback state */
  BtStatus (*get_playback_state_cmd)(const RawAddress& bd_addr);

  /** get the now playing list */
  BtStatus (*get_now_playing_list_cmd)(const RawAddress& bd_addr, uint32_t start, uint32_t end);

  /** get the folder list */
  BtStatus (*get_folder_list_cmd)(const RawAddress& bd_addr, uint32_t start, uint32_t end);

  /** get the player list */
  BtStatus (*get_player_list_cmd)(const RawAddress& bd_addr, uint32_t start, uint32_t end);

  /** change the folder path */
  BtStatus (*change_folder_path_cmd)(const RawAddress& bd_addr, uint8_t direction, uint8_t* uid);

  /** set browsed player */
  BtStatus (*set_browsed_player_cmd)(const RawAddress& bd_addr, uint16_t player_id);

  /** set addressed player */
  BtStatus (*set_addressed_player_cmd)(const RawAddress& bd_addr, uint16_t player_id);

  /** send rsp to set_abs_vol received from target */
  BtStatus (*set_volume_rsp)(const RawAddress& bd_addr, uint8_t abs_vol, uint8_t label);

  /** send notification rsp for abs vol to target */
  BtStatus (*register_abs_vol_rsp)(const RawAddress& bd_addr, btrc_notification_type_t rsp_type,
                                   uint8_t abs_vol, uint8_t label);

  /** Closes the interface. */
  void (*cleanup)(void);
} btrc_ctrl_interface_t;

__END_DECLS

#if __has_include(<bluetooth/log.h>)
#include <bluetooth/log.h>

namespace std {
template <>
struct formatter<btrc_connection_state_t> : enum_formatter<btrc_connection_state_t> {};
template <>
struct formatter<btrc_status_t> : enum_formatter<btrc_status_t> {};
template <>
struct formatter<btrc_event_id_t> : enum_formatter<btrc_event_id_t> {};
template <>
struct formatter<btrc_remote_features_t> : enum_formatter<btrc_remote_features_t> {};
template <>
struct formatter<btrc_notification_type_t> : enum_formatter<btrc_notification_type_t> {};
}  // namespace std

#endif  // __has_include(<bluetooth/log.h>)

#endif /* ANDROID_INCLUDE_BT_RC_H */
