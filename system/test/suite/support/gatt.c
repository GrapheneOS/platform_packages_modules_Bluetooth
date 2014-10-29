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

#include "base.h"
#include "btcore/include/bdaddr.h"
#include "support/callbacks.h"
#include "support/gatt.h"

const btgatt_interface_t *gatt_interface;
static int gatt_client_interface;
static int gatt_server_interface;
static int gatt_status;

bool gatt_init() {
  gatt_interface = bt_interface->get_profile_interface(BT_PROFILE_GATT_ID);
  return gatt_interface->init(callbacks_get_gatt_struct()) == BT_STATUS_SUCCESS;
}

int gatt_get_client_interface() {
  return gatt_client_interface;
}

int gatt_get_server_interface() {
  return gatt_server_interface;
}

int gatt_get_status() {
  return gatt_status;
}

// GATT client callbacks
void btgattc_register_app_cb(int status, int clientIf, bt_uuid_t *app_uuid) {
  gatt_status = status;
  gatt_client_interface = clientIf;
  CALLBACK_RET();
}

void btgattc_scan_result_cb(bt_bdaddr_t* bda, int rssi, uint8_t* adv_data) {
  CALLBACK_RET();
}

void btgattc_open_cb(int conn_id, int status, int clientIf, bt_bdaddr_t* bda) {
  CALLBACK_RET();
}

void btgattc_close_cb(int conn_id, int status, int clientIf, bt_bdaddr_t* bda) {
  CALLBACK_RET();
}

void btgattc_search_complete_cb(int conn_id, int status) {
  CALLBACK_RET();
}

void btgattc_search_result_cb(int conn_id, btgatt_srvc_id_t *srvc_id) {
  CALLBACK_RET();
}

void btgattc_get_characteristic_cb(int conn_id, int status, btgatt_srvc_id_t *srvc_id, btgatt_gatt_id_t *char_id, int char_prop) {
  CALLBACK_RET();
}

void btgattc_get_descriptor_cb(int conn_id, int status, btgatt_srvc_id_t *srvc_id, btgatt_gatt_id_t *char_id, btgatt_gatt_id_t *descr_id) {
  CALLBACK_RET();
}

void btgattc_get_included_service_cb(int conn_id, int status, btgatt_srvc_id_t *srvc_id, btgatt_srvc_id_t *incl_srvc_id) {
  CALLBACK_RET();
}

void btgattc_register_for_notification_cb(int conn_id, int registered, int status, btgatt_srvc_id_t *srvc_id, btgatt_gatt_id_t *char_id) {
  CALLBACK_RET();
}

void btgattc_notify_cb(int conn_id, btgatt_notify_params_t *p_data) {
  CALLBACK_RET();
}

void btgattc_read_characteristic_cb(int conn_id, int status, btgatt_read_params_t *p_data) {
  CALLBACK_RET();
}

void btgattc_write_characteristic_cb(int conn_id, int status, btgatt_write_params_t *p_data) {
  CALLBACK_RET();
}

void btgattc_execute_write_cb(int conn_id, int status) {
  CALLBACK_RET();
}

void btgattc_read_descriptor_cb(int conn_id, int status, btgatt_read_params_t *p_data) {
  CALLBACK_RET();
}

void btgattc_write_descriptor_cb(int conn_id, int status, btgatt_write_params_t *p_data) {
  CALLBACK_RET();
}

void btgattc_remote_rssi_cb(int client_if,bt_bdaddr_t* bda, int rssi, int status) {
  CALLBACK_RET();
}

void btgattc_advertise_cb(int status, int client_if) {
  gatt_status = status;
  gatt_client_interface = client_if;
  CALLBACK_RET();
}

// GATT server callbacks
void btgatts_register_app_cb(int status, int server_if, bt_uuid_t *uuid) {
  gatt_status = status;
  gatt_server_interface = server_if;
  CALLBACK_RET();
}

void btgatts_connection_cb(int conn_id, int server_if, int connected, bt_bdaddr_t *bda) {
  CALLBACK_RET();
}

void btgatts_service_added_cb(int status, int server_if, btgatt_srvc_id_t *srvc_id, int srvc_handle) {
  CALLBACK_RET();
}

void btgatts_included_service_added_cb(int status, int server_if, int srvc_handle, int incl_srvc_handle) {
  CALLBACK_RET();
}

void btgatts_characteristic_added_cb(int status, int server_if, bt_uuid_t *char_id, int srvc_handle, int char_handle) {
  CALLBACK_RET();
}

void btgatts_descriptor_added_cb(int status, int server_if, bt_uuid_t *descr_id, int srvc_handle, int descr_handle) {
  CALLBACK_RET();
}

void btgatts_service_started_cb(int status, int server_if, int srvc_handle) {
  CALLBACK_RET();
}

void btgatts_service_stopped_cb(int status, int server_if, int srvc_handle) {
  CALLBACK_RET();
}

void btgatts_service_deleted_cb(int status, int server_if, int srvc_handle) {
  CALLBACK_RET();
}

void btgatts_request_read_cb(int conn_id, int trans_id, bt_bdaddr_t *bda, int attr_handle, int offset, bool is_long) {
  CALLBACK_RET();
}

void btgatts_request_write_cb(int conn_id, int trans_id, bt_bdaddr_t *bda, int attr_handle, int offset, int length, bool need_rsp, bool is_prep, uint8_t* value) {
  CALLBACK_RET();
}

void btgatts_request_exec_write_cb(int conn_id, int trans_id, bt_bdaddr_t *bda, int exec_write) {
  CALLBACK_RET();
}

void btgatts_response_confirmation_cb(int status, int handle) {
  CALLBACK_RET();
}