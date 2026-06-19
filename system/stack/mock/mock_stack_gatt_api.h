/*
 * Copyright 2026 The Android Open Source Project
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

/*
 * Generated mock file from original source file
 *   Functions generated:26
 *
 *  mockcify.pl ver 0.5.0
 */

#include <cstdint>
#include <functional>
#include <string>

// Original included files, if any

#include <bluetooth/types/address.h>
#include <bluetooth/types/bt_transport.h>
#include <bluetooth/types/uuid.h>

#include "stack/include/gatt_api.h"

// Original usings
using bluetooth::Uuid;

// Mocked compile conditionals, if any

namespace test {
namespace mock {
namespace stack_gatt_api {

// Shared state between mocked functions and tests
// Name: GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest
// Params: RawAddress& remote_bda
// Return: std::list<uint16_t>
struct GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest {
  static std::list<uint16_t> return_value;
  std::function<std::list<uint16_t>(const RawAddress& remote_bda)> body{
          [](const RawAddress& /* remote_bda */) { return return_value; }};
  std::list<uint16_t> operator()(const RawAddress& remote_bda) { return body(remote_bda); }
};
extern struct GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest
        GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest;

// Shared state between mocked functions and tests
// Name: GATTC_ConfigureMTU
// Params: RawAddress& remote_bda, tBT_TRANSPORT transport, uint16_t conn_id,
//         uint16_t *current_mtu
// Return: tGATTC_TryMtuRequestResult
struct GATTC_TryMtuRequest {
  static tGATTC_TryMtuRequestResult return_value;
  std::function<tGATTC_TryMtuRequestResult(const RawAddress& remote_bda, tBT_TRANSPORT transport,
                                           uint16_t conn_id, uint16_t* current_mtu)>
          body{[](const RawAddress& /* remote_bda */, tBT_TRANSPORT /* transport */,
                  uint16_t /* conn_id */, uint16_t* /* current_mtu */) { return return_value; }};
  tGATTC_TryMtuRequestResult operator()(const RawAddress& remote_bda, tBT_TRANSPORT transport,
                                        uint16_t conn_id, uint16_t* current_mtu) {
    return body(remote_bda, transport, conn_id, current_mtu);
  }
};
extern struct GATTC_TryMtuRequest GATTC_TryMtuRequest;

// Shared state between mocked functions and tests
// Name: GATTC_ConfigureMTU
// Params: RawAddress& remote_bda, tBT_TRANSPORT transport,
//         uint16_t user_mtu
// Return: void
struct GATTC_UpdateUserAttMtuIfNeeded {
  std::function<void(const RawAddress& remote_bda, tBT_TRANSPORT transport, uint16_t user_mtu)>
          body{[](const RawAddress& /* remote_bda */, tBT_TRANSPORT /* transport */,
                  uint16_t /* user_mtu */) {}};
  void operator()(const RawAddress& remote_bda, tBT_TRANSPORT transport, uint16_t user_mtu) {
    body(remote_bda, transport, user_mtu);
  }
};
extern struct GATTC_UpdateUserAttMtuIfNeeded GATTC_UpdateUserAttMtuIfNeeded;

// Shared state between mocked functions and tests
// Name: GATTC_ConfigureMTU
// Params: uint16_t conn_id, uint16_t mtu
// Return: tGATT_STATUS
struct GATTC_ConfigureMTU {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, uint16_t mtu)> body{
          [](uint16_t /* conn_id */, uint16_t /* mtu */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, uint16_t mtu) { return body(conn_id, mtu); }
};
extern struct GATTC_ConfigureMTU GATTC_ConfigureMTU;

// Name: GATTC_Discover
// Params: uint16_t conn_id, tGATT_DISC_TYPE disc_type, uint16_t start_handle,
// uint16_t end_handle Return: tGATT_STATUS
struct GATTC_Discover {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, tGATT_DISC_TYPE disc_type, uint16_t start_handle,
                             uint16_t end_handle)>
          body{[](uint16_t /* conn_id */, tGATT_DISC_TYPE /* disc_type */,
                  uint16_t /* start_handle */, uint16_t /* end_handle */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, tGATT_DISC_TYPE disc_type, uint16_t start_handle,
                          uint16_t end_handle) {
    return body(conn_id, disc_type, start_handle, end_handle);
  }
};
extern struct GATTC_Discover GATTC_Discover;

// Name: GATTC_ExecuteWrite
// Params: uint16_t conn_id, bool is_execute
// Return: tGATT_STATUS
struct GATTC_ExecuteWrite {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, bool is_execute)> body{
          [](uint16_t /* conn_id */, bool /* is_execute */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, bool is_execute) { return body(conn_id, is_execute); }
};
extern struct GATTC_ExecuteWrite GATTC_ExecuteWrite;

// Name: GATTC_Read
// Params: uint16_t conn_id, tGATT_READ_TYPE type, tGATT_READ_PARAM* p_read
// Return: tGATT_STATUS
struct GATTC_Read {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, tGATT_READ_TYPE type, tGATT_READ_PARAM* p_read)>
          body{[](uint16_t /* conn_id */, tGATT_READ_TYPE /* type */,
                  tGATT_READ_PARAM* /* p_read */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, tGATT_READ_TYPE type, tGATT_READ_PARAM* p_read) {
    return body(conn_id, type, p_read);
  }
};
extern struct GATTC_Read GATTC_Read;

// Name: GATTC_SendHandleValueConfirm
// Params: uint16_t conn_id, uint16_t cid
// Return: tGATT_STATUS
struct GATTC_SendHandleValueConfirm {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, uint16_t cid)> body{
          [](uint16_t /* conn_id */, uint16_t /* cid */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, uint16_t cid) { return body(conn_id, cid); }
};
extern struct GATTC_SendHandleValueConfirm GATTC_SendHandleValueConfirm;

// Name: GATTC_Write
// Params: uint16_t conn_id, tGATT_WRITE_TYPE type, tGATT_VALUE* p_write
// Return: tGATT_STATUS
struct GATTC_Write {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, tGATT_WRITE_TYPE type, tGATT_VALUE* p_write)> body{
          [](uint16_t /* conn_id */, tGATT_WRITE_TYPE /* type */, tGATT_VALUE* /* p_write */) {
            return return_value;
          }};
  tGATT_STATUS operator()(uint16_t conn_id, tGATT_WRITE_TYPE type, tGATT_VALUE* p_write) {
    return body(conn_id, type, p_write);
  }
};
extern struct GATTC_Write GATTC_Write;

// Name: GATTS_AddService
// Params: tGATT_IF gatt_if, btgatt_db_element_t* service, int count
// Return: tGATT_STATUS
struct GATTS_AddService {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(tGATT_IF gatt_if, btgatt_db_element_t* service, int count)> body{
          [](tGATT_IF /* gatt_if */, btgatt_db_element_t* /* service */, int /* count */) {
            return return_value;
          }};
  tGATT_STATUS operator()(tGATT_IF gatt_if, btgatt_db_element_t* service, int count) {
    return body(gatt_if, service, count);
  }
};
extern struct GATTS_AddService GATTS_AddService;

// Name: GATTS_DeleteService
// Params: tGATT_IF gatt_if, Uuid* p_svc_uuid, uint16_t svc_inst
// Return: bool
struct GATTS_DeleteService {
  static bool return_value;
  std::function<bool(tGATT_IF gatt_if, Uuid* p_svc_uuid, uint16_t svc_inst)> body{
          [](tGATT_IF /* gatt_if */, Uuid* /* p_svc_uuid */, uint16_t /* svc_inst */) {
            return return_value;
          }};
  bool operator()(tGATT_IF gatt_if, Uuid* p_svc_uuid, uint16_t svc_inst) {
    return body(gatt_if, p_svc_uuid, svc_inst);
  }
};
extern struct GATTS_DeleteService GATTS_DeleteService;

// Name: GATTS_HandleValueIndication
// Params: uint16_t conn_id, uint16_t attr_handle, uint16_t val_len, uint8_t*
// p_val Return: tGATT_STATUS
struct GATTS_HandleValueIndication {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, uint16_t attr_handle, uint16_t val_len,
                             uint8_t* p_val)>
          body{[](uint16_t /* conn_id */, uint16_t /* attr_handle */, uint16_t /* val_len */,
                  uint8_t* /* p_val */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, uint16_t attr_handle, uint16_t val_len,
                          uint8_t* p_val) {
    return body(conn_id, attr_handle, val_len, p_val);
  }
};
extern struct GATTS_HandleValueIndication GATTS_HandleValueIndication;

// Name: GATTS_HandleValueNotification
// Params: uint16_t conn_id, uint16_t attr_handle, uint16_t val_len, uint8_t*
// p_val Return: tGATT_STATUS
struct GATTS_HandleValueNotification {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, uint16_t attr_handle, uint16_t val_len,
                             uint8_t* p_val)>
          body{[](uint16_t /* conn_id */, uint16_t /* attr_handle */, uint16_t /* val_len */,
                  uint8_t* /* p_val */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, uint16_t attr_handle, uint16_t val_len,
                          uint8_t* p_val) {
    return body(conn_id, attr_handle, val_len, p_val);
  }
};
extern struct GATTS_HandleValueNotification GATTS_HandleValueNotification;

// Name: GATTS_HandleMultipleValueNotification
struct GATTS_HandleMultipleValueNotification {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, std::vector<tGATT_VALUE> notif_vector)> body{
          [](uint16_t /* conn_id */, std::vector<tGATT_VALUE> /* notif_vector */) {
            return return_value;
          }};
  tGATT_STATUS operator()(uint16_t conn_id, std::vector<tGATT_VALUE> notif_vector) {
    return body(conn_id, notif_vector);
  }
};
extern struct GATTS_HandleMultipleValueNotification GATTS_HandleMultipleValueNotification;

// Name: GATTS_NVRegister
// Params: tGATT_APPL_INFO* p_cb_info
// Return: bool
struct GATTS_NVRegister {
  static bool return_value;
  std::function<bool(tGATT_APPL_INFO* p_cb_info)> body{
          [](tGATT_APPL_INFO* /* p_cb_info */) { return return_value; }};
  bool operator()(tGATT_APPL_INFO* p_cb_info) { return body(p_cb_info); }
};
extern struct GATTS_NVRegister GATTS_NVRegister;

// Name: GATTS_SendRsp
// Params: uint16_t conn_id, uint32_t trans_id, tGATT_STATUS status, tGATTS_RSP*
// p_msg Return: tGATT_STATUS
struct GATTS_SendRsp {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id, uint32_t trans_id, tGATT_STATUS status,
                             tGATTS_RSP* p_msg)>
          body{[](uint16_t /* conn_id */, uint32_t /* trans_id */, tGATT_STATUS /* status */,
                  tGATTS_RSP* /* p_msg */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id, uint32_t trans_id, tGATT_STATUS status,
                          tGATTS_RSP* p_msg) {
    return body(conn_id, trans_id, status, p_msg);
  }
};
extern struct GATTS_SendRsp GATTS_SendRsp;

// Name: GATTS_StopService
// Params: uint16_t service_handle
// Return: void
struct GATTS_StopService {
  std::function<void(uint16_t service_handle)> body{[](uint16_t /* service_handle */) {}};
  void operator()(uint16_t service_handle) { body(service_handle); }
};
extern struct GATTS_StopService GATTS_StopService;

// Name: GATT_BR_Connect
// Params: tGATT_IF gatt_if, const RawAddress& bd_addr
// bool auto_mtu_enabled Return: bool
struct GATT_BR_Connect {
  static bool return_value;
  std::function<bool(tGATT_IF gatt_if, const RawAddress& bd_addr)> body{
          [](tGATT_IF /* gatt_if */, const RawAddress& /* bd_addr */) { return return_value; }};
  bool operator()(tGATT_IF gatt_if, const RawAddress& bd_addr) { return body(gatt_if, bd_addr); }
};
extern struct GATT_BR_Connect GATT_BR_Connect;

// Name: GATT_Disconnect
// Params: uint16_t conn_id
// Return: tGATT_STATUS
struct GATT_Disconnect {
  static tGATT_STATUS return_value;
  std::function<tGATT_STATUS(uint16_t conn_id)> body{
          [](uint16_t /* conn_id */) { return return_value; }};
  tGATT_STATUS operator()(uint16_t conn_id) { return body(conn_id); }
};
extern struct GATT_Disconnect GATT_Disconnect;

// Name: GATT_GetConnIdIfConnected
// Params: tGATT_IF gatt_if, const RawAddress& bd_addr, uint16_t* p_conn_id,
// tBT_TRANSPORT transport Return: bool
struct GATT_GetConnIdIfConnected {
  static bool return_value;
  std::function<bool(tGATT_IF gatt_if, const RawAddress& bd_addr, uint16_t* p_conn_id,
                     tBT_TRANSPORT transport)>
          body{[](tGATT_IF /* gatt_if */, const RawAddress& /* bd_addr */,
                  uint16_t* /* p_conn_id */,
                  tBT_TRANSPORT /* transport */) { return return_value; }};
  bool operator()(tGATT_IF gatt_if, const RawAddress& bd_addr, uint16_t* p_conn_id,
                  tBT_TRANSPORT transport) {
    return body(gatt_if, bd_addr, p_conn_id, transport);
  }
};
extern struct GATT_GetConnIdIfConnected GATT_GetConnIdIfConnected;

// Name: GATT_GetConnectionInfor
// Params: uint16_t conn_id, tGATT_IF* p_gatt_if, RawAddress& bd_addr,
// tBT_TRANSPORT* p_transport Return: bool
struct GATT_GetConnectionInfor {
  static bool return_value;
  std::function<bool(uint16_t conn_id, tGATT_IF* p_gatt_if, RawAddress& bd_addr,
                     tBT_TRANSPORT* p_transport)>
          body{[](uint16_t /* conn_id */, tGATT_IF* /* p_gatt_if */, RawAddress& /* bd_addr */,
                  tBT_TRANSPORT* /* p_transport */) { return return_value; }};
  bool operator()(uint16_t conn_id, tGATT_IF* p_gatt_if, RawAddress& bd_addr,
                  tBT_TRANSPORT* p_transport) {
    return body(conn_id, p_gatt_if, bd_addr, p_transport);
  }
};
extern struct GATT_GetConnectionInfor GATT_GetConnectionInfor;

// Name: GATTC_OffloadCharacteristics
// Params: tCONN_ID conn_id, btgatt_db_element_t* service, size_t elements_count, uint64_t
// endpoint_id, uint64_t hub_id, std::promise<btgatt_offload_result_t> promise
struct GATTC_OffloadCharacteristics {
  std::function<void(tCONN_ID conn_id, btgatt_db_element_t* service, size_t elements_count,
                     uint64_t endpoint_id, uint64_t hub_id, int uid, std::string attribution_tag,
                     std::promise<btgatt_offload_result_t> promise)>
          body{[](tCONN_ID /* conn_id */, btgatt_db_element_t* /* service */,
                  size_t /* elements_count */, uint64_t /* endpoint_id */, uint64_t /* hub_id */,
                  int /* uid */, std::string /* attribution_tag */,
                  std::promise<btgatt_offload_result_t> /* promise */) {}};
  void operator()(tCONN_ID conn_id, btgatt_db_element_t* service, size_t elements_count,
                  uint64_t endpoint_id, uint64_t hub_id, int uid, std::string attribution_tag,
                  std::promise<btgatt_offload_result_t> promise) {
    body(conn_id, service, elements_count, endpoint_id, hub_id, uid, std::move(attribution_tag),
         std::move(promise));
  }
};
extern struct GATTC_OffloadCharacteristics GATTC_OffloadCharacteristics;

// Name: GATTC_UnoffloadCharacteristics
// Params: tCONN_ID conn_id, uint16_t session_id
struct GATTC_UnoffloadCharacteristics {
  std::function<void(tCONN_ID conn_id, uint16_t session_id)> body{
          [](tCONN_ID /* conn_id */, uint16_t /* session_id */) {}};
  void operator()(tCONN_ID conn_id, uint16_t session_id) { body(conn_id, session_id); }
};
extern struct GATTC_UnoffloadCharacteristics GATTC_UnoffloadCharacteristics;

// Name: GATTC_InformNotificationHandle
// Params: const RawAddress& remote_bda, uint16_t handle
struct GATTC_InformNotificationHandle {
  std::function<void(const RawAddress& remote_bda, uint16_t handle)> body{
          [](const RawAddress& /* remote_bda */, uint16_t /* handle */) {}};
  void operator()(const RawAddress& remote_bda, uint16_t handle) { body(remote_bda, handle); }
};
extern struct GATTC_InformNotificationHandle GATTC_InformNotificationHandle;

// Name: GATTC_InformServiceChangedIndication
// Params: const RawAddress& remote_bda
struct GATTC_InformServiceChangedIndication {
  std::function<void(const RawAddress& remote_bda)> body{[](const RawAddress& /* remote_bda */) {}};
  void operator()(const RawAddress& remote_bda) { body(remote_bda); }
};
extern struct GATTC_InformServiceChangedIndication GATTC_InformServiceChangedIndication;

// Name: GATTC_SetDefaultMtu
// Params: const RawAddress& remote_bda
struct GATTC_SetDefaultMtu {
  std::function<void(const RawAddress& remote_bda)> body{[](const RawAddress& /* remote_bda */) {}};
  void operator()(const RawAddress& remote_bda) { body(remote_bda); }
};
extern struct GATTC_SetDefaultMtu GATTC_SetDefaultMtu;

// Name: GATTS_OffloadCharacteristics
// Params: tCONN_ID conn_id, btgatt_db_element_t* service, size_t elements_count, uint64_t
// endpoint_id, uint64_t hub_id, std::promise<btgatt_offload_result_t> promise
struct GATTS_OffloadCharacteristics {
  std::function<void(tCONN_ID conn_id, btgatt_db_element_t* service, size_t elements_count,
                     uint64_t endpoint_id, uint64_t hub_id, int uid, std::string attribution_tag,
                     std::promise<btgatt_offload_result_t> promise)>
          body{[](tCONN_ID /* conn_id */, btgatt_db_element_t* /* service */,
                  size_t /* elements_count */, uint64_t /* endpoint_id */, uint64_t /* hub_id */,
                  int /* uid */, std::string /* attribution_tag */,
                  std::promise<btgatt_offload_result_t> /* promise */) {}};
  void operator()(tCONN_ID conn_id, btgatt_db_element_t* service, size_t elements_count,
                  uint64_t endpoint_id, uint64_t hub_id, int uid, std::string attribution_tag,
                  std::promise<btgatt_offload_result_t> promise) {
    body(conn_id, service, elements_count, endpoint_id, hub_id, uid, std::move(attribution_tag),
         std::move(promise));
  }
};
extern struct GATTS_OffloadCharacteristics GATTS_OffloadCharacteristics;

// Name: GATTS_UnoffloadCharacteristics
// Params: tCONN_ID conn_id, uint16_t session_id
struct GATTS_UnoffloadCharacteristics {
  std::function<void(tCONN_ID conn_id, uint16_t session_id)> body{
          [](tCONN_ID /* conn_id */, uint16_t /* session_id */) {}};
  void operator()(tCONN_ID conn_id, uint16_t session_id) { body(conn_id, session_id); }
};
extern struct GATTS_UnoffloadCharacteristics GATTS_UnoffloadCharacteristics;

}  // namespace stack_gatt_api
}  // namespace mock
}  // namespace test

// END mockcify generation
