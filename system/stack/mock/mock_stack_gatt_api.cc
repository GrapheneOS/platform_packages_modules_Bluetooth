/*
 * Copyright 2022 The Android Open Source Project
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
/*
 * Generated mock file from original source file
 *   Functions generated:26
 *
 *  mockcify.pl ver 0.5.0
 */
// Mock include file to share data between tests and mock
#include "stack/mock/mock_stack_gatt_api.h"

#include <cstdint>
#include <string>

#include "test/common/mock_functions.h"

// Original usings
using bluetooth::Uuid;

// Mocked internal structures, if any

namespace test {
namespace mock {
namespace stack_gatt_api {

// Function state capture and return values, if needed
struct GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest
        GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest;
struct GATTC_TryMtuRequest GATTC_TryMtuRequest;
struct GATTC_UpdateUserAttMtuIfNeeded GATTC_UpdateUserAttMtuIfNeeded;
struct GATTC_ConfigureMTU GATTC_ConfigureMTU;
struct GATTC_Discover GATTC_Discover;
struct GATTC_ExecuteWrite GATTC_ExecuteWrite;
struct GATTC_Read GATTC_Read;
struct GATTC_SendHandleValueConfirm GATTC_SendHandleValueConfirm;
struct GATTC_Write GATTC_Write;
struct GATTC_OffloadCharacteristics GATTC_OffloadCharacteristics;
struct GATTC_UnoffloadCharacteristics GATTC_UnoffloadCharacteristics;
struct GATTC_InformNotificationHandle GATTC_InformNotificationHandle;
struct GATTC_InformServiceChangedIndication GATTC_InformServiceChangedIndication;
struct GATTC_SetDefaultMtu GATTC_SetDefaultMtu;
struct GATTS_AddService GATTS_AddService;
struct GATTS_DeleteService GATTS_DeleteService;
struct GATTS_HandleValueIndication GATTS_HandleValueIndication;
struct GATTS_HandleValueNotification GATTS_HandleValueNotification;
struct GATTS_HandleMultipleValueNotification GATTS_HandleMultipleValueNotification;
struct GATTS_NVRegister GATTS_NVRegister;
struct GATTS_SendRsp GATTS_SendRsp;
struct GATTS_StopService GATTS_StopService;
struct GATTS_OffloadCharacteristics GATTS_OffloadCharacteristics;
struct GATTS_UnoffloadCharacteristics GATTS_UnoffloadCharacteristics;
struct GATT_BR_Connect GATT_BR_Connect;
struct GATT_Disconnect GATT_Disconnect;
struct GATT_GetConnIdIfConnected GATT_GetConnIdIfConnected;
struct GATT_GetConnectionInfor GATT_GetConnectionInfor;

}  // namespace stack_gatt_api
}  // namespace mock
}  // namespace test

// Mocked function return values, if any
namespace test {
namespace mock {
namespace stack_gatt_api {

std::list<uint16_t> GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest::return_value =
        std::list<uint16_t>();
tGATTC_TryMtuRequestResult GATTC_TryMtuRequest::return_value = MTU_EXCHANGE_NOT_DONE_YET;
tGATT_STATUS GATTC_ConfigureMTU::return_value = GATT_SUCCESS;
tGATT_STATUS GATTC_Discover::return_value = GATT_SUCCESS;
tGATT_STATUS GATTC_ExecuteWrite::return_value = GATT_SUCCESS;
tGATT_STATUS GATTC_Read::return_value = GATT_SUCCESS;
tGATT_STATUS GATTC_SendHandleValueConfirm::return_value = GATT_SUCCESS;
tGATT_STATUS GATTC_Write::return_value = GATT_SUCCESS;
tGATT_STATUS GATTS_AddService::return_value = GATT_SUCCESS;
bool GATTS_DeleteService::return_value = false;
tGATT_STATUS GATTS_HandleValueIndication::return_value = GATT_SUCCESS;
tGATT_STATUS GATTS_HandleValueNotification::return_value = GATT_SUCCESS;
tGATT_STATUS GATTS_HandleMultipleValueNotification::return_value = GATT_SUCCESS;
bool GATTS_NVRegister::return_value = false;
tGATT_STATUS GATTS_SendRsp::return_value = GATT_SUCCESS;
bool GATT_BR_Connect::return_value = false;
tGATT_STATUS GATT_Disconnect::return_value = GATT_SUCCESS;
bool GATT_GetConnIdIfConnected::return_value = false;
bool GATT_GetConnectionInfor::return_value = false;

}  // namespace stack_gatt_api
}  // namespace mock
}  // namespace test

// Mocked functions, if any
std::list<uint16_t> GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest(
        const RawAddress& remote_bda) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_GetAndRemoveListOfConnIdsWaitingForMtuRequest(
          remote_bda);
}
tGATTC_TryMtuRequestResult GATTC_TryMtuRequest(const RawAddress& remote_bda,
                                               tBT_TRANSPORT transport, uint16_t conn_id,
                                               uint16_t* current_mtu) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_TryMtuRequest(remote_bda, transport, conn_id,
                                                         current_mtu);
}
void GATTC_UpdateUserAttMtuIfNeeded(const RawAddress& remote_bda, tBT_TRANSPORT transport,
                                    uint16_t user_mtu) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTC_UpdateUserAttMtuIfNeeded(remote_bda, transport, user_mtu);
}
tGATT_STATUS GATTC_ConfigureMTU(uint16_t conn_id, uint16_t mtu) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_ConfigureMTU(conn_id, mtu);
}
tGATT_STATUS GATTC_Discover(uint16_t conn_id, tGATT_DISC_TYPE disc_type, uint16_t start_handle,
                            uint16_t end_handle) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_Discover(conn_id, disc_type, start_handle, end_handle);
}
tGATT_STATUS GATTC_ExecuteWrite(uint16_t conn_id, bool is_execute) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_ExecuteWrite(conn_id, is_execute);
}
tGATT_STATUS GATTC_Read(uint16_t conn_id, tGATT_READ_TYPE type, tGATT_READ_PARAM* p_read) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_Read(conn_id, type, p_read);
}
tGATT_STATUS GATTC_SendHandleValueConfirm(uint16_t conn_id, uint16_t cid) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_SendHandleValueConfirm(conn_id, cid);
}
tGATT_STATUS GATTC_Write(uint16_t conn_id, tGATT_WRITE_TYPE type, tGATT_VALUE* p_write) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTC_Write(conn_id, type, p_write);
}
tGATT_STATUS GATTS_AddService(tGATT_IF gatt_if, btgatt_db_element_t* service, int count) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTS_AddService(gatt_if, service, count);
}
bool GATTS_DeleteService(tGATT_IF gatt_if, Uuid* p_svc_uuid, uint16_t svc_inst) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTS_DeleteService(gatt_if, p_svc_uuid, svc_inst);
}
tGATT_STATUS GATTS_HandleValueIndication(uint16_t conn_id, uint16_t attr_handle, uint16_t val_len,
                                         uint8_t* p_val) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTS_HandleValueIndication(conn_id, attr_handle, val_len,
                                                                 p_val);
}
tGATT_STATUS GATTS_HandleValueNotification(uint16_t conn_id, uint16_t attr_handle, uint16_t val_len,
                                           uint8_t* p_val) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTS_HandleValueNotification(conn_id, attr_handle, val_len,
                                                                   p_val);
}
tGATT_STATUS GATTS_HandleMultipleValueNotification(uint16_t conn_id,
                                                   std::vector<tGATT_VALUE> notif_vector) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTS_HandleMultipleValueNotification(conn_id, notif_vector);
}
bool GATTS_NVRegister(tGATT_APPL_INFO* p_cb_info) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTS_NVRegister(p_cb_info);
}
tGATT_STATUS GATTS_SendRsp(uint16_t conn_id, uint32_t trans_id, tGATT_STATUS status,
                           tGATTS_RSP* p_msg) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATTS_SendRsp(conn_id, trans_id, status, p_msg);
}
void GATTS_StopService(uint16_t service_handle) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTS_StopService(service_handle);
}
tGATT_STATUS GATT_Disconnect(uint16_t conn_id) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATT_Disconnect(conn_id);
}
bool GATT_GetConnIdIfConnected(tGATT_IF gatt_if, const RawAddress& bd_addr, uint16_t* p_conn_id,
                               tBT_TRANSPORT transport) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATT_GetConnIdIfConnected(gatt_if, bd_addr, p_conn_id,
                                                               transport);
}
bool GATT_GetConnectionInfor(uint16_t conn_id, tGATT_IF* p_gatt_if, RawAddress& bd_addr,
                             tBT_TRANSPORT* p_transport) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATT_GetConnectionInfor(conn_id, p_gatt_if, bd_addr,
                                                             p_transport);
}
void GATTC_OffloadCharacteristics(tCONN_ID conn_id, btgatt_db_element_t* service,
                                  size_t elements_count, uint64_t endpoint_id, uint64_t hub_id,
                                  int uid, std::string attribution_tag,
                                  std::promise<btgatt_offload_result_t> promise) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTC_OffloadCharacteristics(
          conn_id, service, elements_count, endpoint_id, hub_id, uid, std::move(attribution_tag),
          std::move(promise));
}
void GATTC_UnoffloadCharacteristics(tCONN_ID conn_id, uint16_t session_id) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTC_UnoffloadCharacteristics(conn_id, session_id);
}
void GATTC_InformNotificationHandle(const RawAddress& remote_bda, uint16_t handle) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTC_InformNotificationHandle(remote_bda, handle);
}
void GATTC_InformServiceChangedIndication(const RawAddress& remote_bda) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTC_InformServiceChangedIndication(remote_bda);
}
void GATTC_SetDefaultMtu(const RawAddress& remote_bda) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTC_SetDefaultMtu(remote_bda);
}
void GATTS_OffloadCharacteristics(tCONN_ID conn_id, btgatt_db_element_t* service,
                                  size_t elements_count, uint64_t endpoint_id, uint64_t hub_id,
                                  int uid, std::string attribution_tag,
                                  std::promise<btgatt_offload_result_t> promise) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTS_OffloadCharacteristics(
          conn_id, service, elements_count, endpoint_id, hub_id, uid, std::move(attribution_tag),
          std::move(promise));
}
void GATTS_UnoffloadCharacteristics(tCONN_ID conn_id, uint16_t session_id) {
  inc_func_call_count(__func__);
  test::mock::stack_gatt_api::GATTS_UnoffloadCharacteristics(conn_id, session_id);
}
std::optional<bluetooth::Uuid> GATTS_LookupServiceUuidByStartHandle(uint16_t /* start_handle */) {
  inc_func_call_count(__func__);
  return std::nullopt;
}
void gatt_load_bonded(void) { inc_func_call_count(__func__); }
// Mocked functions complete
//
bool GATT_BR_Connect(tGATT_IF gatt_if, const RawAddress& bd_addr) {
  inc_func_call_count(__func__);
  return test::mock::stack_gatt_api::GATT_BR_Connect(gatt_if, bd_addr);
}
// END mockcify generation
