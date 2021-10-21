/*
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

/*
 * Copyright 2017 The Android Open Source Project
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

#include "gattc_ops_queue.h"

#include <list>
#include <unordered_map>
#include <unordered_set>

namespace bluetooth {
namespace bap {

using gatt_operation = GattOpsQueue::gatt_operation;
using bluetooth::Uuid;

constexpr uint8_t GATT_READ_CHAR = 1;
constexpr uint8_t GATT_READ_DESC = 2;
constexpr uint8_t GATT_WRITE_CHAR = 3;
constexpr uint8_t GATT_WRITE_DESC = 4;
constexpr uint8_t GATT_SERV_SEARCH = 5;

struct gatt_read_op_data {
  BAP_GATT_READ_OP_CB cb;
  void* cb_data;
};

std::unordered_map<uint16_t, std::list<gatt_operation>>
    GattOpsQueue::gatt_op_queue;
std::unordered_set<uint16_t> GattOpsQueue::gatt_op_queue_executing;

std::unordered_map<uint16_t, bool> GattOpsQueue::congestion_queue;

void GattOpsQueue::mark_as_not_executing(uint16_t conn_id) {
  gatt_op_queue_executing.erase(conn_id);
}

void GattOpsQueue::gatt_read_op_finished(uint16_t conn_id, tGATT_STATUS status,
                                         uint16_t handle, uint16_t len,
                                         uint8_t* value, void* data) {
  gatt_read_op_data* tmp = (gatt_read_op_data*)data;
  BAP_GATT_READ_OP_CB tmp_cb = tmp->cb;
  void* tmp_cb_data = tmp->cb_data;

  APPL_TRACE_DEBUG("%s: conn_id=0x%x handle=%d status=%d len=%d", __func__,
    conn_id, handle, status, len);

  osi_free(data);

  auto map_ptr = gatt_op_queue.find(conn_id);
  if (map_ptr == gatt_op_queue.end() || map_ptr->second.empty()) {
    APPL_TRACE_DEBUG("%s: no more operations queued for conn_id %d", __func__,
                     conn_id);
    return;
  }

  std::list<gatt_operation>& gatt_ops = map_ptr->second;
  gatt_operation op = gatt_ops.front();
  gatt_ops.pop_front();

  mark_as_not_executing(conn_id);
  gatt_execute_next_op(conn_id);

  if (tmp_cb) {
    tmp_cb(op.client_id, conn_id, status, handle, len, value, tmp_cb_data);
    return;
  }
}

struct gatt_write_op_data {
  BAP_GATT_WRITE_OP_CB cb;
  void* cb_data;
};

void GattOpsQueue::gatt_write_op_finished(uint16_t conn_id, tGATT_STATUS status,
                                          uint16_t handle, void* data) {
  gatt_write_op_data* tmp = (gatt_write_op_data*)data;
  BAP_GATT_WRITE_OP_CB tmp_cb = tmp->cb;
  void* tmp_cb_data = tmp->cb_data;

  APPL_TRACE_DEBUG("%s: conn_id=0x%x handle=%d status=%d", __func__, conn_id,
    handle, status);

  osi_free(data);

  auto map_ptr = gatt_op_queue.find(conn_id);
  if (map_ptr == gatt_op_queue.end() || map_ptr->second.empty()) {
    APPL_TRACE_DEBUG("%s: no more operations queued for conn_id %d", __func__,
                     conn_id);
    return;
  }

  std::list<gatt_operation>& gatt_ops = map_ptr->second;
  gatt_operation op = gatt_ops.front();
  gatt_ops.pop_front();

  mark_as_not_executing(conn_id);
  gatt_execute_next_op(conn_id);

  if (tmp_cb) {
    tmp_cb(op.client_id, conn_id, status, handle, tmp_cb_data);
    return;
  }
}

void GattOpsQueue::gatt_execute_next_op(uint16_t conn_id) {
  APPL_TRACE_DEBUG("%s: conn_id=0x%x", __func__, conn_id);
  if (gatt_op_queue.empty()) {
    APPL_TRACE_DEBUG("%s: op queue is empty", __func__);
    return;
  }

  auto ptr = congestion_queue.find(conn_id);

  if (ptr != congestion_queue.end()) {
    bool is_congested = ptr->second;
    APPL_TRACE_DEBUG("%s: congestion queue exist, conn_id: %d, is_congested: %d",
                                               __func__, conn_id, is_congested);
    if(is_congested) {
      APPL_TRACE_DEBUG("%s: lower layer is congested", __func__);
      return;
    }
  }

  auto map_ptr = gatt_op_queue.find(conn_id);

  if (map_ptr == gatt_op_queue.end()) {
    APPL_TRACE_DEBUG("%s: Queue is null", __func__);
    return;
  }

  if (map_ptr->second.empty()) {
    APPL_TRACE_DEBUG("%s: queue is empty for conn_id: %d", __func__,
                     conn_id);
    return;
  }

  if (gatt_op_queue_executing.count(conn_id)) {
    APPL_TRACE_DEBUG("%s: can't enqueue next op, already executing", __func__);
    return;
  }

  gatt_op_queue_executing.insert(conn_id);

  std::list<gatt_operation>& gatt_ops = map_ptr->second;

  gatt_operation& op = gatt_ops.front();

  APPL_TRACE_DEBUG("%s: op.type=%d, handle=%d", __func__, op.type,
    op.handle);
  if (op.type == GATT_READ_CHAR) {
    gatt_read_op_data* data =
        (gatt_read_op_data*)osi_malloc(sizeof(gatt_read_op_data));
    data->cb = op.read_cb;
    data->cb_data = op.read_cb_data;
    BTA_GATTC_ReadCharacteristic(conn_id, op.handle, GATT_AUTH_REQ_NONE,
                                 gatt_read_op_finished, data);

  } else if (op.type == GATT_READ_DESC) {
    gatt_read_op_data* data =
        (gatt_read_op_data*)osi_malloc(sizeof(gatt_read_op_data));
    data->cb = op.read_cb;
    data->cb_data = op.read_cb_data;
    BTA_GATTC_ReadCharDescr(conn_id, op.handle, GATT_AUTH_REQ_NONE,
                            gatt_read_op_finished, data);

  } else if (op.type == GATT_WRITE_CHAR) {
    gatt_write_op_data* data =
        (gatt_write_op_data*)osi_malloc(sizeof(gatt_write_op_data));
    data->cb = op.write_cb;
    data->cb_data = op.write_cb_data;
    BTA_GATTC_WriteCharValue(conn_id, op.handle, op.write_type,
                             std::move(op.value), GATT_AUTH_REQ_NONE,
                             gatt_write_op_finished, data);

  } else if (op.type == GATT_WRITE_DESC) {
    gatt_write_op_data* data =
        (gatt_write_op_data*)osi_malloc(sizeof(gatt_write_op_data));
    data->cb = op.write_cb;
    data->cb_data = op.write_cb_data;
    BTA_GATTC_WriteCharDescr(conn_id, op.handle, std::move(op.value),
                             GATT_AUTH_REQ_NONE, gatt_write_op_finished, data);
  } else if (op.type == GATT_SERV_SEARCH) {
    BTA_GATTC_ServiceSearchRequest(conn_id, op.p_srvc_uuid);
  }
}

void GattOpsQueue::Clean(uint16_t conn_id) {
  APPL_TRACE_DEBUG("%s: conn_id=0x%x", __func__, conn_id);

  gatt_op_queue.erase(conn_id);
  gatt_op_queue_executing.erase(conn_id);
}

void GattOpsQueue::ReadCharacteristic(uint16_t client_id,
                                      uint16_t conn_id, uint16_t handle,
                                      BAP_GATT_READ_OP_CB cb, void* cb_data) {
  gatt_op_queue[conn_id].push_back({.type = GATT_READ_CHAR,
                                    .client_id = client_id,
                                    .handle = handle,
                                    .read_cb = cb,
                                    .read_cb_data = cb_data});
  gatt_execute_next_op(conn_id);
}

void GattOpsQueue::ReadDescriptor(uint16_t client_id,
                                  uint16_t conn_id, uint16_t handle,
                                  BAP_GATT_READ_OP_CB cb, void* cb_data) {
  gatt_op_queue[conn_id].push_back({.type = GATT_READ_DESC,
                                    .client_id = client_id,
                                    .handle = handle,
                                    .read_cb = cb,
                                    .read_cb_data = cb_data});
  gatt_execute_next_op(conn_id);
}

void GattOpsQueue::WriteCharacteristic(uint16_t client_id,
                                       uint16_t conn_id, uint16_t handle,
                                       std::vector<uint8_t> value,
                                       tGATT_WRITE_TYPE write_type,
                                       BAP_GATT_WRITE_OP_CB cb, void* cb_data) {
  gatt_op_queue[conn_id].push_back({.type = GATT_WRITE_CHAR,
                                    .client_id = client_id,
                                    .handle = handle,
                                    .write_type = write_type,
                                    .write_cb = cb,
                                    .write_cb_data = cb_data,
                                    .value = std::move(value)});
  gatt_execute_next_op(conn_id);
}

void GattOpsQueue::WriteDescriptor(uint16_t client_id,
                                   uint16_t conn_id, uint16_t handle,
                                   std::vector<uint8_t> value,
                                   tGATT_WRITE_TYPE write_type,
                                   BAP_GATT_WRITE_OP_CB cb, void* cb_data) {
  gatt_op_queue[conn_id].push_back({.type = GATT_WRITE_DESC,
                                    .client_id = client_id,
                                    .handle = handle,
                                    .write_type = write_type,
                                    .write_cb = cb,
                                    .write_cb_data = cb_data,
                                    .value = std::move(value)});
  gatt_execute_next_op(conn_id);
}

void GattOpsQueue::ServiceSearch(uint16_t client_id,
                                 uint16_t conn_id, Uuid* srvc_uuid) {
  gatt_op_queue[conn_id].push_back({.type = GATT_SERV_SEARCH,
                                    .client_id = client_id,
                                    .p_srvc_uuid = srvc_uuid});
  gatt_execute_next_op(conn_id);
}

uint16_t GattOpsQueue::ServiceSearchComplete(uint16_t conn_id,
                                          tGATT_STATUS status) {
  auto map_ptr = gatt_op_queue.find(conn_id);
  if (map_ptr == gatt_op_queue.end() || map_ptr->second.empty()) {
    APPL_TRACE_DEBUG("%s: no more operations queued for conn_id %d", __func__,
                     conn_id);
    return 0;
  }

  std::list<gatt_operation>& gatt_ops = map_ptr->second;

  gatt_operation gatt_op = gatt_ops.front();
  gatt_ops.pop_front();
  mark_as_not_executing(conn_id);
  gatt_execute_next_op(conn_id);
  return gatt_op.client_id;
}

void GattOpsQueue::CongestionCallback(uint16_t conn_id, bool congested) {
  congestion_queue[conn_id] = congested;
  if(!congested) {
    gatt_execute_next_op(conn_id);
  }
}

}  // namespace bap
}  // namespace bluetooth
