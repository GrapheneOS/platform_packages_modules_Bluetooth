/*
 * Copyright 2023 The Android Open Source Project
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
 */

#include "stack/btm/btm_dev.h"
#include "stack/btm/btm_sec.h"
#include "stack/btm/btm_sec_cb.h"
#include "stack/include/btm_ble_sec_api.h"
#include "stack/include/btm_sec_api.h"
#include "stack/include/security_client_callbacks.h"

static SecurityClientInterface security = {
    .BTM_Sec_Init = BTM_Sec_Init,
    .BTM_Sec_Free = BTM_Sec_Free,
    .BTM_SecAddDevice = BTM_SecAddDevice,
    .BTM_SecAddRmtNameNotifyCallback = BTM_SecAddRmtNameNotifyCallback,
    .BTM_SecDeleteDevice = BTM_SecDeleteDevice,
    .BTM_SecRegister = BTM_SecRegister,
    .BTM_SecReadDevName = BTM_SecReadDevName,
    .BTM_SecBond = BTM_SecBond,
    .BTM_SecBondCancel = BTM_SecBondCancel,
    .BTM_SecAddBleKey = BTM_SecAddBleKey,
    .BTM_SecAddBleDevice = BTM_SecAddBleDevice,
    .BTM_SecClearSecurityFlags = BTM_SecClearSecurityFlags,
    .BTM_SecClrService = BTM_SecClrService,
    .BTM_SecClrServiceByPsm = BTM_SecClrServiceByPsm,
    .BTM_RemoteOobDataReply = BTM_RemoteOobDataReply,
    .BTM_PINCodeReply = BTM_PINCodeReply,
    .BTM_ConfirmReqReply = BTM_ConfirmReqReply,
    .BTM_SecDeleteRmtNameNotifyCallback = BTM_SecDeleteRmtNameNotifyCallback,
    .BTM_SetEncryption = BTM_SetEncryption,
    .BTM_IsEncrypted = BTM_IsEncrypted,
    .BTM_SecIsSecurityPending = BTM_SecIsSecurityPending,
    .BTM_IsLinkKeyKnown = BTM_IsLinkKeyKnown,
    .BTM_BleSirkConfirmDeviceReply = BTM_BleSirkConfirmDeviceReply,
    .BTM_GetSecurityMode = BTM_GetSecurityMode,
};

const SecurityClientInterface& get_security_client_interface() {
  return security;
}
