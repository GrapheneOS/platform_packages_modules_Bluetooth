/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
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

/******************************************************************************
 *
 *  This file contains the Bluetooth Manager (BTM) API function external
 *  definitions.
 *
 ******************************************************************************/
#ifndef BTM_BLE_API_H
#define BTM_BLE_API_H

#include <hardware/bt_common_types.h>
#include "bt_common.h"
#include "btm_api.h"
#include "btm_ble_api_types.h"
#include "osi/include/alarm.h"

tBTM_BLE_SCAN_SETUP_CBACK bta_ble_scan_setup_cb;

/*****************************************************************************
 *  EXTERNAL FUNCTION DECLARATIONS
 ****************************************************************************/
/*******************************************************************************
 *
 * Function         BTM_SecAddBleDevice
 *
 * Description      Add/modify device.  This function will be normally called
 *                  during host startup to restore all required information
 *                  for a LE device stored in the NVRAM.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  bd_name          - Name of the peer device. NULL if unknown.
 *                  dev_type         - Remote device's device type.
 *                  addr_type        - LE device address type.
 *
 * Returns          true if added OK, else false
 *
 ******************************************************************************/
extern bool BTM_SecAddBleDevice(const BD_ADDR bd_addr, BD_NAME bd_name,
                                tBT_DEVICE_TYPE dev_type,
                                tBLE_ADDR_TYPE addr_type);

/*******************************************************************************
 *
 * Function         BTM_SecAddBleKey
 *
 * Description      Add/modify LE device information.  This function will be
 *                  normally called during host startup to restore all required
 *                  information stored in the NVRAM.
 *
 * Parameters:      bd_addr          - BD address of the peer
 *                  p_le_key         - LE key values.
 *                  key_type         - LE SMP key type.
*
 * Returns          true if added OK, else false
 *
 ******************************************************************************/
extern bool BTM_SecAddBleKey(BD_ADDR bd_addr, tBTM_LE_KEY_VALUE* p_le_key,
                             tBTM_LE_KEY_TYPE key_type);

/*******************************************************************************
 *
 * Function         BTM_BleSetAdvParams
 *
 * Description      This function is called to set advertising parameters.
 *
 * Parameters:       None.
 *
 * Returns          void
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleSetAdvParams(uint16_t adv_int_min,
                                       uint16_t adv_int_max,
                                       tBLE_BD_ADDR* p_dir_bda,
                                       tBTM_BLE_ADV_CHNL_MAP chnl_map);

/*******************************************************************************
 *
 * Function         BTM_BleObtainVendorCapabilities
 *
 * Description      This function is called to obatin vendor capabilties
 *
 * Parameters       p_cmn_vsc_cb - Returns the vednor capabilities
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleObtainVendorCapabilities(tBTM_BLE_VSC_CB* p_cmn_vsc_cb);

/*******************************************************************************
 *
 * Function         BTM_BleSetScanParams
 *
 * Description      This function is called to set Scan parameters.
 *
 * Parameters       client_if - Client IF value
 *                  scan_interval - Scan interval
 *                  scan_window - Scan window
 *                  scan_type - Scan type
 *                  scan_setup_status_cback - Scan setup status callback
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleSetScanParams(
    tGATT_IF client_if, uint32_t scan_interval, uint32_t scan_window,
    tBLE_SCAN_MODE scan_type,
    tBLE_SCAN_PARAM_SETUP_CBACK scan_setup_status_cback);

/*******************************************************************************
 *
 * Function         BTM_BleGetVendorCapabilities
 *
 * Description      This function reads local LE features
 *
 * Parameters       p_cmn_vsc_cb : Locala LE capability structure
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleGetVendorCapabilities(tBTM_BLE_VSC_CB* p_cmn_vsc_cb);
/*******************************************************************************
 *
 * Function         BTM_BleSetStorageConfig
 *
 * Description      This function is called to setup storage configuration and
 *                  setup callbacks.
 *
 * Parameters       uint8_t batch_scan_full_max -Batch scan full maximum
                    uint8_t batch_scan_trunc_max - Batch scan truncated value
 maximum
                    uint8_t batch_scan_notify_threshold - Threshold value
                    tBTM_BLE_SCAN_SETUP_CBACK *p_setup_cback - Setup callback
                    tBTM_BLE_SCAN_THRESHOLD_CBACK *p_thres_cback -Threshold
 callback
                    void *p_ref - Reference value
 *
 * Returns          tBTM_STATUS
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleSetStorageConfig(
    uint8_t batch_scan_full_max, uint8_t batch_scan_trunc_max,
    uint8_t batch_scan_notify_threshold,
    tBTM_BLE_SCAN_SETUP_CBACK* p_setup_cback,
    tBTM_BLE_SCAN_THRESHOLD_CBACK* p_thres_cback,
    tBTM_BLE_SCAN_REP_CBACK* p_cback, tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleEnableBatchScan
 *
 * Description      This function is called to enable batch scan
 *
 * Parameters       tBTM_BLE_BATCH_SCAN_MODE scan_mode - Batch scan mode
                    uint32_t scan_interval -Scan interval
                    uint32_t scan_window - Scan window value
                    tBLE_ADDR_TYPE addr_type - Address type
                    tBTM_BLE_DISCARD_RULE discard_rule - Data discard rules
 *
 * Returns          tBTM_STATUS
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleEnableBatchScan(tBTM_BLE_BATCH_SCAN_MODE scan_mode,
                                          uint32_t scan_interval,
                                          uint32_t scan_window,
                                          tBTM_BLE_DISCARD_RULE discard_rule,
                                          tBLE_ADDR_TYPE addr_type,
                                          tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleDisableBatchScan
 *
 * Description      This function is called to disable batch scanning
 *
 * Parameters       void
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleDisableBatchScan(tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleReadScanReports
 *
 * Description      This function is called to read batch scan reports
 *
 * Parameters       tBLE_SCAN_MODE scan_mode - Scan mode report to be read out
                    tBTM_BLE_SCAN_REP_CBACK* p_cback - Reports callback
 *
 * Returns          tBTM_STATUS
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleReadScanReports(tBLE_SCAN_MODE scan_mode,
                                          tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleTrackAdvertiser
 *
 * Description      This function is called to read batch scan reports
 *
 * Parameters       p_track_cback - Tracking callback
 *                  ref_value - Reference value
 *
 * Returns          tBTM_STATUS
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleTrackAdvertiser(
    tBTM_BLE_TRACK_ADV_CBACK* p_track_cback, tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleWriteScanRsp
 *
 * Description      This function is called to write LE scan response.
 *
 * Parameters:      p_scan_rsp: scan response.
 *
 * Returns          status
 *
 ******************************************************************************/
extern void BTM_BleWriteScanRsp(uint8_t* data, uint8_t length,
                                tBTM_BLE_ADV_DATA_CMPL_CBACK* p_adv_data_cback);

/*******************************************************************************
 *
 * Function         BTM_BleObserve
 *
 * Description      This procedure keep the device listening for advertising
 *                  events from a broadcast device.
 *
 * Parameters       start: start or stop observe.
 *
 * Returns          void
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleObserve(bool start, uint8_t duration,
                                  tBTM_INQ_RESULTS_CB* p_results_cb,
                                  tBTM_CMPL_CB* p_cmpl_cb);

/*******************************************************************************
 *
 * Function         BTM_GetDeviceIDRoot
 *
 * Description      This function is called to read the local device identity
 *                  root.
 *
 * Returns          void
 *                  the local device ER is copied into er
 *
 ******************************************************************************/
extern void BTM_GetDeviceIDRoot(BT_OCTET16 ir);

/*******************************************************************************
 *
 * Function         BTM_GetDeviceEncRoot
 *
 * Description      This function is called to read the local device encryption
 *                  root.
 *
 * Returns          void
 *                  the local device ER is copied into er
 *
 ******************************************************************************/
extern void BTM_GetDeviceEncRoot(BT_OCTET16 er);

/*******************************************************************************
 *
 * Function         BTM_GetDeviceDHK
 *
 * Description      This function is called to read the local device DHK.
 *
 * Returns          void
 *                  the local device DHK is copied into dhk
 *
 ******************************************************************************/
extern void BTM_GetDeviceDHK(BT_OCTET16 dhk);

/*******************************************************************************
 *
 * Function         BTM_SecurityGrant
 *
 * Description      This function is called to grant security process.
 *
 * Parameters       bd_addr - peer device bd address.
 *                  res     - result of the operation BTM_SUCCESS if success.
 *                            Otherwise, BTM_REPEATED_ATTEMPTS is too many
 *                            attempts.
 *
 * Returns          None
 *
 ******************************************************************************/
extern void BTM_SecurityGrant(BD_ADDR bd_addr, uint8_t res);

/*******************************************************************************
 *
 * Function         BTM_BlePasskeyReply
 *
 * Description      This function is called after Security Manager submitted
 *                  passkey request to the application.
 *
 * Parameters:      bd_addr - Address of the device for which passkey was
 *                            requested
 *                  res     - result of the operation SMP_SUCCESS if success
 *                  passkey - numeric value in the range of
 *                               BTM_MIN_PASSKEY_VAL(0) -
 *                               BTM_MAX_PASSKEY_VAL(999999(0xF423F)).
 *
 ******************************************************************************/
extern void BTM_BlePasskeyReply(BD_ADDR bd_addr, uint8_t res, uint32_t passkey);

/*******************************************************************************
 *
 * Function         BTM_BleConfirmReply
 *
 * Description      This function is called after Security Manager submitted
 *                  numeric comparison request to the application.
 *
 * Parameters:      bd_addr      - Address of the device with which numeric
 *                                 comparison was requested
 *                  res          - comparison result BTM_SUCCESS if success
 *
 ******************************************************************************/
extern void BTM_BleConfirmReply(BD_ADDR bd_addr, uint8_t res);

/*******************************************************************************
 *
 * Function         BTM_LeOobDataReply
 *
 * Description      This function is called to provide the OOB data for
 *                  SMP in response to BTM_LE_OOB_REQ_EVT
 *
 * Parameters:      bd_addr     - Address of the peer device
 *                  res         - result of the operation SMP_SUCCESS if success
 *                  p_data      - simple pairing Randomizer  C.
 *
 ******************************************************************************/
extern void BTM_BleOobDataReply(BD_ADDR bd_addr, uint8_t res, uint8_t len,
                                uint8_t* p_data);

/*******************************************************************************
 *
 * Function         BTM_BleSecureConnectionOobDataReply
 *
 * Description      This function is called to provide the OOB data for
 *                  SMP in response to BTM_LE_OOB_REQ_EVT when secure connection
 *                  data is available
 *
 * Parameters:      bd_addr     - Address of the peer device
 *                  p_c         - pointer to Confirmation
 *                  p_r         - pointer to Randomizer.
 *
 ******************************************************************************/
extern void BTM_BleSecureConnectionOobDataReply(BD_ADDR bd_addr, uint8_t* p_c,
                                                uint8_t* p_r);

/*******************************************************************************
 *
 * Function         BTM_BleDataSignature
 *
 * Description      This function is called to sign the data using AES128 CMAC
 *                  algorith.
 *
 * Parameter        bd_addr: target device the data to be signed for.
 *                  p_text: singing data
 *                  len: length of the signing data
 *                  signature: output parameter where data signature is going to
 *                             be stored.
 *
 * Returns          true if signing sucessul, otherwise false.
 *
 ******************************************************************************/
extern bool BTM_BleDataSignature(BD_ADDR bd_addr, uint8_t* p_text, uint16_t len,
                                 BLE_SIGNATURE signature);

/*******************************************************************************
 *
 * Function         BTM_BleVerifySignature
 *
 * Description      This function is called to verify the data signature
 *
 * Parameter        bd_addr: target device the data to be signed for.
 *                  p_orig:  original data before signature.
 *                  len: length of the signing data
 *                  counter: counter used when doing data signing
 *                  p_comp: signature to be compared against.

 * Returns          true if signature verified correctly; otherwise false.
 *
 ******************************************************************************/
extern bool BTM_BleVerifySignature(BD_ADDR bd_addr, uint8_t* p_orig,
                                   uint16_t len, uint32_t counter,
                                   uint8_t* p_comp);

/*******************************************************************************
 *
 * Function         BTM_ReadConnectionAddr
 *
 * Description      Read the local device random address.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_ReadConnectionAddr(BD_ADDR remote_bda, BD_ADDR local_conn_addr,
                                   tBLE_ADDR_TYPE* p_addr_type);

/*******************************************************************************
 *
 * Function         BTM_ReadRemoteConnectionAddr
 *
 * Description      Read the remote device address currently used.
 *
 * Returns          void
 *
 ******************************************************************************/
extern bool BTM_ReadRemoteConnectionAddr(BD_ADDR pseudo_addr, BD_ADDR conn_addr,
                                         tBLE_ADDR_TYPE* p_addr_type);

/*******************************************************************************
 *
 * Function         BTM_BleLoadLocalKeys
 *
 * Description      Local local identity key, encryption root or sign counter.
 *
 * Parameters:      key_type: type of key, can be BTM_BLE_KEY_TYPE_ID,
 *                            BTM_BLE_KEY_TYPE_ER
 *                            or BTM_BLE_KEY_TYPE_COUNTER.
 *                  p_key: pointer to the key.
*
 * Returns          non2.
 *
 ******************************************************************************/
extern void BTM_BleLoadLocalKeys(uint8_t key_type, tBTM_BLE_LOCAL_KEYS* p_key);

/**
 * Set BLE connectable mode to auto connect
 */
extern void BTM_BleStartAutoConn();

/*******************************************************************************
 *
 * Function         BTM_BleUpdateBgConnDev
 *
 * Description      This function is called to add or remove a device into/from
 *                  background connection procedure. The background connection
*                   procedure is decided by the background connection type, it
*can be
*                   auto connection, or selective connection.
 *
 * Parameters       add_remove: true to add; false to remove.
 *                  remote_bda: device address to add/remove.
 *
 * Returns          void
 *
 ******************************************************************************/
extern bool BTM_BleUpdateBgConnDev(bool add_remove, BD_ADDR remote_bda);

/*******************************************************************************
 *
 * Function         BTM_BleClearBgConnDev
 *
 * Description      This function is called to clear the whitelist,
 *                  end any pending whitelist connections,
 *                  and reset the local bg device list.
 *
 * Parameters       void
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleClearBgConnDev(void);

/********************************************************
 *
 * Function         BTM_BleSetPrefConnParams
 *
 * Description      Set a peripheral's preferred connection parameters. When
 *                  any of the value does not want to be updated while others
 *                  do, use BTM_BLE_CONN_PARAM_UNDEF for the ones want to
 *                  leave untouched.
 *
 * Parameters:      bd_addr          - BD address of the peripheral
 *                  min_conn_int     - minimum preferred connection interval
 *                  max_conn_int     - maximum preferred connection interval
 *                  slave_latency    - preferred slave latency
 *                  supervision_tout - preferred supervision timeout
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleSetPrefConnParams(BD_ADDR bd_addr, uint16_t min_conn_int,
                                     uint16_t max_conn_int,
                                     uint16_t slave_latency,
                                     uint16_t supervision_tout);

/******************************************************************************
 *
 * Function         BTM_BleSetConnScanParams
 *
 * Description      Set scan parameters used in BLE connection request
 *
 * Parameters:      scan_interval    - scan interval
 *                  scan_window      - scan window
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleSetConnScanParams(uint32_t scan_interval,
                                     uint32_t scan_window);

/******************************************************************************
 *
 * Function         BTM_BleReadControllerFeatures
 *
 * Description      Reads BLE specific controller features
 *
 * Parameters:      tBTM_BLE_CTRL_FEATURES_CBACK : Callback to notify when
 *                  features are read
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleReadControllerFeatures(
    tBTM_BLE_CTRL_FEATURES_CBACK* p_vsc_cback);

/*******************************************************************************
 *
 * Function         BTM_CheckAdvData
 *
 * Description      This function is called to get ADV data for a specific type.
 *
 * Parameters       p_adv - pointer of ADV data
 *                  type   - finding ADV data type
 *                  p_length - return the length of ADV data not including type
 *
 * Returns          pointer of ADV data
 *
 ******************************************************************************/
extern uint8_t* BTM_CheckAdvData(uint8_t* p_adv, uint8_t type,
                                 uint8_t* p_length);

/*******************************************************************************
 *
 * Function         BTM__BLEReadDiscoverability
 *
 * Description      This function is called to read the current LE
 *                  discoverability mode of the device.
 *
 * Returns          BTM_BLE_NON_DISCOVERABLE ,BTM_BLE_LIMITED_DISCOVERABLE or
 *                     BTM_BLE_GENRAL_DISCOVERABLE
 *
 ******************************************************************************/
uint16_t BTM_BleReadDiscoverability();

/*******************************************************************************
 *
 * Function         BTM__BLEReadConnectability
 *
 * Description      This function is called to read the current LE
 *                  connectibility mode of the device.
 *
 * Returns          BTM_BLE_NON_CONNECTABLE or BTM_BLE_CONNECTABLE
 *
 ******************************************************************************/
extern uint16_t BTM_BleReadConnectability();

/*******************************************************************************
 *
 * Function         BTM_ReadDevInfo
 *
 * Description      This function is called to read the device/address type
 *                  of BD address.
 *
 * Parameter        remote_bda: remote device address
 *                  p_dev_type: output parameter to read the device type.
 *                  p_addr_type: output parameter to read the address type.
 *
 ******************************************************************************/
extern void BTM_ReadDevInfo(const BD_ADDR remote_bda,
                            tBT_DEVICE_TYPE* p_dev_type,
                            tBLE_ADDR_TYPE* p_addr_type);

/*******************************************************************************
 *
 * Function         BTM_ReadConnectedTransportAddress
 *
 * Description      This function is called to read the paired device/address
 *                  type of other device paired corresponding to the BD_address
 *
 * Parameter        remote_bda: remote device address, carry out the transport
 *                              address
 *                  transport: active transport
 *
 * Return           true if an active link is identified; false otherwise
 *
 ******************************************************************************/
extern bool BTM_ReadConnectedTransportAddress(BD_ADDR remote_bda,
                                              tBT_TRANSPORT transport);

/*******************************************************************************
 *
 * Function         BTM_BleConfigPrivacy
 *
 * Description      This function is called to enable or disable the privacy in
 *                  the local device.
 *
 * Parameters       enable: true to enable it; false to disable it.
 *
 * Returns          bool    privacy mode set success; otherwise failed.
 *
 ******************************************************************************/
extern bool BTM_BleConfigPrivacy(bool enable);

/*******************************************************************************
 *
 * Function         BTM_BleLocalPrivacyEnabled
 *
 * Description        Checks if local device supports private address
 *
 * Returns          Return true if local privacy is enabled else false
 *
 ******************************************************************************/
extern bool BTM_BleLocalPrivacyEnabled(void);

/*******************************************************************************
 *
 * Function         BTM_BleEnableMixedPrivacyMode
 *
 * Description      This function is called to enabled Mixed mode if privacy 1.2
 *                  is applicable in controller.
 *
 * Parameters       mixed_on:  mixed mode to be used or not.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleEnableMixedPrivacyMode(bool mixed_on);

/*******************************************************************************
 *
 * Function          BTM_BleMaxMultiAdvInstanceCount
 *
 * Description      Returns the maximum number of multi adv instances supported
 *                  by the controller.
 *
 * Returns          Max multi adv instance count
 *
 ******************************************************************************/
extern uint8_t BTM_BleMaxMultiAdvInstanceCount();

/*******************************************************************************
 *
 * Function         BTM_BleSetConnectableMode
 *
 * Description      This function is called to set BLE connectable mode for a
 *                  peripheral device.
 *
 * Parameters       connectable_mode:  directed connectable mode, or
 *                                     non-directed. It can be
 *                                     BTM_BLE_CONNECT_EVT,
 *                                     BTM_BLE_CONNECT_DIR_EVT or
 *                                     BTM_BLE_CONNECT_LO_DUTY_DIR_EVT
 *
 * Returns          BTM_ILLEGAL_VALUE if controller does not support BLE.
 *                  BTM_SUCCESS is status set successfully; otherwise failure.
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleSetConnectableMode(
    tBTM_BLE_CONN_MODE connectable_mode);

/*******************************************************************************
 *
 * Function         BTM_BleTurnOnPrivacyOnRemote
 *
 * Description      This function is called to enable or disable the privacy on
 *                  the remote device.
 *
 * Parameters       bd_addr: remote device address.
 *                  privacy_on: true to enable it; false to disable it.
 *
 * Returns          void
 *
 ******************************************************************************/
extern void BTM_BleTurnOnPrivacyOnRemote(BD_ADDR bd_addr, bool privacy_on);

/*******************************************************************************
 *
 * Function         BTM_BleUpdateAdvFilterPolicy
 *
 * Description      This function update the filter policy of advertiser.
 *
 * Parameter        adv_policy: advertising filter policy
 *
 * Return           void
 ******************************************************************************/
extern void BTM_BleUpdateAdvFilterPolicy(tBTM_BLE_AFP adv_policy);

/*******************************************************************************
 *
 * Function         BTM_BleReceiverTest
 *
 * Description      This function is called to start the LE Receiver test
 *
 * Parameter       rx_freq - Frequency Range
 *               p_cmd_cmpl_cback - Command Complete callback
 *
 ******************************************************************************/
void BTM_BleReceiverTest(uint8_t rx_freq, tBTM_CMPL_CB* p_cmd_cmpl_cback);

/*******************************************************************************
 *
 * Function         BTM_BleTransmitterTest
 *
 * Description      This function is called to start the LE Transmitter test
 *
 * Parameter       tx_freq - Frequency Range
 *                       test_data_len - Length in bytes of payload data in each
 *                                       packet
 *                       packet_payload - Pattern to use in the payload
 *                       p_cmd_cmpl_cback - Command Complete callback
 *
 ******************************************************************************/
void BTM_BleTransmitterTest(uint8_t tx_freq, uint8_t test_data_len,
                            uint8_t packet_payload,
                            tBTM_CMPL_CB* p_cmd_cmpl_cback);

/*******************************************************************************
 *
 * Function         BTM_BleTestEnd
 *
 * Description     This function is called to stop the in-progress TX or RX test
 *
 * Parameter       p_cmd_cmpl_cback - Command complete callback
 *
 ******************************************************************************/
void BTM_BleTestEnd(tBTM_CMPL_CB* p_cmd_cmpl_cback);

/*******************************************************************************
 *
 * Function         BTM_UseLeLink
 *
 * Description      Select the underlying physical link to use.
 *
 * Returns          true to use LE, false use BR/EDR.
 *
 ******************************************************************************/
extern bool BTM_UseLeLink(BD_ADDR bd_addr);

/*******************************************************************************
 *
 * Function         BTM_BleStackEnable
 *
 * Description      Enable/Disable BLE functionality on stack regardless of
 *                  controller capability.
 *
 * Parameters:      enable: true to enable, false to disable.
 *
 * Returns          true if added OK, else false
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleStackEnable(bool enable);

/*******************************************************************************
 *
 * Function         BTM_GetLeSecurityState
 *
 * Description      This function is called to get security mode 1 flags and
 *                  encryption key size for LE peer.
 *
 * Returns          bool    true if LE device is found, false otherwise.
 *
 ******************************************************************************/
extern bool BTM_GetLeSecurityState(BD_ADDR bd_addr, uint8_t* p_le_dev_sec_flags,
                                   uint8_t* p_le_key_size);

/*******************************************************************************
 *
 * Function         BTM_BleSecurityProcedureIsRunning
 *
 * Description      This function indicates if LE security procedure is
 *                  currently running with the peer.
 *
 * Returns          bool true if security procedure is running, false otherwise.
 *
 ******************************************************************************/
extern bool BTM_BleSecurityProcedureIsRunning(BD_ADDR bd_addr);

/*******************************************************************************
 *
 * Function         BTM_BleGetSupportedKeySize
 *
 * Description      This function gets the maximum encryption key size in bytes
 *                  the local device can suport.
 *                  record.
 *
 * Returns          the key size or 0 if the size can't be retrieved.
 *
 ******************************************************************************/
extern uint8_t BTM_BleGetSupportedKeySize(BD_ADDR bd_addr);

/*******************************************************************************
 *
 * Function         BTM_BleAdvFilterParamSetup
 *
 * Description      This function is called to setup the adv data payload filter
 *                  condition.
 *
 * Parameters       p_target: enabble the filter condition on a target device;
 *                            if NULL enable the generic scan condition.
 *                  enable: enable or disable the filter condition
 *
 * Returns          void
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleAdvFilterParamSetup(
    int action, tBTM_BLE_PF_FILT_INDEX filt_index,
    btgatt_filt_param_setup_t* p_filt_params, tBLE_BD_ADDR* p_target,
    tBTM_BLE_PF_PARAM_CBACK* p_cmpl_cback, tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleCfgFilterCondition
 *
 * Description      This function is called to configure the adv data payload
 *                  filter condition.
 *
 * Parameters       action: to read/write/clear
 *                  cond_type: filter condition type.
 *                  p_cond: filter condition paramter
 *
 * Returns          tBTM_STATUS
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleCfgFilterCondition(
    tBTM_BLE_SCAN_COND_OP action, tBTM_BLE_PF_COND_TYPE cond_type,
    tBTM_BLE_PF_FILT_INDEX filt_index, tBTM_BLE_PF_COND_PARAM* p_cond,
    tBTM_BLE_PF_CFG_CBACK* p_cmpl_cback, tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleEnableDisableFilterFeature
 *
 * Description      Enable or disable the APCF feature
 *
 * Parameters       enable - true - enables APCF, false - disables APCF
 *                       ref_value - Ref value
 *
 * Returns          tBTM_STATUS
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleEnableDisableFilterFeature(
    uint8_t enable, tBTM_BLE_PF_STATUS_CBACK* p_stat_cback,
    tBTM_BLE_REF_VALUE ref_value);

/*******************************************************************************
 *
 * Function         BTM_BleGetEnergyInfo
 *
 * Description      This function obtains the energy info
 *
 * Parameters       p_ener_cback - Callback pointer
 *
 * Returns          status
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_BleGetEnergyInfo(
    tBTM_BLE_ENERGY_INFO_CBACK* p_ener_cback);

/*******************************************************************************
 *
 * Function         BTM_SetBleDataLength
 *
 * Description      Set the maximum BLE transmission packet size
 *
 * Returns          BTM_SUCCESS if success; otherwise failed.
 *
 ******************************************************************************/
extern tBTM_STATUS BTM_SetBleDataLength(BD_ADDR bd_addr,
                                        uint16_t tx_pdu_length);

extern void btm_ble_multi_adv_cleanup(void);

#endif
