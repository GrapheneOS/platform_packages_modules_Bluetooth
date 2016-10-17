/*
 * Copyright (C) 2013 The Android Open Source Project
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


#define LOG_TAG "BtGatt.JNI"

#define LOG_NDEBUG 0

#define CHECK_CALLBACK_ENV                                                      \
   if (!checkCallbackThread()) {                                                \
       error("Callback: '%s' is not called on the correct thread", __FUNCTION__);\
       return;                                                                  \
   }

#include "com_android_bluetooth.h"
#include "hardware/bt_gatt.h"
#include "utils/Log.h"
#include "android_runtime/AndroidRuntime.h"

#include <base/bind.h>
#include <string.h>

#include <cutils/log.h>
#define info(fmt, ...)  ALOGI ("%s(L%d): " fmt,__FUNCTION__, __LINE__,  ## __VA_ARGS__)
#define debug(fmt, ...) ALOGD ("%s(L%d): " fmt,__FUNCTION__, __LINE__,  ## __VA_ARGS__)
#define warn(fmt, ...) ALOGW ("WARNING: %s(L%d): " fmt "##",__FUNCTION__, __LINE__, ## __VA_ARGS__)
#define error(fmt, ...) ALOGE ("ERROR: %s(L%d): " fmt "##",__FUNCTION__, __LINE__, ## __VA_ARGS__)
#define asrt(s) if(!(s)) ALOGE ("%s(L%d): ASSERT %s failed! ##",__FUNCTION__, __LINE__, #s)

#define BD_ADDR_LEN 6

#define UUID_PARAMS(uuid_ptr) \
    uuid_lsb(uuid_ptr),  uuid_msb(uuid_ptr)

static void set_uuid(uint8_t* uuid, jlong uuid_msb, jlong uuid_lsb)
{
    for (int i = 0; i != 8; ++i)
    {
        uuid[i]     = (uuid_lsb >> (8 * i)) & 0xFF;
        uuid[i + 8] = (uuid_msb >> (8 * i)) & 0xFF;
    }
}

static uint64_t uuid_lsb(const bt_uuid_t* uuid)
{
    uint64_t  lsb = 0;
    int i;

    for (i = 7; i >= 0; i--)
    {
        lsb <<= 8;
        lsb |= uuid->uu[i];
    }

    return lsb;
}

static uint64_t uuid_msb(const bt_uuid_t* uuid)
{
    uint64_t msb = 0;
    int i;

    for (i = 15; i >= 8; i--)
    {
        msb <<= 8;
        msb |= uuid->uu[i];
    }

    return msb;
}

static void bd_addr_str_to_addr(const char* str, uint8_t *bd_addr)
{
    int    i;
    char   c;

    c = *str++;
    for (i = 0; i < BD_ADDR_LEN; i++)
    {
        if (c >= '0' && c <= '9')
            bd_addr[i] = c - '0';
        else if (c >= 'a' && c <= 'z')
            bd_addr[i] = c - 'a' + 10;
        else   // (c >= 'A' && c <= 'Z')
            bd_addr[i] = c - 'A' + 10;

        c = *str++;
        if (c != ':')
        {
            bd_addr[i] <<= 4;
            if (c >= '0' && c <= '9')
                bd_addr[i] |= c - '0';
            else if (c >= 'a' && c <= 'z')
                bd_addr[i] |= c - 'a' + 10;
            else   // (c >= 'A' && c <= 'Z')
                bd_addr[i] |= c - 'A' + 10;

            c = *str++;
        }

        c = *str++;
    }
}

static void jstr2bdaddr(JNIEnv* env, bt_bdaddr_t *bda, jstring address)
{
    const char* c_bda = env->GetStringUTFChars(address, NULL);
    if (c_bda != NULL && bda != NULL && strlen(c_bda) == 17)
    {
        bd_addr_str_to_addr(c_bda, bda->address);
        env->ReleaseStringUTFChars(address, c_bda);
    }
}

static jstring bdaddr2newjstr(JNIEnv *env, bt_bdaddr_t* bda) {
    char c_address[32];
    snprintf(c_address, sizeof(c_address),"%02X:%02X:%02X:%02X:%02X:%02X",
        bda->address[0], bda->address[1], bda->address[2],
        bda->address[3], bda->address[4], bda->address[5]);

    return env->NewStringUTF(c_address);
}

namespace android {

/**
 * Client callback methods
 */

static jmethodID method_onClientRegistered;
static jmethodID method_onScanResult;
static jmethodID method_onConnected;
static jmethodID method_onDisconnected;
static jmethodID method_onReadCharacteristic;
static jmethodID method_onWriteCharacteristic;
static jmethodID method_onExecuteCompleted;
static jmethodID method_onSearchCompleted;
static jmethodID method_onReadDescriptor;
static jmethodID method_onWriteDescriptor;
static jmethodID method_onNotify;
static jmethodID method_onRegisterForNotifications;
static jmethodID method_onReadRemoteRssi;
static jmethodID method_onAdvertiseCallback;
static jmethodID method_onConfigureMTU;
static jmethodID method_onScanFilterConfig;
static jmethodID method_onScanFilterParamsConfigured;
static jmethodID method_onScanFilterEnableDisabled;
static jmethodID method_onAdvertiserRegistered;
static jmethodID method_onMultiAdvSetParams;
static jmethodID method_onMultiAdvSetAdvData;
static jmethodID method_onMultiAdvEnable;
static jmethodID method_onClientCongestion;
static jmethodID method_onBatchScanStorageConfigured;
static jmethodID method_onBatchScanStartStopped;
static jmethodID method_onBatchScanReports;
static jmethodID method_onBatchScanThresholdCrossed;

static jmethodID method_CreateonTrackAdvFoundLostObject;
static jmethodID method_onTrackAdvFoundLost;
static jmethodID method_onScanParamSetupCompleted;
static jmethodID method_getSampleGattDbElement;
static jmethodID method_onGetGattDb;

/**
 * Server callback methods
 */
static jmethodID method_onServerRegistered;
static jmethodID method_onClientConnected;
static jmethodID method_onServiceAdded;
static jmethodID method_onServiceStopped;
static jmethodID method_onServiceDeleted;
static jmethodID method_onResponseSendCompleted;
static jmethodID method_onServerReadCharacteristic;
static jmethodID method_onServerReadDescriptor;
static jmethodID method_onServerWriteCharacteristic;
static jmethodID method_onServerWriteDescriptor;
static jmethodID method_onExecuteWrite;
static jmethodID method_onNotificationSent;
static jmethodID method_onServerCongestion;
static jmethodID method_onServerMtuChanged;

/**
 * Static variables
 */

static const btgatt_interface_t *sGattIf = NULL;
static jobject mCallbacksObj = NULL;
static JNIEnv *sCallbackEnv = NULL;

static bool checkCallbackThread() {
    sCallbackEnv = getCallbackEnv();

    JNIEnv* env = AndroidRuntime::getJNIEnv();
    if (sCallbackEnv != env || sCallbackEnv == NULL) return false;
    return true;
}

/**
 * BTA client callbacks
 */

void btgattc_register_app_cb(int status, int clientIf, bt_uuid_t *app_uuid)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onClientRegistered, status,
        clientIf, UUID_PARAMS(app_uuid));
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_scan_result_cb(bt_bdaddr_t* bda, int rssi, vector<uint8_t> adv_data)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    jbyteArray jb = sCallbackEnv->NewByteArray(62);
    sCallbackEnv->SetByteArrayRegion(jb, 0, 62, (jbyte *) adv_data.data());

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onScanResult
        , address, rssi, jb);

    sCallbackEnv->DeleteLocalRef(address);
    sCallbackEnv->DeleteLocalRef(jb);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_open_cb(int conn_id, int status, int clientIf, bt_bdaddr_t* bda)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onConnected,
        clientIf, conn_id, status, address);
    sCallbackEnv->DeleteLocalRef(address);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_close_cb(int conn_id, int status, int clientIf, bt_bdaddr_t* bda)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onDisconnected,
        clientIf, conn_id, status, address);
    sCallbackEnv->DeleteLocalRef(address);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_search_complete_cb(int conn_id, int status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onSearchCompleted,
                                 conn_id, status);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_register_for_notification_cb(int conn_id, int registered, int status, uint16_t handle)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onRegisterForNotifications,
        conn_id, status, registered, handle);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_notify_cb(int conn_id, btgatt_notify_params_t *p_data)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, &p_data->bda);
    jbyteArray jb = sCallbackEnv->NewByteArray(p_data->len);
    sCallbackEnv->SetByteArrayRegion(jb, 0, p_data->len, (jbyte *) p_data->value);

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onNotify
        , conn_id, address, p_data->handle, p_data->is_notify, jb);

    sCallbackEnv->DeleteLocalRef(address);
    sCallbackEnv->DeleteLocalRef(jb);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_read_characteristic_cb(int conn_id, int status, btgatt_read_params_t *p_data)
{
    CHECK_CALLBACK_ENV

    jbyteArray jb;
    if ( status == 0 )      //successful
    {
        jb = sCallbackEnv->NewByteArray(p_data->value.len);
        sCallbackEnv->SetByteArrayRegion(jb, 0, p_data->value.len,
            (jbyte *) p_data->value.value);
    } else {
        uint8_t value = 0;
        jb = sCallbackEnv->NewByteArray(1);
        sCallbackEnv->SetByteArrayRegion(jb, 0, 1, (jbyte *) &value);
    }

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onReadCharacteristic,
        conn_id, status, p_data->handle, jb);
    sCallbackEnv->DeleteLocalRef(jb);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_write_characteristic_cb(int conn_id, int status, uint16_t handle)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onWriteCharacteristic
        , conn_id, status, handle);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_execute_write_cb(int conn_id, int status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onExecuteCompleted
        , conn_id, status);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_read_descriptor_cb(int conn_id, int status, btgatt_read_params_t *p_data)
{
    CHECK_CALLBACK_ENV

    jbyteArray jb;
    if ( p_data->value.len != 0 )
    {
        jb = sCallbackEnv->NewByteArray(p_data->value.len);
        sCallbackEnv->SetByteArrayRegion(jb, 0, p_data->value.len,
                                (jbyte *) p_data->value.value);
    } else {
        jb = sCallbackEnv->NewByteArray(1);
    }

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onReadDescriptor,
        conn_id, status, p_data->handle, jb);

    sCallbackEnv->DeleteLocalRef(jb);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_write_descriptor_cb(int conn_id, int status, uint16_t handle)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onWriteDescriptor
        , conn_id, status, handle);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_remote_rssi_cb(int client_if,bt_bdaddr_t* bda, int rssi, int status)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onReadRemoteRssi,
       client_if, address, rssi, status);
    sCallbackEnv->DeleteLocalRef(address);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_advertise_cb(int status, int client_if)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onAdvertiseCallback, status, client_if);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_configure_mtu_cb(int conn_id, int status, int mtu)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onConfigureMTU,
                                 conn_id, status, mtu);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_scan_filter_cfg_cb(int action, int client_if, int status, int filt_type,
                                int avbl_space)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onScanFilterConfig,
                                 action, status, client_if, filt_type, avbl_space);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_scan_filter_param_cb(int action, int client_if, int status, int avbl_space)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onScanFilterParamsConfigured,
            action, status, client_if, avbl_space);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_scan_filter_status_cb(int action, int client_if, int status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onScanFilterEnableDisabled,
            action, status, client_if);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_congestion_cb(int conn_id, bool congested)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onClientCongestion, conn_id, congested);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_batchscan_cfg_storage_cb(int client_if, int status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onBatchScanStorageConfigured, status, client_if);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_batchscan_startstop_cb(int startstop_action, int client_if, int status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onBatchScanStartStopped, startstop_action,
                                 status, client_if);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_batchscan_reports_cb(int client_if, int status, int report_format,
                        int num_records, std::vector<uint8_t> data)
{
    CHECK_CALLBACK_ENV
    jbyteArray jb = sCallbackEnv->NewByteArray(data.size());
    sCallbackEnv->SetByteArrayRegion(jb, 0, data.size(), (jbyte *) data.data());

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onBatchScanReports, status, client_if,
                                report_format, num_records, jb);
    sCallbackEnv->DeleteLocalRef(jb);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_batchscan_threshold_cb(int client_if)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onBatchScanThresholdCrossed, client_if);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_track_adv_event_cb(btgatt_track_adv_info_t *p_adv_track_info)
{
    CHECK_CALLBACK_ENV
    jobject trackadv_obj = NULL;

    jstring address = bdaddr2newjstr(sCallbackEnv, &p_adv_track_info->bd_addr);

    jbyteArray jb_adv_pkt = sCallbackEnv->NewByteArray(p_adv_track_info->adv_pkt_len);
    jbyteArray jb_scan_rsp = sCallbackEnv->NewByteArray(p_adv_track_info->scan_rsp_len);

    sCallbackEnv->SetByteArrayRegion(jb_adv_pkt, 0, p_adv_track_info->adv_pkt_len,
                                     (jbyte *) p_adv_track_info->p_adv_pkt_data);

    sCallbackEnv->SetByteArrayRegion(jb_scan_rsp, 0, p_adv_track_info->scan_rsp_len,
                                     (jbyte *) p_adv_track_info->p_scan_rsp_data);

    trackadv_obj = sCallbackEnv->CallObjectMethod(mCallbacksObj, method_CreateonTrackAdvFoundLostObject,
                    p_adv_track_info->client_if, p_adv_track_info->adv_pkt_len, jb_adv_pkt,
                    p_adv_track_info->scan_rsp_len, jb_scan_rsp, p_adv_track_info->filt_index,
                    p_adv_track_info->advertiser_state, p_adv_track_info->advertiser_info_present,
                    address, p_adv_track_info->addr_type, p_adv_track_info->tx_power,
                    p_adv_track_info->rssi_value, p_adv_track_info->time_stamp);

    if (NULL != trackadv_obj) {
        sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onTrackAdvFoundLost, trackadv_obj);
        sCallbackEnv->DeleteLocalRef(trackadv_obj);
    }
    sCallbackEnv->DeleteLocalRef(address);
    sCallbackEnv->DeleteLocalRef(jb_adv_pkt);
    sCallbackEnv->DeleteLocalRef(jb_scan_rsp);

    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgattc_scan_parameter_setup_completed_cb(int client_if, btgattc_error_t status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onScanParamSetupCompleted, status, client_if);
    checkAndClearExceptionFromCallback(sCallbackEnv, __func__);
}

void fillGattDbElementArray(JNIEnv *env, jobject *array, const btgatt_db_element_t *db, int count) {
    // Because JNI uses a different class loader in the callback context, we cannot simply get the class.
    // As a workaround, we have to make sure we obtain an object of the class first, as this will cause
    // class loader to load it.
    jobject objectForClass = env->CallObjectMethod(mCallbacksObj, method_getSampleGattDbElement);
    jclass gattDbElementClazz = env->GetObjectClass(objectForClass);
    env->DeleteLocalRef(objectForClass);

    jmethodID gattDbElementConstructor = env->GetMethodID(gattDbElementClazz, "<init>", "()V");

    jclass arrayListclazz = env->FindClass("java/util/ArrayList");
    jmethodID arrayAdd = env->GetMethodID(arrayListclazz, "add", "(Ljava/lang/Object;)Z");
    env->DeleteLocalRef(arrayListclazz);

    jclass uuidClazz = env->FindClass("java/util/UUID");
    jmethodID uuidConstructor = env->GetMethodID(uuidClazz, "<init>", "(JJ)V");

    for (int i = 0; i < count; i++) {
        const btgatt_db_element_t &curr = db[i];

        jobject element = env->NewObject(gattDbElementClazz, gattDbElementConstructor);

        jfieldID fid = env->GetFieldID(gattDbElementClazz, "id", "I");
        env->SetIntField(element, fid, curr.id);

        fid = env->GetFieldID(gattDbElementClazz, "attributeHandle", "I");
        env->SetIntField(element, fid, curr.attribute_handle);

        jobject uuid = env->NewObject(uuidClazz, uuidConstructor, uuid_msb(&curr.uuid), uuid_lsb(&curr.uuid));
        fid = env->GetFieldID(gattDbElementClazz, "uuid", "java/util/UUID");
        env->SetObjectField(element, fid, uuid);
        env->DeleteLocalRef(uuid);

        fid = env->GetFieldID(gattDbElementClazz, "type", "I");
        env->SetIntField(element, fid, curr.type);

        fid = env->GetFieldID(gattDbElementClazz, "attributeHandle", "I");
        env->SetIntField(element, fid, curr.attribute_handle);

        fid = env->GetFieldID(gattDbElementClazz, "startHandle", "I");
        env->SetIntField(element, fid, curr.start_handle);

        fid = env->GetFieldID(gattDbElementClazz, "endHandle", "I");
        env->SetIntField(element, fid, curr.end_handle);

        fid = env->GetFieldID(gattDbElementClazz, "properties", "I");
        env->SetIntField(element, fid, curr.properties);

        env->CallBooleanMethod(*array, arrayAdd, element);
        env->DeleteLocalRef(element);
    }

    env->DeleteLocalRef(gattDbElementClazz);
    env->DeleteLocalRef(uuidClazz);
}

void btgattc_get_gatt_db_cb(int conn_id, btgatt_db_element_t *db, int count)
{
    CHECK_CALLBACK_ENV

    jclass arrayListclazz = sCallbackEnv->FindClass("java/util/ArrayList");
    jobject array = sCallbackEnv->NewObject(arrayListclazz, sCallbackEnv->GetMethodID(arrayListclazz, "<init>", "()V"));

    fillGattDbElementArray(sCallbackEnv, &array, db, count);

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onGetGattDb, conn_id, array);
    sCallbackEnv->DeleteLocalRef(array);

    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

static const btgatt_client_callbacks_t sGattClientCallbacks = {
    btgattc_register_app_cb,
    btgattc_scan_result_cb,
    btgattc_open_cb,
    btgattc_close_cb,
    btgattc_search_complete_cb,
    btgattc_register_for_notification_cb,
    btgattc_notify_cb,
    btgattc_read_characteristic_cb,
    btgattc_write_characteristic_cb,
    btgattc_read_descriptor_cb,
    btgattc_write_descriptor_cb,
    btgattc_execute_write_cb,
    btgattc_remote_rssi_cb,
    btgattc_advertise_cb,
    btgattc_configure_mtu_cb,
    btgattc_scan_filter_cfg_cb,
    btgattc_scan_filter_param_cb,
    btgattc_scan_filter_status_cb,
    btgattc_congestion_cb,
    btgattc_batchscan_cfg_storage_cb,
    btgattc_batchscan_startstop_cb,
    btgattc_batchscan_reports_cb,
    btgattc_batchscan_threshold_cb,
    btgattc_track_adv_event_cb,
    btgattc_scan_parameter_setup_completed_cb,
    btgattc_get_gatt_db_cb,
    NULL, /* services_removed_cb */
    NULL  /* services_added_cb */
};

/**
 * Advertiser callbacks
 */
void ble_advertiser_register_cb(bt_uuid_t uuid, uint8_t advertiser_id, uint8_t status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onAdvertiserRegistered,
                                 status, advertiser_id, UUID_PARAMS(&uuid));
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void ble_advertiser_set_params_cb(uint8_t advertiser_id, uint8_t status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onMultiAdvSetParams, status, advertiser_id);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void ble_advertiser_setadv_data_cb(uint8_t advertiser_id, uint8_t status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onMultiAdvSetAdvData, status, advertiser_id);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void ble_advertiser_enable_cb(bool enable, uint8_t advertiser_id, uint8_t status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onMultiAdvEnable, status, advertiser_id, enable);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

/**
 * BTA server callbacks
 */

void btgatts_register_app_cb(int status, int server_if, bt_uuid_t *uuid)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServerRegistered
        , status, server_if, UUID_PARAMS(uuid));
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_connection_cb(int conn_id, int server_if, int connected, bt_bdaddr_t *bda)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onClientConnected,
                                 address, connected, conn_id, server_if);
    sCallbackEnv->DeleteLocalRef(address);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_service_added_cb(int status, int server_if,
                              vector<btgatt_db_element_t> service)
{
    CHECK_CALLBACK_ENV

    jclass arrayListclazz = sCallbackEnv->FindClass("java/util/ArrayList");
    jobject array = sCallbackEnv->NewObject(arrayListclazz,
        sCallbackEnv->GetMethodID(arrayListclazz, "<init>", "()V"));
    fillGattDbElementArray(sCallbackEnv, &array, service.data(), service.size());

    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServiceAdded, status,
                                 server_if, array);
    sCallbackEnv->DeleteLocalRef(array);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_service_stopped_cb(int status, int server_if, int srvc_handle)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServiceStopped, status,
                                 server_if, srvc_handle);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_service_deleted_cb(int status, int server_if, int srvc_handle)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServiceDeleted, status,
                                 server_if, srvc_handle);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_request_read_characteristic_cb(int conn_id, int trans_id, bt_bdaddr_t *bda,
                             int attr_handle, int offset, bool is_long)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServerReadCharacteristic,
                                 address, conn_id, trans_id, attr_handle,
                                 offset, is_long);
    sCallbackEnv->DeleteLocalRef(address);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_request_read_descriptor_cb(int conn_id, int trans_id, bt_bdaddr_t *bda,
                             int attr_handle, int offset, bool is_long)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServerReadDescriptor,
                                 address, conn_id, trans_id, attr_handle,
                                 offset, is_long);
    sCallbackEnv->DeleteLocalRef(address);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_request_write_characteristic_cb(int conn_id, int trans_id,
                              bt_bdaddr_t *bda, int attr_handle,
                              int offset, bool need_rsp, bool is_prep,
                              vector<uint8_t> value)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    jbyteArray val = sCallbackEnv->NewByteArray(value.size());
    if (val) sCallbackEnv->SetByteArrayRegion(val, 0, value.size(), (jbyte*)value.data());
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServerWriteCharacteristic,
                                 address, conn_id, trans_id, attr_handle,
                                 offset, value.size(), need_rsp, is_prep, val);
    sCallbackEnv->DeleteLocalRef(address);
    sCallbackEnv->DeleteLocalRef(val);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_request_write_descriptor_cb(int conn_id, int trans_id,
                              bt_bdaddr_t *bda, int attr_handle,
                              int offset, bool need_rsp, bool is_prep,
                              vector<uint8_t> value)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    jbyteArray val = sCallbackEnv->NewByteArray(value.size());
    if (val) sCallbackEnv->SetByteArrayRegion(val, 0, value.size(), (jbyte*)value.data());
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServerWriteDescriptor,
                                 address, conn_id, trans_id, attr_handle,
                                 offset, value.size(), need_rsp, is_prep, val);
    sCallbackEnv->DeleteLocalRef(address);
    sCallbackEnv->DeleteLocalRef(val);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}


void btgatts_request_exec_write_cb(int conn_id, int trans_id,
                                   bt_bdaddr_t *bda, int exec_write)
{
    CHECK_CALLBACK_ENV

    jstring address = bdaddr2newjstr(sCallbackEnv, bda);
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onExecuteWrite,
                                 address, conn_id, trans_id, exec_write);
    sCallbackEnv->DeleteLocalRef(address);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_response_confirmation_cb(int status, int handle)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onResponseSendCompleted,
                                 status, handle);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_indication_sent_cb(int conn_id, int status)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onNotificationSent,
                                 conn_id, status);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_congestion_cb(int conn_id, bool congested)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServerCongestion, conn_id, congested);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

void btgatts_mtu_changed_cb(int conn_id, int mtu)
{
    CHECK_CALLBACK_ENV
    sCallbackEnv->CallVoidMethod(mCallbacksObj, method_onServerMtuChanged, conn_id, mtu);
    checkAndClearExceptionFromCallback(sCallbackEnv, __FUNCTION__);
}

static const btgatt_server_callbacks_t sGattServerCallbacks = {
    btgatts_register_app_cb,
    btgatts_connection_cb,
    btgatts_service_added_cb,
    btgatts_service_stopped_cb,
    btgatts_service_deleted_cb,
    btgatts_request_read_characteristic_cb,
    btgatts_request_read_descriptor_cb,
    btgatts_request_write_characteristic_cb,
    btgatts_request_write_descriptor_cb,
    btgatts_request_exec_write_cb,
    btgatts_response_confirmation_cb,
    btgatts_indication_sent_cb,
    btgatts_congestion_cb,
    btgatts_mtu_changed_cb
};

/**
 * GATT callbacks
 */

static const btgatt_callbacks_t sGattCallbacks = {
    sizeof(btgatt_callbacks_t),
    &sGattClientCallbacks,
    &sGattServerCallbacks,
};

/**
 * Native function definitions
 */
static void classInitNative(JNIEnv* env, jclass clazz) {

    // Client callbacks

    method_onClientRegistered = env->GetMethodID(clazz, "onClientRegistered", "(IIJJ)V");
    method_onScanResult = env->GetMethodID(clazz, "onScanResult", "(Ljava/lang/String;I[B)V");
    method_onConnected   = env->GetMethodID(clazz, "onConnected", "(IIILjava/lang/String;)V");
    method_onDisconnected = env->GetMethodID(clazz, "onDisconnected", "(IIILjava/lang/String;)V");
    method_onReadCharacteristic = env->GetMethodID(clazz, "onReadCharacteristic", "(III[B)V");
    method_onWriteCharacteristic = env->GetMethodID(clazz, "onWriteCharacteristic", "(III)V");
    method_onExecuteCompleted = env->GetMethodID(clazz, "onExecuteCompleted",  "(II)V");
    method_onSearchCompleted = env->GetMethodID(clazz, "onSearchCompleted",  "(II)V");
    method_onReadDescriptor = env->GetMethodID(clazz, "onReadDescriptor", "(III[B)V");
    method_onWriteDescriptor = env->GetMethodID(clazz, "onWriteDescriptor", "(III)V");
    method_onNotify = env->GetMethodID(clazz, "onNotify", "(ILjava/lang/String;IZ[B)V");
    method_onRegisterForNotifications = env->GetMethodID(clazz, "onRegisterForNotifications", "(IIII)V");
    method_onReadRemoteRssi = env->GetMethodID(clazz, "onReadRemoteRssi", "(ILjava/lang/String;II)V");
    method_onConfigureMTU = env->GetMethodID(clazz, "onConfigureMTU", "(III)V");
    method_onAdvertiseCallback = env->GetMethodID(clazz, "onAdvertiseCallback", "(II)V");
    method_onScanFilterConfig = env->GetMethodID(clazz, "onScanFilterConfig", "(IIIII)V");
    method_onScanFilterParamsConfigured = env->GetMethodID(clazz, "onScanFilterParamsConfigured", "(IIII)V");
    method_onScanFilterEnableDisabled = env->GetMethodID(clazz, "onScanFilterEnableDisabled", "(III)V");
    method_onAdvertiserRegistered = env->GetMethodID(clazz, "onAdvertiserRegistered", "(IIJJ)V");
    method_onMultiAdvSetParams = env->GetMethodID(clazz, "onAdvertiseParamsSet", "(II)V");
    method_onMultiAdvSetAdvData = env->GetMethodID(clazz, "onAdvertiseDataSet", "(II)V");
    method_onMultiAdvEnable = env->GetMethodID(clazz, "onAdvertiseInstanceEnabled", "(IIZ)V");
    method_onClientCongestion = env->GetMethodID(clazz, "onClientCongestion", "(IZ)V");
    method_onBatchScanStorageConfigured = env->GetMethodID(clazz, "onBatchScanStorageConfigured", "(II)V");
    method_onBatchScanStartStopped = env->GetMethodID(clazz, "onBatchScanStartStopped", "(III)V");
    method_onBatchScanReports = env->GetMethodID(clazz, "onBatchScanReports", "(IIII[B)V");
    method_onBatchScanThresholdCrossed = env->GetMethodID(clazz, "onBatchScanThresholdCrossed", "(I)V");
    method_CreateonTrackAdvFoundLostObject = env->GetMethodID(clazz, "CreateonTrackAdvFoundLostObject", "(II[BI[BIIILjava/lang/String;IIII)Lcom/android/bluetooth/gatt/AdvtFilterOnFoundOnLostInfo;");
    method_onTrackAdvFoundLost = env->GetMethodID(clazz, "onTrackAdvFoundLost",
                                                         "(Lcom/android/bluetooth/gatt/AdvtFilterOnFoundOnLostInfo;)V");
    method_onScanParamSetupCompleted = env->GetMethodID(clazz, "onScanParamSetupCompleted", "(II)V");
    method_getSampleGattDbElement = env->GetMethodID(clazz, "GetSampleGattDbElement", "()Lcom/android/bluetooth/gatt/GattDbElement;");
    method_onGetGattDb = env->GetMethodID(clazz, "onGetGattDb", "(ILjava/util/ArrayList;)V");

    // Server callbacks

    method_onServerRegistered = env->GetMethodID(clazz, "onServerRegistered", "(IIJJ)V");
    method_onClientConnected = env->GetMethodID(clazz, "onClientConnected", "(Ljava/lang/String;ZII)V");
    method_onServiceAdded = env->GetMethodID(clazz, "onServiceAdded", "(IILjava/util/List;)V");
    method_onServiceStopped = env->GetMethodID(clazz, "onServiceStopped", "(III)V");
    method_onServiceDeleted = env->GetMethodID(clazz, "onServiceDeleted", "(III)V");
    method_onResponseSendCompleted = env->GetMethodID(clazz, "onResponseSendCompleted", "(II)V");
    method_onServerReadCharacteristic = env->GetMethodID(clazz, "onServerReadCharacteristic", "(Ljava/lang/String;IIIIZ)V");
    method_onServerReadDescriptor = env->GetMethodID(clazz, "onServerReadDescriptor", "(Ljava/lang/String;IIIIZ)V");
    method_onServerWriteCharacteristic = env->GetMethodID(clazz, "onServerWriteCharacteristic", "(Ljava/lang/String;IIIIIZZ[B)V");
    method_onServerWriteDescriptor = env->GetMethodID(clazz, "onServerWriteDescriptor", "(Ljava/lang/String;IIIIIZZ[B)V");
    method_onExecuteWrite= env->GetMethodID(clazz, "onExecuteWrite", "(Ljava/lang/String;III)V");
    method_onNotificationSent = env->GetMethodID(clazz, "onNotificationSent", "(II)V");
    method_onServerCongestion = env->GetMethodID(clazz, "onServerCongestion", "(IZ)V");
    method_onServerMtuChanged = env->GetMethodID(clazz, "onMtuChanged", "(II)V");

    info("classInitNative: Success!");
}

static const bt_interface_t* btIf;

static void initializeNative(JNIEnv *env, jobject object) {
    if(btIf)
        return;

    if ( (btIf = getBluetoothInterface()) == NULL) {
        error("Bluetooth module is not loaded");
        return;
    }

    if (sGattIf != NULL) {
         ALOGW("Cleaning up Bluetooth GATT Interface before initializing...");
         sGattIf->cleanup();
         sGattIf = NULL;
    }

    if (mCallbacksObj != NULL) {
         ALOGW("Cleaning up Bluetooth GATT callback object");
         env->DeleteGlobalRef(mCallbacksObj);
         mCallbacksObj = NULL;
    }

    if ( (sGattIf = (btgatt_interface_t *)
          btIf->get_profile_interface(BT_PROFILE_GATT_ID)) == NULL) {
        error("Failed to get Bluetooth GATT Interface");
        return;
    }

    bt_status_t status;
    if ( (status = sGattIf->init(&sGattCallbacks)) != BT_STATUS_SUCCESS) {
        error("Failed to initialize Bluetooth GATT, status: %d", status);
        sGattIf = NULL;
        return;
    }

    mCallbacksObj = env->NewGlobalRef(object);
}

static void cleanupNative(JNIEnv *env, jobject object) {
    if (!btIf) return;

    if (sGattIf != NULL) {
        sGattIf->cleanup();
        sGattIf = NULL;
    }

    if (mCallbacksObj != NULL) {
        env->DeleteGlobalRef(mCallbacksObj);
        mCallbacksObj = NULL;
    }
    btIf = NULL;
}

/**
 * Native Client functions
 */

static int gattClientGetDeviceTypeNative(JNIEnv* env, jobject object, jstring address)
{
    if (!sGattIf) return 0;
    bt_bdaddr_t bda;
    jstr2bdaddr(env, &bda, address);
    return sGattIf->client->get_device_type(&bda);
}

static void gattClientRegisterAppNative(JNIEnv* env, jobject object,
                                        jlong app_uuid_lsb, jlong app_uuid_msb )
{
    bt_uuid_t uuid;

    if (!sGattIf) return;
    set_uuid(uuid.uu, app_uuid_msb, app_uuid_lsb);
    sGattIf->client->register_client(&uuid);
}

static void gattClientUnregisterAppNative(JNIEnv* env, jobject object, jint clientIf)
{
    if (!sGattIf) return;
    sGattIf->client->unregister_client(clientIf);
}

static void gattClientScanNative(JNIEnv* env, jobject object, jboolean start)
{
    if (!sGattIf) return;
    sGattIf->client->scan(start);
}

static void gattClientConnectNative(JNIEnv* env, jobject object, jint clientif,
                                 jstring address, jboolean isDirect, jint transport)
{
    if (!sGattIf) return;

    bt_bdaddr_t bda;
    jstr2bdaddr(env, &bda, address);
    sGattIf->client->connect(clientif, &bda, isDirect, transport);
}

static void gattClientDisconnectNative(JNIEnv* env, jobject object, jint clientIf,
                                  jstring address, jint conn_id)
{
    if (!sGattIf) return;
    bt_bdaddr_t bda;
    jstr2bdaddr(env, &bda, address);
    sGattIf->client->disconnect(clientIf, &bda, conn_id);
}

static void gattClientRefreshNative(JNIEnv* env, jobject object, jint clientIf,
                                    jstring address)
{
    if (!sGattIf) return;

    bt_bdaddr_t bda;
    jstr2bdaddr(env, &bda, address);
    sGattIf->client->refresh(clientIf, &bda);
}

static void gattClientSearchServiceNative(JNIEnv* env, jobject object, jint conn_id,
            jboolean search_all, jlong service_uuid_lsb, jlong service_uuid_msb)
{
    if (!sGattIf) return;

    bt_uuid_t uuid;
    set_uuid(uuid.uu, service_uuid_msb, service_uuid_lsb);
    sGattIf->client->search_service(conn_id, search_all ? 0 : &uuid);
}

static void gattClientGetGattDbNative(JNIEnv* env, jobject object,
    jint conn_id)
{
    if (!sGattIf) return;

    sGattIf->client->get_gatt_db(conn_id);
}

static void gattClientReadCharacteristicNative(JNIEnv* env, jobject object,
    jint conn_id, jint handle, jint authReq)
{
    if (!sGattIf) return;

    sGattIf->client->read_characteristic(conn_id, handle, authReq);
}

static void gattClientReadDescriptorNative(JNIEnv* env, jobject object,
    jint conn_id, jint  handle, jint authReq)
{
    if (!sGattIf) return;

    sGattIf->client->read_descriptor(conn_id, handle, authReq);
}

static void gattClientWriteCharacteristicNative(JNIEnv* env, jobject object,
    jint conn_id, jint handle, jint write_type, jint auth_req, jbyteArray value)
{
    if (!sGattIf) return;

    if (value == NULL) {
        warn("gattClientWriteCharacteristicNative() ignoring NULL array");
        return;
    }

    uint16_t len = (uint16_t) env->GetArrayLength(value);
    jbyte *p_value = env->GetByteArrayElements(value, NULL);
    if (p_value == NULL) return;

    vector<uint8_t> vect_val(p_value, p_value + len);
    env->ReleaseByteArrayElements(value, p_value, 0);

    sGattIf->client->write_characteristic(conn_id, handle, write_type, auth_req,
                                          std::move(vect_val));
}

static void gattClientExecuteWriteNative(JNIEnv* env, jobject object,
    jint conn_id, jboolean execute)
{
    if (!sGattIf) return;
    sGattIf->client->execute_write(conn_id, execute ? 1 : 0);
}

static void gattClientWriteDescriptorNative(JNIEnv* env, jobject object,
    jint conn_id, jint handle, jint auth_req, jbyteArray value)
{
    if (!sGattIf) return;

    if (value == NULL) {
        warn("gattClientWriteDescriptorNative() ignoring NULL array");
        return;
    }

    uint16_t len = (uint16_t) env->GetArrayLength(value);
    jbyte *p_value = env->GetByteArrayElements(value, NULL);
    if (p_value == NULL) return;

    std::vector<uint8_t> vect_val(p_value, p_value + len);
    env->ReleaseByteArrayElements(value, p_value, 0);

    sGattIf->client->write_descriptor(conn_id, handle, auth_req,
                                      std::move(vect_val));
}

static void gattClientRegisterForNotificationsNative(JNIEnv* env, jobject object,
    jint clientIf, jstring address, jint handle, jboolean enable)
{
    if (!sGattIf) return;

    bt_bdaddr_t bd_addr;
    const char *c_address = env->GetStringUTFChars(address, NULL);
    bd_addr_str_to_addr(c_address, bd_addr.address);

    if (enable)
        sGattIf->client->register_for_notification(clientIf, &bd_addr, handle);
    else
        sGattIf->client->deregister_for_notification(clientIf, &bd_addr, handle);
}

static void gattClientReadRemoteRssiNative(JNIEnv* env, jobject object, jint clientif,
                                 jstring address)
{
    if (!sGattIf) return;

    bt_bdaddr_t bda;
    jstr2bdaddr(env, &bda, address);

    sGattIf->client->read_remote_rssi(clientif, &bda);
}

static void gattAdvertiseNative(JNIEnv *env, jobject object,
        jint client_if, jboolean start)
{
    if (!sGattIf) return;
    sGattIf->client->listen(client_if, start);
}

static void gattSetAdvDataNative(JNIEnv *env, jobject object, jint client_if,
        jboolean setScanRsp, jboolean inclName, jboolean inclTxPower, jint minInterval,
        jint maxInterval, jint appearance, jbyteArray manufacturerData, jbyteArray serviceData,
        jbyteArray serviceUuid)
{
    if (!sGattIf) return;
    jbyte* arr_data = env->GetByteArrayElements(manufacturerData, NULL);
    uint16_t arr_len = (uint16_t) env->GetArrayLength(manufacturerData);
    vector<uint8_t> data(arr_data, arr_data + arr_len);
    env->ReleaseByteArrayElements(manufacturerData, arr_data, JNI_ABORT);

    jbyte* arr_service_data = env->GetByteArrayElements(serviceData, NULL);
    uint16_t arr_service_data_len = (uint16_t) env->GetArrayLength(serviceData);
    vector<uint8_t> service_data(arr_service_data, arr_service_data + arr_service_data_len);
    env->ReleaseByteArrayElements(serviceData, arr_service_data, JNI_ABORT);

    jbyte* arr_service_uuid = env->GetByteArrayElements(serviceUuid, NULL);
    uint16_t arr_service_uuid_len = (uint16_t) env->GetArrayLength(serviceUuid);
    vector<uint8_t> service_uuid(arr_service_uuid, arr_service_uuid + arr_service_uuid_len);
    env->ReleaseByteArrayElements(serviceUuid, arr_service_uuid, JNI_ABORT);

    sGattIf->advertiser->SetData(client_if, setScanRsp, inclName, inclTxPower,
        minInterval, maxInterval, appearance, std::move(data),
        std::move(service_data), std::move(service_uuid));
}

static void gattSetScanParametersNative(JNIEnv* env, jobject object,
                                        jint client_if, jint scan_interval_unit,
                                        jint scan_window_unit)
{
    if (!sGattIf) return;
    sGattIf->client->set_scan_parameters(client_if, scan_interval_unit, scan_window_unit);
}

static void gattClientScanFilterParamAddNative(JNIEnv* env, jobject object, jobject params)
{
    if (!sGattIf) return;
    const int add_scan_filter_params_action = 0;
    btgatt_filt_param_setup_t filt_params;

    jmethodID methodId = 0;
    jclass filtparam = env->GetObjectClass(params);

    methodId = env->GetMethodID(filtparam, "getClientIf", "()I");
    filt_params.client_if = env->CallIntMethod(params, methodId);;

    filt_params.action = add_scan_filter_params_action;

    methodId = env->GetMethodID(filtparam, "getFiltIndex", "()I");
    filt_params.filt_index = env->CallIntMethod(params, methodId);;

    methodId = env->GetMethodID(filtparam, "getFeatSeln", "()I");
    filt_params.feat_seln = env->CallIntMethod(params, methodId);;

    methodId = env->GetMethodID(filtparam, "getListLogicType", "()I");
    filt_params.list_logic_type = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getFiltLogicType", "()I");
    filt_params.filt_logic_type = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getDelyMode", "()I");
    filt_params.dely_mode = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getFoundTimeout", "()I");
    filt_params.found_timeout = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getLostTimeout", "()I");
    filt_params.lost_timeout = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getFoundTimeOutCnt", "()I");
    filt_params.found_timeout_cnt = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getNumOfTrackEntries", "()I");
    filt_params.num_of_tracking_entries = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getRSSIHighValue", "()I");
    filt_params.rssi_high_thres = env->CallIntMethod(params, methodId);

    methodId = env->GetMethodID(filtparam, "getRSSILowValue", "()I");
    filt_params.rssi_low_thres = env->CallIntMethod(params, methodId);

    env->DeleteLocalRef(filtparam);
    sGattIf->client->scan_filter_param_setup(filt_params);
}

static void gattClientScanFilterParamDeleteNative(JNIEnv* env, jobject object,
        jint client_if, jint filt_index)
{
    if (!sGattIf) return;
    const int delete_scan_filter_params_action = 1;
    btgatt_filt_param_setup_t filt_params;
    memset(&filt_params, 0, sizeof(btgatt_filt_param_setup_t));
    filt_params.client_if = client_if;
    filt_params.action = delete_scan_filter_params_action;
    filt_params.filt_index = filt_index;
    sGattIf->client->scan_filter_param_setup(filt_params);
}

static void gattClientScanFilterParamClearAllNative(JNIEnv* env, jobject object, jint client_if)
{
    if (!sGattIf) return;
    const int clear_scan_filter_params_action = 2;
    btgatt_filt_param_setup_t filt_params;
    memset(&filt_params, 0, sizeof(btgatt_filt_param_setup_t));
    filt_params.client_if = client_if;
    filt_params.action = clear_scan_filter_params_action;
    sGattIf->client->scan_filter_param_setup(filt_params);
}

static void gattClientScanFilterAddRemoveNative(JNIEnv* env, jobject object,
        jint client_if, jint action, jint filt_type, jint filt_index, jint company_id,
        jint company_id_mask, jlong uuid_lsb,  jlong uuid_msb, jlong uuid_mask_lsb,
        jlong uuid_mask_msb, jstring name, jstring address, jbyte addr_type,
        jbyteArray data, jbyteArray mask)
{
    switch(filt_type)
    {
        case 0: // BTM_BLE_PF_ADDR_FILTER
        {
            bt_bdaddr_t bda;
            jstr2bdaddr(env, &bda, address);
            sGattIf->client->scan_filter_add_remove(client_if, action, filt_type, filt_index, 0,
                                             0, NULL, NULL, &bda, addr_type, {}, {});
            break;
        }

        case 1: // BTM_BLE_PF_SRVC_DATA
        {
            jbyte* data_array = env->GetByteArrayElements(data, 0);
            int data_len = env->GetArrayLength(data);
            vector<uint8_t> vec_data(data_array, data_array + data_len);
            env->ReleaseByteArrayElements(data, data_array, JNI_ABORT);

            jbyte* mask_array = env->GetByteArrayElements(mask, NULL);
            uint16_t mask_len = (uint16_t) env->GetArrayLength(mask);
            vector<uint8_t> vec_mask(mask_array, mask_array + mask_len);
            env->ReleaseByteArrayElements(mask, mask_array, JNI_ABORT);

            sGattIf->client->scan_filter_add_remove(client_if, action, filt_type, filt_index,
               0, 0, NULL, NULL, NULL, 0, std::move(vec_data), std::move(vec_mask));
            break;
        }

        case 2: // BTM_BLE_PF_SRVC_UUID
        case 3: // BTM_BLE_PF_SRVC_SOL_UUID
        {
            bt_uuid_t uuid, uuid_mask;
            set_uuid(uuid.uu, uuid_msb, uuid_lsb);
            set_uuid(uuid_mask.uu, uuid_mask_msb, uuid_mask_lsb);
            if (uuid_mask_lsb != 0 && uuid_mask_msb != 0)
                sGattIf->client->scan_filter_add_remove(client_if, action, filt_type, filt_index,
                                 0, 0, &uuid, &uuid_mask, NULL,0,{}, {});
            else
                sGattIf->client->scan_filter_add_remove(client_if, action, filt_type, filt_index,
                                 0, 0, &uuid, NULL, NULL, 0,{}, {});
            break;
        }

        case 4: // BTM_BLE_PF_LOCAL_NAME
        {
            const char* c_name = env->GetStringUTFChars(name, NULL);
            if (c_name != NULL && strlen(c_name) != 0)
            {
                vector<uint8_t> vec_name(c_name, c_name + strlen(c_name));
                env->ReleaseStringUTFChars(name, c_name);
                sGattIf->client->scan_filter_add_remove(client_if, action, filt_type,
                                 filt_index, 0, 0, NULL, NULL, NULL, 0, std::move(vec_name), {});
            }
            break;
        }

        case 5: // BTM_BLE_PF_MANU_DATA
        case 6: // BTM_BLE_PF_SRVC_DATA_PATTERN
        {
            jbyte* data_array = env->GetByteArrayElements(data, 0);
            int data_len = env->GetArrayLength(data);
            vector<uint8_t> vec_data(data_array, data_array + data_len);
            env->ReleaseByteArrayElements(data, data_array, JNI_ABORT);

            jbyte* mask_array = env->GetByteArrayElements(mask, NULL);
            uint16_t mask_len = (uint16_t) env->GetArrayLength(mask);
            vector<uint8_t> vec_mask(mask_array, mask_array + mask_len);
            env->ReleaseByteArrayElements(mask, mask_array, JNI_ABORT);

            sGattIf->client->scan_filter_add_remove(client_if, action, filt_type, filt_index,
                company_id, company_id_mask, NULL, NULL, NULL, 0, std::move(vec_data),
                std::move(vec_mask));
            break;
        }

        default:
            break;
    }
}

static void gattClientScanFilterAddNative(JNIEnv* env, jobject object, jint client_if,
                jint filt_type, jint filt_index, jint company_id, jint company_id_mask,
                jlong uuid_lsb,  jlong uuid_msb, jlong uuid_mask_lsb, jlong uuid_mask_msb,
                jstring name, jstring address, jbyte addr_type, jbyteArray data, jbyteArray mask)
{
    if (!sGattIf) return;
    int action = 0;
    gattClientScanFilterAddRemoveNative(env, object, client_if, action, filt_type, filt_index,
                    company_id, company_id_mask, uuid_lsb, uuid_msb, uuid_mask_lsb, uuid_mask_msb,
                    name, address, addr_type, data, mask);

}

static void gattClientScanFilterDeleteNative(JNIEnv* env, jobject object, jint client_if,
                jint filt_type, jint filt_index, jint company_id, jint company_id_mask,
                jlong uuid_lsb,  jlong uuid_msb, jlong uuid_mask_lsb, jlong uuid_mask_msb,
                jstring name, jstring address, jbyte addr_type, jbyteArray data, jbyteArray mask)
{
    if (!sGattIf) return;
    int action = 1;
    gattClientScanFilterAddRemoveNative(env, object, client_if, action, filt_type, filt_index,
                    company_id, company_id_mask, uuid_lsb, uuid_msb, uuid_mask_lsb, uuid_mask_msb,
                    name, address, addr_type, data, mask);
}

static void gattClientScanFilterClearNative(JNIEnv* env, jobject object, jint client_if,
                        jint filt_index)
{
    if (!sGattIf) return;
    sGattIf->client->scan_filter_clear(client_if, filt_index);
}

static void gattClientScanFilterEnableNative (JNIEnv* env, jobject object, jint client_if,
                          jboolean enable)
{
    if (!sGattIf) return;
    sGattIf->client->scan_filter_enable(client_if, enable);
}

static void gattClientConfigureMTUNative(JNIEnv *env, jobject object,
        jint conn_id, jint mtu)
{
    if (!sGattIf) return;
    sGattIf->client->configure_mtu(conn_id, mtu);
}

static void gattConnectionParameterUpdateNative(JNIEnv *env, jobject object, jint client_if,
        jstring address, jint min_interval, jint max_interval, jint latency, jint timeout)
{
    if (!sGattIf) return;
    bt_bdaddr_t bda;
    jstr2bdaddr(env, &bda, address);
    sGattIf->client->conn_parameter_update(&bda, min_interval, max_interval, latency, timeout);
}

static void registerAdvertiserNative(JNIEnv* env, jobject object,
                                     jlong app_uuid_lsb, jlong app_uuid_msb)
{
    bt_uuid_t uuid;

    if (!sGattIf) return;

    set_uuid(uuid.uu, app_uuid_msb, app_uuid_lsb);
    sGattIf->advertiser->RegisterAdvertiser(base::Bind(&ble_advertiser_register_cb, uuid));
}

static void unregisterAdvertiserNative(JNIEnv* env, jobject object, jint advertiser_id)
{
    if (!sGattIf) return;

    sGattIf->advertiser->Unregister(advertiser_id);
}

static void gattClientEnableAdvNative(JNIEnv* env, jobject object, jint advertiser_id,
       jboolean enable, jint timeout_s)
{
    if (!sGattIf) return;

    sGattIf->advertiser->MultiAdvEnable(
        advertiser_id, enable,
        base::Bind(&ble_advertiser_enable_cb, enable, advertiser_id), timeout_s,
        base::Bind(&ble_advertiser_enable_cb, false, advertiser_id));
}

static void gattClientSetAdvParamsNative(JNIEnv* env, jobject object, jint advertiser_id,
       jint min_interval, jint max_interval, jint adv_type, jint chnl_map, jint tx_power)
{
    if (!sGattIf) return;

    sGattIf->advertiser->MultiAdvSetParameters(
        advertiser_id, min_interval, max_interval, adv_type, chnl_map, tx_power,
        base::Bind(&ble_advertiser_set_params_cb, advertiser_id));
}

static void gattClientSetAdvDataNative(JNIEnv* env, jobject object, jint advertiser_id,
        jboolean set_scan_rsp, jboolean incl_name, jboolean incl_txpower, jint appearance,
        jbyteArray manufacturer_data,jbyteArray service_data, jbyteArray service_uuid)
{
    if (!sGattIf) return;
    jbyte* manu_data = env->GetByteArrayElements(manufacturer_data, NULL);
    uint16_t manu_len = (uint16_t) env->GetArrayLength(manufacturer_data);
    vector<uint8_t> manu_vec(manu_data, manu_data + manu_len);
    env->ReleaseByteArrayElements(manufacturer_data, manu_data, JNI_ABORT);

    jbyte* serv_data = env->GetByteArrayElements(service_data, NULL);
    uint16_t serv_data_len = (uint16_t) env->GetArrayLength(service_data);
    vector<uint8_t> serv_data_vec(serv_data, serv_data + serv_data_len);
    env->ReleaseByteArrayElements(service_data, serv_data, JNI_ABORT);

    jbyte* serv_uuid = env->GetByteArrayElements(service_uuid, NULL);
    uint16_t serv_uuid_len = (uint16_t) env->GetArrayLength(service_uuid);
    vector<uint8_t> serv_uuid_vec(serv_uuid, serv_uuid + serv_uuid_len);
    env->ReleaseByteArrayElements(service_uuid, serv_uuid, JNI_ABORT);

    sGattIf->advertiser->MultiAdvSetInstData(
        advertiser_id, set_scan_rsp, incl_name, incl_txpower, appearance,
        std::move(manu_vec), std::move(serv_data_vec), std::move(serv_uuid_vec),
        base::Bind(&ble_advertiser_setadv_data_cb, advertiser_id));
}

static void gattClientConfigBatchScanStorageNative(JNIEnv* env, jobject object, jint client_if,
            jint max_full_reports_percent, jint max_trunc_reports_percent,
            jint notify_threshold_level_percent)
{
    if (!sGattIf) return;
    sGattIf->client->batchscan_cfg_storage(client_if, max_full_reports_percent,
            max_trunc_reports_percent, notify_threshold_level_percent);
}

static void gattClientStartBatchScanNative(JNIEnv* env, jobject object, jint client_if,
            jint scan_mode, jint scan_interval_unit, jint scan_window_unit, jint addr_type,
            jint discard_rule)
{
    if (!sGattIf) return;
    sGattIf->client->batchscan_enb_batch_scan(client_if, scan_mode, scan_interval_unit,
            scan_window_unit, addr_type, discard_rule);
}

static void gattClientStopBatchScanNative(JNIEnv* env, jobject object, jint client_if)
{
    if (!sGattIf) return;
    sGattIf->client->batchscan_dis_batch_scan(client_if);
}

static void gattClientReadScanReportsNative(JNIEnv* env, jobject object, jint client_if,
        jint scan_type)
{
    if (!sGattIf) return;
    sGattIf->client->batchscan_read_reports(client_if, scan_type);
}

/**
 * Native server functions
 */
static void gattServerRegisterAppNative(JNIEnv* env, jobject object,
                                        jlong app_uuid_lsb, jlong app_uuid_msb )
{
    bt_uuid_t uuid;
    if (!sGattIf) return;
    set_uuid(uuid.uu, app_uuid_msb, app_uuid_lsb);
    sGattIf->server->register_server(&uuid);
}

static void gattServerUnregisterAppNative(JNIEnv* env, jobject object, jint serverIf)
{
    if (!sGattIf) return;
    sGattIf->server->unregister_server(serverIf);
}

static void gattServerConnectNative(JNIEnv *env, jobject object,
                                 jint server_if, jstring address, jboolean is_direct, jint transport)
{
    if (!sGattIf) return;

    bt_bdaddr_t bd_addr;
    const char *c_address = env->GetStringUTFChars(address, NULL);
    bd_addr_str_to_addr(c_address, bd_addr.address);

    sGattIf->server->connect(server_if, &bd_addr, is_direct, transport);
}

static void gattServerDisconnectNative(JNIEnv* env, jobject object, jint serverIf,
                                  jstring address, jint conn_id)
{
    if (!sGattIf) return;
    bt_bdaddr_t bda;
    jstr2bdaddr(env, &bda, address);
    sGattIf->server->disconnect(serverIf, &bda, conn_id);
}

static void gattServerAddServiceNative(JNIEnv *env, jobject object, jint server_if,
                                       jobject gatt_db_elements)
{
    if (!sGattIf) return;

    jclass arrayListclazz = env->FindClass("java/util/List");
    jmethodID arrayGet = env->GetMethodID(arrayListclazz, "get", "(I)Ljava/lang/Object;");
    jmethodID arraySize = env->GetMethodID(arrayListclazz, "size", "()I");

    int count = env->CallIntMethod(gatt_db_elements, arraySize);
    vector<btgatt_db_element_t> db;

    jclass uuidClazz = env->FindClass("java/util/UUID");
    jmethodID uuidGetMsb = env->GetMethodID(uuidClazz, "getMostSignificantBits", "()J");
    jmethodID uuidGetLsb = env->GetMethodID(uuidClazz, "getLeastSignificantBits", "()J");

    jobject objectForClass = env->CallObjectMethod(mCallbacksObj, method_getSampleGattDbElement);
    jclass gattDbElementClazz = env->GetObjectClass(objectForClass);

    for (int i = 0; i < count; i++) {
        btgatt_db_element_t curr;

        jint index = i;
        jobject element = env->CallObjectMethod(gatt_db_elements, arrayGet, index);

        jfieldID fid;

        fid = env->GetFieldID(gattDbElementClazz, "id", "I");
        curr.id = env->GetIntField(element, fid);

        fid = env->GetFieldID(gattDbElementClazz, "uuid", "java/util/UUID");
        jobject uuid = env->GetObjectField(element, fid);

        jlong uuid_msb = env->CallLongMethod(uuid, uuidGetMsb);
        jlong uuid_lsb = env->CallLongMethod(uuid, uuidGetLsb);
        set_uuid(curr.uuid.uu, uuid_msb, uuid_lsb);
        env->DeleteLocalRef(uuid);

        fid = env->GetFieldID(gattDbElementClazz, "type", "I");
        curr.type = (bt_gatt_db_attribute_type_t) env->GetIntField(element, fid);

        fid = env->GetFieldID(gattDbElementClazz, "attributeHandle", "I");
        curr.attribute_handle = env->GetIntField(element, fid);

        fid = env->GetFieldID(gattDbElementClazz, "startHandle", "I");
        curr.start_handle = env->GetIntField(element, fid);

        fid = env->GetFieldID(gattDbElementClazz, "endHandle", "I");
        curr.end_handle = env->GetIntField(element, fid);

        fid = env->GetFieldID(gattDbElementClazz, "properties", "I");
        curr.properties = env->GetIntField(element, fid);

        fid = env->GetFieldID(gattDbElementClazz, "permissions", "I");
        curr.permissions = env->GetIntField(element, fid);

        db.push_back(curr);

        env->DeleteLocalRef(element);
    }

    sGattIf->server->add_service(server_if, std::move(db));
}

static void gattServerStopServiceNative (JNIEnv *env, jobject object,
                                         jint server_if, jint svc_handle)
{
    if (!sGattIf) return;
    sGattIf->server->stop_service(server_if, svc_handle);
}

static void gattServerDeleteServiceNative (JNIEnv *env, jobject object,
                                           jint server_if, jint svc_handle)
{
    if (!sGattIf) return;
    sGattIf->server->delete_service(server_if, svc_handle);
}

static void gattServerSendIndicationNative (JNIEnv *env, jobject object,
        jint server_if, jint attr_handle, jint conn_id, jbyteArray val)
{
    if (!sGattIf) return;

    jbyte* array = env->GetByteArrayElements(val, 0);
    int val_len = env->GetArrayLength(val);

    std::vector<uint8_t> vect_val((uint8_t*)array, (uint8_t*)array + val_len);
    env->ReleaseByteArrayElements(val, array, JNI_ABORT);

    sGattIf->server->send_indication(server_if, attr_handle, conn_id,
                                     /*confirm*/ 1, std::move(vect_val));
}

static void gattServerSendNotificationNative (JNIEnv *env, jobject object,
        jint server_if, jint attr_handle, jint conn_id, jbyteArray val)
{
    if (!sGattIf) return;

    jbyte* array = env->GetByteArrayElements(val, 0);
    int val_len = env->GetArrayLength(val);

    std::vector<uint8_t> vect_val((uint8_t*)array, (uint8_t*)array + val_len);
    env->ReleaseByteArrayElements(val, array, JNI_ABORT);

    sGattIf->server->send_indication(server_if, attr_handle, conn_id,
                                     /*confirm*/ 0, std::move(vect_val));
}

static void gattServerSendResponseNative (JNIEnv *env, jobject object,
        jint server_if, jint conn_id, jint trans_id, jint status,
        jint handle, jint offset, jbyteArray val, jint auth_req)
{
    if (!sGattIf) return;

    btgatt_response_t response;

    response.attr_value.handle = handle;
    response.attr_value.auth_req = auth_req;
    response.attr_value.offset = offset;
    response.attr_value.len = 0;

    if (val != NULL)
    {
        response.attr_value.len = (uint16_t) env->GetArrayLength(val);
        jbyte* array = env->GetByteArrayElements(val, 0);

        for (int i = 0; i != response.attr_value.len; ++i)
            response.attr_value.value[i] = (uint8_t) array[i];
        env->ReleaseByteArrayElements(val, array, JNI_ABORT);
    }

    sGattIf->server->send_response(conn_id, trans_id, status, &response);
}

static void gattTestNative(JNIEnv *env, jobject object, jint command,
                           jlong uuid1_lsb, jlong uuid1_msb, jstring bda1,
                           jint p1, jint p2, jint p3, jint p4, jint p5 )
{
    if (!sGattIf) return;

    bt_bdaddr_t bt_bda1;
    jstr2bdaddr(env, &bt_bda1, bda1);

    bt_uuid_t uuid1;
    set_uuid(uuid1.uu, uuid1_msb, uuid1_lsb);

    btgatt_test_params_t params;
    params.bda1 = &bt_bda1;
    params.uuid1 = &uuid1;
    params.u1 = p1;
    params.u2 = p2;
    params.u3 = p3;
    params.u4 = p4;
    params.u5 = p5;
    sGattIf->client->test_command(command, &params);
}

/**
 * JNI function definitinos
 */

// JNI functions defined in AdvertiseManager class.
static JNINativeMethod sAdvertiseMethods[] = {
    {"registerAdvertiserNative", "(JJ)V", (void *) registerAdvertiserNative},
    {"unregisterAdvertiserNative", "(I)V", (void *) unregisterAdvertiserNative},
    {"gattClientSetParamsNative", "(IIIIII)V", (void *) gattClientSetAdvParamsNative},
    {"gattClientSetAdvDataNative", "(IZZZI[B[B[B)V", (void *) gattClientSetAdvDataNative},
    {"gattClientEnableAdvNative", "(IZI)V", (void *) gattClientEnableAdvNative},
    {"gattSetAdvDataNative", "(IZZZIII[B[B[B)V", (void *) gattSetAdvDataNative},
    {"gattAdvertiseNative", "(IZ)V", (void *) gattAdvertiseNative},
};

// JNI functions defined in ScanManager class.
static JNINativeMethod sScanMethods[] = {
    {"gattClientScanNative", "(Z)V", (void *) gattClientScanNative},
    // Batch scan JNI functions.
    {"gattClientConfigBatchScanStorageNative", "(IIII)V",(void *) gattClientConfigBatchScanStorageNative},
    {"gattClientStartBatchScanNative", "(IIIIII)V", (void *) gattClientStartBatchScanNative},
    {"gattClientStopBatchScanNative", "(I)V", (void *) gattClientStopBatchScanNative},
    {"gattClientReadScanReportsNative", "(II)V", (void *) gattClientReadScanReportsNative},
    // Scan filter JNI functions.
    {"gattClientScanFilterParamAddNative", "(Lcom/android/bluetooth/gatt/FilterParams;)V", (void *) gattClientScanFilterParamAddNative},
    {"gattClientScanFilterParamDeleteNative", "(II)V", (void *) gattClientScanFilterParamDeleteNative},
    {"gattClientScanFilterParamClearAllNative", "(I)V", (void *) gattClientScanFilterParamClearAllNative},
    {"gattClientScanFilterAddNative", "(IIIIIJJJJLjava/lang/String;Ljava/lang/String;B[B[B)V", (void *) gattClientScanFilterAddNative},
    {"gattClientScanFilterDeleteNative", "(IIIIIJJJJLjava/lang/String;Ljava/lang/String;B[B[B)V", (void *) gattClientScanFilterDeleteNative},
    {"gattClientScanFilterClearNative", "(II)V", (void *) gattClientScanFilterClearNative},
    {"gattClientScanFilterEnableNative", "(IZ)V", (void *) gattClientScanFilterEnableNative},
    {"gattSetScanParametersNative", "(III)V", (void *) gattSetScanParametersNative},
};

// JNI functions defined in GattService class.
static JNINativeMethod sMethods[] = {
    {"classInitNative", "()V", (void *) classInitNative},
    {"initializeNative", "()V", (void *) initializeNative},
    {"cleanupNative", "()V", (void *) cleanupNative},
    {"gattClientGetDeviceTypeNative", "(Ljava/lang/String;)I", (void *) gattClientGetDeviceTypeNative},
    {"gattClientRegisterAppNative", "(JJ)V", (void *) gattClientRegisterAppNative},
    {"gattClientUnregisterAppNative", "(I)V", (void *) gattClientUnregisterAppNative},
    {"gattClientConnectNative", "(ILjava/lang/String;ZI)V", (void *) gattClientConnectNative},
    {"gattClientDisconnectNative", "(ILjava/lang/String;I)V", (void *) gattClientDisconnectNative},
    {"gattClientRefreshNative", "(ILjava/lang/String;)V", (void *) gattClientRefreshNative},
    {"gattClientSearchServiceNative", "(IZJJ)V", (void *) gattClientSearchServiceNative},
    {"gattClientGetGattDbNative", "(I)V", (void *) gattClientGetGattDbNative},
    {"gattClientReadCharacteristicNative", "(III)V", (void *) gattClientReadCharacteristicNative},
    {"gattClientReadDescriptorNative", "(III)V", (void *) gattClientReadDescriptorNative},
    {"gattClientWriteCharacteristicNative", "(IIII[B)V", (void *) gattClientWriteCharacteristicNative},
    {"gattClientWriteDescriptorNative", "(III[B)V", (void *) gattClientWriteDescriptorNative},
    {"gattClientExecuteWriteNative", "(IZ)V", (void *) gattClientExecuteWriteNative},
    {"gattClientRegisterForNotificationsNative", "(ILjava/lang/String;IZ)V", (void *) gattClientRegisterForNotificationsNative},
    {"gattClientReadRemoteRssiNative", "(ILjava/lang/String;)V", (void *) gattClientReadRemoteRssiNative},
    {"gattClientConfigureMTUNative", "(II)V", (void *) gattClientConfigureMTUNative},
    {"gattConnectionParameterUpdateNative", "(ILjava/lang/String;IIII)V", (void *) gattConnectionParameterUpdateNative},
    {"gattServerRegisterAppNative", "(JJ)V", (void *) gattServerRegisterAppNative},
    {"gattServerUnregisterAppNative", "(I)V", (void *) gattServerUnregisterAppNative},
    {"gattServerConnectNative", "(ILjava/lang/String;ZI)V", (void *) gattServerConnectNative},
    {"gattServerDisconnectNative", "(ILjava/lang/String;I)V", (void *) gattServerDisconnectNative},
    {"gattServerAddServiceNative", "(ILjava/util/List;)V", (void *) gattServerAddServiceNative},
    {"gattServerStopServiceNative", "(II)V", (void *) gattServerStopServiceNative},
    {"gattServerDeleteServiceNative", "(II)V", (void *) gattServerDeleteServiceNative},
    {"gattServerSendIndicationNative", "(III[B)V", (void *) gattServerSendIndicationNative},
    {"gattServerSendNotificationNative", "(III[B)V", (void *) gattServerSendNotificationNative},
    {"gattServerSendResponseNative", "(IIIIII[BI)V", (void *) gattServerSendResponseNative},

    {"gattTestNative", "(IJJLjava/lang/String;IIIII)V", (void *) gattTestNative},
};

int register_com_android_bluetooth_gatt(JNIEnv* env)
{
    int register_success =
        jniRegisterNativeMethods(env, "com/android/bluetooth/gatt/ScanManager$ScanNative",
                sScanMethods, NELEM(sScanMethods));
    register_success &=
        jniRegisterNativeMethods(env, "com/android/bluetooth/gatt/AdvertiseManager$AdvertiseNative",
                sAdvertiseMethods, NELEM(sAdvertiseMethods));
    return register_success &
        jniRegisterNativeMethods(env, "com/android/bluetooth/gatt/GattService",
                sMethods, NELEM(sMethods));
}
}
