/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#include "bta_bap_uclient_api.h"
#include "ucast_client_int.h"
#include "bta_pacs_client_api.h"
#include "bta_ascs_client_api.h"
#include <hardware/bt_pacs_client.h>
#include <base/bind.h>
#include <base/callback.h>
#include <base/logging.h>
#include "bta_closure_api.h"
#include "bt_trace.h"

namespace bluetooth {
namespace bap {
namespace ucast {

using base::Bind;
using base::Unretained;
using base::Closure;
using bluetooth::Uuid;

using bluetooth::bap::pacs::PacsClient;
using bluetooth::bap::pacs::ConnectionState;
using bluetooth::bap::pacs::CodecConfig;
using bluetooth::bap::pacs::PacsClientCallbacks;

using bluetooth::bap::ascs::AscsClient;
using bluetooth::bap::ascs::GattState;
using bluetooth::bap::ascs::AscsClientCallbacks;
using bluetooth::bap::ascs::AseOpId;
using bluetooth::bap::ascs::AseOpStatus;
using bluetooth::bap::ascs::AseParams;

using bluetooth::bap::ucast::UstreamManagers;
using bluetooth::bap::ucast::UstreamManager;

using bluetooth::bap::ucast::BapEventData;
using bluetooth::bap::ucast::BapEvent;
using bluetooth::bap::ucast::BapConnect;
using bluetooth::bap::ucast::BapDisconnect;
using bluetooth::bap::ucast::BapStart;
using bluetooth::bap::ucast::BapStop;
using bluetooth::bap::ucast::BapReconfig;
using bluetooth::bap::ucast::PacsConnectionState;
using bluetooth::bap::ucast::PacsDiscovery;
using bluetooth::bap::ucast::PacsAvailableContexts;

using bluetooth::bap::ucast::CisGroupState;
using bluetooth::bap::ucast::CisStreamState;
using bluetooth::bap::cis::CigState;
using bluetooth::bap::cis::CisState;
using bluetooth::bap::cis::CisInterface;

using bluetooth::bap::alarm::BapAlarm;
using bluetooth::bap::alarm::BapAlarmCallbacks;

class UcastClientImpl;
UcastClientImpl* instance = nullptr;

class CisInterfaceCallbacksImpl : public CisInterfaceCallbacks {
  public:
    ~CisInterfaceCallbacksImpl() = default;
        /** Callback for connection state change */
    void OnCigState(uint8_t cig_id, CigState state) {
      do_in_bta_thread(FROM_HERE, Bind(&CisInterfaceCallbacks::OnCigState,
                                       Unretained(UcastClient::Get()), cig_id,
                                       state));

    }

    void OnCisState(uint8_t cig_id, uint8_t cis_id,
                   uint8_t direction, CisState state) {
      do_in_bta_thread(FROM_HERE, Bind(&CisInterfaceCallbacks::OnCisState,
                                       Unretained(UcastClient::Get()), cig_id,
                                       cis_id, direction, state));
    }
};

class PacsClientCallbacksImpl : public PacsClientCallbacks {
  public:
    ~PacsClientCallbacksImpl() = default;
    void OnInitialized(int status, int client_id) override {
      LOG(WARNING) << __func__ << ": status =" << loghex(status);
      do_in_bta_thread(FROM_HERE, Bind(&PacsClientCallbacks::OnInitialized,
                                       Unretained(UcastClient::Get()), status,
                                       client_id));
    }

    void OnConnectionState(const RawAddress& address,
                       bluetooth::bap::pacs::ConnectionState state) override {
      LOG(WARNING) << __func__ << ": address=" << address;
      do_in_bta_thread(FROM_HERE, Bind(&PacsClientCallbacks::OnConnectionState,
                                       Unretained(UcastClient::Get()),
                                       address, state));
    }

    void OnAudioContextAvailable(const RawAddress& address,
                          uint32_t available_contexts) override {
      do_in_bta_thread(FROM_HERE,
                       Bind(&PacsClientCallbacks::OnAudioContextAvailable,
                            Unretained(UcastClient::Get()),
                            address, available_contexts));
    }

    void OnSearchComplete(int status, const RawAddress& address,
                          std::vector<CodecConfig> sink_pac_records,
                          std::vector<CodecConfig> src_pac_records,
                          uint32_t sink_locations,
                          uint32_t src_locations,
                          uint32_t available_contexts,
                          uint32_t supported_contexts) override {
      do_in_bta_thread(FROM_HERE, Bind(&PacsClientCallbacks::OnSearchComplete,
                                       Unretained(UcastClient::Get()),
                                       status, address,
                                       sink_pac_records,
                                       src_pac_records,
                                       sink_locations,
                                       src_locations,
                                       available_contexts,
                                       supported_contexts));
    }
};

class AscsClientCallbacksImpl : public AscsClientCallbacks {
  public:
    ~AscsClientCallbacksImpl() = default;
    void OnAscsInitialized(int status, int client_id) override {
      do_in_bta_thread(FROM_HERE, Bind(&AscsClientCallbacks::OnAscsInitialized,
                                       Unretained(UcastClient::Get()), status,
                                       client_id));
    }

    void OnConnectionState(const RawAddress& address,
                       bluetooth::bap::ascs::GattState state) override {
      DVLOG(2) << __func__ << " address: " << address;
      do_in_bta_thread(FROM_HERE, Bind(&AscsClientCallbacks::OnConnectionState,
                                       Unretained(UcastClient::Get()),
                                       address, state));
    }

    void OnAseOpFailed(const RawAddress& address,
                             AseOpId ase_op_id,
                             std::vector<AseOpStatus> status) {
      do_in_bta_thread(FROM_HERE,
                       Bind(&AscsClientCallbacks::OnAseOpFailed,
                            Unretained(UcastClient::Get()),
                            address, ase_op_id, status));

    }

    void OnAseState(const RawAddress& address,
                          AseParams ase) override {
      do_in_bta_thread(FROM_HERE,
                       Bind(&AscsClientCallbacks::OnAseState,
                            Unretained(UcastClient::Get()),
                            address, ase));
    }

    void OnSearchComplete(int status, const RawAddress& address,
                          std::vector<AseParams> sink_ase_list,
                          std::vector<AseParams> src_ase_list) override {
      do_in_bta_thread(FROM_HERE, Bind(&AscsClientCallbacks::OnSearchComplete,
                                       Unretained(UcastClient::Get()),
                                       status, address, sink_ase_list,
                                       src_ase_list));
    }
};

class BapAlarmCallbacksImpl : public BapAlarmCallbacks {
  public:
    ~BapAlarmCallbacksImpl() = default;
    /** Callback for timer timeout */
    void OnTimeout(void* data) {
      do_in_bta_thread(FROM_HERE, Bind(&BapAlarmCallbacks::OnTimeout,
                                       Unretained(UcastClient::Get()), data));
    }
};

class UcastClientImpl : public UcastClient {
 public:
  ~UcastClientImpl() override = default;

  // APIs exposed for upper layers
  void Connect(std::vector<RawAddress> address, bool is_direct,
               std::vector<StreamConnect> streams) override {
    if(address.size() == 1) {
      UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address[0],
                                      pacs_client, pacs_client_id,
                                      ascs_client, cis_intf,
                                      ucl_callbacks, bap_alarm);
      // hand over the request to stream manager
      BapConnect data = { .bd_addr = address, .is_direct = is_direct,
                          .streams = streams};
      mgr->ProcessEvent(BAP_CONNECT_REQ_EVT, &data);
    }
  }

  void Disconnect(const RawAddress& address,
                  std::vector<StreamType> streams) override {
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);

    // hand over the request to stream manager
    BapDisconnect data = { .bd_addr = address,
                          .streams = streams};
    mgr->ProcessEvent(BAP_DISCONNECT_REQ_EVT, &data);
  }

  void Start(const RawAddress& address,
             std::vector<StreamType> streams) override {
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);

    // hand over the request to stream manager
    BapStart data = { .bd_addr = address,
                      .streams = streams};
    mgr->ProcessEvent(BAP_START_REQ_EVT, &data);
  }

  void Stop(const RawAddress& address,
            std::vector<StreamType> streams) override {
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);

    // hand over the request to stream manager
    BapStop data = { .bd_addr = address,
                     .streams = streams};
    mgr->ProcessEvent(BAP_STOP_REQ_EVT, &data);

  }

  void Reconfigure(const RawAddress& address,
                   std::vector<StreamReconfig> streams) override  {
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);

    // hand over the request to stream manager
    BapReconfig data = { .bd_addr = address,
                         .streams = streams};
    mgr->ProcessEvent(BAP_RECONFIG_REQ_EVT, &data);
  }

  void UpdateStream(const RawAddress& address,
                   std::vector<StreamUpdate> update_streams) override  {
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);

    // hand over the request to stream manager
    BapStreamUpdate data = { .bd_addr = address,
                            .update_streams = update_streams};
    mgr->ProcessEvent(BAP_STREAM_UPDATE_REQ_EVT, &data);
  }

  // To be called from device specific stream manager
  bool ReportStreamState(const RawAddress& address) {
    //TODO to check
    return true;

  }

  // PACS client related callbacks
  // to be forwarded to device specific stream manager
  void OnInitialized(int status, int client_id) override {
    LOG(WARNING) << __func__ << ": actual client_id = " << loghex(client_id);
    pacs_client_id = client_id;
  }

  void OnConnectionState(const RawAddress& address,
                         ConnectionState state) override {
    LOG(WARNING) << __func__ << ": address=" << address;
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    PacsConnectionState data = { .bd_addr = address,
                                 .state = state
                               };
    mgr->ProcessEvent(PACS_CONNECTION_STATE_EVT, &data);
  }

  void OnAudioContextAvailable(const RawAddress& address,
                        uint32_t available_contexts) override {
    LOG(WARNING) << __func__ << ": address=" << address;
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    PacsAvailableContexts data = {
                           .bd_addr = address,
                           .available_contexts = available_contexts,
                         };
    mgr->ProcessEvent(PACS_AUDIO_CONTEXT_RES_EVT, &data);
  }

  void OnSearchComplete(int status, const RawAddress& address,
                        std::vector<CodecConfig> sink_pac_records,
                        std::vector<CodecConfig> src_pac_records,
                        uint32_t sink_locations,
                        uint32_t src_locations,
                        uint32_t available_contexts,
                        uint32_t supported_contexts) override {
    LOG(WARNING) << __func__ << ": address=" << address;
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    PacsDiscovery data = {
                           .status = status,
                           .bd_addr = address,
                           .sink_pac_records = sink_pac_records,
                           .src_pac_records = src_pac_records,
                           .sink_locations = sink_locations,
                           .src_locations = src_locations,
                           .available_contexts = available_contexts,
                           .supported_contexts = supported_contexts
                         };
    mgr->ProcessEvent(PACS_DISCOVERY_RES_EVT, &data);
  }

  // ASCS client related callbacks
  // to be forwarded to device specific stream manager
  void OnAscsInitialized(int status, int client_id) override {

  }

  void OnConnectionState(const RawAddress& address,
                     bluetooth::bap::ascs::GattState state) override {
    LOG(WARNING) << __func__ << ": address=" << address;
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    AscsConnectionState data = { .bd_addr = address,
                                 .state = state
                               };
    mgr->ProcessEvent(ASCS_CONNECTION_STATE_EVT, &data);
  }

  void OnAseOpFailed(const RawAddress& address,
                     AseOpId ase_op_id,
                     std::vector<AseOpStatus> status) {

    LOG(WARNING) << __func__ << ": address=" << address;
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    AscsOpFailed data = {
                           .bd_addr = address,
                           .ase_op_id = ase_op_id,
                           .ase_list = status
                        };
    mgr->ProcessEvent(ASCS_ASE_OP_FAILED_EVT, &data);
  }

  void OnAseState(const RawAddress& address,
                        AseParams ase_params) override {
    LOG(WARNING) << __func__ << ": address=" << address;
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    AscsState data = {
                           .bd_addr = address,
                           .ase_params = ase_params
                     };
    mgr->ProcessEvent(ASCS_ASE_STATE_EVT, &data);
  }

  void OnSearchComplete(int status, const RawAddress& address,
                                std::vector<AseParams> sink_ase_list,
                                std::vector<AseParams> src_ase_list) override {
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(address,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    AscsDiscovery data = {
                           .status = status,
                           .bd_addr = address,
                           .sink_ases_list = sink_ase_list,
                           .src_ases_list = src_ase_list
                         };
    mgr->ProcessEvent(ASCS_DISCOVERY_RES_EVT, &data);
  }

  // cis callbacks
  void OnCigState(uint8_t cig_id, CigState state) override {
    std::vector<UstreamManager *> *mgrs_list =  strm_mgrs.GetAllManagers();
    // hand over the request to stream manager
    CisGroupState data = {
                      .cig_id = cig_id,
                      .state = state
                    };

    for (auto it = mgrs_list->begin(); it != mgrs_list->end(); it++) {
      (*it)->ProcessEvent(CIS_GROUP_STATE_EVT, &data);
    }
  }

  void OnCisState(uint8_t cig_id, uint8_t cis_id, uint8_t direction,
                                         CisState state) override {
    std::vector<UstreamManager *> *mgrs_list =  strm_mgrs.GetAllManagers();
    // hand over the request to stream manager
    CisStreamState data = {
                           .cig_id = cig_id,
                           .cis_id = cis_id,
                           .direction = direction,
                           .state = state
                         };

    for (auto it = mgrs_list->begin(); it != mgrs_list->end(); it++) {
      (*it)->ProcessEvent(CIS_STATE_EVT, &data);
    }
  }

  void OnTimeout(void* data) override {
    LOG(ERROR) << __func__;
    BapTimeout* data_ = (BapTimeout *)data;
    UstreamManager *mgr = strm_mgrs.FindorAddByAddress(data_->bd_addr,
                                    pacs_client, pacs_client_id,
                                    ascs_client, cis_intf,
                                    ucl_callbacks, bap_alarm);
    // hand over the request to stream manager
    mgr->ProcessEvent(BAP_TIME_OUT_EVT, data);
  }

  bool Init(UcastClientCallbacks *callback) {
    // register callbacks with CIS, ASCS client, PACS client
    pacs_callbacks = new PacsClientCallbacksImpl;
    PacsClient::Initialize(pacs_callbacks);
    pacs_client = PacsClient::Get();

    ascs_callbacks = new AscsClientCallbacksImpl;
    AscsClient::Init(ascs_callbacks);
    ascs_client = AscsClient::Get();

    cis_callbacks = new CisInterfaceCallbacksImpl;
    CisInterface::Initialize(cis_callbacks);
    cis_intf = CisInterface::Get();

    bap_alarm_cb = new BapAlarmCallbacksImpl;
    BapAlarm::Initialize(bap_alarm_cb);
    bap_alarm = BapAlarm::Get();

    pacs_client_id = 0;
    if(ucl_callbacks != nullptr) {
      // flag an error
      return false;
    } else {
      ucl_callbacks = callback;
      return true;
    }
  }

  bool CleanUp() {
    if(ucl_callbacks != nullptr) {
      ucl_callbacks = nullptr;
      //call clean ups for each clients(ascs, pacs, cis and bap_alarm)
      LOG(ERROR) << __func__
                 <<": Cleaning up pacs, ascs clients, cis intf and bap_alarm.";
      pacs_client->CleanUp(pacs_client_id);
      ascs_client->CleanUp(0x01);
      cis_intf->CleanUp();
      bap_alarm->CleanUp();
      pacs_client = nullptr;
      ascs_client = nullptr;
      cis_intf = nullptr;
      bap_alarm = nullptr;
      // remove all stream managers and other clean ups
      return true;
    } else {
      return false;
    }
  }

 private:
  UcastClientCallbacks* ucl_callbacks;
  UstreamManagers strm_mgrs;
  PacsClient *pacs_client;
  AscsClient *ascs_client;
  PacsClientCallbacks *pacs_callbacks;
  AscsClientCallbacks *ascs_callbacks;
  CisInterface *cis_intf;
  CisInterfaceCallbacks *cis_callbacks;
  uint16_t pacs_client_id;
  BapAlarm* bap_alarm;
  BapAlarmCallbacks* bap_alarm_cb;
};

void UcastClient::Initialize(UcastClientCallbacks* callbacks) {
  if (!instance) {
    instance = new UcastClientImpl();
    instance->Init(callbacks);
  } else {
    LOG(ERROR) << __func__ << " 2nd client registration ignored";
  }
}

void UcastClient::CleanUp() {
  if(instance && instance->CleanUp()) {
    delete instance;
    instance = nullptr;
  }
}

UcastClient* UcastClient::Get() {
  CHECK(instance);
  return instance;
}

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
