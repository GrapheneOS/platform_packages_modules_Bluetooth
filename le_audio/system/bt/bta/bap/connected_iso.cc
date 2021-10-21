/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#include "bta_bap_uclient_api.h"
#include "btm_int.h"
#include <list>
#include "state_machine.h"
#include "stack/include/btm_ble_api_types.h"
#include "bt_trace.h"
#include "btif_util.h"
#include "osi/include/properties.h"

namespace bluetooth {
namespace bap {
namespace cis {

typedef struct {
  uint8_t status;
  uint16_t cis_handle;
  uint8_t reason;
} tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM;

typedef struct {
  uint8_t status;
  uint16_t conn_handle;
} tBTM_BLE_CIS_DATA_PATH_EVT_PARAM;

typedef struct {
uint8_t status;
uint8_t cig_id;
} tBTM_BLE_SET_CIG_REMOVE_PARAM;

struct CIS;
class CisInterfaceCallbacks;
using bluetooth::bap::cis::CisInterfaceCallbacks;

struct tIsoSetUpDataPath {
  uint16_t conn_handle;
  uint8_t data_path_direction;
  uint8_t data_path_id;
};

struct tIsoRemoveDataPath {
  uint16_t conn_handle;
  uint8_t data_path_direction;
};

enum IsoHciEvent {
  CIG_CONFIGURE_REQ = 0,
  CIG_CONFIGURED_EVT,
  CIS_CREATE_REQ,
  CIS_STATUS_EVT,
  CIS_ESTABLISHED_EVT,
  CIS_DISCONNECT_REQ,
  CIS_DISCONNECTED_EVT,
  CIG_REMOVE_REQ,
  CIG_REMOVED_EVT,
  SETUP_DATA_PATH_REQ,
  SETUP_DATA_PATH_DONE_EVT,
  REMOVE_DATA_PATH_REQ,
  REMOVE_DATA_PATH_DONE_EVT,
  CIS_CREATE_REQ_DUMMY
};

struct DataPathNode {
  IsoHciEvent type;
  union {
    tIsoSetUpDataPath setup_datapath;
    tIsoRemoveDataPath rmv_datapath;
  };
};

class CisStateMachine : public bluetooth::common::StateMachine {
 public:
  enum {
    kStateIdle,
    kStateSettingDataPath,
    kStateReady,
    kStateEstablishing,
    kStateDestroying,
    kStateEstablished,
  };

  class StateIdle : public State {
   public:
    StateIdle(CisStateMachine& sm)
        : State(sm, kStateIdle), cis_(sm.GetCis()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Idle"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    CIS &cis_;
  };

  class StateSettingDataPath : public State {
   public:
    StateSettingDataPath(CisStateMachine& sm)
        : State(sm, kStateSettingDataPath), cis_(sm.GetCis()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "SettingDataPath"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    CIS &cis_;
  };

  class StateReady : public State {
   public:
    StateReady(CisStateMachine& sm)
        : State(sm, kStateReady), cis_(sm.GetCis()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Ready"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    CIS &cis_;
  };

  class StateDestroying : public State {
   public:
    StateDestroying(CisStateMachine& sm)
        : State(sm, kStateDestroying), cis_(sm.GetCis()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Destroying"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    CIS &cis_;
  };

  class StateEstablishing : public State {
   public:
    StateEstablishing(CisStateMachine& sm)
        : State(sm, kStateEstablishing), cis_(sm.GetCis()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Establishing"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    CIS &cis_;
  };

  class StateEstablished : public State {
   public:
    StateEstablished(CisStateMachine& sm)
        : State(sm, kStateEstablished), cis_(sm.GetCis()) {}
    void OnEnter() override;
    void OnExit() override;
    const char* GetState() { return "Established"; }
    bool ProcessEvent(uint32_t event, void* p_data) override;

   private:
    CIS &cis_;
  };

  CisStateMachine(CIS &cis) :
       cis(cis) {
    state_idle_ = new StateIdle(*this);
    state_setting_data_path_ = new StateSettingDataPath(*this);
    state_ready_ = new StateReady(*this);
    state_destroying_ = new StateDestroying(*this);
    state_establishing_ = new StateEstablishing(*this);
    state_established_ = new StateEstablished(*this);

    AddState(state_idle_);
    AddState(state_setting_data_path_);
    AddState(state_ready_);
    AddState(state_destroying_);
    AddState(state_establishing_);
    AddState(state_established_);

    SetInitialState(state_idle_);
  }

  CIS  &GetCis() { return cis; }

  const char* GetEventName(uint32_t event) {
    switch (event) {
      CASE_RETURN_STR(CIG_CONFIGURE_REQ)
      CASE_RETURN_STR(CIG_CONFIGURED_EVT)
      CASE_RETURN_STR(CIS_CREATE_REQ)
      CASE_RETURN_STR(CIS_STATUS_EVT)
      CASE_RETURN_STR(CIS_ESTABLISHED_EVT)
      CASE_RETURN_STR(CIS_DISCONNECT_REQ)
      CASE_RETURN_STR(CIS_DISCONNECTED_EVT)
      CASE_RETURN_STR(CIG_REMOVE_REQ)
      CASE_RETURN_STR(CIG_REMOVED_EVT)
      CASE_RETURN_STR(SETUP_DATA_PATH_REQ)
      CASE_RETURN_STR(SETUP_DATA_PATH_DONE_EVT)
      CASE_RETURN_STR(REMOVE_DATA_PATH_REQ)
      CASE_RETURN_STR(REMOVE_DATA_PATH_DONE_EVT)
      CASE_RETURN_STR(CIS_CREATE_REQ_DUMMY)
      default:
       return "Unknown Event";
    }
  }

 private:
  CIS &cis;
  StateIdle *state_idle_;
  StateSettingDataPath *state_setting_data_path_;
  StateReady *state_ready_;
  StateDestroying *state_destroying_;
  StateEstablishing *state_establishing_;
  StateEstablished *state_established_;
};

struct CIS {
  uint8_t cig_id;
  uint8_t cis_id;
  uint16_t cis_handle;
  bool to_air_setup_done;
  bool from_air_setup_done;
  uint8_t datapath_status;
  uint8_t disc_direction;
  uint8_t direction; // input or output or both
  CisInterfaceCallbacks *cis_callback;
  RawAddress peer_bda;
  CISConfig cis_config;
  CisStateMachine cis_sm;
  CisState cis_state;
  std::list <DataPathNode> datapath_queue;

  CIS(uint8_t cig_id, uint8_t cis_id, uint8_t direction,
      CisInterfaceCallbacks* callback):
      cig_id(cig_id), cis_id(cis_id), direction(direction),
      cis_callback(callback),
      cis_sm(*this) {
      to_air_setup_done = false;
      from_air_setup_done = false;
  }
};

struct CreateCisNode {
  uint8_t cig_id;
  std::vector<uint8_t> cis_ids;
  std::vector<uint16_t> cis_handles;
  RawAddress peer_bda;
};

struct CIG {
  CIGConfig cig_config;
  CigState cig_state;
  std::map<RawAddress, uint8_t> clients_list; // address and count
  std::map<uint8_t, CIS *> cis_list; // cis id to CIS
};

class CisInterfaceImpl;
CisInterfaceImpl *instance;

static void hci_cig_param_callback(tBTM_BLE_SET_CIG_RET_PARAM *param);
static void hci_cig_param_test_callback(tBTM_BLE_SET_CIG_PARAM_TEST_RET *param);
static void hci_cig_remove_param_callback(uint8_t status, uint8_t cig_id);
static void hci_cis_create_status_callback( uint8_t status);
static void hci_cis_create_callback(tBTM_BLE_CIS_ESTABLISHED_EVT_PARAM *param);
static void hci_cis_setup_datapath_callback( uint8_t status,
                                              uint16_t conn_handle);
static void hci_cis_disconnect_callback(uint8_t status, uint16_t cis_handle,
                                         uint8_t reason);

void CisStateMachine::StateIdle::OnEnter() {
  LOG(INFO) << __func__ << ": CIS State : " << GetState();
}

void CisStateMachine::StateIdle::OnExit() {

}

bool CisStateMachine::StateIdle::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": CIS State = " << GetState()
                        <<": Event = " << cis_.cis_sm.GetEventName(event);
  LOG(INFO) <<__func__  <<": CIS Id = " << loghex(cis_.cis_id);
  LOG(INFO) <<__func__  <<": CIS Handle = " << loghex(cis_.cis_handle);

  bool cis_status = true;
  switch (event) {
    case SETUP_DATA_PATH_REQ: {
      tIsoSetUpDataPath *data_path_info = (tIsoSetUpDataPath *) p_data;
      tBTM_BLE_SET_ISO_DATA_PATH_PARAM p_params;
      p_params.conn_handle = cis_.cis_handle;
      p_params.data_path_dir = data_path_info->data_path_direction >> 1;
      p_params.data_path_id = data_path_info->data_path_id;
      p_params.codec_id[0] = 0x06;
      memset(&p_params.codec_id[1], 0x00, sizeof(p_params.codec_id) - 1);
      memset(&p_params.cont_delay, 0x00, sizeof(p_params.cont_delay));
      p_params.codec_config_length = 0x00;
      p_params.codec_config = nullptr;
      p_params.p_cb = &hci_cis_setup_datapath_callback;
      if(BTM_BleSetIsoDataPath(&p_params) == HCI_SUCCESS) {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateSettingDataPath);
        DataPathNode node = {
                             .type = SETUP_DATA_PATH_REQ,
                             .setup_datapath = {
                               .conn_handle = cis_.cis_handle,
                               .data_path_direction  =
                                    data_path_info->data_path_direction,
                               .data_path_id = data_path_info->data_path_id
                             },
                            };
        cis_.datapath_queue.push_back(node);
      }
    } break;
    default:
      cis_status = false;
      break;
  }
  return cis_status;
}

void CisStateMachine::StateSettingDataPath::OnEnter() {
  LOG(INFO) << __func__ << ": CIS State : " << GetState();
}

void CisStateMachine::StateSettingDataPath::OnExit() {

}

bool CisStateMachine::StateSettingDataPath::ProcessEvent(uint32_t event,
                                                         void* p_data) {
  LOG(INFO) <<__func__  <<": CIS State = " << GetState()
                        <<": Event = " << cis_.cis_sm.GetEventName(event);
  LOG(INFO) <<__func__  <<": CIS Id = " << loghex(cis_.cis_id);
  LOG(INFO) <<__func__  <<": CIS Handle = " << loghex(cis_.cis_handle);

  bool cis_status = true;
  switch (event) {
    case SETUP_DATA_PATH_REQ: {
      // add them to the queue
      tIsoSetUpDataPath *data_path_info = (tIsoSetUpDataPath *) p_data;

      DataPathNode node = {
                           .type = SETUP_DATA_PATH_REQ,
                           .setup_datapath = {
                           .conn_handle =  cis_.cis_handle,
                           .data_path_direction  =
                                data_path_info->data_path_direction,
                            .data_path_id = data_path_info->data_path_id
                           }
                          };

      cis_.datapath_queue.push_back(node);
    } break;
    case SETUP_DATA_PATH_DONE_EVT: {
      tBTM_BLE_CIS_DATA_PATH_EVT_PARAM *param =
                  (tBTM_BLE_CIS_DATA_PATH_EVT_PARAM *) p_data;
      cis_.datapath_status = param->status;

      if(!cis_.datapath_queue.empty()) {
        if(cis_.datapath_status == ISO_HCI_SUCCESS) {
          DataPathNode node = cis_.datapath_queue.front();
          if(node.type == SETUP_DATA_PATH_REQ) {
            uint8_t direction = node.setup_datapath.data_path_direction;
            if(direction == DIR_TO_AIR) {
              cis_.to_air_setup_done = true;
            } else if( direction == DIR_FROM_AIR) {
              cis_.from_air_setup_done = true;
            }
          }
        }
        // remove the entry as it is processed
        cis_.datapath_queue.pop_front();
      }

      // check if there are any more entries in queue now
      // expect the queue entry to be of setup datapath only
      if(!cis_.datapath_queue.empty()) {
        DataPathNode node = cis_.datapath_queue.front();
        if(node.type == SETUP_DATA_PATH_REQ) {
          tBTM_BLE_SET_ISO_DATA_PATH_PARAM p_params;
          p_params.conn_handle = node.setup_datapath.conn_handle;
          p_params.data_path_dir = node.setup_datapath.data_path_direction >> 1;
          p_params.data_path_id = node.setup_datapath.data_path_id;
          p_params.codec_id[0] = 0x06;
          memset(&p_params.codec_id[1], 0x00, sizeof(p_params.codec_id) - 1);
          memset(&p_params.cont_delay, 0x00, sizeof(p_params.cont_delay));
          p_params.codec_config_length = 0x00;
          p_params.codec_config = nullptr;
          p_params.p_cb = &hci_cis_setup_datapath_callback;
          if(BTM_BleSetIsoDataPath(&p_params) != HCI_SUCCESS) {
            LOG(ERROR) << "Setup Datapath Failed";
            cis_.datapath_queue.pop_front();
            cis_.cis_sm.TransitionTo(CisStateMachine::kStateReady);
          }
        } else {
          LOG(ERROR) << "Unexpected entry";
        }
      } else {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateReady);
      }
    } break;
    default:
      cis_status = false;
      break;
  }
  return cis_status;
}


void CisStateMachine::StateReady::OnEnter() {
  LOG(INFO) << __func__ << ": CIS State : " << GetState();
  // update the ready state incase of transitioned from states except
  // setting up datapath as CIG state event is sufficient for transition
  // from setting up data path to ready.
  if(cis_.cis_sm.PreviousStateId() != CisStateMachine::kStateSettingDataPath) {
    cis_.cis_callback->OnCisState(cis_.cig_id, cis_.cis_id,
                                  cis_.direction,
                                  CisState::READY);
  }
}

void CisStateMachine::StateReady::OnExit() {

}

bool CisStateMachine::StateReady::ProcessEvent(uint32_t event, void* p_data) {
  LOG(INFO) <<__func__  <<": CIS State = " << GetState()
                        <<": Event = " << cis_.cis_sm.GetEventName(event);
  LOG(INFO) <<__func__  <<": CIS Id = " << loghex(cis_.cis_id);
  LOG(INFO) <<__func__  <<": CIS Handle = " << loghex(cis_.cis_handle);

  bool cis_status = true;
  switch (event) {
    case CIS_CREATE_REQ: {
      tBTM_BLE_ISO_CREATE_CIS_CMD_PARAM cmd_data;
      CreateCisNode *pNode = (CreateCisNode *) p_data;
      cmd_data.cis_count = pNode->cis_ids.size();
      cmd_data.p_cb = &hci_cis_create_status_callback;
      cmd_data.p_evt_cb = &hci_cis_create_callback;
      tACL_CONN* acl = btm_bda_to_acl(pNode->peer_bda, BT_TRANSPORT_LE);
      if(!acl) {
        BTIF_TRACE_DEBUG("%s create_cis return ", __func__);
        return false;
      }
      for (auto i: pNode->cis_handles) {

        tBTM_BLE_CHANNEL_MAP map = { .cis_conn_handle = i,
                                     .acl_conn_handle = acl->hci_handle };
        cmd_data.link_conn_handles.push_back(map);
      }
      if(BTM_BleCreateCis(&cmd_data, &hci_cis_disconnect_callback)
                          == HCI_SUCCESS)
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateEstablishing);
    } break;
    case CIS_CREATE_REQ_DUMMY: {
      cis_.cis_sm.TransitionTo(CisStateMachine::kStateEstablishing);
    } break;
    default:
      cis_status = false;
      break;
  }
  return cis_status;
}


void CisStateMachine::StateDestroying::OnEnter() {
  LOG(INFO) << __func__ << ": CIS State : " << GetState();
  cis_.cis_callback->OnCisState(cis_.cig_id, cis_.cis_id,
                                cis_.direction,
                                CisState::DESTROYING);
}

void CisStateMachine::StateDestroying::OnExit() {

}

bool CisStateMachine::StateDestroying::ProcessEvent(uint32_t event,
                                                    void* p_data) {
  LOG(INFO) <<__func__  <<": CIS State = " << GetState()
                        <<": Event = " << cis_.cis_sm.GetEventName(event);
  LOG(INFO) <<__func__  <<": CIS Id = " << loghex(cis_.cis_id);
  LOG(INFO) <<__func__  <<": CIS Handle = " << loghex(cis_.cis_handle);

  bool cis_status = true;
  switch (event) {
    case CIS_DISCONNECTED_EVT: {
      tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM *param =
                    (tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM *) p_data;
      if(param->status != ISO_HCI_SUCCESS) {
        LOG(ERROR) <<__func__  << " cis disconnection failed";
        cis_.cis_sm.TransitionTo(cis_.cis_sm.PreviousStateId());
      } else {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateReady);
      }
    } break;
    default:
      cis_status = false;
      break;
  }
  return cis_status;
}


void CisStateMachine::StateEstablishing::OnEnter() {
  LOG(INFO) << __func__ << ": CIS State : " << GetState();
  cis_.cis_callback->OnCisState(cis_.cig_id, cis_.cis_id,
                                cis_.direction,
                                CisState::ESTABLISHING);
}

void CisStateMachine::StateEstablishing::OnExit() {

}

bool CisStateMachine::StateEstablishing::ProcessEvent(uint32_t event,
                                                      void* p_data) {
  LOG(INFO) <<__func__  <<": CIS State = " << GetState()
                        <<": Event = " << cis_.cis_sm.GetEventName(event);
  LOG(INFO) <<__func__  <<": CIS Id = " << loghex(cis_.cis_id);
  LOG(INFO) <<__func__  <<": CIS Handle = " << loghex(cis_.cis_handle);

  bool cis_status = true;
  switch (event) {
    case CIS_STATUS_EVT: {
      uint8_t status = *((uint8_t *)(p_data));
      if(status != ISO_HCI_SUCCESS) {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateReady);
      }
    } break;
    case CIS_ESTABLISHED_EVT: {
      tBTM_BLE_CIS_ESTABLISHED_EVT_PARAM *param =
                     (tBTM_BLE_CIS_ESTABLISHED_EVT_PARAM *) p_data;
      if(param->status != ISO_HCI_SUCCESS) {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateReady);
      } else {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateEstablished);

      }
    } break;
    default:
      cis_status = false;
      break;
  }
  return cis_status;
}

void CisStateMachine::StateEstablished::OnEnter() {
  LOG(INFO) << __func__ << ": CIS State : " << GetState();
  cis_.disc_direction = cis_.direction;
  cis_.cis_callback->OnCisState(cis_.cig_id, cis_.cis_id,
                                cis_.direction,
                                CisState::ESTABLISHED);
}

void CisStateMachine::StateEstablished::OnExit() {

}

bool CisStateMachine::StateEstablished::ProcessEvent(uint32_t event,
                                                     void* p_data) {
  LOG(INFO) <<__func__  <<": CIS State = " << GetState()
                        <<": Event = " << cis_.cis_sm.GetEventName(event);
  LOG(INFO) <<__func__  <<": CIS Id = " << loghex(cis_.cis_id);
  LOG(INFO) <<__func__  <<": CIS Handle = " << loghex(cis_.cis_handle);

  switch (event) {
    case CIS_DISCONNECT_REQ:
      if(BTM_BleIsoCisDisconnect(cis_.cis_handle, 0x13 ,
                                 &hci_cis_disconnect_callback) ==
                                 HCI_SUCCESS) {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateDestroying);
      }
      break;
    case CIS_DISCONNECTED_EVT: {
      tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM *param =
                    (tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM *) p_data;
      if(param->status != ISO_HCI_SUCCESS) {
        LOG(ERROR) <<__func__  << " cis disconnection failed";
        cis_.cis_sm.TransitionTo(cis_.cis_sm.PreviousStateId());
      } else {
        cis_.cis_sm.TransitionTo(CisStateMachine::kStateReady);
      }
    } break;
    default:
      break;
  }
  return true;
}

class CisInterfaceImpl : public CisInterface {
 public:
  CisInterfaceImpl(CisInterfaceCallbacks* callback):
     callbacks(callback)  { }

  ~CisInterfaceImpl() override = default;

  void CleanUp () {

  }

  CigState GetCigState(const uint8_t &cig_id) override {
    CIG *cig = GetCig(cig_id);
    if (cig != nullptr) {
      return cig->cig_state;
    } else {
      return CigState::IDLE;
    }
  }

  CisState GetCisState(const uint8_t &cig_id, uint8_t cis_id) override {
    return CisState::READY;
  }

  uint8_t GetCisCount(const uint8_t &cig_id) override {
    return 0;
  }

  IsoHciStatus CreateCig(RawAddress client_peer_bda, bool reconfig,
                         CIGConfig &cig_config,
                         std::vector<CISConfig> &cis_configs) override {
    // check if CIG already exists
    LOG(INFO) << __func__  << " : CIG Id = " << loghex(cig_config.cig_id);
    CIG *cig = GetCig(cig_config.cig_id);
    if (cig != nullptr) {
      auto it = cig->clients_list.find(client_peer_bda);
      if (it == cig->clients_list.end()) {
        cig->clients_list.insert(std::make_pair(client_peer_bda, 0x01));
      } else {
        if(!reconfig) {
          // increment the count
          it->second++;
        }
      }
      // check if params are same for group requested
      // and for the group alredy exists
      if(cig->cig_state == CigState::CREATING) {
        return ISO_HCI_IN_PROGRESS;
      } else if(IsCigParamsSame(cig_config, cis_configs)) {
        if(cig->cig_state == CigState::CREATED) {
          return ISO_HCI_SUCCESS;
        }
      }
    }

    // check if the CIS vector length is same as cis count passed
    // in CIG confifuration
    if(cig_config.cis_count != cis_configs.size()) {
      return ISO_HCI_FAILED;
    }

    char value[PROPERTY_VALUE_MAX] = {0};
    bool create_cig = false;
    property_get("persist.vendor.btstack.get_cig_test_param", value, "");
    uint16_t ft_m_s, ft_s_m, iso_int, clk_accuracy, nse, pdu_m_s, pdu_s_m, bn_m_s, bn_s_m;
    int res = sscanf(value, "%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu,%hu", &ft_m_s, &ft_s_m, &iso_int,
                            &clk_accuracy, &nse, &pdu_m_s, &pdu_s_m, &bn_m_s, &bn_s_m);
    LOG(WARNING) << __func__<< ": FT_M_S: " << loghex(ft_m_s) << ", FT_S_M: " << loghex(ft_s_m)
                 << ", ISO_Interval: " << loghex(iso_int) << ", slave_clock: " << loghex(clk_accuracy)
                 << ", NSE: " << loghex(nse) << ", PDU_M_S:" << loghex(pdu_m_s)
                 << " PDU_S_M:" << loghex(pdu_s_m) << ", BN_M_S: " << loghex(bn_m_s)
                 << ", BN_S_M: " << loghex(bn_s_m);
    if (res == 9) {
      tBTM_BLE_SET_CIG_PARAM_TEST p_data_test;
      p_data_test.cig_id = cig_config.cig_id;
      memcpy(&p_data_test.sdu_int_s_to_m, &cig_config.sdu_interval_s_to_m,
              sizeof(p_data_test.sdu_int_s_to_m));

      memcpy(&p_data_test.sdu_int_m_to_s, &cig_config.sdu_interval_m_to_s,
              sizeof(p_data_test.sdu_int_m_to_s));

      p_data_test.ft_m_to_s = ft_m_s;
      p_data_test.ft_s_to_m = ft_s_m;
      p_data_test.iso_interval = iso_int;
      p_data_test.slave_clock_accuracy = clk_accuracy;
      p_data_test.packing = cig_config.packing;
      p_data_test.framing = cig_config.framing;
      p_data_test.cis_count = cig_config.cis_count;

      for (auto it = cis_configs.begin(); it != cis_configs.end();) {
        tBTM_BLE_CIS_TEST_CONFIG cis_config;
        cis_config.cis_id = it->cis_id;
        cis_config.nse = nse;
        cis_config.max_sdu_m_to_s = it->max_sdu_m_to_s;
        cis_config.max_sdu_s_to_m = it->max_sdu_s_to_m;
        cis_config.max_pdu_m_to_s = it->max_sdu_m_to_s;
        cis_config.max_pdu_s_to_m = it->max_sdu_s_to_m;
        cis_config.phy_m_to_s = it->phy_m_to_s;
        cis_config.phy_s_to_m = it->phy_s_to_m;
        cis_config.bn_m_to_s = bn_m_s;
        cis_config.bn_s_to_m = 0;
        if (cis_config.max_sdu_s_to_m > 0) {
          cis_config.bn_s_to_m = bn_s_m;
          if (cis_config.max_sdu_m_to_s > 0 && cis_config.nse > 13) {
            cis_config.nse = 13;
          }
        }
        p_data_test.cis_config.push_back(cis_config);
        it++;
      }
      p_data_test.p_cb = &hci_cig_param_test_callback;
      create_cig = (BTM_BleSetCigParametersTest(&p_data_test) == HCI_SUCCESS);
    } else {
      tBTM_BLE_ISO_SET_CIG_CMD_PARAM p_data;
      p_data.cig_id = cig_config.cig_id;
      memcpy(&p_data.sdu_int_s_to_m, &cig_config.sdu_interval_s_to_m,
              sizeof(p_data.sdu_int_s_to_m));

      memcpy(&p_data.sdu_int_m_to_s, &cig_config.sdu_interval_m_to_s,
              sizeof(p_data.sdu_int_m_to_s));

      p_data.slave_clock_accuracy = 0x00;
      p_data.packing = cig_config.packing;
      p_data.framing = cig_config.framing;
      p_data.max_transport_latency_m_to_s = cig_config.max_tport_latency_m_to_s;
      p_data.max_transport_latency_s_to_m = cig_config.max_tport_latency_s_to_m;
      p_data.cis_count = cig_config.cis_count;

      for (auto it = cis_configs.begin(); it != cis_configs.end();) {
        tBTM_BLE_CIS_CONFIG cis_config;
        memcpy(&cis_config, &(*it), sizeof(tBTM_BLE_CIS_CONFIG));
        p_data.cis_config.push_back(cis_config);
        it++;
      }
      p_data.p_cb = &hci_cig_param_callback;
      create_cig = (BTM_BleSetCigParam(&p_data) == HCI_SUCCESS);
    }
    if(create_cig) {
      // create new CIG and add it to the list
      if(cig == nullptr) {
        CIG *cig = new (CIG);
        cig_list.insert(std::make_pair(cig_config.cig_id, cig));
        cig->cig_config = cig_config;
        cig->cig_state = CigState::CREATING;

        for(uint8_t i = 0; i < cig_config.cis_count; i++)  {
          uint8_t direction = 0;
          if(cis_configs[i].max_sdu_m_to_s) direction |= DIR_TO_AIR;
          if(cis_configs[i].max_sdu_s_to_m) direction |= DIR_FROM_AIR;

          CIS *cis = new CIS(cig_config.cig_id, cis_configs[i].cis_id,
                         direction, callbacks);
          cis->cis_config = cis_configs[i];
          cig->cis_list.insert(std::make_pair(cis_configs[i].cis_id, cis));
        }

        auto it = cig->clients_list.find(client_peer_bda);
        if (it == cig->clients_list.end()) {
          cig->clients_list.insert(std::make_pair(client_peer_bda, 0x01));
        } else {
          // increment the count
          it->second++;
          LOG(WARNING) << __func__  << "count " << loghex(it->second);
        }
      } else {
        cig->cig_config = cig_config;
        cig->cig_state = CigState::CREATING;

        uint8_t i = 0;
        for (auto it = cig->cis_list.begin(); it != cig->cis_list.end();) {
          CIS *cis = it->second;
          cis->cis_config = cis_configs[i];
          cis->cis_sm.TransitionTo(CisStateMachine::kStateIdle);
          it++; i++;
        }

        auto it = cig->clients_list.find(client_peer_bda);
        if (it == cig->clients_list.end()) {
          cig->clients_list.insert(std::make_pair(client_peer_bda, 0x01));
        }
      }
      return ISO_HCI_IN_PROGRESS;
    } else {
      return ISO_HCI_FAILED;
    }
  }

  IsoHciStatus RemoveCig(RawAddress client_peer_bda, uint8_t cig_id) override {
    LOG(INFO) <<__func__  << ": CIG Id = " << loghex(cig_id);
    // check if the CIG exists
    CIG *cig = GetCig(cig_id);
    if (cig == nullptr) {
      return ISO_HCI_FAILED;
    }

    if(cig->cig_state == CigState::IDLE ||
       cig->cig_state == CigState::CREATING) {
      return ISO_HCI_FAILED;
    } else if(cig->cig_state == CigState::CREATED) {

      auto it = cig->clients_list.find(client_peer_bda);
      if (it == cig->clients_list.end()) {
        return ISO_HCI_FAILED;
      } else {
        // decrement the count
        it->second--;
        LOG(WARNING) << __func__  << ": Count : " << loghex(it->second);
      }

      // check if all clients have voted off then go for CIG removal
      uint8_t vote_on_count = 0;
      for (auto it = cig->clients_list.begin();
                                it != cig->clients_list.end();) {
        vote_on_count += it->second;
        it++;
      }

      if(vote_on_count) {
        LOG(WARNING) << __func__  << " : Vote On Count : "
                                  << loghex(vote_on_count);
        return ISO_HCI_SUCCESS;
      }

      // check if any of the CIS are in established/streaming state
      // if so return false as it is not allowed
      if(IsCisActive(cig_id, 0xFF)) return ISO_HCI_FAILED;

      if(BTM_BleRemoveCig(cig_id, &hci_cig_remove_param_callback)
              == HCI_SUCCESS) {
        cig->cig_state = CigState::REMOVING;
        return ISO_HCI_IN_PROGRESS;
      } else return ISO_HCI_FAILED;
    }
    return ISO_HCI_FAILED;
  }

  IsoHciStatus CreateCis(uint8_t cig_id, std::vector<uint8_t> cis_ids,
                         RawAddress peer_bda) override  {
    LOG(INFO) <<__func__  << ": CIG Id = " << loghex(cig_id);
    LOG(INFO) <<__func__  << ": No. of CISes = " << loghex(cis_ids.size());

    IsoHciStatus ret;
    uint32_t cur_state;
    // check if the CIG exists
    CIG *cig = GetCig(cig_id);
    if (cig == nullptr) {
      return ISO_HCI_FAILED;
    }

    if(cig->cig_state != CigState::CREATED) {
      return ISO_HCI_FAILED;
    }

    bool cis_created = false;
    CreateCisNode param;
    param.cig_id = cig_id;
    param.cis_ids = cis_ids;
    param.peer_bda = peer_bda;
    std::vector<uint16_t> cis_handles;

    for (auto i: cis_ids) {
      CIS *cis = GetCis(cig_id, i);
      if (cis == nullptr) {
        return ISO_HCI_FAILED;
      }
      cis_handles.push_back(cis->cis_handle);
    }
    param.cis_handles = cis_handles;

    for (auto i: cis_ids) {
      LOG(INFO) <<__func__ << ": CIS Id = " << loghex(i);
      // check if CIS ID mentioned is present as part of CIG
      CIS *cis = GetCis(cig_id, i);
      if (cis == nullptr) {
        ret = ISO_HCI_FAILED;
        break;
      }

      cur_state = cis->cis_sm.StateId();

      // check if CIS is already created or in progress
      if(cur_state == CisStateMachine::kStateEstablishing) {
        ret = ISO_HCI_IN_PROGRESS;
        break;
      } else if(cur_state == CisStateMachine::kStateEstablished) {
        ret = ISO_HCI_SUCCESS;
        break;
      } else if(cur_state == CisStateMachine::kStateDestroying) {
        ret = ISO_HCI_FAILED;
        break;
      }
      if (cis_created == false) {
        // queue it if there is pending create CIS
        if (cis_queue.size()) {
          // hand it over to the CIS module
          // check if the new request is already exists
          // as the head entry in the list
          CreateCisNode& head = cis_queue.front();
          if(head.cig_id == cig_id && head.cis_ids == cis_ids &&
             head.peer_bda == peer_bda) {
             if(cis->cis_sm.ProcessEvent(
                          IsoHciEvent::CIS_CREATE_REQ, &param)) {
               ret = ISO_HCI_IN_PROGRESS;
             } else {
               ret = ISO_HCI_FAILED;
               break;
             }
          } else {
            cis_queue.push_back(param);
          }
        } else {
          cis_queue.push_back(param);
          if(cis->cis_sm.ProcessEvent(IsoHciEvent::CIS_CREATE_REQ,
                                          &param)) {
            ret = ISO_HCI_IN_PROGRESS;
          } else {
            ret = ISO_HCI_FAILED;
            break;
          }
        }
        cis_created = true;
      } else {
        if(cis->cis_sm.ProcessEvent(IsoHciEvent::CIS_CREATE_REQ_DUMMY,
                                        &peer_bda)) {
          ret = ISO_HCI_IN_PROGRESS;
        } else {
          ret = ISO_HCI_FAILED;
          break;
        }
      }
    }
    return ret;
  }

  IsoHciStatus DisconnectCis(uint8_t cig_id, uint8_t cis_id,
                             uint8_t direction) override {
    LOG(INFO) <<__func__  << ": CIG Id = " << loghex(cig_id)
                          << ": CIS Id = " << loghex(cis_id);

    uint32_t cur_state;
    // check if the CIG exists
    CIG *cig = GetCig(cig_id);
    if (cig == nullptr) {
      return ISO_HCI_FAILED;
    }

    if(cig->cig_state != CigState::CREATED) {
      return ISO_HCI_FAILED;
    }

    // check if CIS ID mentioned is present as part of CIG
    CIS *cis = GetCis(cig_id, cis_id);
    if (cis == nullptr) {
      return ISO_HCI_FAILED;
    }

    if(cis->disc_direction & direction) {
       // remove the direction bit form disc direciton
       cis->disc_direction &= ~direction;
    }

    if(cis->disc_direction) return ISO_HCI_SUCCESS;

    // if all directions are voted off go for CIS disconneciton
    cur_state = cis->cis_sm.StateId();

    // check if CIS is not created or in progress
    if(cur_state == CisStateMachine::kStateReady) {
      return ISO_HCI_SUCCESS;
    } else if(cur_state == CisStateMachine::kStateEstablishing) {
      return ISO_HCI_FAILED;
    } else if(cur_state == CisStateMachine::kStateDestroying) {
      return ISO_HCI_IN_PROGRESS;
    }

    LOG(INFO) <<__func__  << " Request issued to CIS SM";
    // hand it over to the CIS module
    if(cis->cis_sm.ProcessEvent(
              IsoHciEvent::CIS_DISCONNECT_REQ, nullptr)) {
      return ISO_HCI_IN_PROGRESS;
    } else return ISO_HCI_FAILED;
  }

  IsoHciStatus SetupDataPath(uint8_t cig_id, uint8_t cis_id,
          uint8_t data_path_direction, uint8_t data_path_id)  override {
    LOG(INFO) <<__func__  << ": CIG Id = " << loghex(cig_id)
                          << ": CIS Id = " << loghex(cis_id);

    uint32_t cur_state;
    // check if the CIG exists
    CIG *cig = GetCig(cig_id);
    if (cig == nullptr) {
      return ISO_HCI_FAILED;
    }

    if(cig->cig_state != CigState::CREATED) {
      return ISO_HCI_FAILED;
    }

    // check if CIS ID mentioned is present as part of CIG
    CIS *cis = GetCis(cig_id, cis_id);
    if (cis == nullptr) {
      return ISO_HCI_FAILED;
    }

    cur_state = cis->cis_sm.StateId();

    // check if CIS is not created or in progress
    if(cur_state == CisStateMachine::kStateReady ||
       cur_state == CisStateMachine::kStateEstablishing ||
       cur_state == CisStateMachine::kStateDestroying) {
      return ISO_HCI_FAILED;
    } else if(cur_state == CisStateMachine::kStateEstablished) {
      // return success as it is already created
      return ISO_HCI_SUCCESS;
    }

    // hand it over to the CIS module
    tIsoSetUpDataPath data_path_info;
    data_path_info.data_path_direction = data_path_direction;
    data_path_info.data_path_id = data_path_id;

    if(cis->cis_sm.ProcessEvent(
        IsoHciEvent::SETUP_DATA_PATH_REQ, &data_path_info)) {
      return ISO_HCI_IN_PROGRESS;
    } else return ISO_HCI_FAILED;
  }

  IsoHciStatus RemoveDataPath(uint8_t cig_id, uint8_t cis_id,
                      uint8_t data_path_direction) override {
    LOG(INFO) <<__func__  << ": CIG Id = " << loghex(cig_id)
                          << ": CIS Id = " << loghex(cis_id);

    uint32_t cur_state;
    // check if the CIG exists
    CIG *cig = GetCig(cig_id);
    if (cig == nullptr) {
      return ISO_HCI_FAILED;
    }

    if(cig->cig_state != CigState::CREATED) {
      return ISO_HCI_FAILED;
    }

    // check if CIS ID mentioned is present as part of CIG
    CIS *cis = GetCis(cig_id, cis_id);
    if (cis == nullptr) {
      return ISO_HCI_FAILED;
    }

    cur_state = cis->cis_sm.StateId();

    // check if CIS is not created or in progress
    if(cur_state == CisStateMachine::kStateReady ||
       cur_state == CisStateMachine::kStateEstablishing ||
       cur_state == CisStateMachine::kStateDestroying ||
       cur_state == CisStateMachine::kStateEstablished) {
      return ISO_HCI_FAILED;
    }

    // hand it over to the CIS module
    if(cis->cis_sm.ProcessEvent(
           IsoHciEvent::REMOVE_DATA_PATH_REQ, &data_path_direction)) {
      return ISO_HCI_SUCCESS;
    } else return ISO_HCI_FAILED;
  }

  const char* GetEventName(uint32_t event) {
    switch (event) {
      CASE_RETURN_STR(CIG_CONFIGURED_EVT)
      CASE_RETURN_STR(CIS_STATUS_EVT)
      CASE_RETURN_STR(CIS_ESTABLISHED_EVT)
      CASE_RETURN_STR(CIS_DISCONNECTED_EVT)
      CASE_RETURN_STR(CIG_REMOVED_EVT)
      CASE_RETURN_STR(SETUP_DATA_PATH_DONE_EVT)
      CASE_RETURN_STR(REMOVE_DATA_PATH_DONE_EVT)
      default:
       return "Unknown Event";
    }
  }

  IsoHciStatus ProcessEvent (uint32_t event, void* p_data) {
    LOG(INFO) <<__func__ <<": Event = " << GetEventName(event);
    switch (event) {
      case CIG_CONFIGURED_EVT: {
        tBTM_BLE_SET_CIG_RET_PARAM *param =
                            (tBTM_BLE_SET_CIG_RET_PARAM *) p_data;
        LOG(INFO) <<__func__ <<": CIG Id = " << loghex(param->cig_id)
                  << ": status = " << loghex(param->status);

        auto it = cig_list.find(param->cig_id);
        if (it == cig_list.end()) {
          return ISO_HCI_FAILED;
        }

        if(!param->status) {
          uint8_t i = 0;
          CIG *cig = it->second;
          tIsoSetUpDataPath data_path_info;

          for (auto it = cig->cis_list.begin();
                    it != cig->cis_list.end(); it++) {
            CIS *cis = it->second;
            cis->cis_handle = *(param->conn_handle + i++);
            cis->cis_sm.Start();
            if(cis->direction & DIR_TO_AIR) {
              data_path_info.data_path_direction = DIR_TO_AIR;
              data_path_info.data_path_id = 0x01;
              cis->cis_sm.ProcessEvent(IsoHciEvent::SETUP_DATA_PATH_REQ,
                                        &data_path_info);
            }
            if(cis->direction & DIR_FROM_AIR) {
              data_path_info.data_path_direction = DIR_FROM_AIR;
              data_path_info.data_path_id = 0x01;
              cis->cis_sm.ProcessEvent(IsoHciEvent::SETUP_DATA_PATH_REQ,
                                        &data_path_info);
            }
          }
        } else {
          // delete CIG and CIS
          CIG *cig = it->second;
          cig->cig_state = CigState::IDLE;

          while (!cig->cis_list.empty()) {
            auto it = cig->cis_list.begin();
            CIS * cis = it->second;
            cig->cis_list.erase(it);
            delete cis;
          }
          callbacks->OnCigState(param->cig_id, CigState::IDLE);
          cig_list.erase(it);
          delete cig;
        }

      } break;
      case CIG_REMOVED_EVT: {
        tBTM_BLE_SET_CIG_REMOVE_PARAM *param =
                                (tBTM_BLE_SET_CIG_REMOVE_PARAM *) p_data;
        auto it = cig_list.find(param->cig_id);
        if (it == cig_list.end()) {
          return ISO_HCI_FAILED;
        } else {
          // delete CIG and CIS
          CIG *cig = it->second;
          while (!cig->cis_list.empty()) {
            auto it = cig->cis_list.begin();
            CIS * cis = it->second;
            cig->cis_list.erase(it);
            delete cis;
          }
          cig->cig_state = CigState::IDLE;
          cig_list.erase(it);
          callbacks->OnCigState(param->cig_id, CigState::IDLE);
          delete cig;
        }
      } break;
      case CIS_STATUS_EVT: {
        // clear the first entry from cis queue and send the next
        // CIS creation request queue it if there is pending create CIS
        CreateCisNode &head = cis_queue.front();
        for (auto i: head.cis_ids) {
          CIS *cis = GetCis(head.cig_id, i);
          if(cis) {
            cis->cis_sm.ProcessEvent(IsoHciEvent::CIS_STATUS_EVT, p_data);
          }
        }
      } break;
      case CIS_ESTABLISHED_EVT: {
        tBTM_BLE_CIS_ESTABLISHED_EVT_PARAM *param =
                       (tBTM_BLE_CIS_ESTABLISHED_EVT_PARAM *) p_data;
        LOG(INFO) << __func__  << ": CIS handle = "
                                  << loghex(param->connection_handle)
                                  << ": Status = " << loghex(param->status);
        CIS *cis = GetCis(param->connection_handle);
        if (cis == nullptr) {
          return ISO_HCI_FAILED;
        } else {
          cis->cis_sm.ProcessEvent(IsoHciEvent::CIS_ESTABLISHED_EVT, p_data);
        }
        bool cis_status = false;
        if (cis_queue.size()) {
          cis_queue.pop_front();
        }
        while(cis_queue.size() && !cis_status) {
          CreateCisNode &head = cis_queue.front();
          CIS *cis = GetCis(head.cig_id, head.cis_ids[0]);
          if(cis == nullptr ||
             cis->cis_sm.StateId() == CisStateMachine::kStateEstablished) {
            // remove the entry
            cis_queue.pop_front();
          } else if(cis) {
            IsoHciStatus hci_status =  CreateCis(head.cig_id, head.cis_ids,
                                                 head.peer_bda);
            if(hci_status == ISO_HCI_SUCCESS ||
               hci_status == ISO_HCI_IN_PROGRESS) {
              cis_status = true;
            } else {
              // remove the entry
              cis_queue.pop_front();
            }
          }
        }
      } break;
      case CIS_DISCONNECTED_EVT: {
        tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM *param =
                      (tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM *) p_data;
        CIS *cis = GetCis(param->cis_handle);
        if (cis == nullptr) {
          return ISO_HCI_FAILED;
        } else {
          cis->cis_sm.ProcessEvent(IsoHciEvent::CIS_DISCONNECTED_EVT, p_data);
        }
      } break;
      case SETUP_DATA_PATH_DONE_EVT: {
        tBTM_BLE_CIS_DATA_PATH_EVT_PARAM *param =
                   (tBTM_BLE_CIS_DATA_PATH_EVT_PARAM *) p_data;

        CIS *cis = GetCis(param->conn_handle);
        CIG *cig = nullptr;
        if (cis == nullptr) {
          return ISO_HCI_FAILED;
        } else {
          cis->cis_sm.ProcessEvent(IsoHciEvent::SETUP_DATA_PATH_DONE_EVT,
                                                  p_data);
        }
        uint8_t cig_id = cis->cig_id;

        auto it = cig_list.find(cig_id);
        if (it == cig_list.end()) {
          break;
        } else {
          // delete CIG and CIS
          cig = it->second;
        }

        uint8_t num_cis_is_ready = 0;
        for(auto it = cig->cis_list.begin(); it != cig->cis_list.end(); it++) {
          CIS *cis = it->second;
          if(cis->cis_sm.StateId() == CisStateMachine::kStateReady) {
            num_cis_is_ready++;
          }
        }

        // check if all setup data paths are completed
        if(num_cis_is_ready == cig->cis_list.size()) {
          cig->cig_state = CigState::CREATED;
          callbacks->OnCigState(cig_id, CigState::CREATED);
        }
      } break;
      case REMOVE_DATA_PATH_DONE_EVT: {
        tBTM_BLE_CIS_DATA_PATH_EVT_PARAM *param =
                   (tBTM_BLE_CIS_DATA_PATH_EVT_PARAM *) p_data;
        CIS *cis = GetCis(param->conn_handle);
        if (cis == nullptr) {
            return ISO_HCI_FAILED;
        } else {
          cis->cis_sm.ProcessEvent(IsoHciEvent::REMOVE_DATA_PATH_DONE_EVT,
                                                  p_data);
        }
      } break;
      default:
        break;
    }
    return ISO_HCI_SUCCESS;
  }

 private:
  std::map<uint8_t, CIG *> cig_list; // cig id to CIG structure
  std::list <CreateCisNode> cis_queue;
  CisInterfaceCallbacks *callbacks;
  // 0xFF will be passed for cis id in case search is for any of the
  // CIS part of that group
  bool IsCisActive(uint8_t cig_id, uint8_t cis_id)  {
    bool is_cis_active = false;
    auto it = cig_list.find(cig_id);
    if (it == cig_list.end()) {
      return is_cis_active;
    } else {
      CIG *cig = it->second;
      if(cis_id != 0XFF) {
        auto it = cig->cis_list.find(cis_id);
        if (it != cig->cis_list.end()) {
          CIS *cis = it->second;
          if(cis->cis_sm.StateId() == CisStateMachine::kStateEstablished) {
            is_cis_active = true;
          }
        }
      } else {
        for (auto it : cig->cis_list) {
          CIS *cis = it.second;
          if(cis->cis_sm.StateId() == CisStateMachine::kStateEstablished) {
            is_cis_active = true;
            break;
          }
        }
      }
    }
    return is_cis_active;
  }

  bool IsCigParamsSame(CIGConfig &cig_config,
                       std::vector<CISConfig> &cis_configs)  {
    CIG *cig = GetCig(cig_config.cig_id);
    bool is_params_same = true;
    uint8_t i = 0;

    if(cig == nullptr || (cis_configs.size() != cig->cig_config.cis_count)) {
      LOG(WARNING) << __func__  << ": Count is different ";
      return false;
    }

    if(cig->cig_config.cig_id != cig_config.cig_id ||
       cig->cig_config.cis_count != cig_config.cis_count ||
       cig->cig_config.packing !=  cig_config.packing ||
       cig->cig_config.framing != cig_config.framing ||
       cig->cig_config.max_tport_latency_m_to_s !=
                          cig_config.max_tport_latency_m_to_s ||
       cig->cig_config.max_tport_latency_s_to_m !=
                            cig_config.max_tport_latency_s_to_m ||
       cig->cig_config.sdu_interval_m_to_s[0] !=
                         cig_config.sdu_interval_m_to_s[0] ||
       cig->cig_config.sdu_interval_m_to_s[1] !=
                         cig_config.sdu_interval_m_to_s[1] ||
       cig->cig_config.sdu_interval_m_to_s[2] !=
                         cig_config.sdu_interval_m_to_s[2] ||
       cig->cig_config.sdu_interval_s_to_m[0] !=
                         cig_config.sdu_interval_s_to_m[0] ||
       cig->cig_config.sdu_interval_s_to_m[1] !=
                         cig_config.sdu_interval_s_to_m[1] ||
       cig->cig_config.sdu_interval_s_to_m[2] !=
                         cig_config.sdu_interval_s_to_m[2]) {
      LOG(WARNING) << __func__  << " cig params are different ";
      return false;
    }

    for (auto it = cig->cis_list.begin(); it != cig->cis_list.end();) {
      CIS *cis = it->second;
      if(cis->cis_config.cis_id  ==  cis_configs[i].cis_id &&
         cis->cis_config.max_sdu_m_to_s == cis_configs[i].max_sdu_m_to_s &&
         cis->cis_config.max_sdu_s_to_m == cis_configs[i].max_sdu_s_to_m &&
         cis->cis_config.phy_m_to_s == cis_configs[i].phy_m_to_s  &&
         cis->cis_config.phy_s_to_m == cis_configs[i].phy_s_to_m  &&
         cis->cis_config.rtn_m_to_s == cis_configs[i].rtn_m_to_s  &&
         cis->cis_config.rtn_s_to_m == cis_configs[i].rtn_s_to_m) {
        it++; i++;
      } else {
        is_params_same = false;
        break;
      }
    }
    LOG(WARNING) << __func__  << ": is_params_same : "
                              << loghex(is_params_same);
    return is_params_same;
  }

  bool IsCisExists(uint8_t cig_id, uint8_t cis_id)  {
    bool is_cis_exists = false;
    auto it = cig_list.find(cig_id);
    if (it != cig_list.end()) {
      CIG *cig = it->second;
      auto it = cig->cis_list.find(cis_id);
      if (it != cig->cis_list.end()) {
        is_cis_exists = true;
      }
    }
    return is_cis_exists;
  }

  CIS *GetCis(uint8_t cig_id, uint8_t cis_id)  {
    auto it = cig_list.find(cig_id);
    if (it != cig_list.end()) {
      CIG *cig = it->second;
      auto it = cig->cis_list.find(cis_id);
      if (it != cig->cis_list.end()) {
        return it->second;
      }
    }
    return nullptr;
  }

  CIG *GetCig(uint8_t cig_id)  {
    auto it = cig_list.find(cig_id);
    if (it != cig_list.end()) {
      return it->second;
    }
    return nullptr;
  }

  CIS *GetCis(uint16_t cis_handle)  {
    bool cis_found = false;
    CIS *cis = nullptr;
    for (auto it : cig_list) {
      CIG *cig = it.second;
      if(cig->cig_state == CigState::CREATED ||
         cig->cig_state == CigState::CREATING) {
        for (auto it : cig->cis_list) {
          cis = it.second;
          if(cis->cis_handle == cis_handle) {
            cis_found = true;
            break;
          }
        }
      }
      if(cis_found) return cis;
    }
    return nullptr;
  }

  // TODO to remove if there is no need
  bool IsCisEstablished(uint8_t cig_id, uint8_t cis_id) {
    bool is_cis_established = false;
    auto it = cig_list.find(cig_id);
    if (it == cig_list.end()) {
      return false;
    } else {
      CIG *cig = it->second;
      if(cis_id != 0XFF) {
        auto it = cig->cis_list.find(cis_id);
        if (it != cig->cis_list.end()) {
          CIS *cis = it->second;
          if(cis->cis_sm.StateId() == CisStateMachine::kStateEstablished) {
            is_cis_established = true;
          }
        }
      } else {
        for (auto it : cig->cis_list) {
          CIS *cis = it.second;
          if(cis->cis_sm.StateId() == CisStateMachine::kStateEstablished) {
            is_cis_established = true;
            break;
          }
        }
      }
    }
    return is_cis_established;
  }

  // TODO to remove if there is no need
  bool IsCisStreaming(uint8_t cig_id, uint8_t cis_id)  {
    bool is_cis_streaming = false;
    auto it = cig_list.find(cig_id);
    if (it == cig_list.end()) {
      return false;
    } else {
      CIG *cig = it->second;
      if(cis_id != 0XFF) {
        auto it = cig->cis_list.find(cis_id);
        if (it != cig->cis_list.end()) {
          CIS *cis = it->second;
          if(cis->cis_sm.StateId() == CisStateMachine::kStateEstablished) {
            is_cis_streaming = true;
          }
        }
      } else {
        for (auto it : cig->cis_list) {
          CIS *cis = it.second;
          if(cis->cis_sm.StateId() == CisStateMachine::kStateEstablished) {
            is_cis_streaming = true;
            break;
          }
        }
      }
    }
    return is_cis_streaming;
  }
};

void CisInterface::Initialize(
                   CisInterfaceCallbacks* callbacks) {
  if (instance) {
    LOG(ERROR) << "Already initialized!";
  } else {
    instance = new CisInterfaceImpl(callbacks);
  }
}

void CisInterface::CleanUp() {

  CisInterfaceImpl* ptr = instance;
  instance = nullptr;
  ptr->CleanUp();
  delete ptr;
}

CisInterface* CisInterface::Get() {
  CHECK(instance);
  return instance;
}

static void hci_cig_param_callback(tBTM_BLE_SET_CIG_RET_PARAM *param) {
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::CIG_CONFIGURED_EVT, param);
  }
}

static void hci_cig_param_test_callback(tBTM_BLE_SET_CIG_PARAM_TEST_RET *param) {
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::CIG_CONFIGURED_EVT, param);
  }
}

static void hci_cig_remove_param_callback(uint8_t status, uint8_t cig_id) {
  tBTM_BLE_SET_CIG_REMOVE_PARAM param = { .status = status,
                                          .cig_id = cig_id };
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::CIG_REMOVED_EVT, &param);
  }
}

static void hci_cis_create_status_callback ( uint8_t status) {
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::CIS_STATUS_EVT, &status);
  }
}

static void hci_cis_create_callback (
              tBTM_BLE_CIS_ESTABLISHED_EVT_PARAM *param) {
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::CIS_ESTABLISHED_EVT, param);
  }
}

static void hci_cis_setup_datapath_callback ( uint8_t status,
                            uint16_t conn_handle) {
  tBTM_BLE_CIS_DATA_PATH_EVT_PARAM param = { .status = status,
                                             .conn_handle = conn_handle };
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::SETUP_DATA_PATH_DONE_EVT, &param);
  }
}

static void hci_cis_disconnect_callback ( uint8_t status, uint16_t cis_handle,
                                          uint8_t reason) {
  tBTM_BLE_CIS_DISCONNECTED_EVT_PARAM param = { .status = status,
                                                .cis_handle = cis_handle,
                                                .reason = reason
                                             };
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::CIS_DISCONNECTED_EVT, &param);
  }
}

#if 0
static void hci_cis_remove_datapath_callback ( uint8_t status,
                                              uint16_t conn_handle) {
  tBTM_BLE_CIS_DATA_PATH_EVT_PARAM param = { .status = status,
                                             .conn_handle = conn_handle };
  if (instance) {
    instance->ProcessEvent(IsoHciEvent::REMOVE_DATA_PATH_DONE_EVT, &param);
  }
}
#endif

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
