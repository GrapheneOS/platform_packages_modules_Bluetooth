/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#pragma once

#include <string>
#include "connected_iso_api.h"
#include <hardware/bt_bap_uclient.h>
#include "bta_ascs_client_api.h"
#include "bta/bap/uclient_alarm.h"

namespace bluetooth {
namespace bap {
namespace ucast {

using bluetooth::bap::pacs::PacsClientCallbacks;
using bluetooth::bap::ascs::AscsClientCallbacks;
using bluetooth::bap::cis::CisInterfaceCallbacks;
using bluetooth::bap::ucast::StreamConnect;
using bluetooth::bap::ucast::StreamType;
using bluetooth::bap::alarm::BapAlarmCallbacks;

class UcastClient : public PacsClientCallbacks,
                    public AscsClientCallbacks,
                    public CisInterfaceCallbacks,
                    public BapAlarmCallbacks {
 public:
  virtual ~UcastClient() = default;

  static void Initialize(UcastClientCallbacks* callbacks);
  static void CleanUp();
  static UcastClient* Get();

  // APIs exposed to upper layer
  virtual void Connect(std::vector<RawAddress> address, bool is_direct,
                       std::vector<StreamConnect> streams) = 0;
  virtual void Disconnect(const RawAddress& address,
                       std::vector<StreamType> streams) = 0;
  virtual void Start(const RawAddress& address,
                     std::vector<StreamType> streams) = 0;
  virtual void Stop(const RawAddress& address,
                    std::vector<StreamType> streams) = 0;
  virtual void Reconfigure(const RawAddress& address,
                           std::vector<StreamReconfig> streams) = 0;
  virtual void UpdateStream(const RawAddress& address,
                           std::vector<StreamUpdate> update_streams) = 0;
};

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
