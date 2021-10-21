/******************************************************************************
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 ******************************************************************************/

#include <hardware/bluetooth.h>
#include "bt_trace.h"
#include "btif_acm_source.h"
#include "btif_ahim.h"
#include "btif_acm.h"
#include "osi/include/thread.h"

extern thread_t* get_worker_thread();

#if AHIM_ENABLED


void btif_acm_process_request(tA2DP_CTRL_CMD cmd)
{
  tA2DP_CTRL_ACK status = A2DP_CTRL_ACK_FAILURE;
  // update pending command
  btif_ahim_update_pending_command(cmd, AUDIO_GROUP_MGR);

  BTIF_TRACE_IMP("%s: cmd %u", __func__, cmd);

  switch (cmd) {
    case A2DP_CTRL_CMD_START:
    {
      if (btif_acm_is_call_active()) {
        BTIF_TRACE_IMP("%s: call active, return incall_failure", __func__);
        status = A2DP_CTRL_ACK_INCALL_FAILURE;
      } else {
        // ACM is in right state
        status = A2DP_CTRL_ACK_PENDING;
        btif_acm_stream_start();
      }
      btif_ahim_ack_stream_started(status, AUDIO_GROUP_MGR);
      break;
    }

    case A2DP_CTRL_CMD_SUSPEND:
    {
      if (btif_acm_is_call_active()) {
        BTIF_TRACE_IMP("%s: call active, return success", __func__);
        status = A2DP_CTRL_ACK_SUCCESS;
      } else {
        status = A2DP_CTRL_ACK_PENDING;
        btif_acm_stream_suspend();
      }
      btif_ahim_ack_stream_suspended(status, AUDIO_GROUP_MGR);
      break;
    }

    case A2DP_CTRL_CMD_STOP:
    {
      status = A2DP_CTRL_ACK_SUCCESS;
      if (btif_acm_is_call_active()) {
        BTIF_TRACE_IMP("%s: call active, return success", __func__);
      } else {
        btif_acm_stream_stop();
      }
      btif_ahim_ack_stream_suspended(status, AUDIO_GROUP_MGR);
      break;
    }
    default:
      APPL_TRACE_ERROR("%s: unsupported command %d", __func__, cmd);
      break;
  }
}


void btif_acm_handle_event(uint16_t event, char* p_param)
{

  switch(event) {
    case BTIF_ACM_PROCESS_HIDL_REQ_EVT:
      btif_acm_process_request((tA2DP_CTRL_CMD ) *p_param);
      break;
    default:
      BTIF_TRACE_IMP("%s: unhandled event", __func__);
      break;
  }
}

void process_hidl_req_acm(tA2DP_CTRL_CMD cmd)
{
   btif_transfer_context(btif_acm_handle_event, BTIF_ACM_PROCESS_HIDL_REQ_EVT, (char*)&cmd, sizeof(cmd), NULL);
}

static btif_ahim_client_callbacks_t sAhimAcmCallbacks = {
  1, // mode
  process_hidl_req_acm,
  btif_acm_get_sample_rate,
  btif_acm_get_ch_mode,
  btif_acm_get_bitrate,
  btif_acm_get_octets,
  btif_acm_get_framelength,
  btif_acm_get_ch_count,
  nullptr,
  btif_acm_get_current_active_profile,
  btif_acm_is_codec_type_lc3q,
  btif_acm_lc3q_ver
};

void btif_register_cb()
{
  reg_cb_with_ahim(AUDIO_GROUP_MGR, &sAhimAcmCallbacks);
}

bt_status_t btif_acm_source_setup_codec() {
  APPL_TRACE_EVENT("%s", __func__);

  bt_status_t status = BT_STATUS_FAIL;


  APPL_TRACE_EVENT("%s ## setup_codec ##", __func__);
  btif_ahim_setup_codec(AUDIO_GROUP_MGR);

  // TODO: check the status
  return status;
}

bool btif_acm_source_start_session(const RawAddress& peer_address) {
  bt_status_t status = BT_STATUS_FAIL;
  APPL_TRACE_DEBUG("%s: starting session for BD addr %s",__func__,
        peer_address.ToString().c_str());

  // initialize hal.
  btif_ahim_init_hal(get_worker_thread(), AUDIO_GROUP_MGR);

  status = btif_acm_source_setup_codec();

  btif_ahim_start_session();

  return true;
}

bool btif_acm_source_end_session(const RawAddress& peer_address) {
  APPL_TRACE_DEBUG("%s: starting session for BD addr %s",__func__,
        peer_address.ToString().c_str());

  btif_ahim_end_session();

  return true;
}

bool btif_acm_source_restart_session(const RawAddress& old_peer_address,
                                      const RawAddress& new_peer_address) {
  bool is_streaming = btif_ahim_is_streaming();
  SessionType session_type = btif_ahim_get_session_type();

  APPL_TRACE_IMP("%s: old_peer_address=%s, new_peer_address=%s, is_streaming=%d ",
      __func__, old_peer_address.ToString().c_str(),
    new_peer_address.ToString().c_str(), is_streaming);

   // TODO: do we need to check for new empty address
  //CHECK(!new_peer_address.IsEmpty());

  // If the old active peer was valid or if session is not
  // unknown, end the old session.
  if (!old_peer_address.IsEmpty() ||
    session_type != SessionType::UNKNOWN) {
    btif_acm_source_end_session(old_peer_address);
  }

  btif_acm_source_start_session(new_peer_address);

  return true;
}

bool btif_acm_update_sink_latency_change(uint16_t sink_latency) {
  APPL_TRACE_DEBUG("%s: update_sink_latency %d for active session ",__func__,
                                sink_latency);

  btif_ahim_set_remote_delay(sink_latency);

  return true;
}

void btif_acm_source_command_ack(tA2DP_CTRL_CMD cmd, tA2DP_CTRL_ACK status) {
  switch (cmd) {
    case A2DP_CTRL_CMD_START:
      btif_ahim_ack_stream_started(status, AUDIO_GROUP_MGR);
      break;
    case A2DP_CTRL_CMD_SUSPEND:
    case A2DP_CTRL_CMD_STOP:
      btif_ahim_ack_stream_suspended(status, AUDIO_GROUP_MGR);
      break;
    default:
      break;
  }
}

void btif_acm_source_on_stopped(tA2DP_CTRL_ACK status) {
  APPL_TRACE_EVENT("%s: status %u", __func__, status);

  btif_ahim_ack_stream_suspended(status, AUDIO_GROUP_MGR);

  btif_ahim_reset_pending_command(AUDIO_GROUP_MGR);
}

void btif_acm_source_on_suspended(tA2DP_CTRL_ACK status) {
  APPL_TRACE_EVENT("%s: status %u", __func__, status);

  btif_ahim_ack_stream_suspended(status, AUDIO_GROUP_MGR);

  btif_ahim_reset_pending_command(AUDIO_GROUP_MGR);
}

bool btif_acm_on_started(tA2DP_CTRL_ACK status) {
  APPL_TRACE_EVENT("%s: status %u", __func__, status);
  bool retval = false;

  if(0/* TODO: check if call is in progress*/) {
    APPL_TRACE_WARNING("%s: call in progress, sending failure", __func__);
    btif_ahim_ack_stream_started(A2DP_CTRL_ACK_INCALL_FAILURE, AUDIO_GROUP_MGR);
  }
  else {
    btif_ahim_ack_stream_started(status, AUDIO_GROUP_MGR);
    retval = true;
  }

  btif_ahim_reset_pending_command(AUDIO_GROUP_MGR);
  return retval;
}


#endif // AHIM_ENABLED
