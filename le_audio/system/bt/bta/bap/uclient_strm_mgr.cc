/******************************************************************************
 *  Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *****************************************************************************/

#include "bta_bap_uclient_api.h"
#include "ucast_client_int.h"
#include "bt_trace.h"

namespace bluetooth {
namespace bap {
namespace ucast {

using namespace std;
using bluetooth::bap::ucast::UstreamManagers;
using bluetooth::bap::ucast::UstreamManager;

std::map<StreamState, int> state_map = {
   {StreamState::DISCONNECTED,  StreamTracker::kStateIdle} ,
   {StreamState::CONNECTING,    StreamTracker::kStateConnecting},
   {StreamState::CONNECTED,     StreamTracker::kStateConnected},
   {StreamState::STARTING,      StreamTracker::kStateStarting},
   {StreamState::STREAMING,     StreamTracker::kStateStreaming},
   {StreamState::STOPPING,      StreamTracker::kStateStopping},
   {StreamState::DISCONNECTING, StreamTracker::kStateDisconnecting},
   {StreamState::RECONFIGURING, StreamTracker::kStateReconfiguring}
};

StreamContext *StreamContexts::FindByType(StreamType stream_type) {
  auto iter = std::find_if(strm_contexts.begin(), strm_contexts.end(),
                       [&stream_type](StreamContext *context) {
                       return ((context->stream_type.type == stream_type.type)
                            && (context->stream_type.direction ==
                                stream_type.direction));
                       });

  if (iter == strm_contexts.end()) {
    return nullptr;
  } else {
    return (*iter);
  }
}

std::vector<StreamContext *> StreamContexts::FindByAseAttachedState(
                             uint16_t ase_id, StreamAttachedState state) {
  std::vector<StreamContext *> contexts_list;
  for(auto i = strm_contexts.begin(); i != strm_contexts.end();i++) {
    if(static_cast<uint8_t>((*i)->attached_state) &
       static_cast<uint8_t>(state)) {
      for(auto j = (*i)->stream_ids.begin(); j != (*i)->stream_ids.end();j++) {
        if(j->ase_id  == ase_id) {
          contexts_list.push_back(*i);
          break;
        }
      }
    }
  }
  return contexts_list;
}

StreamContext *StreamContexts::FindOrAddByType(StreamType stream_type) {
  auto iter = std::find_if(strm_contexts.begin(), strm_contexts.end(),
                       [&stream_type](StreamContext *context) {
                       return ((context->stream_type.type ==
                                stream_type.type) &&
                               (context->stream_type.direction ==
                                stream_type.direction));
                       });

  if (iter == strm_contexts.end()) {
    StreamContext *context = new StreamContext(stream_type);
    strm_contexts.push_back(context);
    return context;
  } else {
    return (*iter);
  }
}

void StreamContexts::Remove(StreamType stream_type) {
  for (auto it = strm_contexts.begin(); it != strm_contexts.end();) {
    if (((*it)->stream_type.type = stream_type.type) &&
        ((*it)->stream_type.direction = stream_type.direction)) {
      delete(*it);
      it = strm_contexts.erase(it);
    } else {
      it++;
    }
  }
}

bool StreamContexts::IsAseAttached(StreamType stream_type) {
  return false;

}

StreamContext* StreamContexts::FindByAseId(uint16_t ase_id) {
  auto iter = std::find_if(strm_contexts.begin(), strm_contexts.end(),
                       [&ase_id](StreamContext *context) {
                         auto it =  std::find_if(context->stream_ids.begin(),
                                                 context->stream_ids.end(),
                                            [&ase_id](StreamIdType id) {
                                            return (id.ase_id == ase_id);
                                            });
                         if (it != context->stream_ids.end()) {
                           return true;
                         } else return false;

                       });

  if (iter == strm_contexts.end()) {
    return nullptr;
  } else {
    return (*iter);
  }
}

StreamTracker* StreamTrackers::FindOrAddByType(int init_state_id,
                     UstreamManager *strm_mgr,
                     std::vector<StreamConnect> *connect_streams,
                     std::vector<StreamReconfig> *reconfig_streams,
                     std::vector<StreamType> *streams,
                     StreamControlType ops_type) {
  bool found = false;
  auto iter = stream_trackers.begin();
  while (iter != stream_trackers.end() && !found) {
    if((*iter)->GetControlType()  == ops_type) {
      if(ops_type == StreamControlType::Connect) {
        // compare connection streams
        std::vector<StreamConnect> *conn_strms = (*iter)->GetConnStreams();
        if(conn_strms->size() == connect_streams->size()) {
          uint8_t len = connect_streams->size();
          for (uint8_t i = 0; i < len ; i++) {
            StreamConnect src = conn_strms->at(i);
            StreamConnect dst = connect_streams->at(i);
            if((src.stream_type.type == dst.stream_type.type) &&
               (src.stream_type.direction == dst.stream_type.direction)) {
              LOG(WARNING) << __func__ << " StreamConnect found";
              found = true;
              break;
            }
          }
        }
      } else if(ops_type == StreamControlType::Reconfig) {
        // compare connection streams
        std::vector<StreamReconfig> *reconf_strms = (*iter)->GetReconfStreams();
        if(reconf_strms->size() == reconfig_streams->size()) {
          uint8_t len = reconfig_streams->size();
          for (uint8_t i = 0; i < len ; i++) {
            StreamReconfig src = reconf_strms->at(i);
            StreamReconfig dst = reconfig_streams->at(i);
            if((src.stream_type.type == dst.stream_type.type) &&
               (src.stream_type.direction == dst.stream_type.direction)) {
              LOG(WARNING) << __func__ << " StreamReconfig found";
              found = true;
              break;
            }
          }
        }
      } else if(ops_type != StreamControlType::None &&
                ops_type != StreamControlType::UpdateStream) {
        // compare connection streams
        std::vector<StreamType> *strms = (*iter)->GetStreams();
        if(strms->size() == streams->size()) {
          uint8_t len = streams->size();
          for (uint8_t i = 0; i < len ; i++) {
            StreamType src = strms->at(i);
            StreamType dst = streams->at(i);
            if((src.type == dst.type) &&
               (src.direction == dst.direction)) {
              LOG(WARNING) << __func__ << " StreamType found";
              found = true;
              break;
            }
          }
        }
      }
    }
    iter++;
  }

  if (iter == stream_trackers.end()) {
    StreamTracker *tracker =  new StreamTracker(init_state_id, strm_mgr,
                                   connect_streams, reconfig_streams,
                                   streams, ops_type);
    stream_trackers.push_back(tracker);
    return tracker;
  } else {
    return (*iter);
  }
}

bool StreamTrackers::Remove(std::vector<StreamType> streams,
            StreamControlType ops_type) {
  return true;
}

std::vector<StreamTracker *> StreamTrackers::GetTrackersByStates(
                                   std::vector<int> *state_ids) {
  vector<StreamTracker *> trackers;
  for (auto i = stream_trackers.begin();
                       i != stream_trackers.end();i++) {
    for (auto j = state_ids->begin(); j != state_ids->end();j++) {
      if((*i)->StateId()  == *j) {
        LOG(WARNING) << __func__ << " tracker found";
        trackers.push_back(*i);
      }
    }
  }
  return trackers;
}

void StreamTrackers::RemoveByStates(std::vector<int> state_ids) {
  for (auto i = stream_trackers.begin();
                       i != stream_trackers.end();) {
    bool found = false;
    for (auto j = state_ids.begin(); j != state_ids.end();j++) {
      if((*i)->StateId()  == *j) {
        LOG(WARNING) << __func__ << " tracker found";
        found = true;
        break;
      }
    }
    if(found) {
      delete(*i);
      i = stream_trackers.erase(i);
    } else {
      i++;
    }
  }
}


std::map<StreamTracker * , std::vector<StreamType> >
                           StreamTrackers::GetTrackersByType(
                           std::vector<StreamType> *streams) {
  std::vector<StreamType> req_types = *streams;
  std::vector<StreamType> all_types;
  std::map<StreamTracker * , std::vector<StreamType> > tracker_and_type_map;
  for (auto iter = stream_trackers.begin(); iter != stream_trackers.end();
                                            iter++) {
    all_types.clear();
    if((*iter)->GetControlType() == StreamControlType::Connect) {
      // compare connection streams
      std::vector<StreamConnect> *conn_strms = (*iter)->GetConnStreams();
      uint8_t len = conn_strms->size();
      for (uint8_t i = 0; i < len ; i++) {
        StreamConnect src = conn_strms->at(i);
        all_types.push_back(src.stream_type);
      }
    } else if((*iter)->GetControlType() == StreamControlType::Reconfig) {
      // compare connection streams
      std::vector<StreamReconfig> *reconf_strms = (*iter)->GetReconfStreams();
      uint8_t len = reconf_strms->size();
      for (uint8_t i = 0; i < len ; i++) {
        StreamReconfig src = reconf_strms->at(i);
        all_types.push_back(src.stream_type);
      }
    } else if((*iter)->GetControlType() == StreamControlType::UpdateStream) {
      // compare connection streams
      std::vector<StreamUpdate> *update_streams = (*iter)->GetMetaUpdateStreams();
      uint8_t len = update_streams->size();
      for (uint8_t i = 0; i < len ; i++) {
        StreamUpdate src = update_streams->at(i);
        all_types.push_back(src.stream_type);
      }
    } else if((*iter)->GetControlType() != StreamControlType::None) {
      // compare connection streams
      std::vector<StreamType> *strms = (*iter)->GetStreams();
      uint8_t len = strms->size();
      for (uint8_t i = 0; i < len ; i++) {
        StreamType src = strms->at(i);
        all_types.push_back(src);
      }
    }
    uint8_t count = 0;
    std::vector<StreamType> filtered_types;
    if(all_types.size() <= req_types.size()) {
      filtered_types.clear();
      for (auto it = all_types.begin(); it != all_types.end(); it++) {
        for (auto it_2 = req_types.begin(); it_2 != req_types.end();) {
          if (((it_2)->type == it->type) &&
              ((it_2)->direction == it->direction)) {
            filtered_types.push_back(*it_2);
            tracker_and_type_map[*iter] = filtered_types;
            it_2 = req_types.erase(it_2);
            count++;
          } else {
            it_2++;
          }
        }
      }
      if(all_types.size() != count) {
        LOG(ERROR) << __func__ << " invalid request";
      }
    } else {
      LOG(ERROR) << __func__ << " invalid request";
    }
  }
  if(req_types.size()) {
    tracker_and_type_map[nullptr] = req_types;
  }
  return tracker_and_type_map;
}


StreamTracker *StreamTrackers::FindByStreamsType(
                               std::vector<StreamType> *streams) {
  bool found = false;
  auto iter = stream_trackers.begin();
  while (iter != stream_trackers.end()) {
    if((*iter)->GetControlType() == StreamControlType::Connect) {
      // compare connection streams
      std::vector<StreamConnect> *conn_strms = (*iter)->GetConnStreams();
      if(conn_strms->size() == streams->size()) {
        uint8_t len = streams->size();
        for (uint8_t i = 0; i < len ; i++) {
          StreamConnect src = conn_strms->at(i);
          StreamType dst = streams->at(i);
          if((src.stream_type.type == dst.type) &&
             (src.stream_type.direction == dst.direction)) {
            LOG(WARNING) << __func__ << " StreamConnect found";
            found = true;
            break;
          }
        }
      }
    } else if((*iter)->GetControlType() == StreamControlType::Reconfig) {
      // compare connection streams
      std::vector<StreamReconfig> *reconf_strms = (*iter)->GetReconfStreams();
      if(reconf_strms->size() == streams->size()) {
        uint8_t len = streams->size();
        for (uint8_t i = 0; i < len ; i++) {
          StreamReconfig src = reconf_strms->at(i);
          StreamType dst = streams->at(i);
          if((src.stream_type.type == dst.type) &&
             (src.stream_type.direction == dst.direction)) {
            LOG(WARNING) << __func__ << " StreamReconfig found";
            found = true;
            break;
          }
        }
      }
    } else if((*iter)->GetControlType() == StreamControlType::UpdateStream) {
      // compare connection streams
      std::vector<StreamUpdate> *update_strms = (*iter)->GetMetaUpdateStreams();
      if(update_strms->size() == streams->size()) {
        uint8_t len = streams->size();
        for (uint8_t i = 0; i < len ; i++) {
          StreamUpdate src = update_strms->at(i);
          StreamType dst = streams->at(i);
          if((src.stream_type.type == dst.type) &&
             (src.stream_type.direction == dst.direction)) {
            LOG(WARNING) << __func__ << " StreamUpdate found";
            found = true;
            break;
          }
        }
      }
    } else if((*iter)->GetControlType() != StreamControlType::None) {
      // compare connection streams
      std::vector<StreamType> *strms = (*iter)->GetStreams();
      if(strms->size() == streams->size()) {
        uint8_t len = streams->size();
        for (uint8_t i = 0; i < len ; i++) {
          StreamType src = strms->at(i);
          StreamType dst = streams->at(i);
          if((src.type == dst.type) &&
             (src.direction == dst.direction)) {
            LOG(WARNING) << __func__ << " StreamType found";
            found = true;
            break;
          }
        }
      }
    }
    if(found) break;
    iter++;
  }

  if (iter == stream_trackers.end()) {
    return nullptr;
  } else {
    return (*iter);
  }
}

bool StreamTrackers::ChangeOpType( StreamType stream_type,
                   StreamControlType new_ops_type) {
  return true;
}

bool StreamTrackers::IsStreamTrackerValid(StreamTracker* tracker,
                                           std::vector<int> *state_ids) {
  vector<StreamTracker *> trackers_ = GetTrackersByStates(state_ids);
  LOG(WARNING) << __func__;
  if(trackers_.empty()) return false;

  for (auto it = trackers_.begin(); it != trackers_.end(); it++) {
    if ((*it) == tracker) {
      LOG(WARNING) << __func__ <<": Cached Tracker is valid";
      return true;
    }
  }
  return false;
}

bool UstreamManager::PushEventToTracker(uint32_t event, void *p_data,
                                        std::vector<int> *state_ids) {
  vector<StreamTracker *> trackers = stream_trackers.GetTrackersByStates(
                                                    state_ids);
  if(trackers.empty()) return false;

  for (auto it = trackers.begin(); it != trackers.end(); it++) {
    (*it)->ProcessEvent(event, p_data);
  }
  return true;
}


std::map<int , std::vector<StreamType> > UstreamManager::SplitContextOnState(
                             std::vector<StreamType> *streams) {
  StreamContexts *contexts = GetStreamContexts();
  std::vector<StreamType> req_types = *streams;
  std::map<int , std::vector<StreamType> > state_and_type_map;

  for (auto it = req_types.begin(); it != req_types.end();) {
    StreamContext *context = contexts->FindOrAddByType(*it);
    if (context) {
      int state = state_map[context->stream_state];
      state_and_type_map[state].push_back(*it);
      it = req_types.erase(it);
    } else {
      it++;
    }
  }
  return state_and_type_map;
}

void UstreamManager::ProcessEvent(uint32_t event, void *p_data) {
  LOG(WARNING) << __func__  <<": Event: " << GetEventName(event)
                            <<", bt_addr: " << GetAddress();

  std::vector<int> stable_state_ids = {
                                        StreamTracker::kStateConnected,
                                        StreamTracker::kStateStreaming,
                                        StreamTracker::kStateIdle
                                      };

  std::vector<int> transient_state_ids = {
                                           StreamTracker::kStateConnecting,
                                           StreamTracker::kStateReconfiguring,
                                           StreamTracker::kStateDisconnecting,
                                           StreamTracker::kStateStarting,
                                           StreamTracker::kStateStopping,
                                           StreamTracker::kStateUpdating,
                                         };
  StreamContexts *contexts = GetStreamContexts();

  switch (event) {

    case BAP_CONNECT_REQ_EVT: {
      BapConnect *evt_data = (BapConnect *) p_data;
      std::vector<StreamConnect> conn_streams = evt_data->streams;
      LOG(WARNING) << __func__  << ": size: " << conn_streams.size();

      for (auto it = conn_streams.begin(); it != conn_streams.end();) {
        StreamContext *context = contexts->FindOrAddByType(it->stream_type);
        if(context && context->stream_state != StreamState::DISCONNECTED) {
          LOG(WARNING) << __func__  << ": Stream is not in disconnected state";
          it = conn_streams.erase(it);
        } else {
          it++;
        }
      }

      if(!conn_streams.size()) {
        LOG(ERROR) << __func__  << ": All streams are not in disconnected state";
        break;
      }

      // validate the combinations media Tx or voice TX|RX
      StreamTracker *tracker = stream_trackers.FindOrAddByType(
                            StreamTracker::kStateIdle,
                            this, &conn_streams, nullptr, nullptr,
                            StreamControlType::Connect);

      if(tracker) {
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      }
    } break;

    case BAP_DISCONNECT_REQ_EVT: {
      BapDisconnect *evt_data = (BapDisconnect *) p_data;
      std::vector<StreamType> disc_streams = evt_data->streams;
      BapDisconnect int_evt_data;

      for (auto it = disc_streams.begin(); it != disc_streams.end();) {
        StreamContext *context = contexts->FindOrAddByType(*it);
        if(!context || context->stream_state == StreamState::DISCONNECTED) {
          LOG(WARNING) << __func__  << " Stream is already disconnected";
          it = disc_streams.erase(it);
        } else {
          it++;
        }
      }

      if(!disc_streams.size()) {
        LOG(ERROR) << __func__  << " All streams are already disconnected";
        break;
      }

      LOG(WARNING) << __func__  << " disc streams size " << disc_streams.size();

      // validate the combinations media Tx or voice TX|RX
      std::map<StreamTracker * , std::vector<StreamType> >
         tracker_and_type_list =
                    stream_trackers.GetTrackersByType(&disc_streams);


      // check if all streams disconnection or subset of streams
      // create the new tracker
      for (auto itr = tracker_and_type_list.begin();
                itr != tracker_and_type_list.end(); itr++) {
        if(itr->first == nullptr) {
          std::map<int , std::vector<StreamType> >
             list = SplitContextOnState(&itr->second);
          for (auto itr_2 = list.begin(); itr_2 != list.end(); itr_2++) {
            StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                itr_2->first,
                                this, nullptr, nullptr, &itr_2->second,
                                StreamControlType::Disconnect);
            LOG(ERROR) << __func__ << " new tracker start ";
            tracker->Start();
            int_evt_data.streams = itr_2->second;
            tracker->ProcessEvent(event, &int_evt_data);
          }
        } else {
          LOG(ERROR) << __func__ << " existing tracker start ";
          StreamTracker *tracker = itr->first;
          int_evt_data.streams = itr->second;
          tracker->ProcessEvent(event, &int_evt_data);
        }
      }
    } break;

    case BAP_START_REQ_EVT: {
      BapStart *evt_data = (BapStart *) p_data;
      std::vector<StreamType> start_streams = evt_data->streams;
      LOG(WARNING) << __func__ << " start streams size " << start_streams.size();

      for (auto it = start_streams.begin(); it != start_streams.end();) {
        StreamContext *context = contexts->FindOrAddByType(*it);
        if(!context || context->stream_state != StreamState::CONNECTED) {
          LOG(WARNING) << __func__  << " Stream is not in connected state";
          it = start_streams.erase(it);
        } else {
          it++;
        }
      }

      if(!start_streams.size()) {
        LOG(WARNING) << __func__  << " Not eligible for stream start";
        break;
      }

      // validate the combinations media Tx or voice TX|RX
      StreamTracker *tracker = stream_trackers.FindByStreamsType(
                                                      &start_streams);
      // create new tracker
      if(tracker == nullptr) {
        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                      StreamTracker::kStateConnected,
                                      this, nullptr, nullptr, &start_streams,
                                      StreamControlType::Start);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      } else {
        tracker->ProcessEvent(event, p_data);
      }
    } break;

    case BAP_STOP_REQ_EVT: {
      BapStop *evt_data = (BapStop *) p_data;
      std::vector<StreamType> stop_streams = evt_data->streams;
      LOG(WARNING) << __func__  << " stop streams size " << stop_streams.size();

      for (auto it = stop_streams.begin(); it != stop_streams.end();) {
        StreamContext *context = contexts->FindOrAddByType(*it);
        if(!context || (context->stream_state != StreamState::STREAMING &&
                       context->stream_state != StreamState::STARTING)) {
          LOG(WARNING) << __func__  << " Stream is not in streaming state";
          it = stop_streams.erase(it);
        } else {
          it++;
        }
      }

      if(!stop_streams.size()) {
        LOG(WARNING) << __func__  << " Not eligible for stream stop";
        break;
      }

      StreamTracker *tracker = stream_trackers.FindByStreamsType(
                                                      &stop_streams);
      // create the new tracker
      if(tracker == nullptr) {
        // validate the combinations media Tx or voice TX|RX
        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                              StreamTracker::kStateStreaming,
                              this, nullptr, nullptr, &stop_streams,
                              StreamControlType::Stop);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      } else {
        tracker->ProcessEvent(event, p_data);
      }
    } break;

    case BAP_STREAM_UPDATE_REQ_EVT: {
      BapStreamUpdate *evt_data = (BapStreamUpdate *) p_data;
      std::vector<StreamUpdate> update_streams = evt_data->update_streams;
      std::vector<StreamType> streams;

      for (auto it = update_streams.begin(); it != update_streams.end();) {
        StreamContext *context = contexts->FindOrAddByType(it->stream_type);
        if(!context || (context->stream_state != StreamState::STREAMING &&
                        context->stream_state != StreamState::STARTING)) {
          LOG(WARNING) << __func__  << " Stream is not in proper state";
          it = update_streams.erase(it);
        } else {
          it++;
        }
      }

      if(!update_streams.size()) {
        LOG(WARNING) << __func__  << " All streams are not in proper state";
        break;
      }

      for (auto it = update_streams.begin();
                           it != update_streams.end(); it++) {
        StreamType type = it->stream_type;
        streams.push_back(type);
      }

      LOG(WARNING) << __func__  << " update streams size " << streams.size();

      StreamTracker *tracker = stream_trackers.FindByStreamsType(
                                                  &streams);
      // create the new tracker
      if(tracker == nullptr) {
        // validate the combinations media Tx or voice TX|RX
        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                              StreamTracker::kStateStreaming,
                              this, nullptr, nullptr, nullptr,
                              StreamControlType::UpdateStream);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      } else {
        tracker->ProcessEvent(event, p_data);
      }
    } break;

    case BAP_RECONFIG_REQ_EVT: {
      BapReconfig *evt_data = (BapReconfig *) p_data;
      std::vector<StreamReconfig> reconf_streams = evt_data->streams;
      std::vector<StreamType> streams;

      for (auto it = reconf_streams.begin(); it != reconf_streams.end();) {
        StreamContext *context = contexts->FindOrAddByType(it->stream_type);
        if(!context || context->stream_state != StreamState::CONNECTED) {
          LOG(WARNING) << __func__  << " Stream is not in Connected state";
          it = reconf_streams.erase(it);
        } else {
          it++;
        }
      }

      if(!reconf_streams.size()) {
        LOG(WARNING) << __func__  << " All streams are not connected";
        break;
      }

      for (auto it = reconf_streams.begin();
                           it != reconf_streams.end(); it++) {
        StreamType type = it->stream_type;
        streams.push_back(type);
      }

      LOG(WARNING) << __func__  << " reconf streams size " << streams.size();

      StreamTracker *tracker = stream_trackers.FindByStreamsType(
                                                  &streams);
      // create the new tracker
      if(tracker == nullptr) {
        // validate the combinations media Tx or voice TX|RX
        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                              StreamTracker::kStateConnected,
                              this, nullptr, &reconf_streams, nullptr,
                              StreamControlType::Reconfig);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      } else {
        tracker->ProcessEvent(event, p_data);
      }
    } break;

    case PACS_CONNECTION_STATE_EVT: {
      PacsConnectionState *pacs_state =  (PacsConnectionState *) p_data;
      UpdatePacsState(pacs_state->state);
      int state = StreamTracker::kStateIdle;
      if (pacs_state->state != ConnectionState::DISCONNECTED) {
        if(PushEventToTracker(event, p_data, &transient_state_ids)) {
          break;
        } else {

          std::vector<StreamContext *> *context_list = contexts->GetAllContexts();
          std::vector<StreamType> streams;

          for (auto it = context_list->begin(); it != context_list->end(); it++) {
             if((*it)->stream_state != StreamState::DISCONNECTED) {
              streams.push_back((*it)->stream_type);
              state = state_map[(*it)->stream_state];
            }
          }

          StreamTracker *tracker = stream_trackers.FindByStreamsType(
                                                          &streams);
          // create the new tracker
          if(tracker == nullptr) {
            // validate the combinations media Tx or voice TX|RX
            StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                  state,
                                  this, nullptr, nullptr, &streams,
                                  StreamControlType::Disconnect);
            tracker->Start();
            tracker->ProcessEvent(event, p_data);
          } else {
            tracker->ProcessEvent(event, p_data);
          }
        }
      } else {

        std::vector<StreamContext *> *context_list = contexts->GetAllContexts();
        std::vector<StreamType> disc_streams;

        for (auto it = context_list->begin(); it != context_list->end(); it++) {
           if((*it)->stream_state != StreamState::DISCONNECTED) {
            disc_streams.push_back((*it)->stream_type);
          }
        }

        LOG(WARNING) << __func__  << ": size: " << disc_streams.size();

        // validate the combinations media Tx or voice TX|RX
        std::map<StreamTracker * , std::vector<StreamType> >
           tracker_and_type_list =
                      stream_trackers.GetTrackersByType(&disc_streams);

        // check if all streams disconnection or subset of streams
        // create the new tracker
        for (auto itr = tracker_and_type_list.begin();
                  itr != tracker_and_type_list.end(); itr++) {
          if(itr->first == nullptr) {
            std::map<int , std::vector<StreamType> >
               list = SplitContextOnState(&itr->second);
            for (auto itr_2 = list.begin(); itr_2 != list.end(); itr_2++) {
              StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                  itr_2->first,
                                  this, nullptr, nullptr, &itr_2->second,
                                  StreamControlType::Disconnect);
              LOG(ERROR) << __func__ << " new tracker start ";
              tracker->Start();
              tracker->ProcessEvent(event, p_data);
            }
          } else {
            LOG(ERROR) << __func__ << " existing tracker start ";
            StreamTracker *tracker = itr->first;
            tracker->ProcessEvent(event, p_data);
          }
        }
      }
    } break;

    case PACS_AUDIO_CONTEXT_RES_EVT: {
      // update the same event to upper layers also
      PacsAvailableContexts *contexts = (PacsAvailableContexts *) p_data;
      ucl_callbacks->OnStreamAvailable(
                          address,
                          (contexts->available_contexts >> 16),
                          (contexts->available_contexts & 0xFFFF));
      std::vector<int> state_ids = { StreamTracker::kStateStarting,
                                     StreamTracker::kStateUpdating};
      PushEventToTracker(event, p_data, &state_ids);
    } break;

    case PACS_DISCOVERY_RES_EVT:
    case ASCS_DISCOVERY_RES_EVT: {
      // validate the combinations media Tx or voice TX|RX
      std::vector<int> state_ids = { StreamTracker::kStateConnecting,
                                     StreamTracker::kStateReconfiguring };
      PushEventToTracker(event, p_data, &state_ids);
    } break;

    case ASCS_CONNECTION_STATE_EVT: {
      AscsConnectionState *ascs_state =  (AscsConnectionState *) p_data;
      UpdateAscsState(ascs_state->state);
      PushEventToTracker(event, p_data, &transient_state_ids);
    } break;

    case ASCS_ASE_OP_FAILED_EVT: {
      if(PushEventToTracker(event, p_data, &transient_state_ids)) {
        break;
      }
    } break;

    case ASCS_ASE_STATE_EVT: {
      if(PushEventToTracker(event, p_data, &transient_state_ids)) {
        break;
      }
      // create strm trackers based on ase ID and push it to
      // newly created tracker.
      // TODO Handle Releasing , disabling, codec configured states
      // initiated from remote device

      AscsState *ascs =  ((AscsState *) p_data);
      UcastAudioStream *audio_stream = nullptr;
      // find out the stream for the given ase id
      uint8_t ase_id = ascs->ase_params.ase_id;
      std::vector<StreamType> streams;
      int state = StreamTracker::kStateIdle;

      UcastAudioStreams *audio_strms = GetAudioStreams();
      audio_stream = audio_strms->FindByAseId(ase_id);
      if(audio_stream) {
        StreamType type = {
                           .type = audio_stream->audio_context,
                           .direction = audio_stream->direction
                          };
        streams.push_back(type);
        state = audio_stream->overall_state;
      }

      LOG(WARNING) << __func__  << " size " << streams.size();

      if (ascs->ase_params.ase_state == ascs::ASE_STATE_RELEASING) {

        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                 state,
                                 this, nullptr, nullptr, &streams,
                                 StreamControlType::Disconnect);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      } else if (ascs->ase_params.ase_state == ascs::ASE_STATE_DISABLING) {

        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                 state,
                                 this, nullptr, nullptr, &streams,
                                 StreamControlType::Stop);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      } else if (ascs->ase_params.ase_state ==
                                      ascs::ASE_STATE_CODEC_CONFIGURED) {
        // TODO reconfig from remote device
      }  else if (ascs->ase_params.ase_state ==
                                      ascs::ASE_STATE_QOS_CONFIGURED) {
        // this can happen when CIS is lost and detected on remote side
        // first so it will immediately transition to QOS configured.
        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                 state,
                                 this, nullptr, nullptr, &streams,
                                 StreamControlType::Stop);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      }
    } break;

    case CIS_GROUP_STATE_EVT: {
      // validate the combinations media Tx or voice TX|RX
      std::vector<int> state_ids = { StreamTracker::kStateStarting,
                                     StreamTracker::kStateStopping,
                                     StreamTracker::kStateDisconnecting };
      PushEventToTracker(event, p_data, &state_ids);
    } break;

    case CIS_STATE_EVT: {
      CisStreamState *data = (CisStreamState *) p_data;

      if(PushEventToTracker(event, p_data, &transient_state_ids)) {
        break;
      }

      // find out the stream for the given ase id
      int state = StreamTracker::kStateIdle;
      std::vector<StreamType> streams;

      UcastAudioStreams *audio_strms = GetAudioStreams();
      std::vector<UcastAudioStream *> cis_streams = audio_strms->FindByCisId(
                                                 data->cig_id, data->cis_id);


      if(cis_streams.empty()) break;

      for (auto it = cis_streams.begin(); it != cis_streams.end(); it++) {
        StreamType type = {
                           .type = (*it)->audio_context,
                           .direction = (*it)->direction
                          };
        streams.push_back(type);
        state = (*it)->overall_state;
      }

      LOG(WARNING) << __func__  << " size " << streams.size();

      // create strm trackers based on CIS ID and push it to
      // newly created tracker.
      // CIS disconnected
      if(data->state == CisState::READY) {
        StreamTracker *tracker = stream_trackers.FindOrAddByType(
                                 state,
                                 this, nullptr, nullptr, &streams,
                                 StreamControlType::Stop);
        tracker->Start();
        tracker->ProcessEvent(event, p_data);
      }
    } break;

    case BAP_TIME_OUT_EVT: {
      BapTimeout* evt_data = (BapTimeout*) p_data;

      //Get Cached tracker and check if it is valid
      if (stream_trackers.IsStreamTrackerValid(evt_data->tracker,
                                                &transient_state_ids)) {
        PushEventToTracker(event, p_data, &transient_state_ids);
      } else {
        LOG(WARNING) << __func__  << ": Tracker is not valid ";
      }
    } break;

    default:
      break;
  }

  // look for all stream trackers which are moved to stable states
  // like connected, streaming, idle, and destroy those trackers here
  stream_trackers.RemoveByStates(stable_state_ids);
}

// TODO to introduce a queue for serializing the Audio stream establishment
UstreamManager* UstreamManagers::FindByAddress(const RawAddress& address) {
  auto iter = std::find_if(strm_mgrs.begin(), strm_mgrs.end(),
                       [&address](UstreamManager *strm_mgr) {
                          return strm_mgr->GetAddress() == address;
                       });

  return (iter == strm_mgrs.end()) ? nullptr : (*iter);
}

UstreamManager* UstreamManagers::FindorAddByAddress(const RawAddress& address,
                        PacsClient *pacs_client, uint16_t pacs_client_id,
                        AscsClient *ascs_client, CisInterface *cis_intf,
                        UcastClientCallbacks* ucl_callbacks,
                        BapAlarm *bap_alarm)  {
  auto iter = std::find_if(strm_mgrs.begin(), strm_mgrs.end(),
                       [&address](UstreamManager *strm_mgr) {
                          return strm_mgr->GetAddress() == address;
                       });

  if (iter == strm_mgrs.end()) {
    UstreamManager *strm_mgr = new UstreamManager(address, pacs_client,
                                   pacs_client_id, ascs_client, cis_intf,
                                   ucl_callbacks, bap_alarm);
    strm_mgrs.push_back(strm_mgr);
    return strm_mgr;
  } else {
    return (*iter);
  }
}

std::vector<UstreamManager *> *UstreamManagers::GetAllManagers() {
  return &strm_mgrs;

}

void UstreamManagers::Remove(const RawAddress& address) {
  for (auto it = strm_mgrs.begin(); it != strm_mgrs.end();) {
    if ((*it)->GetAddress() == address) {
      delete(*it);
      it = strm_mgrs.erase(it);
    } else {
      it++;
    }
  }
}

}  // namespace ucast
}  // namespace bap
}  // namespace bluetooth
