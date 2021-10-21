/******************************************************************************
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 *
 ******************************************************************************/

#include <iostream>
#include <string.h>
#include <vector>
#include <stack>
#include <log/log.h>

#include "bt_types.h"
#include "bt_trace.h"

#include <libxml/parser.h>
#include "btif_bap_codec_utils.h"
#include "btif_vmcp.h"
#include "btif_api.h"
#include <bluetooth/uuid.h>

using namespace std;

unsigned long voice_codec_count, media_codec_count, qos_settings_count;

// holds the value of current profile being parsed from xml
uint8_t current_profile = 1;

std::vector<codec_config>vmcp_voice_codec;
std::vector<codec_config>vmcp_media_codec;
std::vector<qos_config>vmcp_qos_low_lat_voice;
std::vector<qos_config>vmcp_qos_low_lat_media;
std::vector<qos_config>vmcp_qos_high_rel_media;

std::vector<codec_config>bap_voice_codec;
std::vector<codec_config>bap_media_codec;
std::vector<qos_config>bap_qos_low_lat_voice;
std::vector<qos_config>bap_qos_low_lat_media;
std::vector<qos_config>bap_qos_high_rel_media;

std::vector<codec_config>gcp_voice_codec;
std::vector<codec_config>gcp_media_codec;
std::vector<qos_config>gcp_qos_low_lat_voice;
std::vector<qos_config>gcp_qos_low_lat_media;

std::vector<codec_config>wmcp_media_codec;
std::vector<qos_config>wmcp_qos_high_rel_media;

vector<CodecConfig> get_all_codec_configs(uint8_t profile, uint8_t context)
{
  vector<CodecConfig> ret_config;
  CodecConfig temp_config;
  vector<codec_config> *vptr = NULL;

  if (profile == VMCP) {
    if (context == VOICE_CONTEXT) {
      vptr = &vmcp_voice_codec;
    }
    else if(context == MEDIA_CONTEXT) {
      vptr = &vmcp_media_codec;
    } else {
      // if no valid context is provided, use voice context
      vptr = &vmcp_voice_codec;
    }
  } else if (profile == BAP) {
    if (context == VOICE_CONTEXT) {
      vptr = &bap_voice_codec;
    }
    else if(context == MEDIA_CONTEXT) {
      vptr = &bap_media_codec;
    } else {
      // if no valid context is provided, use voice context
      vptr = &bap_voice_codec;
    }
  } else if (profile == GCP) {
    if (context == VOICE_CONTEXT) {
      vptr = &gcp_voice_codec;
    }
    else if(context == MEDIA_CONTEXT) {
      vptr = &gcp_media_codec;
    } else {
      // if no valid context is provided, use media context
      vptr = &gcp_media_codec;
    }
  } else if (profile == WMCP) {
    if(context == MEDIA_CONTEXT) {
      vptr = &wmcp_media_codec;
    } else {
      // if no valid context is provided, use media context
      vptr = &wmcp_media_codec;
    }
  }

  if (!vptr){
     return { };
  }

  for (uint8_t i = 0; i < (uint8_t)vptr->size(); i++) {
    memset(&temp_config, 0, sizeof(CodecConfig));

    temp_config.codec_type = CodecIndex::CODEC_INDEX_SOURCE_LC3;

    switch (vptr->at(i).freq_in_hz)
    {
      case SAMPLE_RATE_8000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_8000;
        break;
      case SAMPLE_RATE_16000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_16000;
        break;
      case SAMPLE_RATE_24000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_24000;
        break;
      case SAMPLE_RATE_32000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_32000;
        break;
      case SAMPLE_RATE_44100:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_44100;
        break;
      case SAMPLE_RATE_48000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_48000;
        break;
      default:
        break;
    }

    if (vptr->at(i).frame_dur_msecs == FRM_DURATION_7_5_MS)
      UpdateFrameDuration(&temp_config, static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_7_5));
    else if (vptr->at(i).frame_dur_msecs == FRM_DURATION_10_MS)
      UpdateFrameDuration(&temp_config, static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));

    UpdateOctsPerFrame(&temp_config, vptr->at(i).oct_per_codec_frm);

    ret_config.push_back(temp_config);
  }

  return ret_config;
}

vector<CodecConfig> get_preferred_codec_configs(uint8_t profile, uint8_t context)
{
  vector<CodecConfig> ret_config;
  CodecConfig temp_config;
  vector<codec_config> *vptr = NULL;

  if (profile == VMCP) {
    if (context == VOICE_CONTEXT) {
      vptr = &vmcp_voice_codec;
    }
    else if(context == MEDIA_CONTEXT) {
      vptr = &vmcp_media_codec;
    } else {
      // if no valid context is provided, use voice context
      vptr = &vmcp_voice_codec;
    }
  } else if (profile == BAP) {
    if (context == VOICE_CONTEXT) {
      vptr = &bap_voice_codec;
    }
    else if(context == MEDIA_CONTEXT) {
      vptr = &bap_media_codec;
    } else {
      // if no valid context is provided, use voice context
      vptr = &bap_voice_codec;
    }
  } else if (profile == GCP) {
    if (context == VOICE_CONTEXT) {
      vptr = &gcp_voice_codec;
    }
    else if(context == MEDIA_CONTEXT) {
      vptr = &gcp_media_codec;
    } else {
      // if no valid context is provided, use media context
      vptr = &gcp_media_codec;
    }
  } else if (profile == WMCP) {
    if(context == MEDIA_CONTEXT) {
      vptr = &wmcp_media_codec;
    } else {
      // if no valid context is provided, use media context
      vptr = &wmcp_media_codec;
    }
  }

  if (!vptr) {
     return {};
  }

  for (uint8_t i = 0; i < (uint8_t)vptr->size(); i++) {
    if (vptr->at(i).mandatory == 1) {
      memset(&temp_config, 0, sizeof(CodecConfig));

      temp_config.codec_type = CodecIndex::CODEC_INDEX_SOURCE_LC3;

      switch (vptr->at(i).freq_in_hz)
      {
        case SAMPLE_RATE_8000:
          temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_8000;
          break;
        case SAMPLE_RATE_16000:
          temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_16000;
          break;
        case SAMPLE_RATE_24000:
          temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_24000;
          break;
        case SAMPLE_RATE_32000:
          temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_32000;
          break;
        case SAMPLE_RATE_44100:
          temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_44100;
          break;
        case SAMPLE_RATE_48000:
          temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_48000;
          break;
        default:
          break;
      }

      if (vptr->at(i).frame_dur_msecs == FRM_DURATION_7_5_MS)
        UpdateFrameDuration(&temp_config, static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_7_5));
      else if (vptr->at(i).frame_dur_msecs == FRM_DURATION_10_MS)
        UpdateFrameDuration(&temp_config, static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10));

      UpdateOctsPerFrame(&temp_config, vptr->at(i).oct_per_codec_frm);

      ret_config.push_back(temp_config);
    }
  }

  return ret_config;
}

vector<QoSConfig> get_all_qos_params(uint8_t profile, uint8_t context)
{
  vector<QoSConfig> ret_config;
  QoSConfig temp_config;
  vector<qos_config> *vptr = NULL;

  if (profile == VMCP) {
    if (context == VOICE_CONTEXT)
       vptr =  &vmcp_qos_low_lat_voice;
    else if (context == MEDIA_LL_CONTEXT)
       vptr = &vmcp_qos_low_lat_media;
    else if (context == MEDIA_HR_CONTEXT)
       vptr = &vmcp_qos_high_rel_media;
  } else if (profile == BAP) {
    if (context == VOICE_CONTEXT)
       vptr =  &bap_qos_low_lat_voice;
    else if (context == MEDIA_LL_CONTEXT)
       vptr = &bap_qos_low_lat_media;
    else if (context == MEDIA_HR_CONTEXT)
       vptr = &bap_qos_high_rel_media;
  } else if (profile == GCP) {
    if (context == VOICE_CONTEXT)
       vptr =  &gcp_qos_low_lat_voice;
    else if (context == MEDIA_LL_CONTEXT)
       vptr = &gcp_qos_low_lat_media;
  } else if (profile == WMCP) {
    if (context == MEDIA_HR_CONTEXT)
       vptr = &wmcp_qos_high_rel_media;
  }

  if (!vptr) {
     return {};
  }

  for (uint8_t i = 0; i < (uint8_t)vptr->size(); i++) {
    memset(&temp_config, 0, sizeof(QoSConfig));

    switch (vptr->at(i).freq_in_hz)
    {
      case SAMPLE_RATE_8000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_8000;
        break;
      case SAMPLE_RATE_16000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_16000;
        break;
      case SAMPLE_RATE_24000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_24000;
        break;
      case SAMPLE_RATE_32000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_32000;
        break;
      case SAMPLE_RATE_44100:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_44100;
        break;
      case SAMPLE_RATE_48000:
        temp_config.sample_rate = CodecSampleRate::CODEC_SAMPLE_RATE_48000;
        break;
      default:
        break;
    }

    temp_config.sdu_int_micro_secs = vptr->at(i).sdu_int_micro_secs;
    temp_config.framing = vptr->at(i).framing;
    temp_config.max_sdu_size = vptr->at(i).max_sdu_size;
    temp_config.retrans_num = vptr->at(i).retrans_num;
    temp_config.max_trans_lat = vptr->at(i).max_trans_lat;
    temp_config.presentation_delay = vptr->at(i).presentation_delay;
    temp_config.mandatory = vptr->at(i).mandatory;

    ret_config.push_back(temp_config);
  }

  return ret_config;
}

vector<QoSConfig> get_qos_params_for_codec(uint8_t profile, uint8_t context, CodecSampleRate freq, uint8_t frame_dur, uint8_t octets)
{
  vector<QoSConfig> ret_config;
  QoSConfig temp_config;
  vector<qos_config> *vptr = NULL;
  uint32_t frame_dur_micro_sec = 0;
  uint32_t local_freq = 0;

  if (frame_dur == static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_7_5))
    frame_dur_micro_sec = FRM_DURATION_7_5_MS * 1000;
  else if (frame_dur == static_cast<uint8_t>(CodecFrameDuration::FRAME_DUR_10))
    frame_dur_micro_sec = FRM_DURATION_10_MS * 1000;

  switch (freq)
  {
    case CodecSampleRate::CODEC_SAMPLE_RATE_8000:
      local_freq = SAMPLE_RATE_8000;
      break;
    case CodecSampleRate::CODEC_SAMPLE_RATE_16000:
      local_freq = SAMPLE_RATE_16000;
      break;
    case CodecSampleRate::CODEC_SAMPLE_RATE_24000:
      local_freq = SAMPLE_RATE_24000;
      break;
    case CodecSampleRate::CODEC_SAMPLE_RATE_32000:
      local_freq = SAMPLE_RATE_32000;
      break;
    case CodecSampleRate::CODEC_SAMPLE_RATE_44100:
      local_freq = SAMPLE_RATE_44100;
      break;
    case CodecSampleRate::CODEC_SAMPLE_RATE_48000:
      local_freq = SAMPLE_RATE_48000;
      break;
    default:
      break;
  }

  if (profile == VMCP) {
    if (context == VOICE_CONTEXT)
       vptr =  &vmcp_qos_low_lat_voice;
    else if (context == MEDIA_LL_CONTEXT)
       vptr = &vmcp_qos_low_lat_media;
    else if (context == MEDIA_HR_CONTEXT)
       vptr = &vmcp_qos_high_rel_media;
  } else if (profile == BAP) {
    if (context == VOICE_CONTEXT)
       vptr =  &bap_qos_low_lat_voice;
    else if (context == MEDIA_LL_CONTEXT) {
       BTIF_TRACE_IMP("%s: filling BAP LL vptr", __func__);
       vptr = &bap_qos_low_lat_media;
    } else if (context == MEDIA_HR_CONTEXT) {
       BTIF_TRACE_IMP("%s: filling BAP HR vptr", __func__);
       vptr = &bap_qos_high_rel_media;
    }
  } else if (profile == GCP) {
    if (context == VOICE_CONTEXT)
       vptr =  &gcp_qos_low_lat_voice;
    else if (context == MEDIA_LL_CONTEXT)
       vptr = &gcp_qos_low_lat_media;
  } else if (profile == WMCP) {
    if (context == MEDIA_HR_CONTEXT) {
       BTIF_TRACE_IMP("%s: filling WMCP HR vptr", __func__);
       vptr = &wmcp_qos_high_rel_media;
    }
  }

  if (!vptr) {
     return { };
  }

  BTIF_TRACE_IMP("%s: vptr size: %d", __func__, (uint8_t)vptr->size());
  BTIF_TRACE_IMP("%s: local_freq: %d, frame_dur_micro_sec: %d, octets: %d",
       __func__, local_freq, frame_dur_micro_sec, octets);

  for (uint8_t i = 0; i < (uint8_t)vptr->size(); i++) {
    BTIF_TRACE_IMP("%s: freq_in_hz: %d, sdu_int_micro_secs: %d, max_sdu_size: %d",
       __func__, vptr->at(i).freq_in_hz, vptr->at(i).sdu_int_micro_secs,
       vptr->at(i).max_sdu_size);
    if (vptr->at(i).freq_in_hz == local_freq &&
        vptr->at(i).sdu_int_micro_secs == frame_dur_micro_sec &&
        vptr->at(i).max_sdu_size == octets) {
      BTIF_TRACE_IMP("%s: Local and vptr matched.", __func__);
      memset(&temp_config, 0, sizeof(QoSConfig));

      temp_config.sample_rate = freq;
      temp_config.sdu_int_micro_secs = vptr->at(i).sdu_int_micro_secs;
      temp_config.framing = vptr->at(i).framing;
      temp_config.max_sdu_size = vptr->at(i).max_sdu_size;
      temp_config.retrans_num = vptr->at(i).retrans_num;
      temp_config.max_trans_lat = vptr->at(i).max_trans_lat;
      temp_config.presentation_delay = vptr->at(i).presentation_delay;
      temp_config.mandatory = vptr->at(i).mandatory;

      ret_config.push_back(temp_config);
    }
  }

  return ret_config;
}

bool is_leaf(xmlNode *node)
{
  xmlNode *child = node->children;
  while(child)
  {
    if(child->type == XML_ELEMENT_NODE)
      return false;

    child = child->next;
  }

  return true;
}

void parseCodecConfigs(xmlNode *input_node, int context)
{
   stack<xmlNode*> profile_node_stack;
   unsigned int TempCodecCount = 0;
   unsigned int TempFieldsCount = 0;
   xmlNode *FirstChild = xmlFirstElementChild(input_node);
   unsigned long CodecFields = xmlChildElementCount(FirstChild);
   codec_config temp_codec_config;
   memset(&temp_codec_config, 0, sizeof(codec_config));


   BTIF_TRACE_IMP("codec Fields count is %ld \n", CodecFields);
   for (xmlNode *node = input_node->children; node != NULL || !profile_node_stack.empty(); node = node->children)
   {
     if (node == NULL)
     {
       node = profile_node_stack.top();
       profile_node_stack.pop();
     }

     if(node)
     {
       if(node->type == XML_ELEMENT_NODE)
       {
         if((is_leaf(node)))
         {
           string content = (const char*)(xmlNodeGetContent(node));
           if (content[0] == '\0') {
               return;
           }
           if(!xmlStrcmp(node->name,(const xmlChar*)"SamplingFrequencyInHz"))
           {
             temp_codec_config.freq_in_hz = atoi(content.c_str());
             TempFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"FrameDurationInMicroSecs"))
           {
             temp_codec_config.frame_dur_msecs = (float)atoi(content.c_str())/1000;
             TempFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"OctetsPerCodecFrame"))
           {
             temp_codec_config.oct_per_codec_frm = atoi(content.c_str());
             TempFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"Mandatory"))
           {
             temp_codec_config.mandatory = atoi(content.c_str());
             TempFieldsCount++;
           }
         }
         if(TempFieldsCount == CodecFields)
         {
           if (current_profile == VMCP) {
             if (context == VOICE_CONTEXT) {
               vmcp_voice_codec.push_back(temp_codec_config);
             } else if (context == MEDIA_CONTEXT) {
               vmcp_media_codec.push_back(temp_codec_config);
             }
           } else if (current_profile == BAP) {
             if (context == VOICE_CONTEXT) {
               bap_voice_codec.push_back(temp_codec_config);
             } else if (context == MEDIA_CONTEXT) {
               bap_media_codec.push_back(temp_codec_config);
             }
           } else if (current_profile == GCP) {
             if (context == VOICE_CONTEXT) {
               gcp_voice_codec.push_back(temp_codec_config);
             } else if (context == MEDIA_CONTEXT) {
               gcp_media_codec.push_back(temp_codec_config);
             }
           } else if (current_profile == WMCP) {
             if (context == MEDIA_CONTEXT) {
               BTIF_TRACE_IMP("%s: parsed codec config for wmcp", __func__);
               wmcp_media_codec.push_back(temp_codec_config);
             }
           }

           TempFieldsCount = 0;
           TempCodecCount++;
         }
       }

       if(node->next != NULL)
       {
         profile_node_stack.push(node->next);
         node = node->next;
       }
     } // end of if (node)
   } // end of for
   if(context == VOICE_CONTEXT && TempCodecCount == voice_codec_count)
   {
     if (current_profile < GCP) {
       BTIF_TRACE_IMP("All %ld CG codecs are parsed successfully\n", voice_codec_count);
     } else {
       BTIF_TRACE_IMP("All %ld GAT Rx codecs are parsed successfully\n", voice_codec_count);
     }
   }
   else if(context == MEDIA_CONTEXT && TempCodecCount == media_codec_count)
   {
     if (current_profile < GCP) {
       BTIF_TRACE_IMP("All %ld UMS codecs are parsed successfully\n", media_codec_count);
     } else if (current_profile == GCP) {
       BTIF_TRACE_IMP("All %ld GAT Tx codecs are parsed successfully\n", media_codec_count);
     } else if (current_profile == WMCP) {
       BTIF_TRACE_IMP("All %ld WM Rx codecs are parsed successfully\n", media_codec_count);
     }
   }
}

void parseQoSConfigs(xmlNode *QoSInputNode, int context)
{
   stack<xmlNode*> QoS_Stack;
   unsigned int TempQoSCodecCount = 0;
   unsigned int TempQoSFieldsCount = 0;
   xmlNode * FirstChild = xmlFirstElementChild(QoSInputNode);
   unsigned long QoSCodecFields = xmlChildElementCount(FirstChild);
   qos_config temp_qos_config ;
   memset(&temp_qos_config, 0, sizeof(qos_config));

   BTIF_TRACE_IMP("QoS Fields count %ld \n", QoSCodecFields);
   for (xmlNode *node = QoSInputNode->children; node != NULL || !QoS_Stack.empty(); node = node->children)
   {
     if (node == NULL)
     {
       node = QoS_Stack.top();
       QoS_Stack.pop();
     }
     if(node)
     {
       if(node->type == XML_ELEMENT_NODE)
       {
         if(is_leaf(node))
         {
           string content = (const char*)(xmlNodeGetContent(node));
           if (content[0] == '\0') {
               return;
           }
           if(!xmlStrcmp(node->name,(const xmlChar*)"SamplingFrequencyInHz"))
           {
             temp_qos_config.freq_in_hz = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"SDUIntervalInMicroSecs"))
           {
             temp_qos_config.sdu_int_micro_secs = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"Framing"))
           {
             temp_qos_config.framing = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"MaxSDUSize"))
           {
             temp_qos_config.max_sdu_size = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"RetransmissionNumber"))
           {
             temp_qos_config.retrans_num = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"MaxTransportLatency"))
           {
             temp_qos_config.max_trans_lat = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"PresentationDelay"))
           {
             temp_qos_config.presentation_delay = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
           else if(!xmlStrcmp(node->name, (const xmlChar*)"Mandatory"))
           {
             temp_qos_config.mandatory = atoi(content.c_str());
             TempQoSFieldsCount++;
           }
          }
          if(TempQoSFieldsCount == QoSCodecFields)
          {
            if(current_profile == VMCP) {
              if (context == VOICE_CONTEXT) {
                vmcp_qos_low_lat_voice.push_back(temp_qos_config);
              } else if (context == MEDIA_LL_CONTEXT) {
                vmcp_qos_low_lat_media.push_back(temp_qos_config);
              } else if (context == MEDIA_HR_CONTEXT) {
                vmcp_qos_high_rel_media.push_back(temp_qos_config);
              }
            } else if(current_profile == BAP) {
              if (context == VOICE_CONTEXT) {
                bap_qos_low_lat_voice.push_back(temp_qos_config);
              } else if (context == MEDIA_LL_CONTEXT) {
                bap_qos_low_lat_media.push_back(temp_qos_config);
              } else if (context == MEDIA_HR_CONTEXT) {
                bap_qos_high_rel_media.push_back(temp_qos_config);
              }
            } else if(current_profile == GCP) {
              if (context == VOICE_CONTEXT) {
                gcp_qos_low_lat_voice.push_back(temp_qos_config);
              } else if (context == MEDIA_LL_CONTEXT) {
                gcp_qos_low_lat_media.push_back(temp_qos_config);
              }
            } else if(current_profile == WMCP) {
              if (context == MEDIA_HR_CONTEXT) {
                BTIF_TRACE_IMP("%s: parsed qos config for wmcp", __func__);
                wmcp_qos_high_rel_media.push_back(temp_qos_config);
              }
            }

            TempQoSFieldsCount = 0;
            TempQoSCodecCount++;
          }
        }
       if(node->next != NULL)
       {
         QoS_Stack.push(node->next);
         node = node->next;
       }

    }
  }
  if(TempQoSCodecCount == qos_settings_count)
  {
    if(context == VOICE_CONTEXT)
    {
      if (current_profile < GCP) {
        BTIF_TRACE_IMP("All %ld CG Qos Config are parsed successfully\n", qos_settings_count);
      } else {
        BTIF_TRACE_IMP("All %ld GAT Rx Qos Config are parsed successfully\n", qos_settings_count);
      }
    }
    else if(context == MEDIA_CONTEXT)
    {
      if (current_profile < GCP) {
        BTIF_TRACE_IMP("All %ld UMS Qos Config are parsed successfully\n", qos_settings_count);
      } else if (current_profile == GCP) {
        BTIF_TRACE_IMP("All %ld GAT Tx Qos Config are parsed successfully\n", qos_settings_count);
      } else if (current_profile == WMCP) {
        BTIF_TRACE_IMP("All %ld WM Rx Qos Config are parsed successfully\n", qos_settings_count);
      }
    }
  }
}

void parse_xml(xmlNode *inputNode)
{
   stack<xmlNode*> S;
   for (xmlNode *node = inputNode; node != NULL || !S.empty(); node = node->children)
   {
    if (node == NULL)
    {
       node = S.top();
       S.pop();
    }
    if (node)
    {
      if (node->type == XML_ELEMENT_NODE)
      {
        if (!(is_leaf(node)))
        {
          string content = (const char *) (xmlNodeGetContent (node));
          if (content[0] == '\0') {
              return;
          }
          if (!xmlStrcmp (node->name, (const xmlChar *) "VMCP"))
          {
             BTIF_TRACE_IMP("VMCP configs being parsed\n");
             current_profile = VMCP;
          }
          if (!xmlStrcmp (node->name, (const xmlChar *) "BAP"))
          {
             BTIF_TRACE_IMP("BAP configs being parsed\n");
             current_profile = BAP;
          }
          if (!xmlStrcmp (node->name, (const xmlChar *) "GCP"))
          {
             BTIF_TRACE_IMP("GCP configs being parsed\n");
             current_profile = GCP;
          }
          if (!xmlStrcmp (node->name, (const xmlChar *) "WMCP"))
          {
             BTIF_TRACE_IMP("WMCP configs being parsed\n");
             current_profile = WMCP;
          }

          if (!xmlStrcmp (node->name, (const xmlChar *) "CodecCapabilitiesForVoice"))
          {
            voice_codec_count = xmlChildElementCount(node);
            parseCodecConfigs(node, VOICE_CONTEXT);
          }
          else if (!xmlStrcmp (node->name, (const xmlChar *) "CodecCapabilitiesForMedia"))
          {
            media_codec_count = xmlChildElementCount(node);
            parseCodecConfigs(node, MEDIA_CONTEXT);
          }
          else if (!xmlStrcmp (node->name, (const xmlChar *) "QosSettingsForLowLatencyVoice"))
          {
            qos_settings_count = xmlChildElementCount(node);
            parseQoSConfigs(node, VOICE_CONTEXT);
          }
          else if (!xmlStrcmp (node->name, (const xmlChar *) "QosSettingsForLowLatencyMedia"))
          {
            qos_settings_count = xmlChildElementCount(node);
            parseQoSConfigs(node, MEDIA_LL_CONTEXT);
          }
          else if (!xmlStrcmp (node->name, (const xmlChar *) "QosSettingsForHighReliabilityMedia"))
          {
            qos_settings_count = xmlChildElementCount(node);
            parseQoSConfigs(node, MEDIA_HR_CONTEXT);
          }
        }
      }
      if(node->next != NULL)
      {
        S.push(node -> next);
      }
    }
   }
}

void btif_vmcp_init() {
  xmlDoc *doc = NULL;
  xmlNode *root_element = NULL;

  doc = xmlReadFile(LEAUDIO_CONFIG_PATH, NULL, 0);
  if (doc == NULL) {
    BTIF_TRACE_ERROR("Could not parse the XML file");
  }

  root_element = xmlDocGetRootElement(doc);
  parse_xml(root_element);
  xmlFreeDoc(doc);
  xmlCleanupParser();

  //Register Audio Gaming Service UUID (GCP) with Gattc
  btif_register_uuid_srvc_disc(bluetooth::Uuid::FromString("12994b7e-6d47-4215-8c9e-aae9a1095ba3"));

  //Register Wireless Microphone Configuration Service UUID (WMCP) with Gattc
  btif_register_uuid_srvc_disc(bluetooth::Uuid::FromString("2587db3c-ce70-4fc9-935f-777ab4188fd7"));
}
