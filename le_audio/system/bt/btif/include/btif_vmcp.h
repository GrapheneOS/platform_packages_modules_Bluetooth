/******************************************************************************
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 *
 ******************************************************************************/

#include <vector>
#include "raw_address.h"
#include "hardware/bt_pacs_client.h"

using bluetooth::bap::pacs::CodecSampleRate;
using bluetooth::bap::pacs::CodecIndex;
using bluetooth::bap::pacs::CodecFrameDuration;
using bluetooth::bap::pacs::CodecConfig;

#define BAP        0x01
#define GCP        0x02
#define WMCP       0x04
#define VMCP       0x08
#define BAP_CALL   0x10
#define GCP_TX_RX  0x20

#define EB_CONFIG           1
#define STEREO_HS_CONFIG_1  2
#define STEREO_HS_CONFIG_2  3

#define VOICE_CONTEXT     1
#define MEDIA_CONTEXT     2
#define MEDIA_LL_CONTEXT  3
#define MEDIA_HR_CONTEXT  4

#define SAMPLE_RATE_8000   8000
#define SAMPLE_RATE_16000 16000
#define SAMPLE_RATE_24000 24000
#define SAMPLE_RATE_32000 32000
#define SAMPLE_RATE_44100 44100
#define SAMPLE_RATE_48000 48000


#define FRM_DURATION_7_5_MS   7.5
#define FRM_DURATION_10_MS     10

#define OCT_PER_CODEC_FRM_26     26
#define OCT_PER_CODEC_FRM_30     30
#define OCT_PER_CODEC_FRM_60     60
#define OCT_PER_CODEC_FRM_75     75
#define OCT_PER_CODEC_FRM_80     80
#define OCT_PER_CODEC_FRM_90     90
#define OCT_PER_CODEC_FRM_98     98
#define OCT_PER_CODEC_FRM_100   100
#define OCT_PER_CODEC_FRM_117   117
#define OCT_PER_CODEC_FRM_120   120
#define OCT_PER_CODEC_FRM_130   130
#define OCT_PER_CODEC_FRM_150   150
#define OCT_PER_CODEC_FRM_155   155

#define UNFRAMED 0
#define FRAMED   1

#define RETRANS_NO_2     2
#define RETRANS_NO_5     5
#define RETRANS_NO_7     7
#define RETRANS_NO_11   11
#define RETRANS_NO_13   13
#define RETRANS_NO_23   23
#define RETRANS_NO_29   29
#define RETRANS_NO_35   35
#define RETRANS_NO_41   41
#define RETRANS_NO_47   47
#define RETRANS_NO_53   53

#define MAX_TRANS_LAT_MS_8      8
#define MAX_TRANS_LAT_MS_10    10
#define MAX_TRANS_LAT_MS_15    15
#define MAX_TRANS_LAT_MS_20    20
#define MAX_TRANS_LAT_MS_24    24
#define MAX_TRANS_LAT_MS_25    25
#define MAX_TRANS_LAT_MS_31    31
#define MAX_TRANS_LAT_MS_33    33
#define MAX_TRANS_LAT_MS_45    45
#define MAX_TRANS_LAT_MS_54    54
#define MAX_TRANS_LAT_MS_60    60
#define MAX_TRANS_LAT_MS_71    71
#define MAX_TRANS_LAT_MS_95    95

#define PRES_DELAY_20_MS    20
#define PRES_DELAY_25_MS    25
#define PRES_DELAY_40_MS    40

#define LEAUDIO_CONFIG_PATH "/system_ext/etc/bluetooth/leaudio_configs.xml"
using namespace std;

// for storing codec config as it is read from xml
struct codec_config
{
    uint32_t freq_in_hz;
    float frame_dur_msecs;
    uint8_t oct_per_codec_frm;
    uint8_t mandatory;
};

// for storing QoS settings as it is read from xml
struct qos_config
{
    uint32_t freq_in_hz;
    uint32_t sdu_int_micro_secs;
    uint8_t framing;
    uint8_t max_sdu_size;
    uint8_t retrans_num;
    uint8_t max_trans_lat;
    uint32_t presentation_delay;
    uint8_t mandatory;
};


// QoS configuration in the structure needed by ACM
struct QoSConfig
{
    CodecSampleRate sample_rate;
    uint32_t sdu_int_micro_secs;
    uint8_t framing;
    uint8_t max_sdu_size;
    uint8_t retrans_num;
    uint8_t max_trans_lat;
    uint32_t presentation_delay;
    uint8_t mandatory;
};
void btif_vmcp_init();

vector<CodecConfig> get_all_codec_configs(uint8_t profile, uint8_t context);
vector<CodecConfig> get_preferred_codec_configs(uint8_t profile, uint8_t context);

vector<QoSConfig> get_all_qos_params(uint8_t profile, uint8_t context);
vector<QoSConfig> get_qos_params_for_codec(uint8_t profile, uint8_t context, CodecSampleRate freq, uint8_t frame_dur, uint8_t octets);
