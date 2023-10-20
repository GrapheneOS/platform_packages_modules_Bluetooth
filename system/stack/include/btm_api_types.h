/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
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

#ifndef BTM_API_TYPES_H
#define BTM_API_TYPES_H

#include <base/strings/stringprintf.h>

#include <cstdint>
#include <string>

#include "internal_include/bt_target.h"
#include "stack/include/bt_dev_class.h"
#include "stack/include/bt_hdr.h"
#include "stack/include/bt_name.h"
#include "stack/include/bt_octets.h"
#include "stack/include/btm_status.h"
#include "stack/include/hci_mode.h"
#include "stack/include/hcidefs.h"
#include "stack/include/sdpdefs.h"
#include "types/ble_address_with_type.h"
#include "types/bt_transport.h"
#include "types/raw_address.h"

/* Structure returned with Vendor Specific Command complete callback */
typedef struct {
  uint16_t opcode;
  uint16_t param_len;
  uint8_t* p_param_buf;
} tBTM_VSC_CMPL;

/**************************************************
 *  Device Control and General Callback Functions
 **************************************************/
/* Callback function for when a vendor specific event occurs. The length and
 * array of returned parameter bytes are included. This asynchronous event
 * is enabled/disabled by calling BTM_RegisterForVSEvents().
*/
typedef void(tBTM_VS_EVT_CB)(uint8_t len, const uint8_t* p);

/* General callback function for notifying an application that a synchronous
 * BTM function is complete. The pointer contains the address of any returned
 * data.
 */
typedef void(tBTM_CMPL_CB)(void* p1);

/* VSC callback function for notifying an application that a synchronous
 * BTM function is complete. The pointer contains the address of any returned
 * data.
 */
typedef void(tBTM_VSC_CMPL_CB)(tBTM_VSC_CMPL* p1);

/*****************************************************************************
 *  DEVICE DISCOVERY - Inquiry, Remote Name, Discovery, Class of Device
 ****************************************************************************/
/*******************************
 *  Device Discovery Constants
 *******************************/
/****************************
 * minor device class field
 ****************************/

/* BTM service definitions
 * Used for storing EIR data to bit mask
*/
#define BTM_EIR_MAX_SERVICES 46

/*******************************************************************************
 * BTM Services MACROS handle array of uint32_t bits for more than 32 services
 ******************************************************************************/
/* Determine the number of uint32_t's necessary for services */
#define BTM_EIR_ARRAY_BITS 32 /* Number of bits in each array element */
#define BTM_EIR_SERVICE_ARRAY_SIZE                         \
  (((uint32_t)BTM_EIR_MAX_SERVICES / BTM_EIR_ARRAY_BITS) + \
   (((uint32_t)BTM_EIR_MAX_SERVICES % BTM_EIR_ARRAY_BITS) ? 1 : 0))

/* MACRO to set the service bit mask in a bit stream */
#define BTM_EIR_SET_SERVICE(p, service)                              \
  (((uint32_t*)(p))[(((uint32_t)(service)) / BTM_EIR_ARRAY_BITS)] |= \
   ((uint32_t)1 << (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS)))

/* MACRO to clear the service bit mask in a bit stream */
#define BTM_EIR_CLR_SERVICE(p, service)                              \
  (((uint32_t*)(p))[(((uint32_t)(service)) / BTM_EIR_ARRAY_BITS)] &= \
   ~((uint32_t)1 << (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS)))

/* MACRO to check the service bit mask in a bit stream */
#define BTM_EIR_HAS_SERVICE(p, service)                               \
  ((((uint32_t*)(p))[(((uint32_t)(service)) / BTM_EIR_ARRAY_BITS)] &  \
    ((uint32_t)1 << (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS))) >> \
   (((uint32_t)(service)) % BTM_EIR_ARRAY_BITS))

/* start of EIR in HCI buffer, 4 bytes = HCI Command(2) + Length(1) + FEC_Req(1)
 */
#define BTM_HCI_EIR_OFFSET (BT_HDR_SIZE + 4)

/***************************
 *  Device Discovery Types
 ***************************/
/* Definitions of the parameters passed to BTM_StartInquiry.
 */
constexpr uint8_t BLE_EVT_CONNECTABLE_BIT = 0;
constexpr uint8_t BLE_EVT_SCANNABLE_BIT = 1;
constexpr uint8_t BLE_EVT_DIRECTED_BIT = 2;
constexpr uint8_t BLE_EVT_SCAN_RESPONSE_BIT = 3;
constexpr uint8_t BLE_EVT_LEGACY_BIT = 4;

constexpr uint8_t PHY_LE_NO_PACKET = 0x00;
constexpr uint8_t PHY_LE_1M = 0x01;
constexpr uint8_t PHY_LE_2M = 0x02;
constexpr uint8_t PHY_LE_CODED = 0x04;

constexpr uint8_t NO_ADI_PRESENT = 0xFF;
constexpr uint8_t TX_POWER_NOT_PRESENT = 0x7F;

/*****************************************************************************
 *  ACL CHANNEL MANAGEMENT
 ****************************************************************************/
// NOTE: Moved to stack/include/acl_api_types.h

/*****************************************************************************
 *  SCO CHANNEL MANAGEMENT
 ****************************************************************************/
/******************
 *  SCO Constants
 ******************/

/* Define an invalid SCO index and an invalid HCI handle */
#define BTM_INVALID_SCO_INDEX 0xFFFF

#define BTM_SCO_LINK_ONLY_MASK \
  (ESCO_PKT_TYPES_MASK_HV1 | ESCO_PKT_TYPES_MASK_HV2 | ESCO_PKT_TYPES_MASK_HV3)

#define BTM_ESCO_LINK_ONLY_MASK \
  (ESCO_PKT_TYPES_MASK_EV3 | ESCO_PKT_TYPES_MASK_EV4 | ESCO_PKT_TYPES_MASK_EV5)

/***************
 *  SCO Types
 ***************/
#define BTM_LINK_TYPE_SCO HCI_LINK_TYPE_SCO
#define BTM_LINK_TYPE_ESCO HCI_LINK_TYPE_ESCO
typedef uint8_t tBTM_SCO_TYPE;

/*******************
 * SCO Codec Types
 *******************/
// TODO(b/285458890) This should use common definitions
#define BTM_SCO_CODEC_NONE 0x0000
#define BTM_SCO_CODEC_CVSD 0x0001
#define BTM_SCO_CODEC_MSBC 0x0002
#define BTM_SCO_CODEC_LC3 0x0004
typedef uint16_t tBTM_SCO_CODEC_TYPE;

/*******************
 * SCO Voice Settings
 *******************/

/*******************
 * SCO Data Status
 *******************/
/***************************
 *  SCO Callback Functions
 ***************************/
typedef void(tBTM_SCO_CB)(uint16_t sco_inx);

/***************
 *  eSCO Types
 ***************/
/* tBTM_ESCO_CBACK event types */
#define BTM_ESCO_CONN_REQ_EVT 2
typedef uint8_t tBTM_ESCO_EVT;

/* Returned by BTM_ReadEScoLinkParms() */
struct tBTM_ESCO_DATA {
  RawAddress bd_addr;
  uint8_t link_type; /* BTM_LINK_TYPE_SCO or BTM_LINK_TYPE_ESCO */
};

typedef struct {
  uint16_t sco_inx;
  RawAddress bd_addr;
  DEV_CLASS dev_class;
  tBTM_SCO_TYPE link_type;
} tBTM_ESCO_CONN_REQ_EVT_DATA;

typedef union {
  tBTM_ESCO_CONN_REQ_EVT_DATA conn_evt;
} tBTM_ESCO_EVT_DATA;

/***************************
 *  eSCO Callback Functions
 ***************************/
typedef void(tBTM_ESCO_CBACK)(tBTM_ESCO_EVT event, tBTM_ESCO_EVT_DATA* p_data);

/**************************
 * SCO Types for Debugging and Testing
 **************************/

/* Define the structure for the WBS/SWB packet status dump.  */
typedef struct {
  uint64_t begin_ts_raw_us;
  uint64_t end_ts_raw_us;
  std::string status_in_hex;
  std::string status_in_binary;
} tBTM_SCO_PKT_STATUS_DATA;

/* Returned by BTM_GetScoDebugDump */
typedef struct {
  bool is_active;
  uint16_t codec_id;
  int total_num_decoded_frames;
  double pkt_loss_ratio;
  tBTM_SCO_PKT_STATUS_DATA latest_data;
} tBTM_SCO_DEBUG_DUMP;

inline std::string sco_codec_type_text(tBTM_SCO_CODEC_TYPE codec_type) {
  switch (codec_type) {
    case BTM_SCO_CODEC_CVSD:
      return "CVSD";
    case BTM_SCO_CODEC_MSBC:
      return "MSBC";
    case BTM_SCO_CODEC_LC3:
      return "LC3";
    default:
      return "UNKNOWN";
  }
}

inline uint16_t sco_codec_type_to_id(tBTM_SCO_CODEC_TYPE codec_type) {
  switch (codec_type) {
    case BTM_SCO_CODEC_CVSD:
      return UUID_CODEC_CVSD;
    case BTM_SCO_CODEC_MSBC:
      return UUID_CODEC_MSBC;
    case BTM_SCO_CODEC_LC3:
      return UUID_CODEC_LC3;
    default:
      return 0;
  }
}

/*****************************************************************************
 *  POWER MANAGEMENT
 ****************************************************************************/
/****************************
 *  Power Manager Constants
 ****************************/
/* BTM Power manager status codes */
enum : uint8_t {
  BTM_PM_STS_ACTIVE = HCI_MODE_ACTIVE,  // 0x00
  BTM_PM_STS_HOLD = HCI_MODE_HOLD,      // 0x01
  BTM_PM_STS_SNIFF = HCI_MODE_SNIFF,    // 0x02
  BTM_PM_STS_PARK = HCI_MODE_PARK,      // 0x03
  BTM_PM_STS_SSR,      // Hci sniff subrating event reported the SSR parameters
  BTM_PM_STS_PENDING,  // Successful hci mode change command status received and
                       // now waiting for mode change event to indicate
                       // change to desired mode target.
  BTM_PM_STS_ERROR  // Failed hci mode change command status which will result
                    // in no mode change event.
};
typedef uint8_t tBTM_PM_STATUS;

inline std::string power_mode_status_text(tBTM_PM_STATUS status) {
  switch (status) {
    case BTM_PM_STS_ACTIVE:
      return std::string("active");
    case BTM_PM_STS_HOLD:
      return std::string("hold");
    case BTM_PM_STS_SNIFF:
      return std::string("sniff");
    case BTM_PM_STS_PARK:
      return std::string("park");
    case BTM_PM_STS_SSR:
      return std::string("sniff_subrating");
    case BTM_PM_STS_PENDING:
      return std::string("pending");
    case BTM_PM_STS_ERROR:
      return std::string("error");
    default:
      return std::string("UNKNOWN");
  }
}

/* BTM Power manager modes */
enum : uint8_t {
  BTM_PM_MD_ACTIVE = HCI_MODE_ACTIVE,  // 0x00
  BTM_PM_MD_HOLD = HCI_MODE_HOLD,      // 0x01
  BTM_PM_MD_SNIFF = HCI_MODE_SNIFF,    // 0x02
  BTM_PM_MD_PARK = HCI_MODE_PARK,      // 0x03
  BTM_PM_MD_FORCE = 0x10, /* OR this to force ACL link to a certain mode */
  BTM_PM_MD_UNKNOWN = 0xEF,
};
typedef uint8_t tBTM_PM_MODE;
#define HCI_TO_BTM_POWER_MODE(mode) (static_cast<tBTM_PM_MODE>(mode))

inline bool is_legal_power_mode(tBTM_PM_MODE mode) {
  switch (mode & ~BTM_PM_MD_FORCE) {
    case BTM_PM_MD_ACTIVE:
    case BTM_PM_MD_HOLD:
    case BTM_PM_MD_SNIFF:
    case BTM_PM_MD_PARK:
      return true;
    default:
      return false;
  }
}

inline std::string power_mode_text(tBTM_PM_MODE mode) {
  std::string s = base::StringPrintf((mode & BTM_PM_MD_FORCE) ? "forced:" : "");
  switch (mode & ~BTM_PM_MD_FORCE) {
    case BTM_PM_MD_ACTIVE:
      return s + std::string("active");
    case BTM_PM_MD_HOLD:
      return s + std::string("hold");
    case BTM_PM_MD_SNIFF:
      return s + std::string("sniff");
    case BTM_PM_MD_PARK:
      return s + std::string("park");
    default:
      return s + std::string("UNKNOWN");
  }
}

#define BTM_PM_SET_ONLY_ID 0x80

/* Operation codes */
typedef enum : uint8_t {
  /* The module wants to set the desired power mode */
  BTM_PM_REG_SET = (1u << 0),
  /* The module does not want to involve with PM anymore */
  BTM_PM_DEREG = (1u << 2),
} tBTM_PM_REGISTER;

/************************
 *  Power Manager Types
 ************************/
struct tBTM_PM_PWR_MD {
  uint16_t max = 0;
  uint16_t min = 0;
  uint16_t attempt = 0;
  uint16_t timeout = 0;
  tBTM_PM_MODE mode = BTM_PM_MD_ACTIVE;  // 0

  std::string ToString() const {
    return base::StringPrintf(
        "mode:%s[max:%hu min:%hu attempt:%hu timeout:%hu]",
        power_mode_text(mode).c_str(), max, min, attempt, timeout);
  }
};

/*************************************
 *  Power Manager Callback Functions
 *************************************/
typedef void(tBTM_PM_STATUS_CBACK)(const RawAddress& p_bda,
                                   tBTM_PM_STATUS status, uint16_t value,
                                   tHCI_STATUS hci_status);

#define BTM_CONTRL_UNKNOWN 0
/* ACL link on, SCO link ongoing, sniff mode */
#define BTM_CONTRL_ACTIVE 1
/* Scan state - paging/inquiry/trying to connect*/
#define BTM_CONTRL_SCAN 2
/* Idle state - page scan, LE advt, inquiry scan */
#define BTM_CONTRL_IDLE 3

typedef uint8_t tBTM_CONTRL_STATE;

// Bluetooth Quality Report - Report receiver
typedef void(tBTM_BT_QUALITY_REPORT_RECEIVER)(uint8_t len,
                                              const uint8_t* p_stream);

struct tREMOTE_VERSION_INFO {
  uint8_t lmp_version{0};
  uint16_t lmp_subversion{0};
  uint16_t manufacturer{0};
  bool valid{false};
  std::string ToString() const {
    return (valid) ? base::StringPrintf("%02hhu-%05hu-%05hu", lmp_version,
                                        lmp_subversion, manufacturer)
                   : std::string("UNKNOWN");
  }
};
using remote_version_info = tREMOTE_VERSION_INFO;

#endif  // BTM_API_TYPES_H
