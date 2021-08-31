/*
 * Copyright 2021 The Android Open Source Project
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

#pragma once

#include <cstdint>

/*
 * Events that can be received by multiplexer as well as port state machines
 */
typedef uint8_t tRFC_EVENT;
#define RFC_EVENT_SABME 0
#define RFC_EVENT_UA 1
#define RFC_EVENT_DM 2
#define RFC_EVENT_DISC 3
#define RFC_EVENT_UIH 4
#define RFC_EVENT_TIMEOUT 5
#define RFC_EVENT_BAD_FRAME 50
/*
 * Multiplexer events
 */
typedef uint8_t tRFC_MX_EVENT;
#define RFC_MX_EVENT_SABME RFC_EVENT_SABME
#define RFC_MX_EVENT_UA RFC_EVENT_UA
#define RFC_MX_EVENT_DM RFC_EVENT_DM
#define RFC_MX_EVENT_DISC RFC_EVENT_DISC
#define RFC_MX_EVENT_UIH RFC_EVENT_UIH
#define RFC_MX_EVENT_TIMEOUT RFC_EVENT_TIMEOUT
#define RFC_MX_EVENT_START_REQ 6
#define RFC_MX_EVENT_START_RSP 7
#define RFC_MX_EVENT_CLOSE_REQ 8
#define RFC_MX_EVENT_CONN_CNF 9
#define RFC_MX_EVENT_CONN_IND 10
#define RFC_MX_EVENT_CONF_CNF 11
#define RFC_MX_EVENT_CONF_IND 12
#define RFC_MX_EVENT_QOS_VIOLATION_IND 13
#define RFC_MX_EVENT_DISC_IND 14

/*
 * Port events
 */
typedef uint8_t tRFC_PORT_EVENT;
#define RFC_PORT_EVENT_SABME RFC_EVENT_SABME
#define RFC_PORT_EVENT_UA RFC_EVENT_UA
#define RFC_PORT_EVENT_DM RFC_EVENT_DM
#define RFC_PORT_EVENT_DISC RFC_EVENT_DISC
#define RFC_PORT_EVENT_UIH RFC_EVENT_UIH
#define RFC_PORT_EVENT_TIMEOUT RFC_EVENT_TIMEOUT
#define RFC_PORT_EVENT_OPEN 9
#define RFC_PORT_EVENT_ESTABLISH_RSP 11
#define RFC_PORT_EVENT_CLOSE 12
#define RFC_PORT_EVENT_CLEAR 13
#define RFC_PORT_EVENT_DATA 14
#define RFC_PORT_EVENT_SEC_COMPLETE 15
