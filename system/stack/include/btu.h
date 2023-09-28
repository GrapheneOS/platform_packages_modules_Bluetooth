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

/******************************************************************************
 *
 *  this file contains the main Bluetooth Upper Layer definitions. The Broadcom
 *  implementations of L2CAP RFCOMM, SDP and the BTIf run as one GKI task. The
 *  btu_task switches between them.
 *
 ******************************************************************************/

#ifndef BTU_H
#define BTU_H

#include <cstdint>

#include "stack/include/btu_task.h"

/* Global BTU data */
extern uint8_t btu_trace_level;

#endif
