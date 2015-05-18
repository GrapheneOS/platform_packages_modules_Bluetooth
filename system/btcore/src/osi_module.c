/******************************************************************************
 *
 *  Copyright (C) 2015 Google, Inc.
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

#define LOG_TAG "bt_osi_module"

#include "btcore/include/module.h"
#include "btcore/include/osi_module.h"
#include "osi/include/alarm.h"
#include "osi/include/future.h"
#include "osi/include/log.h"
#include "osi/include/osi.h"

future_t *osi_start_up(void) {
  return NULL;
}

future_t *osi_shut_down(void) {
  alarm_shutdown();
  return NULL;
}

const module_t osi_module = {
  .name = OSI_MODULE,
  .init = NULL,
  .start_up = osi_start_up,
  .shut_down = osi_shut_down,
  .clean_up = NULL,
  .dependencies = {NULL}
};
