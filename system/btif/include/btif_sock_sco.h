/******************************************************************************
 *
 *  Copyright (C) 2013 Google, Inc.
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

/*******************************************************************************
 *
 *  Filename:      btif_sock_sco.h
 *
 *  Description:   Bluetooth SCO socket interface
 *
 *******************************************************************************/

#ifndef BTIF_SOCK_SCO_H
#define BTIF_SOCK_SCO_H

bt_status_t btsock_sco_init(int handle);
bt_status_t btsock_sco_cleanup();
bt_status_t btsock_sco_listen(int* sock_fd, int flags);
bt_status_t btsock_sco_connect(const bt_bdaddr_t *bd_addr, int* sock_fd, int flags);
void btsock_sco_signaled(int fd, int flags, uint32_t user_id);

#endif
