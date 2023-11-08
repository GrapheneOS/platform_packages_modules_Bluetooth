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

/*
 * Generated mock file from original source file
 *   Functions generated:6
 *
 *  mockcify.pl ver 0.2
 */
// Mock include file to share data between tests and mock
#include "test/mock/mock_stack_acl_btm_ble_connection_establishment.h"

#include <cstdint>

// Original included files, if any

#include "test/common/mock_functions.h"
#include "types/raw_address.h"

// Mocked compile conditionals, if any
// Mocked internal structures, if any

namespace test {
namespace mock {
namespace stack_acl_btm_ble_connection_establishment {

// Function state capture and return values, if needed
struct btm_ble_create_ll_conn_complete btm_ble_create_ll_conn_complete;

}  // namespace stack_acl_btm_ble_connection_establishment
}  // namespace mock
}  // namespace test

void btm_ble_create_ll_conn_complete(tHCI_STATUS status) {
  inc_func_call_count(__func__);
  test::mock::stack_acl_btm_ble_connection_establishment::
      btm_ble_create_ll_conn_complete(status);
}

// END mockcify generation
