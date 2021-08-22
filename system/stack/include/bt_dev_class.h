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

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif  // __cplusplus

#define DEV_CLASS_LEN 3
typedef uint8_t DEV_CLASS[DEV_CLASS_LEN]; /* Device class */

#define DEVCLASS_TO_STREAM(p, a)                      \
  {                                                   \
    int ijk;                                          \
    for (ijk = 0; ijk < DEV_CLASS_LEN; ijk++)         \
      *(p)++ = (uint8_t)(a)[DEV_CLASS_LEN - 1 - ijk]; \
  }

#define STREAM_TO_DEVCLASS(a, p)                               \
  {                                                            \
    int ijk;                                                   \
    uint8_t* _pa = (uint8_t*)(a) + DEV_CLASS_LEN - 1;          \
    for (ijk = 0; ijk < DEV_CLASS_LEN; ijk++) *_pa-- = *(p)++; \
  }
