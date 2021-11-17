/******************************************************************************
 *
 *  Copyright 2021 Google, Inc.
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

/**
 * LC3 - Temporal Noise Shaping
 *
 * Reference : Low Complexity Communication Codec (LC3)
 *             Bluetooth Specification v1.0
 */

#ifndef __LC3_TNS_H
#define __LC3_TNS_H

#include "common.h"
#include "bits.h"


/**
 * TNS data
 */

typedef struct lc3_tns_data {
    int nfilters;
    bool lpc_weighting[2];
    int rc_order[2];
    int rc[2][8];
} lc3_tns_data_t;


/**
 * TNS encoding process
 * dt, bw          Duration and bandwith of the frame
 * nn_flag         True when high energy detected near Nyquist frequency
 * data            Return TNS data
 * nbytes          Size in bytes of the frame
 * x               Spectral coefficients, filtered as output
 */
void lc3_tns_encode(enum lc3_dt dt, enum lc3_bandwidth bw,
    bool nn_flag, unsigned nbytes, lc3_tns_data_t *data, float *x);

/**
 * TNS decoding process
 */
void lc3_tns_decode();

/**
 * Return number of bits coding the bitstream data
 * data            Bitstream data
 * return          Bit consumption
 */
int lc3_tns_get_nbits(const lc3_tns_data_t *data);

/**
 * Put TNS data
 * bits            Bitstream context
 * data            TNS data
 */
void lc3_tns_put_data(lc3_bits_t *bits, const lc3_tns_data_t *data);


#endif /* __LC3_TNS_H */
