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
 * LC3 - Spectral Noise Shaping
 *
 * Reference : Low Complexity Communication Codec (LC3)
 *             Bluetooth Specification v1.0
 */

#ifndef __LC3_SNS_H
#define __LC3_SNS_H

#include "common.h"
#include "bits.h"


/**
 * Bitstream data
 */

typedef struct lc3_sns_data {
    int lfcb, hfcb;
    int shape, gain;
    int idx_a, idx_b;
    bool ls_a, ls_b;
} lc3_sns_data_t;


/**
 * SNS encoding process
 * dt, sr          Duration and samplerate of the frame
 * eb              Energy estimation per bands, and count of bands
 * att             1: Attack detected  0: Otherwise
 * data            Return bitstream data
 * x               Spectral coefficients, shapped as output
 */
void lc3_sns_encode(enum lc3_dt dt, enum lc3_srate sr,
    const float *eb, bool att, lc3_sns_data_t *data, float *x);

/**
 * SNS decoding process
 */
void lc3_sns_decode();

/**
 * Return number of bits coding the bitstream data
 * return          Bit consumption
 */
int lc3_sns_get_nbits(void);

/**
 * Put SNS data
 * bits            Bitstream context
 * data            SNS data
 */
void lc3_sns_put_data(lc3_bits_t *bits, const lc3_sns_data_t *data);


#endif /* __LC3_SNS_H */
