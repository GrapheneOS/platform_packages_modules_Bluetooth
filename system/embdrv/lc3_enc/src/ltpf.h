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
 * LC3 - Long Term Postfilter
 *
 * Reference : Low Complexity Communication Codec (LC3)
 *             Bluetooth Specification v1.0
 */

#ifndef __LC3_LTPF_H
#define __LC3_LTPF_H

#include "common.h"
#include "bits.h"


/**
 * LTPF data
 */

typedef struct lc3_ltpf_data {
    bool active;
    int pitch_index;
} lc3_ltpf_data_t;


/**
 * Long Term Postfilter analysis
 * dt, sr          Duration and samplerate of the frame
 * state           State of the LTPF
 * allowed         True when activation of LTPF is allowed
 * x               [-d..-1] Previous, [0..ns-1] Current samples
 * data            Return LTPF data
 * return          True when pitch present, False otherwise
 *
 * The number of previous samples `d` accessed on `x` is :
 *   d: { 10, 20, 30, 40, 60 } - 1 for samplerates from 8KHz to 48KHz
 */
bool lc3_ltpf_analyse(enum lc3_dt dt, enum lc3_srate sr,
    lc3_ltpf_state_t *state, const float *x, lc3_ltpf_data_t *data);

/**
 * Long Term Postfilter synthesis
 */
void lc3_ltpf_synthsize();

/**
 * Long Term Postfilter disable
 * data            LTPF data, diabled activation on return
 */
void lc3_ltpf_disable(lc3_ltpf_data_t *data);

/**
 * Return number of bits coding the bitstream data
 * pitch           True when pitch present, False otherwise
 * return          Bit consumption, including the pitch present flag
 */
int lc3_ltpf_get_nbits(bool pitch);

/**
 * Put LTPF data
 * bits            Bitstream context
 * data            LTPF data
 */
void lc3_ltpf_put_data(lc3_bits_t *bits,
    const struct lc3_ltpf_data *data);


#endif /* __LC3_LTPF_H */
