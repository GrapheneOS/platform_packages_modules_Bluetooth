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
 * LC3 - Spectral quantization
 *
 * Reference : Low Complexity Communication Codec (LC3)
 *             Bluetooth Specification v1.0
 */

#ifndef __LC3_QUANT_H
#define __LC3_QUANT_H

#include "common.h"
#include "tables.h"
#include "bwdet.h"
#include "ltpf.h"
#include "tns.h"
#include "sns.h"


/**
 * Quantization data
 */

typedef struct lc3_quant_data {
    int g_idx, n;
    int16_t x[LC3_MAX_NE];
    bool lsb_mode, high_rate;
} lc3_quant_data_t;


/**
 * Quantize spectral coefficients
 * dt, sr, nbytes  Duration, samplerate and size of the frame
 * pitch, tns      Pitch present indication and TNS frame datas
 * state           State of the quantizer gain estimator
 * x               Spectral coefficients, scaled as output
 * data            Return quantization data
 */
void lc3_quant_perform(enum lc3_dt dt, enum lc3_srate sr,
    unsigned nbytes, bool pitch, const lc3_tns_data_t *tns,
    lc3_quant_state_t *state, float *x, lc3_quant_data_t *data);

/**
 * Put quantization side informations
 * bits            Bitstream context
 * dt, sr          Duration and samplerate of the frame
 * data            Quantization data
 */
void lc3_quant_put_side(lc3_bits_t *bits,
    enum lc3_dt dt, enum lc3_srate sr, const lc3_quant_data_t *data);

/**
 * Put quantized spectrum data
 * bits            Bitstream context
 * dt, sr          Duration and samplerate of the frame
 * data            Quantization data
 * xf              Scaled spectral coefficients
 */
void lc3_quant_put_spectrum(
    lc3_bits_t *bits, enum lc3_dt dt, enum lc3_srate sr,
    const lc3_quant_data_t *data, const float *x);


#endif /* __LC3_QUANT_H */
