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
 * LC3 - Noise level estimation
 *
 * Reference : Low Complexity Communication Codec (LC3)
 *             Bluetooth Specification v1.0
 */

#ifndef __LC3_NOISE_H
#define __LC3_NOISE_H

#include "common.h"
#include "quant.h"
#include "bits.h"


/**
 * Noise level estimation
 * dt, bw          Duration and bandwith of the frame
 * quant           Quantized spectral coefficients
 * x               Quantization scaled spectrum coefficients
 * noise_factor    Return the quantized noise factor (0 to 7)
 */
void lc3_noise_estimate(enum lc3_dt dt, enum lc3_bandwidth bw,
    const struct lc3_quant_data *quant, const float *x, int *noise_factor);

/**
 * Put noise factor
 * bits            Bitstream context
 * noise_factor    Noise factor value
 */
void lc3_noise_put_factor(lc3_bits_t *bits, int noise_factor);


#endif /* __LC3_NOISE_H */
