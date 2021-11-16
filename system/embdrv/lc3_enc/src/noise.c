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

#include "noise.h"


/**
 * Noise level estimation
 */
void lc3_noise_estimate(enum lc3_dt dt, enum lc3_bandwidth bw,
    const struct lc3_quant_data *quant, const float *x, int *noise_factor)
{
    int bw_stop = (dt == LC3_DT_7M5 ? 60 : 80) * (1 + bw);
    int w = 2 + dt;

    float sum = 0;
    int i, n = 0, z = 0;

    for (i = 6*(3 + dt) - w; i < LC3_MIN(quant->n, bw_stop + w); i++) {
        z = quant->x[i] ? 0 : z + 1;
        if (z > 2*w)
            sum += fabs(x[i - w]), n++;
    }

    for ( ; i < bw_stop + w; i++)
        if (++z > 2*w)
            sum += fabs(x[i - w]), n++;

    *noise_factor = n ? 8 - rintf(16 * sum / n) : 0;
    *noise_factor = LC3_CLIP(*noise_factor, 0, 7);
}

/**
 * Put noise factor
 */
void lc3_noise_put_factor(lc3_bits_t *bits, int noise_factor)
{
    lc3_put_bits(bits, noise_factor, 3);
}
