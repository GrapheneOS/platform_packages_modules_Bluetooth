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

#include "quant.h"
#include "bits.h"
#include "tables.h"


/**
 * Bit consumption of the arithmetic coder (cf. 3.3.5)
 * dt, sr, nbytes  Duration, samplerate and size of the frame
 * return          Bit consumption of bitstream data
 */
static int get_nbits_ac(enum lc3_dt dt, enum lc3_srate sr, unsigned nbytes)
{
    int nbits, ne = LC3_NE(dt, sr);

    for (nbits = 6; ne >> nbits; nbits++);
    nbits -= (ne & ((1 << (nbits-1)) - 1)) == 0;

    nbits += 2 + LC3_MIN((nbytes-1) / 160, 2);

    return nbits;
}

/**
 * Quantized gain index offset (cf. 3.3.10.2)
 * sr, nbytes      Samplerate and size of the frame
 * return          Gain index offset
 */
static int get_gain_offset(enum lc3_srate sr, unsigned nbytes)
{
    int g_off = (nbytes * 8) / (10 * (1 + sr));
    g_off = 105 + 5*(1 + sr) + LC3_MIN(g_off, 115);

    return g_off;
}

/**
 * Global Gain Estimation (cf. 3.3.10.2)
 * dt, sr          Duration and samplerate
 * x               Spectral coefficients
 * nbits_budget    Number of bits available coding the spectrum
 * nbits_off       Offset on the available bits, temporarily smoothed
 * g_off           Gain index offset
 * reset_off       Return True when the nbits_off must be reset
 * return          The quantized gain value
 */
static int estimate_gain(
    enum lc3_dt dt, enum lc3_srate sr, const float *x,
    int nbits_budget, float nbits_off, int g_off, bool *reset_off)
{
    int ne = LC3_NE(dt, sr) >> 2;
    float e[ne];

    /* --- Energy (dB) by 4 NDCT blocks ---
     * For the next steps, add energy offset 28/20 dB,
     * and compute the maximum magnitude */

    float x_max = 0;

    for (int i = 0; i < ne; i++, x += 4) {
        float x0 = fabsf(x[0]), x1 = fabsf(x[1]);
        float x2 = fabsf(x[2]), x3 = fabsf(x[3]);

        x_max = fmaxf(x_max, x0);
        x_max = fmaxf(x_max, x1);
        x_max = fmaxf(x_max, x2);
        x_max = fmaxf(x_max, x3);

        float s2 = x0*x0 + x1*x1 + x2*x2 + x3*x3;
        e[i] = 28.f/20 * 10 * (s2 > 0 ? log10f(s2) : -10);
    }

    /* --- Determine gain index --- */

    int nbits = rintf(nbits_budget + nbits_off);
    int g_int = 255 - g_off;

    for (int i = 128; i > 0; i >>= 1) {
        const float *e_ptr = e + ne-1;
        float v = 0;

        g_int -= i;

        for ( ; e_ptr >= e && *e_ptr < g_int; e_ptr--);

        while (e_ptr >= e) {
            float e_diff = *(e_ptr--) - g_int;

            if (e_diff < 0) {
                v += 2.7f * 28.f/20;
            } else {
                v += e_diff + 7 * 28.f/20;
                if (e_diff > 43 * 28.f/20)
                    v += e_diff - 43 * 28.f/20;
            }
        }

        if (v > nbits * 1.4 * 28./20)
            g_int += i;
    }

    /* --- Limit gain index --- */

    int g_min = x_max == 0 ? -g_off :
        ceilf(28 * log10f(x_max / (32768 - 0.375f)));

    *reset_off = g_int < g_min || x_max == 0;
    if (*reset_off)
        g_int = g_min;

    return g_int;
}

/**
 * Global Gain Adjustment  (cf. 3.3.10.6)
 * sr              Samplerate of the frame
 * g_idx           The estimated quantized gain index
 * nbits           Computed number of bits coding the spectrum
 * nbits_budget    Number of bits available for coding the spectrum
 * return          Gain adjust value (-1 to 2)
 */
static int adjust_gain(enum lc3_srate sr,
    int g_idx, int nbits, int nbits_budget)
{
    /* --- Compute delta threshold --- */

    const int *t = (const int [LC3_NUM_SRATE][3]){
        {  80,  500,  850 }, { 230, 1025, 1700 }, { 380, 1550, 2550 },
        { 530, 2075, 3400 }, { 680, 2600, 4250 }
    }[sr];

    int delta, den = 48;

    if (nbits < t[0]) {
        delta = 3*(nbits + 48);

    } else if (nbits < t[1]) {
        int n0 = 3*(t[0] + 48), range = t[1] - t[0];
        delta = n0 * range + (nbits - t[0]) * (t[1] - n0);
        den *= range;

    } else {
        delta = LC3_MIN(nbits, t[2]);
    }

    delta = (delta + den/2) / den;

    /* --- Adjust gain --- */

    if (nbits < nbits_budget - (delta + 2))
        return -(g_idx > 0);

    if (nbits > nbits_budget)
        return (g_idx < 255) + (g_idx < 254 && nbits >= nbits_budget + delta);

    return 0;
}

/**
 * Spectral quantization (cf. 3.3.10.3)
 * dt, sr          Duration and samplerate
 * g_int           Quantization gain value
 * x               Spectral coefficients, scaled as output
 * xq, nq          Output spectral quantized coefficients, and count
 */
static void perform_quantization(enum lc3_dt dt, enum lc3_srate sr,
    int g_int, float *x, int16_t *xq, int *nq)
{
    int ne = LC3_NE(dt, sr);

    /* Unquantization gain table :
     * G[i] = 10 ^ (i / 28) , i = [0..64] */

    static const float iq_table[] = {
        1.00000000e+00, 1.08571112e+00, 1.17876863e+00, 1.27980221e+00,
        1.38949549e+00, 1.50859071e+00, 1.63789371e+00, 1.77827941e+00,
        1.93069773e+00, 2.09617999e+00, 2.27584593e+00, 2.47091123e+00,
        2.68269580e+00, 2.91263265e+00, 3.16227766e+00, 3.43332002e+00,
        3.72759372e+00, 4.04708995e+00, 4.39397056e+00, 4.77058270e+00,
        5.17947468e+00, 5.62341325e+00, 6.10540230e+00, 6.62870316e+00,
        7.19685673e+00, 7.81370738e+00, 8.48342898e+00, 9.21055318e+00,
        1.00000000e+01, 1.08571112e+01, 1.17876863e+01, 1.27980221e+01,
        1.38949549e+01, 1.50859071e+01, 1.63789371e+01, 1.77827941e+01,
        1.93069773e+01, 2.09617999e+01, 2.27584593e+01, 2.47091123e+01,
        2.68269580e+01, 2.91263265e+01, 3.16227766e+01, 3.43332002e+01,
        3.72759372e+01, 4.04708995e+01, 4.39397056e+01, 4.77058270e+01,
        5.17947468e+01, 5.62341325e+01, 6.10540230e+01, 6.62870316e+01,
        7.19685673e+01, 7.81370738e+01, 8.48342898e+01, 9.21055318e+01,
        1.00000000e+02, 1.08571112e+02, 1.17876863e+02, 1.27980221e+02,
        1.38949549e+02, 1.50859071e+02, 1.63789371e+02, 1.77827941e+02,
        1.93069773e+02
    };

    /* --- Unquantize gain index --- */

    float g_inv = iq_table[LC3_ABS(g_int) & 0x3f];
    for(int n64 = LC3_ABS(g_int) >> 6; n64--; )
        g_inv *= iq_table[64];

    if (g_int > 0)
        g_inv = 1 / g_inv;

    /* --- Spectral quantization --- */

    *nq = ne;

    for (int i = 0; i < ne; i += 2) {
        int16_t x0, x1;

        x[i+0] *= g_inv;
        x0 = fminf(floorf(fabsf(x[i+0]) + 0.375f), INT16_MAX);
        xq[i+0] = x[i+0] < 0 ? -x0 : x0;

        x[i+1] *= g_inv;
        x1 = fminf(floorf(fabsf(x[i+1]) + 0.375f), INT16_MAX);
        xq[i+1] = x[i+1] < 0 ? -x1 : x1;

        *nq = x0 || x1 ? ne : *nq - 2;
    }
}

/**
 * Bit consumption (cf. 3.3.10.4)
 * dt, sr, nbytes  Duration, samplerate and size of the frame
 * x               Spectral quantized coefficients
 * n               Count of significant coefficients, updated on truncation
 * nbits_budget    Truncate to stay in budget, when not zero
 * p_lsb_mode      Return True when LSB's are not AC coded, or NULL
 * p_high_rate     Return True when high bitrate mode selected, or NULL
 * return          The number of bits coding the spectrum
 */
static int compute_nbits(
    enum lc3_dt dt, enum lc3_srate sr, unsigned nbytes,
    const int16_t *x, int *n, int nbits_budget,
    bool *p_lsb_mode, bool *p_high_rate)
{
    int ne = LC3_NE(dt, sr);

    /* --- Mode and rate --- */

    bool lsb_mode  = nbytes >= 20 * (3 + sr);
    bool high_rate = nbytes >  20 * (1 + sr);

    /* --- Loop on quantized coefficients --- */

    int nbits = 0, nbits_lsb = 0;
    uint8_t state = 0;

    int nbits_end = 0;
    int n_end = 0;

    nbits_budget = nbits_budget ? nbits_budget * 2048 : INT_MAX;

    for (int i = 0, h = 0; h < 2; h++) {
        const uint8_t (*lut_coeff)[4] = lc3_spectrum_lookup[high_rate][h];

        for ( ; i < LC3_MIN(*n, (ne + 2) >> (1 - h))
                && nbits <= nbits_budget; i += 2) {

            const uint8_t *lut = lut_coeff[state];
            int a = LC3_ABS(x[i]), b = LC3_ABS(x[i+1]);

            /* --- Sign values --- */

            int s = (a != 0) + (b != 0);
            nbits += s * 2048;

            /* --- LSB values Reduce to 2*2 bits MSB values ---
             * Reduce to 2x2 bits MSB values. The LSB's pair are arithmetic
             * coded with an escape code followed by 1 bit for each values.
             * The LSB mode does not arthmetic code the first LSB,
             * add the sign of the LSB when one of pair was at value 1 */

            int k = 0;
            int m = (a | b) >> 2;

            if (m) {
                if (lsb_mode) {
                    nbits += lc3_spectrum_bits[lut[k++]][16] - 2*2048;
                    nbits_lsb += 2 + (a == 1) + (b == 1);
                }

                for (m >>= lsb_mode; m; m >>= 1, k++)
                    nbits += lc3_spectrum_bits[lut[LC3_MIN(k, 3)]][16];

                nbits += k * 2*2048;
                a >>= k;
                b >>= k;

                k = LC3_MIN(k, 3);
            }

            /* --- MSB values --- */

            nbits += lc3_spectrum_bits[lut[k]][a + 4*b];

            /* --- Update state --- */

            if (s && nbits <= nbits_budget) {
                n_end = i + 2;
                nbits_end = nbits;
            }

            state = (state << 4) + (k > 1 ? 12 + k : 1 + (a + b) * (k + 1));
        }
    }

    /* --- Return --- */

    *n = n_end;

    if (p_lsb_mode)
        *p_lsb_mode = lsb_mode &&
            nbits_end + nbits_lsb * 2048 > nbits_budget;

    if (p_high_rate)
        *p_high_rate = high_rate;

    if (nbits_budget >= INT_MAX)
        nbits_end += nbits_lsb * 2048;

    return (nbits_end + 2047) / 2048;
}

/**
 * Put quantized spectrum (cf. 3.3.13.4)
 * bits            Bitstream context
 * dt, sr          Duration and samplerate of the frame
 * x, n            Spectral quantized, and count of significant coefficients
 * lsb_mode        True when LSB's are not AC coded
 * high_rate       True when high bitrate mode selected
 */
static void put_quantized(
    lc3_bits_t *bits, enum lc3_dt dt, enum lc3_srate sr,
    const int16_t *x, int n, bool lsb_mode, bool rate)
{
    int ne = LC3_NE(dt, sr);

    /* --- Loop on quantized coefficients --- */

    uint8_t state = 0;

    for (int i = 0, h = 0; h < 2; h++) {
        const uint8_t (*lut_coeff)[4] = lc3_spectrum_lookup[rate][h];

        for ( ; i < LC3_MIN(n, (ne + 2) >> (1 - h)); i += 2) {

            const uint8_t *lut = lut_coeff[state];
            bool a_sign = x[i] < 0, b_sign = x[i+1] < 0;
            int a = LC3_ABS(x[i]), b = LC3_ABS(x[i+1]);

            /* --- LSB values Reduce to 2*2 bits MSB values ---
             * Reduce to 2x2 bits MSB values. The LSB's pair are arithmetic
             * coded with an escape code and 1 bits for each values.
             * The mode 1 discard the first LSB (at this step) */

            int m = (a | b) >> 2;
            int k = 0, lsb_count = 0;

            if (m) {

                if (lsb_mode)
                    lc3_put_symbol(bits,
                        lc3_spectrum_symbol[lut[k++]][16]);

                for (m >>= lsb_mode; m; m >>= 1, k++) {
                    lc3_put_bits(bits, (a >> k) & 1, 1);
                    lc3_put_bits(bits, (b >> k) & 1, 1);
                    lc3_put_symbol(bits,
                        lc3_spectrum_symbol[lut[LC3_MIN(k, 3)]][16]);
                }

                a >>= lsb_mode;
                b >>= lsb_mode;

                lsb_count = k - lsb_mode;
                k = LC3_MIN(k, 3);
            }

            /* --- Sign values --- */

            if (a) lc3_put_bits(bits, a_sign, 1);
            if (b) lc3_put_bits(bits, b_sign, 1);

            /* --- MSB values --- */

            a >>= lsb_count;
            b >>= lsb_count;

            lc3_put_symbol(bits, lc3_spectrum_symbol[lut[k]][a + 4*b]);

            /* --- Update state --- */

            state = (state << 4) + (k > 1 ? 12 + k : 1 + (a + b) * (k + 1));
        }
    }
}

/**
 * Put residual bits of quantization (cf. 3.3.13.4)
 * bits            Bitstream context
 * nbits           Maximum number of bits to output
 * xq, n           Spectral quantized, and count of significants
 * xf              Scaled spectral coefficients
 */
static void put_residual(lc3_bits_t *bits, int nbits,
    const int16_t *xq, int n, const float *xf)
{
    for (int i = 0; i < n && nbits > 0; i++) {

        if (xq[i] == 0)
            continue;

        lc3_put_bits(bits, xf[i] >= xq[i], 1);
        nbits--;
    }
}

/**
 * Put LSB values of quantized spectrum values (cf. 3.3.13.4)
 * bits            Bitstream context
 * nbits           Maximum number of bits to output
 * xq, n           Spectral quantized, and count of significants
 */
static void put_lsb(lc3_bits_t *bits, int nbits, const int16_t *x, int n)
{
    for (int i = 0; i < n && nbits > 0; i += 2) {

        bool a_sign = x[i] < 0, b_sign = x[i+1] < 0;
        int a = LC3_ABS(x[i]), b = LC3_ABS(x[i+1]);

        if ((a | b) >> 2 == 0)
            continue;

        if (nbits > 0)
            lc3_put_bits(bits, a & 1, 1), nbits--;

        if (nbits > 0 && a == 1)
            lc3_put_bits(bits, a_sign, 1), nbits--;

        if (nbits > 0)
            lc3_put_bits(bits, b & 1, 1), nbits--;

        if (nbits > 0 && b == 1)
            lc3_put_bits(bits, b_sign, 1), nbits--;
    }
}

/**
 * Quantize spectral coefficients
 */
void lc3_quant_perform(enum lc3_dt dt, enum lc3_srate sr,
    unsigned nbytes, bool pitch, const lc3_tns_data_t *tns,
    struct lc3_quant_state *state, float *x, struct lc3_quant_data *data)
{
    bool reset_off;

    /* --- Bit budget --- */

    const int nbits_gain = 8;
    const int nbits_nf = 3;

    int nbits_budget = 8*nbytes - get_nbits_ac(dt, sr, nbytes) -
        lc3_bwdet_get_nbits(sr) - lc3_ltpf_get_nbits(pitch) -
        lc3_sns_get_nbits() - lc3_tns_get_nbits(tns) - nbits_gain - nbits_nf;

    /* --- Global gain --- */

    float nbits_off = state->nbits_off + state->nbits_spare;
    nbits_off = fminf(fmaxf(nbits_off, -40), 40);
    nbits_off = 0.8 * state->nbits_off + 0.2 * nbits_off;

    int g_off = get_gain_offset(sr, nbytes);

    int g_int = estimate_gain(dt, sr,
        x, nbits_budget, nbits_off, g_off, &reset_off);

    /* --- Quantization --- */

    perform_quantization(dt, sr, g_int, x, data->x, &data->n);

    int nbits = compute_nbits(dt, sr, nbytes,
        data->x, &data->n, 0, NULL, NULL);

    state->nbits_off = reset_off ? 0 : nbits_off;
    state->nbits_spare = reset_off ? 0 : nbits_budget - nbits;

    /* --- Adjust gain and requantize --- */

    int g_adj = adjust_gain(sr, g_int + g_off, nbits, nbits_budget);

    if (g_adj)
        perform_quantization(dt, sr, g_adj, x, data->x, &data->n);

    data->g_idx = g_int + g_adj + g_off;
    nbits = compute_nbits(dt, sr, nbytes,
        data->x, &data->n, nbits_budget, &data->lsb_mode, &data->high_rate);
}

/**
 * Put Quantization side informations
 */
void lc3_quant_put_side(lc3_bits_t *bits,
    enum lc3_dt dt, enum lc3_srate sr, const struct lc3_quant_data *data)
{
    int ne = LC3_NE(dt, sr);
    int nbits_n = 4 + (ne > 32) + (ne > 64) + (ne > 128) + (ne > 256);

    lc3_put_bits(bits, LC3_MAX(data->n >> 1, 1) - 1, nbits_n);
    lc3_put_bits(bits, data->lsb_mode, 1);

    lc3_put_bits(bits, data->g_idx, 8);
}

/**
 * Put quantized spectrum data
 */
void lc3_quant_put_spectrum(
    lc3_bits_t *bits, enum lc3_dt dt, enum lc3_srate sr,
    const struct lc3_quant_data *data, const float *x)
{
    put_quantized(bits, dt, sr,
        data->x, data->n, data->lsb_mode, data->high_rate);

    int nbits_left = lc3_get_bits_left(bits);

    if (data->lsb_mode)
        put_lsb(bits, nbits_left, data->x, data->n);
    else
        put_residual(bits, nbits_left, data->x, data->n, x);
}
