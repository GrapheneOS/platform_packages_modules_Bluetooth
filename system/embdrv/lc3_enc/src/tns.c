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

#include "tns.h"
#include "tables.h"


/**
 * Return dot product of 2 vectors
 * a, b, n         The 2 vectors of size `n`
 * return          sum( a[i] * b[i] ), i = [0..n-1]
 */
static inline float dot(const float *a, const float *b, int n)
{
    float v = 0;

    while (n--)
        v += *(a++) * *(b++);

    return v;
}

/**
 * LPC Coefficients (cf. 3.3.8.2)
 * dt, bw          Duration and bandwith of the frame
 * x               Spectral coefficients
 * gain, a         Output the prediction gains and LPC coefficients
 * lim             Return limits of the 1 or 2 filters
 * return          Number of filters
 */
static int compute_lpc_coeffs(enum lc3_dt dt, enum lc3_bandwidth bw,
    const float *x, float *gain, float (*a)[9], int *lim)
{
    static const int sub_7m5_nb[]   = {  9, 26,  43,  60 };
    static const int sub_7m5_wb[]   = {  9, 46,  83, 120 };
    static const int sub_7m5_sswb[] = {  9, 66, 123, 180 };
    static const int sub_7m5_swb[]  = {  9, 46,  82, 120, 159, 200, 240 };
    static const int sub_7m5_fb[]   = {  9, 56, 103, 150, 200, 250, 300 };

    static const int sub_10m_nb[]   = { 12, 34,  57,  80 };
    static const int sub_10m_wb[]   = { 12, 61, 110, 160 };
    static const int sub_10m_sswb[] = { 12, 88, 164, 240 };
    static const int sub_10m_swb[]  = { 12, 61, 110, 160, 213, 266, 320 };
    static const int sub_10m_fb[]   = { 12, 74, 137, 200, 266, 333, 400 };

    static const float lag_window[] = {
        1.00000000e+00, 9.98028026e-01, 9.92135406e-01, 9.82391584e-01,
        9.68910791e-01, 9.51849807e-01, 9.31404933e-01, 9.07808230e-01,
        8.81323137e-01
    };

    const int *sub = (const int * const [LC3_NUM_DT][LC3_NUM_SRATE]){
        { sub_7m5_nb, sub_7m5_wb, sub_7m5_sswb, sub_7m5_swb, sub_7m5_fb },
        { sub_10m_nb, sub_10m_wb, sub_10m_sswb, sub_10m_swb, sub_10m_fb },
    }[dt][bw];

    int nfilters = 1 + (bw >= LC3_BANDWIDTH_SWB);

    /* --- Normalized autocorrelation --- */

    const float *xs, *xe = x + *sub;
    float r[2][9];

    for (int f = 0; f < nfilters; f++) {
        float c[9][3];

        lim[f] = *sub;

        for (int s = 0; s < 3; s++) {
            xs = xe, xe = x + *(++sub);

            for (int k = 0; k < 9; k++)
                c[k][s] = dot(xs, xs + k, (xe - xs) - k);
        }

        float e0 = c[0][0], e1 = c[0][1], e2 = c[0][2];

        r[f][0] = 3;
        for (int k = 1; k < 9; k++)
            r[f][k] = e0 == 0 || e1 == 0 || e2 == 0 ? 0 :
                (c[k][0]/e0 + c[k][1]/e1 + c[k][2]/e2) * lag_window[k];
    }

    lim[nfilters] = *sub;

    /* --- Levinson-Durbin recursion --- */

    for (int f = 0; f < nfilters; f++) {
        float *a0 = a[f], a1[9];
        float err = r[f][0], rc;

        gain[f] = err;

        a0[0] = 1;
        for (int k = 1; k < 9; ) {

            rc = -r[f][k];
            for (int i = 1; i < k; i++)
                rc -= a0[i] * r[f][k-i];

            rc /= err;
            err *= 1 - rc * rc;

            for (int i = 1; i < k; i++)
                a1[i] = a0[i] + rc * a0[k-i];
            a1[k++] = rc;

            rc = -r[f][k];
            for (int i = 1; i < k; i++)
                rc -= a1[i] * r[f][k-i];

            rc /= err;
            err *= 1 - rc * rc;

            for (int i = 1; i < k; i++)
                a0[i] = a1[i] + rc * a1[k-i];
            a0[k++] = rc;
        }

        gain[f] /= err;
    }

    return nfilters;
}

/**
 * LPC Weighting (cf. 3.3.8.2)
 * gain, a         Prediction gain and LPC coefficients, weighted as output
 */
static void do_lpc_weighting(float pred_gain, float *a)
{
    float gamma = 1. - (1. - 0.85) * (2. - pred_gain) / (2. - 1.5), g = 1;
    for (int i = 1; i < 9; i++)
        a[i] *= (g *= gamma);
}

/**
 * LPC reflection (cf. 3.3.8.2)
 * a               LPC coefficients
 * rc              Output refelection coefficients
 */
static void do_lpc_reflection(const float *a, float *rc)
{
    float e, b[2][7], *b0, *b1;

    rc[7] = a[1+7];
    e = 1 - rc[7] * rc[7];

    b1 = b[1];
    for (int i = 0; i < 7; i++)
        b1[i] = (a[1+i] - rc[7] * a[7-i]) / e;

    for (int k = 6; k > 0; k--) {
        b0 = b1, b1 = b[k & 1];

        rc[k] = b0[k];
        e = 1 - rc[k] * rc[k];

        for (int i = 0; i < k; i++)
            b1[i] = (b0[i] - rc[k] * b0[k-1-i]) / e;
    }

    rc[0] = b1[0];
}

/**
 * Quantization (cf. 3.3.8.3)
 * rc              Refelection coefficients
 * rc_order        Return order of coefficients
 * rc_i, rc_q      Return quantized indexes and values
 */
static void do_quantization(
    const float *rc, int *rc_order, int *rc_i, float *rc_q)
{
    /* Qauntization tables :
     *   Q_THR = sin(delta * (i + 0.5)) , delta = Pi / 17
     *   Q_INV = sin(delta * (i       )   i = [0..7]      */

    static float q_thr[] = {
        9.22683595e-02, 2.73662990e-01, 4.45738356e-01, 6.02634636e-01,
        7.39008917e-01, 8.50217136e-01, 9.32472229e-01, 9.82973100e-01
    };

    static float q_inv[] = {
        0.00000000e+00, 1.83749517e-01, 3.61241664e-01, 5.26432173e-01,
        6.73695641e-01, 7.98017215e-01, 8.95163302e-01, 9.61825645e-01,
        9.95734176e-01
    };

    /* --- Resolve quantized value and order --- */

    *rc_order = 8;

    for (int i = 0; i < 8; i++) {
        bool neg = rc[i] < 0;
        float rc_m = fabsf(rc[i]);

        rc_i[i] = 4 * (rc_m >= q_thr[4]);
        for (int j = 0; j < 4 && rc_m >= q_thr[rc_i[i]]; j++, rc_i[i]++);

        rc_q[i] = q_inv[rc_i[i]];

        if (neg) {
            rc_i[i] = -rc_i[i];
            rc_q[i] = -rc_q[i];
        }

        *rc_order = rc_i[i] != 0 ? 8 : *rc_order - 1;
    }
}

/**
 * Filtering (cf. 3.3.8.4) Template
 * st              State of filter, as 8 values initialized to 0
 * rc_order, rc    Order of coefficients, and quantized coefficients
 * rc              Quantized coefficients for each filters
 * x, n            Spectral coefficients and count, filtered as output
 */
static inline void do_filtering_template(float *st,
    const int rc_order, const float *rc, float *x, int n)
{
    for (const float *xe = x + n; x < xe; ) {
        float xi = *x;
        float s0, s1 = xi;

        for (int k = 0; k < rc_order; k++) {
            s0 = st[k];
            st[k] = s1;

            s1  = rc[k] * xi + s0;
            xi += rc[k] * s0;
        }

        *(x++) = xi;
    }
}

/**
 * Filtering implementations for filter orders
 */

static void do_filtering_o1(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 1, rc, x, n);
}

static void do_filtering_o2(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 2, rc, x, n);
}

static void do_filtering_o3(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 3, rc, x, n);
}

static void do_filtering_o4(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 4, rc, x, n);
}

static void do_filtering_o5(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 5, rc, x, n);
}

static void do_filtering_o6(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 6, rc, x, n);
}

static void do_filtering_o7(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 7, rc, x, n);
}

static void do_filtering_o8(float *st, const float *rc, float *x, int n)
{
    do_filtering_template(st, 8, rc, x, n);
}

static void (* const do_filtering[])(float *, const float *, float *, int) =
{
    do_filtering_o1, do_filtering_o2, do_filtering_o3, do_filtering_o4,
    do_filtering_o5, do_filtering_o6, do_filtering_o7, do_filtering_o8
};

/**
 * TNS encoding processing
 */
void lc3_tns_encode(enum lc3_dt dt, enum lc3_bandwidth bw,
    bool nn_flag, unsigned nbytes, struct lc3_tns_data *data, float *x)
{
    /* Processing steps :
     * - Determine the LPC (Linear Predictive Coding) Coefficients
     * - Check is the filtering is disabled
     * - The coefficients are weighted on low bitrates and predicition gain
     * - Convert to reflection coefficients and quantize
     * - Finally filter the spectral coefficients */

    float pred_gain[2], a[2][9];
    float f_state[8] = { 0 };
    int f_lim[3];

    data->nfilters = compute_lpc_coeffs(dt, bw, x, pred_gain, a, f_lim);

    for (int f = 0; f < data->nfilters; f++) {
        float rc[8];

        data->rc_order[f] = 0;
        if (nn_flag || pred_gain[f] <= 1.5)
            continue;

        data->lpc_weighting[f] = nbytes < (dt == LC3_DT_7M5 ? 360/8 : 480/8);
        if (data->lpc_weighting[f] && pred_gain[f] < 2)
            do_lpc_weighting(pred_gain[f], a[f]);

        do_lpc_reflection(a[f], rc);

        do_quantization(rc, &data->rc_order[f], data->rc[f], rc);
        if (!data->rc_order[f])
            continue;

        do_filtering[data->rc_order[f]-1](
            f_state, rc, x + f_lim[f], f_lim[f+1] - f_lim[f]);
    }
}

/**
 * Bit consumption of bitstream data
 */
int lc3_tns_get_nbits(const struct lc3_tns_data *data)
{
    int nbits = 0;

    for (int f = 0; f < data->nfilters; f++) {

        int nbits_2048 = 2048;
        int rc_order = data->rc_order[f];

        nbits_2048 += rc_order > 0 ? lc3_tns_order_bits
            [data->lpc_weighting[f]][rc_order-1] : 0;

        for (int i = 0; i < rc_order; i++)
            nbits_2048 += lc3_tns_coeffs_bits[i][8 + data->rc[f][i]];

        nbits += (nbits_2048 + (1 << 11) - 1) >> 11;
    }

    return nbits;
}

/**
 * Put TNS data
 * bits            Bitstream context
 * data            TNS data
 */
void lc3_tns_put_data(lc3_bits_t *bits, const struct lc3_tns_data *data)
{
    for (int f = 0; f < data->nfilters; f++) {
        int rc_order = data->rc_order[f];

        lc3_put_bits(bits, rc_order > 0, 1);
        if (rc_order <= 0)
            continue;

        lc3_put_symbol(bits,
            lc3_tns_order_symbol[data->lpc_weighting[f]][rc_order-1]);

        for (int i = 0; i < rc_order; i++)
            lc3_put_symbol(bits, lc3_tns_coeffs_symbol[i][8 + data->rc[f][i]]);
    }
}
