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

#include <lc3.h>

#include "common.h"
#include "attdet.h"
#include "bwdet.h"
#include "ltpf.h"
#include "mdct.h"
#include "sns.h"
#include "tns.h"
#include "quant.h"
#include "noise.h"
#include "bits.h"


/**
 * Frame data
 */

struct frame_data {
    enum lc3_bandwidth bw;
    bool pitch_present;
    lc3_ltpf_data_t ltpf;
    lc3_sns_data_t sns;
    lc3_tns_data_t tns;
    lc3_quant_data_t quant;
    int noise_factor;
};


/**
 * Compute Energy estimation per band (cf 3.3.4.4)
 * dt, sr          Duration and samplerate of the frame
 * x               Input MDCT coefficient
 * e               Energy estimation per bands
 * return          True when high energy detected near Nyquist frequency
 */
static bool compute_energy_band(
    enum lc3_dt dt, enum lc3_srate sr, const float *x, float *e)
{
    static const int n1_table[LC3_NUM_DT][LC3_NUM_SRATE] = {
        [LC3_DT_7M5] = { 56, 34, 27, 24, 22 },
        [LC3_DT_10M] = { 49, 28, 23, 20, 18 },
    };

    /* First `n` bands are 1 coefficient width */

    int n1 = n1_table[dt][sr];
    float e_sum[2] = { 0, 0 };
    int iband;

    for (iband = 0; iband < n1; iband++) {
        *e = x[iband] * x[iband];
        e_sum[0] += *(e++);
    }

    /* Mean the square of coefficients within each band,
     * note that 7.5ms 8KHz frame has more bands than samples */

    int nb = LC3_MIN(LC3_NUM_BANDS, LC3_NS(dt, sr));
    int iband_h = nb - 2*(2 - dt);
    const int *lim = lc3_band_lim[dt][sr];

    for (int i = lim[iband]; iband < nb; iband++) {
        int ie = lim[iband+1];
        int n = ie - i;

        float sx2 = x[i] * x[i];
        for (i++; i < ie; i++)
            sx2 += x[i] * x[i];

        *e = sx2 / n;
        e_sum[iband >= iband_h] += *(e++);
    }

    for (; iband < LC3_NUM_BANDS; iband++)
        *(e++) = 0;

    /* Return the near nyquist flag */

    return e_sum[1] > 30 * e_sum[0];
}


/**
 * Analyse LC3 frame
 * encoder         Encoder state
 * nbytes          Size in bytes of the frame
 * frame           Return the frame data
 */
static void analyse_frame(struct lc3_encoder *encoder,
    unsigned nbytes, struct frame_data *frame)
{
    enum lc3_dt dt = encoder->dt;
    enum lc3_srate sr = encoder->sr;
    int ns = LC3_NS(dt, sr);
    int nd = LC3_ND(dt, sr);

    float *xs = encoder->xs + nd;
    float *xf = encoder->xf;

    /* --- Temporal --- */

    bool att = lc3_attdet_run(dt, sr, nbytes, &encoder->attdet, xs);

    frame->pitch_present =
        lc3_ltpf_analyse(dt, sr, &encoder->ltpf, xs, &frame->ltpf);

    /* --- Spectral --- */

    float e[LC3_NUM_BANDS];

    lc3_mdct_forward(dt, sr, xs, xf);
    memmove(xs - nd, xs + ns-nd, nd * sizeof(float));

    bool nn_flag = compute_energy_band(dt, sr, xf, e);
    if (nn_flag)
        lc3_ltpf_disable(&frame->ltpf);

    frame->bw = lc3_bwdet_run(dt, sr, e);

    lc3_sns_encode(dt, sr, e, att, &frame->sns, xf);

    lc3_tns_encode(dt, frame->bw, nn_flag, nbytes, &frame->tns, xf);

    lc3_quant_perform(dt, sr,
        nbytes, frame->pitch_present, &frame->tns,
        &encoder->quant, xf, &frame->quant);

    lc3_noise_estimate(dt, frame->bw,
        &frame->quant, xf, &frame->noise_factor);
}

/**
 * Encode LC3 bitstream
 * dt, sr          Duration and samplerate of the frame
 * frame           The frame data
 * xf              Scaled spectral coefficients
 * buffer, nbytes  Output bitstream buffer
 */
static void encode_bitstream(enum lc3_dt dt, enum lc3_srate sr,
    const struct frame_data *frame, const float *xf,
    void *buffer, unsigned nbytes)
{
    lc3_bits_t bits;

    lc3_setup_bits(&bits, buffer, nbytes);

    lc3_bwdet_put_bw(&bits, sr, frame->bw);

    lc3_quant_put_side(&bits, dt, sr, &frame->quant);

    lc3_tns_put_data(&bits, &frame->tns);

    lc3_put_bits(&bits, frame->pitch_present, 1);

    lc3_sns_put_data(&bits, &frame->sns);

    if (frame->pitch_present)
        lc3_ltpf_put_data(&bits, &frame->ltpf);

    lc3_noise_put_factor(&bits, frame->noise_factor);

    lc3_quant_put_spectrum(&bits, dt, sr, &frame->quant, xf);

    lc3_flush_bits(&bits);
}


/* ----------------------------------------------------------------------------
 *  Interface
 * -------------------------------------------------------------------------- */

/**
 * Resolve frame duration in us
 * us              Frame duration in us
 * return          Frame duration identifier, or LC3_NUM_DT
 */
static enum lc3_dt resolve_dt(int us)
{
    return us ==  7500 ? LC3_DT_7M5 :
           us == 10000 ? LC3_DT_10M : LC3_NUM_DT;
}

/**
 * Resolve samplerate in Hz
 * hz              Samplerate in Hz
 * return          Sample rate identifier, or LC3_NUM_SRATE
 */
static enum lc3_srate resolve_sr(int hz)
{
    return hz ==  8000 ? LC3_SRATE_8K  : hz == 16000 ? LC3_SRATE_16K :
           hz == 24000 ? LC3_SRATE_24K : hz == 32000 ? LC3_SRATE_32K :
           hz == 48000 ? LC3_SRATE_48K : LC3_NUM_SRATE;
}

/**
 * Return the number of PCM samples in a frame
 */
int lc3_frame_samples(int dt_us, int sr_hz)
{
    enum lc3_dt dt = resolve_dt(dt_us);
    enum lc3_srate sr = resolve_sr(sr_hz);

    if (dt >= LC3_NUM_DT || sr >= LC3_NUM_SRATE)
        return 0;

    return LC3_NS(dt, sr);
}

/**
 * Return the size of frames, from bitrate
 */
int lc3_frame_bytes(int dt_us, int bitrate)
{
    if (resolve_dt(dt_us) >= LC3_NUM_DT)
        return 0;

    if (bitrate < LC3_MIN_BITRATE)
        return LC3_MIN_FRAME_BYTES;

    if (bitrate > LC3_MAX_BITRATE)
        return LC3_MAX_FRAME_BYTES;

    int nbytes = ((unsigned)bitrate * dt_us) / (1000*1000*8);

    return LC3_CLIP(nbytes, LC3_MIN_FRAME_BYTES, LC3_MAX_FRAME_BYTES);
}

/**
 * Resolve the bitrate, from the size of frames
 */
int lc3_resolve_bitrate(int dt_us, int nbytes)
{
    if (resolve_dt(dt_us) >= LC3_NUM_DT)
        return 0;

    if (nbytes < LC3_MIN_FRAME_BYTES)
        return LC3_MIN_BITRATE;

    if (nbytes > LC3_MAX_FRAME_BYTES)
        return LC3_MAX_BITRATE;

    int bitrate = ((unsigned)nbytes * (1000*1000*8) + dt_us/2) / dt_us;

    return LC3_CLIP(bitrate, LC3_MIN_BITRATE, LC3_MAX_BITRATE);
}

/**
 * Return size needed for an encoder
 */
unsigned lc3_encoder_size(int dt_us, int sr_hz)
{
    if (resolve_dt(dt_us) >= LC3_NUM_DT ||
        resolve_sr(sr_hz) >= LC3_NUM_SRATE)
        return 0;

    return sizeof(struct lc3_encoder) +
        LC3_ENCODER_BUFFER_COUNT(dt_us, sr_hz) * sizeof(float);
}

/**
 * Setup encoder state
 */
struct lc3_encoder *lc3_setup_encoder(int dt_us, int sr_hz, void *mem)
{
    enum lc3_dt dt = resolve_dt(dt_us);
    enum lc3_srate sr = resolve_sr(sr_hz);

    if (dt >= LC3_NUM_DT || sr >= LC3_NUM_SRATE || !mem)
        return NULL;

    struct lc3_encoder *encoder = mem;
    int ns = LC3_NS(dt, sr);
    int nd = LC3_ND(dt, sr);

    *encoder = (struct lc3_encoder){
        .dt = dt, .sr = sr,
        .xs = encoder->s, .xf = encoder->s + ns+nd,
    };

    memset(encoder->s, 0,
        LC3_ENCODER_BUFFER_COUNT(dt_us, sr_hz) * sizeof(float));

    return encoder;
}

/**
 * Encode a frame
 */
int lc3_encode(struct lc3_encoder *encoder,
    const int16_t *pcm, int pitch, void *out, int nbytes)
{
    /* --- Check parameters --- */

    if (!encoder || nbytes < LC3_MIN_FRAME_BYTES
                 || nbytes > LC3_MAX_FRAME_BYTES)
        return -1;

    /* --- Processing --- */

    enum lc3_dt dt = encoder->dt;
    enum lc3_srate sr = encoder->sr;
    int ns = LC3_NS(dt, sr);
    int nd = LC3_ND(dt, sr);

    float *xs = encoder->xs + nd;
    float *xf = encoder->xf;
    struct frame_data frame;

    for (int i = 0; i < ns; i++)
        xs[i] = pcm[i*pitch];

    analyse_frame(encoder, nbytes, &frame);

    encode_bitstream(dt, sr, &frame, xf, out, nbytes);

    return 0;
}
