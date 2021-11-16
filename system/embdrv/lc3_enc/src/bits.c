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

#include "bits.h"
#include "common.h"


/**
 * Flush the bits accumulator
 * accu            Bitstream accumulator
 * buffer          Bitstream buffer
 */
static void accu_flush(struct lc3_bits_accu *accu,
    struct lc3_bits_buffer *buffer)
{
    unsigned nbytes = LC3_MIN(accu->n >> 3, buffer->nleft);

    accu->n -= 8 * nbytes;
    buffer->nleft -= nbytes;

    for ( ; nbytes; accu->v >>= 8, nbytes--)
        *(--buffer->p_bw) = accu->v & 0xff;

    if (accu->n >= 8)
        accu->n = 0;
}

/**
 * Arithmetic coder put byte
 * buffer          Bitstream buffer
 * byte            Byte to output
 */
static void ac_put(struct lc3_bits_buffer *buffer, unsigned byte)
{
    buffer->overflow |= (buffer->nleft_fw <= 0);
    if (buffer->overflow)
        return;

    *(buffer->p_fw++) = byte;
    buffer->nleft_fw--;
    buffer->nleft--;
}

/**
 * Arithmetic coder range shift
 * ac              Arithmetic coder
 * buffer          Bitstream buffer
 */
static void ac_shift(struct lc3_bits_ac *ac,
    struct lc3_bits_buffer *buffer)
{
    if (ac->low < 0xff0000 || ac->carry)
    {
        if (ac->cache >= 0)
            ac_put(buffer, ac->cache + ac->carry);

        for ( ; ac->carry_count > 0; ac->carry_count--)
            ac_put(buffer, ac->carry ? 0x00 : 0xff);

         ac->cache = ac->low >> 16;
         ac->carry = 0;
    }
    else
    {
         ac->carry_count++;
    }

    ac->low = (ac->low << 8) & 0xffffff;
}

/**
 * Arithmetic coder return range bits
 * ac              Arithmetic coder
 * return          1 + log2(ac->range)
 */
static int ac_get_range_bits(const struct lc3_bits_ac *ac)
{
    int nbits = 0;

    for (unsigned r = ac->range; r; r >>= 1, nbits++);

    return nbits;
}

/**
 * Arithmetic coder return pending bits
 * ac              Arithmetic coder
 * return          Pending bits
 */
static int ac_get_pending_bits(const struct lc3_bits_ac *ac)
{
    return 26 - ac_get_range_bits(ac) +
        ((ac->cache >= 0) + ac->carry_count) * 8;
}

/**
 * Arithmetic coder termination
 * ac              Arithmetic coder
 * buffer          Bitstream buffer
 * end_val/nbits   End value and count of bits to terminate (1 to 8)
 */
static void ac_terminate(struct lc3_bits_ac *ac,
    struct lc3_bits_buffer *buffer)
{
    int nbits = 25 - ac_get_range_bits(ac);
    unsigned mask = 0xffffff >> nbits;
    unsigned val  = ac->low + mask;
    unsigned high = ac->low + ac->range;

    bool over_val  = val  >> 24;
    bool over_high = high >> 24;

    val  = (val  & 0xffffff) & ~mask;
    high = (high & 0xffffff);

    if (over_val == over_high) {

        if (val + mask >= high) {
            nbits++;
            mask >>= 1;
            val = ((ac->low + mask) & 0xffffff) & ~mask;
        }

        ac->carry |= val < ac->low;
    }

    ac->low = val;

    for (; nbits > 8; nbits -= 8)
        ac_shift(ac, buffer);
    ac_shift(ac, buffer);

    int end_val = ac->cache >> (8 - nbits);

    if (ac->carry_count) {
        ac_put(buffer, ac->cache);
        for ( ; ac->carry_count > 1; ac->carry_count--)
            ac_put(buffer, 0xff);

        end_val = nbits < 8 ? 0 : 0xff;
    }

    if (buffer->nleft_fw > 0) {
        *buffer->p_fw &= 0xff >> nbits;
        *buffer->p_fw |= end_val << (8 - nbits);
    }
}

/**
 * Setup bitstream writing
 */
void lc3_setup_bits(struct lc3_bits *bits, void *buffer, unsigned len)
{
    *bits = (struct lc3_bits){

        .ac = {
            .range = 0xffffff,
            .cache = -1
        },

        .buffer = {
            .p_fw  = (uint8_t *)buffer,
            .p_bw  = (uint8_t *)buffer + len,
            .nleft_fw = len, .nleft = len
        }
    };
}

/**
 * Return number of bits left in the bitstream
 */
int lc3_get_bits_left(const struct lc3_bits *bits)
{
    int nbits_left = 8 * bits->buffer.nleft;
    nbits_left -= LC3_MIN(bits->accu.n, nbits_left);
    nbits_left -= LC3_MIN(ac_get_pending_bits(&bits->ac), nbits_left);

    return nbits_left;
}

/**
 * Flush and terminate bitstream
 */
void lc3_flush_bits(struct lc3_bits *bits)
{
    struct lc3_bits_ac *ac = &bits->ac;
    struct lc3_bits_accu *accu = &bits->accu;
    struct lc3_bits_buffer *buffer = &bits->buffer;

    for (int n = 8 * buffer->nleft - accu->n; n > 0; n -= 32)
        lc3_put_bits(bits, 0, LC3_MIN(n, 32));

    accu_flush(accu, buffer);

    ac_terminate(ac, buffer);
}

/**
 * Write from 0 to 32 bits,
 * exceeding the capacity of the accumulator
 */
void __lc3_put_bits_over(struct lc3_bits *bits, unsigned v, int n)
{
    struct lc3_bits_accu *accu = &bits->accu;

    /* --- Fullfill accumulator and flush -- */

    int n1 = LC3_MIN(ACCU_BITS - accu->n, n);
    if (n1) {
        accu->v |= v << accu->n;
        accu->n = ACCU_BITS;
    }

    accu_flush(accu, &bits->buffer);

    /* --- Accumulate remaining bits -- */

    accu->v = v >> n1;
    accu->n = n - n1;
}

/**
 * Arithmetic coder renormalization
 */
void __lc3_renorm_ac(struct lc3_bits *bits)
{
    struct lc3_bits_ac *ac = &bits->ac;

    for ( ; ac->range < 0x10000; ac->range <<= 8)
        ac_shift(ac, &bits->buffer);
}
