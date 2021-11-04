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
 * LC3 - Bitstream management
 *
 * The bitstream is written by the 2 ends of the buffer :
 *
 * - Arthmetic coder put bits while increasing memeory addresses
 *   in the buffer (forward)
 *
 * - Plain bits are puts starting the end of the buffer, whith memeory
 *   adresses decreasing (backward)
 *
 *       .----------------------------------------------------.
 *       | ooooooooooooooooooo :         : xxxxxxxxxxxxxxxxxx |
 *       '----------------------------------------------------'
 *       |---------------------> - - - - - - - - - - - - - - >|
 *                              |< - - - <--------------------|
 *          Arithmetic coding                  Plain bits
 *          `lc3_put_symbol()`               `lc3_put_bits()`
 *
 * - The forward writing is protected against buffer overflow, it cannot
 *   write after the buffer, but can overwrite plain bits previously
 *   written in the buffer.
 *
 * - The backward writing is protected against overwrite of the arithmetic
 *   coder bitstream. In such way, the backward bitstream is always limited
 *   by the aritmetic coder bitstream, and can be overwritten by him.
 *
 *
 * Reference : Low Complexity Communication Codec (LC3)
 *             Bluetooth Specification v1.0
 *
 */

#ifndef __LC3_BITS_H
#define __LC3_BITS_H

#include "common.h"


/**
 * Bitstream context
 */

#define ACCU_BITS (int)(8 * sizeof(unsigned))

struct lc3_bits_accu {
    unsigned v;
    int n;
};

struct lc3_bits_ac {
    unsigned low, range;
    int cache, carry, carry_count;
};

struct lc3_bits_buffer {
    uint8_t *p_fw, *p_bw;
    int nleft_fw, nleft;
    bool overflow;
};

typedef struct lc3_bits {
    struct lc3_bits_ac ac;
    struct lc3_bits_accu accu;
    struct lc3_bits_buffer buffer;
} lc3_bits_t;


/**
 * Arithmetic coder symbol interval
 */

struct lc3_ac_symbol {
    unsigned low   : 16;
    unsigned range : 16;
};


/**
 * Setup bitstream writing
 * bits            Bitstream context
 * buffer, len     Output buffer and length (in bytes)
 */
void lc3_setup_bits(lc3_bits_t *bits, void *buffer, unsigned len);

/**
 * Return number of bits left in the bitstream
 * bits            Bitstream context
 * return          Number of bits left
 */
int lc3_get_bits_left(const lc3_bits_t *bits);

/**
 * Put from 1 to 32 bits
 * bits            Bitstream context
 * v, n            Value, in range 0 to 2^n - 1, and bits count (1 to 32)
 */
static inline void lc3_put_bits(lc3_bits_t *bits, unsigned v, int n);

/**
 * Put arithmetic coder symbol
 * bits            Bitstream context
 * symbol          Symbol interval
 */
static inline void lc3_put_symbol(
    lc3_bits_t *bits, struct lc3_ac_symbol symbol);

/**
 * Flush and terminate bitstream
 * bits            Bitstream context
 */
void lc3_flush_bits(lc3_bits_t *bits);


/* ----------------------------------------------------------------------------
 *  Inline implementations
 * -------------------------------------------------------------------------- */

void __lc3_put_bits_over(lc3_bits_t *bits, unsigned v, int n);
void __lc3_renorm_ac(lc3_bits_t *bits);

/**
 * Put from 0 to 32 bits
 */
static inline void lc3_put_bits(struct lc3_bits *bits, unsigned v, int n)
{
    if (n <= 0)
        return;

    if (bits->accu.n + n <= ACCU_BITS) {
        bits->accu.v |= v << bits->accu.n;
        bits->accu.n += n;
    } else {
        __lc3_put_bits_over(bits, v, n);
    }
}

/**
 * Put arithmetic coder symbol
 */
static inline void lc3_put_symbol(
    struct lc3_bits *bits, struct lc3_ac_symbol symbol)
{
    struct lc3_bits_ac *ac = &bits->ac;
    unsigned range = ac->range >> 10;

    ac->low += range * symbol.low;
    ac->range = range * symbol.range;

    ac->carry |= ac->low >> 24;
    ac->low &= 0xffffff;

    if (ac->range < 0x10000)
        __lc3_renorm_ac(bits);
}

#endif /* __LC3_BITS_H */
