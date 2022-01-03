/******************************************************************************
 *
 *  Copyright 2021 The Android Open Source Project
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

#ifndef __LC3_OWN_FFT_H
#define __LC3_OWN_FFT_H

#include <stdbool.h>

/**
 * Complex floating point number
 */

struct fft_complex {
  float re, im;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Perform FFT
 * inverse         True on inverse transform else forward
 * x, y0, y1       Input, and 2 scratch buffers of size `n`
 * n               Number of points 30, 40, 60, 80, 90, 120, 160, 180, 240
 * return          The buffer `y0` or `y1` that hold the result
 *
 * Input `x` can be the same as the `y0` second scratch buffer
 */
struct fft_complex* fft(bool inverse, const struct fft_complex* x, int n,
                        struct fft_complex* y0, struct fft_complex* y1);

#ifdef __cplusplus
}
#endif

#endif /* __LC3_OWN_FFT_H */