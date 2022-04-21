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

#ifndef __WAVE_H
#define __WAVE_H

#include <stdio.h>
#include <stdint.h>


/**
 * Read WAVE file header
 * fp              Opened file, moved after header on return
 * samplerate      Return samplerate, in Hz
 * nchannels       Return number of channels
 * nframes         Return count of frames
 * return          0: Ok  -1: Bad or unsupported WAVE File
 */
int wave_read_header(FILE *fp, int *samplerate, int *nchannels, int *nframes);

/**
 * Read PCM samples from wave file
 * fp              Opened file
 * nch, count      Number of channels and count of frames to read
 * buffer          Output buffer of `nchannels * count` interleaved samples
 * return          Number of frames read
 */
int wave_read_pcm(FILE *fp, int nch, int count, int16_t *buffer);

/**
 * Write WAVE file header
 * fp              Opened file, moved after header on return
 * samplerate      Samplerate, in Hz
 * nchannels       Number of channels
 * nframes         Count of frames
 */
void wave_write_header(FILE *fp, int samplerate, int nchannels, int nframes);

/**
 * Write PCM samples to wave file
 * fp              Opened file
 * pcm, nch        PCM frames, as 'nch' interleaved samples
 * off, count      Offset and count of frames
 */
void wave_write_pcm(FILE *fp, const int16_t *pcm, int nch, int off, int count);


#endif /* __WAVE_H */
