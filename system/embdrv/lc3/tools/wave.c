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

#include <stdint.h>
#include "wave.h"


/**
 * Id formatting
 */

#define __WAVE_ID(s) \
    (uint32_t)( s[0] | (s[1] << 8) | (s[2] << 16) | (s[3] << 24) )


/**
 * File format statement
 * | type_id     WAVE_FILE_TYPE_ID
 * | size        File size - 8 bytes
 * | type_id     WAVE_FILE_FMT_ID
 */

#define WAVE_FILE_TYPE_ID  __WAVE_ID("RIFF")
#define WAVE_FILE_FMT_ID   __WAVE_ID("WAVE")

struct wave_file {
    uint32_t type_id;
    uint32_t size;
    uint32_t fmt_id;
};


/**
 * Audio format statement
 * | id          WAVE_FORMAT_ID
 * | size        Size of the block - 8 bytes (= 16 bytes)
 * | format      WAVE_FORMAT_PCM
 * | channels    Number of channels
 * | samplerate  Sampling rate
 * | byterate    Bytes per secondes = `samplerate * framesize`
 * | framesize   Bytes per sampling time = `channels * bitdepth / 8`
 * | bitdepth    Number of bits per sample
 */

#define WAVE_FORMAT_ID   __WAVE_ID("fmt ")
#define WAVE_FORMAT_PCM  1

struct wave_format {
    uint32_t id;
    uint32_t size;
    uint16_t fmt;
    uint16_t channels;
    uint32_t samplerate;
    uint32_t byterate;
    uint16_t framesize;
    uint16_t bitdepth;
};


/**
 * Audio data statement
 * | id          WAV_DATA_ID
 * | size        Size of the data following
 */

#define WAVE_DATA_ID  __WAVE_ID("data")

struct wave_data {
    uint32_t id;
    uint32_t size;
};


/**
 * Read WAVE file header
 */
int wave_read_header(FILE *fp,
    int *samplerate, int *nchannels, int *nframes)
{
    struct wave_file file;
    struct wave_format format;
    struct wave_data data;

    if (fread(&file, sizeof(file), 1, fp) != 1
            || file.type_id != WAVE_FILE_TYPE_ID
            || file.fmt_id  != WAVE_FILE_FMT_ID)
        return -1;

    if (fread(&format, sizeof(format), 1, fp) != 1
            || format.id        != WAVE_FORMAT_ID
            || format.fmt       != WAVE_FORMAT_PCM
            || format.byterate  != format.samplerate * format.framesize
            || format.framesize != format.channels * format.bitdepth / 8
            || format.bitdepth  != 16)
        return -1;

    fseek(fp, sizeof(format) - (8 + format.size), SEEK_CUR);

    if (fread(&data, sizeof(data), 1, fp) != 1
            || data.id != WAVE_DATA_ID)
        return -1;

    *nchannels = format.channels;
    *samplerate = format.samplerate;
    *nframes = data.size / format.framesize;

    return 0;
}

/**
 * Read PCM samples from wave file
 */
int wave_read_pcm(FILE *fp, int nch, int count, int16_t *buffer)
{
    return fread(buffer, nch * sizeof(*buffer), count, fp);
}

/**
 * Write WAVE file header
 */
void wave_write_header(FILE *fp, int samplerate, int nchannels, int nframes)
{
    struct {
        struct wave_file file;
        struct wave_format format;
        struct wave_data data;
    } header;

    long data_size = nchannels * nframes * sizeof(uint16_t);
    long file_size = sizeof(header) + data_size;

    header.file = (struct wave_file){
        WAVE_FILE_TYPE_ID, file_size - 8,
        .fmt_id = WAVE_FILE_FMT_ID
    };

    header.format = (struct wave_format){
        WAVE_FORMAT_ID, sizeof(header.format) - 8,
        .fmt = WAVE_FORMAT_PCM,
        .channels = nchannels,
        .samplerate = samplerate,
        .byterate = samplerate * nchannels * sizeof(int16_t),
        .framesize = nchannels * sizeof(int16_t),
        .bitdepth = sizeof(int16_t) * 8,
    };

    header.data = (struct wave_data){
        WAVE_DATA_ID, data_size
    };

    fwrite(&header, sizeof(header), 1, fp);
}

/**
 * Write PCM samples to wave file
 */
void wave_write_pcm(FILE *fp,
    const int16_t *pcm, int nch, int off, int count)
{
    fwrite(pcm + nch * off, nch * sizeof(*pcm), count, fp);
}
