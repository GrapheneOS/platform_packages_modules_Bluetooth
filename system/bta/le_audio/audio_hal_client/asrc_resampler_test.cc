/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <iostream>

#include "audio_source_hal_asrc.cc"

namespace bluetooth::hal {
void NocpIsoClocker::Register(NocpIsoHandler*) {}
void NocpIsoClocker::Unregister() {}
}  // namespace bluetooth::hal

namespace le_audio {

class SourceAudioHalAsrcTest : public SourceAudioHalAsrc {
 public:
  SourceAudioHalAsrcTest(int channels, int bitdepth)
      : SourceAudioHalAsrc(channels, 48000, bitdepth, 10000) {}

  template <typename T>
  void Resample(double ratio, const T* in, size_t in_length, size_t* in_count,
                T* out, size_t out_length, size_t* out_count) {
    auto resamplers = *resamplers_;
    auto channels = resamplers.size();
    unsigned sub_q26;

    for (auto& r : resamplers)
      r.Resample(round(ldexp(ratio, 26)), in, channels, in_length / channels,
                 in_count, out, channels, out_length / channels, out_count,
                 &sub_q26);
  }
};

extern "C" void resample_i16(int channels, int bitdepth, double ratio,
                             const int16_t* in, size_t in_length, int16_t* out,
                             size_t out_length) {
  size_t in_count, out_count;

  SourceAudioHalAsrcTest(channels, bitdepth)
      .Resample<int16_t>(ratio, in, in_length, &in_count, out, out_length,
                         &out_count);

  if (out_count < out_length)
    fprintf(stderr, "wrong output size: %zd:%zd %zd:%zd\n", in_length, in_count,
            out_length, out_count);

  return;
}

extern "C" void resample_i32(int channels, int bitdepth, double ratio,
                             const int32_t* in, size_t in_length, int32_t* out,
                             size_t out_length) {
  size_t in_count, out_count;

  SourceAudioHalAsrcTest(channels, bitdepth)
      .Resample<int32_t>(ratio, in, in_length, &in_count, out, out_length,
                         &out_count);

  if (out_count < out_length)
    fprintf(stderr, "wrong output size: %zd:%zd %zd:%zd\n", in_length, in_count,
            out_length, out_count);

  return;
}

}  // namespace le_audio
