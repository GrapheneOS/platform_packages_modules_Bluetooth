/*
 * Copyright (C) 2021 The Android Open Source Project
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
#include <fuzzer/FuzzedDataProvider.h>

#include "../Api/Lc3Encoder.hpp"

using FrameDuration = Lc3Config::FrameDuration;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  uint16_t fs = fdp.PickValueInArray({8000, 16000, 24000, 32000, 44100, 48000});
  FrameDuration fd =
      fdp.PickValueInArray({FrameDuration::d10ms, FrameDuration::d7p5ms});
  uint16_t output_byte_count = fdp.ConsumeIntegralInRange(20, 400);

  Lc3Config config(fs, fd, 1);
  if (config.getErrorStatus() != Lc3Config::ERROR_FREE) {
    return 0;
  }

  uint16_t num_frames = config.NF * config.Nc;

  if (fdp.remaining_bytes() < num_frames * 2) {
    return 0;
  }

  std::vector<uint16_t> input_frames(num_frames);

  fdp.ConsumeData(input_frames.data(),
                  input_frames.size() * 2 /* each frame is 2 bytes */);

  Lc3Encoder encoder(config);

  std::vector<uint8_t> output(output_byte_count);
  encoder.run((const int16_t*)input_frames.data(), output_byte_count,
              output.data());
  return 0;
}