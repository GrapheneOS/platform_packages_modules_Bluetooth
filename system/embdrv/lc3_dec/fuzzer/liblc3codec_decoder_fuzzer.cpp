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

#include "../Api/Lc3Decoder.hpp"

using FrameDuration = Lc3Config::FrameDuration;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  uint16_t fs = fdp.PickValueInArray({8000, 16000, 24000, 32000, 44100, 48000});
  FrameDuration fd =
      fdp.PickValueInArray({FrameDuration::d10ms, FrameDuration::d7p5ms});
  uint8_t bfi = fdp.ConsumeIntegralInRange(0, 1);
  uint8_t bec_detect = fdp.ConsumeIntegralInRange(0, 1);

  uint16_t input_byte_count = fdp.ConsumeIntegralInRange(20, 400);

  if (fdp.remaining_bytes() < input_byte_count) {
    return 0;
  }

  std::vector<uint8_t> encoded_bytes(input_byte_count);

  fdp.ConsumeData(encoded_bytes.data(), encoded_bytes.size());

  uint16_t output_frame_count = Lc3Config(fs, fd, 1).NF;
  std::vector<uint16_t> decoded_data(output_frame_count * 2);

  Lc3Decoder decoder(fs, fd);
  decoder.run(encoded_bytes.data(), encoded_bytes.size(), bfi,
              (int16_t*)decoded_data.data(), output_frame_count, bec_detect, 0);

  return 0;
}