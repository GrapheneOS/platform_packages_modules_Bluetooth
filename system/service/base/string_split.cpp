//
//  Copyright (C) 2015 Google, Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at:
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//
#include "string_split.h"

namespace base {

std::vector<std::string> SplitString(const std::string& input, char delimiter) {
  std::vector<std::string> output;
  size_t token_start = 0;
  for (size_t i = 0; i <= input.size(); ++i) {
    // Token is the whole string if no delimiter found.
    if (i == input.size() || input[i] == delimiter) {
      size_t token_length = i - token_start;
      // Qualified tokens: substring, end text after token, non-empty whole input.
      if (i != input.size() || !output.empty() || token_length)
        output.emplace_back(input, token_start, token_length);
      token_start = i + 1;
    }
  }
  return output;
}

}  // namespace base
