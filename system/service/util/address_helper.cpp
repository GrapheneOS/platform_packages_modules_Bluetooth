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

#include "service/util/address_helper.h"

#include <base/strings/string_split.h>

namespace util {

bool IsAddressValid(const std::string& address) {
  if (address.length() != 17)
    return false;

  std::vector<std::string> byte_tokens;
  base::SplitString(address, ':', &byte_tokens);

  if (byte_tokens.size() != 6)
    return false;

  for (const auto& token : byte_tokens) {
    if (token.length() != 2)
      return false;

    if (!std::isalpha(token[0]) && !std::isdigit(token[0]))
      return false;

    if (!std::isalpha(token[1]) && !std::isdigit(token[1]))
      return false;
  }

  return true;
}

}  // namespace util
