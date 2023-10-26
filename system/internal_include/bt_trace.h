/******************************************************************************
 *
 *  Copyright 1999-2012 Broadcom Corporation
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

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static const char BTE_LOGMSG_MODULE[] = "bte_logmsg_module";

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus

#include <array>
#include <iomanip>
#include <sstream>
#include <type_traits>

#include "check.h"
#include "os/logging/log_adapter.h"

/* Prints integral parameter x as hex string, with '0' fill */
template <typename T>
std::string loghex(T x) {
  static_assert(std::is_integral<T>::value,
                "loghex parameter must be integral.");
  std::stringstream tmp;
  tmp << std::showbase << std::internal << std::hex << std::setfill('0')
      << std::setw((sizeof(T) * 2) + 2) << +x;
  return tmp.str();
}

/* Prints integral array as hex string, with '0' fill */
template <typename T, size_t N>
std::string loghex(std::array<T, N> array) {
  static_assert(std::is_integral<T>::value,
                "type stored in array must be integral.");
  std::stringstream tmp;
  for (const auto& x : array) {
    tmp << std::internal << std::hex << std::setfill('0')
        << std::setw((sizeof(uint8_t) * 2) + 2) << +x;
  }
  return tmp.str();
}

/**
 * Obtains the string representation of a boolean value.
 *
 * @param value the boolean value to use
 * @return the string representation of the boolean value: "true" or "false"
 */
inline std::string logbool(bool value) {
  std::stringstream tmp;
  tmp << std::boolalpha << value;
  return tmp.str();
}

/**
 * Append a field name to a string.
 *
 * The field names are added to the string with "|" in between.
 *
 * @param p_result a pointer to the result string to add the field name to
 * @param append if true the field name will be added
 * @param name the field name to add
 * @return the result string
 */
inline std::string& AppendField(std::string* p_result, bool append,
                                const std::string& name) {
  CHECK(p_result != nullptr);
  if (!append) return *p_result;
  if (!p_result->empty()) *p_result += "|";
  *p_result += name;
  return *p_result;
}

// This object puts the stream in a state where every time that a new line
// occurs, the next line is indented a certain number of spaces. The stream is
// reset to its previous state when the object is destroyed.
class ScopedIndent {
 public:
  ScopedIndent(std::ostream& stream, int indent_size = DEFAULT_TAB)
      : indented_buf_(stream, indent_size) {
    old_stream_ = &stream;
    old_stream_buf_ = stream.rdbuf();
    stream.rdbuf(&indented_buf_);
  }

  ~ScopedIndent() { old_stream_->rdbuf(old_stream_buf_); }

  static const size_t DEFAULT_TAB = 2;

 private:
  class IndentedStreamBuf : public std::streambuf {
   public:
    IndentedStreamBuf(std::ostream& stream, int indent_size)
        : wrapped_buf_(stream.rdbuf()),
          indent_size_(indent_size),
          indent_next_line_(true){};

   protected:
    virtual int overflow(int character) override {
      if (indent_next_line_ && character != '\n') {
        for (int i = 0; i < indent_size_; i++) wrapped_buf_->sputc(' ');
      }

      indent_next_line_ = false;
      if (character == '\n') {
        indent_next_line_ = true;
      }

      return wrapped_buf_->sputc(character);
    }

   private:
    std::streambuf* wrapped_buf_;
    int indent_size_;
    bool indent_next_line_;
  };

  std::ostream* old_stream_;
  std::streambuf* old_stream_buf_;
  IndentedStreamBuf indented_buf_;
};

#endif
