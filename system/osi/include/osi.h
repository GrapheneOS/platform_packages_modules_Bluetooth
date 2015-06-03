#pragma once

#include <stdbool.h>
#include <stdint.h>

#define UNUSED_ATTR __attribute__((unused))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define INVALID_FD (-1)

#define CONCAT(a, b) a##b

// Use during compile time to check conditional values
// NOTE: The the failures will present as a generic error
// "error: initialization makes pointer from integer without a cast"
// but the file and line number will present the condition that
// failed.
#define DUMMY_COUNTER(c) CONCAT(__osi_dummy_, c)
#define DUMMY_PTR DUMMY_COUNTER(__COUNTER__)

#define COMPILE_ASSERT(x) char * DUMMY_PTR = !(x)

typedef uint32_t timeout_t;

// Macros for safe integer to pointer conversion. In the C language, data is
// commonly cast to opaque pointer containers and back for generic parameter
// passing in callbacks. These macros should be used sparingly in new code
// (never in C++ code). Whenever integers need to be passed as a pointer, use
// these macros.
#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define INT_TO_PTR(i) ((void *) ((intptr_t) (i)))
