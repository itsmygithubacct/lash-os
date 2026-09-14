#pragma once
#include <stdint.h>
#undef major
#undef minor
#undef makedev
#define major(d)                                                                                   \
    ((unsigned int)((((uint64_t)(d) >> 8) & 0xfff) | (((uint64_t)(d) >> 32) & 0xfffff000)))
#define minor(d) ((unsigned int)(((uint64_t)(d) & 0xff) | (((uint64_t)(d) >> 12) & 0xffffff00)))
#define makedev(maj, min)                                                                          \
    ((uint64_t)(((min) & 0xff) | (((uint64_t)(maj) & 0xfff) << 8) |                                \
                (((uint64_t)(min) & ~0xffULL) << 12) | (((uint64_t)(maj) & ~0xfffULL) << 32)))
