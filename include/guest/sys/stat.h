#pragma once
#include_next <sys/stat.h>
#define UTIME_NOW ((1L << 30) - 1)
#define UTIME_OMIT ((1L << 30) - 2)
