#pragma once
#include_next <glob.h>
#define GLOB_ABORTED GLOB_ABEND
#define GLOB_NOESCAPE 0x2000
#define GLOB_PERIOD 0x4000
#define GLOB_TILDE_CHECK 0x8000
