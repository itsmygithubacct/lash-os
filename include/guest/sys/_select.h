#pragma once
/* Picolibc defaults to 64 descriptors; the loader provides 256 logical descriptors. */
#ifndef FD_SETSIZE
#define FD_SETSIZE 256
#endif
#include_next <sys/_select.h>
