#pragma once
#include_next <sys/wait.h>
#ifndef WIFCONTINUED
#define WIFCONTINUED(status) ((status) == 0xffff)
#endif

#define __WALL 0x40000000
