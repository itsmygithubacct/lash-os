#pragma once
#include_next <spawn.h>
#ifndef POSIX_SPAWN_SETSID
#define POSIX_SPAWN_SETSID 128
#endif
int posix_spawn_file_actions_addclosefrom_np(posix_spawn_file_actions_t *, int);
