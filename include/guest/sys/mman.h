#pragma once
#include_next <sys/mman.h>
int memfd_create(const char *, unsigned);

int mlock(const void *, size_t);
int munlock(const void *, size_t);
int mlockall(int);
int munlockall(void);

#define MREMAP_MAYMOVE 1
#define MREMAP_FIXED 2
#define MCL_CURRENT 1
#define MCL_FUTURE 2
void *mremap(void *, size_t, size_t, int, ...);
int mincore(void *, size_t, unsigned char *);
int shm_open(const char *, int, mode_t);
int shm_unlink(const char *);
