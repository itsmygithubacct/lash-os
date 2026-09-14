#ifndef LASH_NATIVE_SYSCALLS_H
#define LASH_NATIVE_SYSCALLS_H
#include <stdint.h>
#include <sys/syscall.h>
#include "linux_bash_syscalls.h"
static inline long native_syscall_number(uint64_t wire) {
    switch (wire) {
#define LASH_NATIVE_SYSCALL(name, number) case LASH_SYS_##name: return SYS_##name;
        LINUX_BASH_SYSCALLS(LASH_NATIVE_SYSCALL)
#undef LASH_NATIVE_SYSCALL
    default:
        return -1;
    }
}
#endif
