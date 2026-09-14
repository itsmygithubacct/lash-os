/* Execute real calls through the wire mapping. Run this under each target's
 * kernel or user-mode emulator to catch accidental use of host syscall IDs. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <unistd.h>
#include "../src/native_syscalls.h"

int main(void) {
    unsigned char random[32] = {0};
    struct rlimit before, after;
    assert(native_syscall_number(UINT64_MAX) == -1);
    assert(native_syscall_number(0) == -1);
    assert(native_syscall_number(56) == SYS_clone);
    assert(syscall(native_syscall_number(318), random, sizeof(random), 0) == sizeof(random));
    assert(getrlimit(RLIMIT_NOFILE, &before) == 0);
    assert(syscall(native_syscall_number(302), 0, RLIMIT_NOFILE, NULL, &after) == 0);
    assert(before.rlim_cur == after.rlim_cur && before.rlim_max == after.rlim_max);
    assert(syscall(native_syscall_number(145), 0) >= 0);
    return 0;
}
