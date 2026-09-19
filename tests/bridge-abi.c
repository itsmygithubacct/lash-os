/* Host-side guest ABI conversions: flag translation, wire records and bounds. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sem.h>
#include <sys/statvfs.h>
#include <sys/timex.h>
#include <unistd.h>
#include "kernel_control.h"
#include "../src/signal_host.h"
#include "../src/abi_host.h"

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void flags(void) {
    require(at_flags(0) == 0 && at_flags(2) == AT_SYMLINK_NOFOLLOW,
            "translate AT_SYMLINK_NOFOLLOW");
    require(at_flags(8 | 16) == (AT_REMOVEDIR | AT_EMPTY_PATH), "translate combined AT flags");
    errno = 0;
    require(at_flags(32) == -1 && errno == EINVAL, "reject unknown AT bit");
    errno = 0;
    require(at_flags(UINT64_C(1) << 32 | 2) == -1 && errno == EINVAL, "reject high AT bits");
    require(statx_flags(2) == AT_SYMLINK_NOFOLLOW, "statx accepts the Picolibc no-follow bit");
    require(statx_flags(AT_SYMLINK_NOFOLLOW) == AT_SYMLINK_NOFOLLOW,
            "statx accepts the Linux no-follow bit");
    require(statx_flags(AT_NO_AUTOMOUNT | AT_STATX_DONT_SYNC) ==
                (AT_NO_AUTOMOUNT | AT_STATX_DONT_SYNC),
            "statx keeps Linux synchronization controls");
    errno = 0;
    require(statx_flags(0x40) == -1 && errno == EINVAL, "statx rejects unknown bits");
    require(open_flags(BO_RDWR | BO_CREATE | BO_CLOEXEC) == (O_RDWR | O_CREAT | O_CLOEXEC),
            "translate open flags");
    require(bridge_signal_number(SIGUSR1) == SIGUSR1, "accept a signal number");
    require(bridge_signal_number(UINT64_C(1) << 32 | SIGUSR1) == -1,
            "reject a truncated 64-bit signal number");
    require(bridge_signal_number(65) == -1, "reject an out-of-range signal number");
}

static void records(void) {
    struct statvfs native;
    struct bridge_statvfs wire;
    require(!statvfs("/", &native), "query root filesystem");
    export_statvfs(&wire, &native);
    require(wire.bsize == native.f_bsize && wire.blocks == native.f_blocks &&
                wire.favail == native.f_favail && wire.fsid == native.f_fsid &&
                wire.flag == native.f_flag && wire.namemax == native.f_namemax,
            "statvfs wire record");

    int epoll = epoll_create1(EPOLL_CLOEXEC), pair[2];
    require(epoll >= 0 && !pipe(pair), "create epoll instance and pipe");
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x1122334455667788)};
    require(!epoll_ctl(epoll, EPOLL_CTL_ADD, pair[0], &event), "watch pipe");
    require(write(pair[1], "x", 1) == 1, "make pipe readable");
    struct epoll_event ready[4];
    struct bridge_epoll_event out[4];
    memset(out, 0xff, sizeof(out));
    int count = epoll_wait(epoll, ready, 4, 1000);
    require(count == 1, "receive one event");
    export_epoll_events(out, ready, count);
    require(out[0].events == EPOLLIN && out[0].pad == 0 &&
                out[0].data == UINT64_C(0x1122334455667788),
            "epoll wire record keeps the 64-bit data at offset 8");
    close(pair[0]);
    close(pair[1]);
    close(epoll);

    /* Only the low 32 microsecond bits of a raw guest timeval are defined. */
    struct bridge_timeval raw = {.sec = 7, .usec = (int64_t)UINT64_C(0xdeadbeef00000005)};
    struct timeval timeout = import_guest_timeval(&raw);
    require(timeout.tv_sec == 7 && timeout.tv_usec == 5, "discard guest timeval padding");
    raw.usec = (int64_t)UINT64_C(0x00000000ffffffff);
    require(import_guest_timeval(&raw).tv_usec == -1, "sign-extend guest microseconds");

    struct timex clock = {.modes = 3,
                          .offset = -4,
                          .freq = 5,
                          .status = 6,
                          .constant = 7,
                          .time = {.tv_sec = 8, .tv_usec = 9},
                          .tick = 10,
                          .shift = 11,
                          .stbcnt = 12,
                          .tai = 13},
                 back;
    struct bridge_timex clock_wire;
    export_timex(&clock_wire, &clock);
    require(clock_wire.time.sec == 8 && clock_wire.time.usec == 9 && clock_wire.tai == 13,
            "timex wire record");
    import_timex(&back, &clock_wire);
    require(back.modes == 3 && back.offset == -4 && back.freq == 5 && back.status == 6 &&
                back.constant == 7 && back.time.tv_sec == 8 && back.time.tv_usec == 9 &&
                back.tick == 10 && back.shift == 11 && back.stbcnt == 12 && back.tai == 13,
            "timex round trip");

    struct semid_ds semaphore = {0}, restored;
    semaphore.sem_perm.uid = 1000;
    semaphore.sem_perm.mode = 0640;
    semaphore.sem_otime = 20;
    semaphore.sem_ctime = 30;
    semaphore.sem_nsems = 4;
    struct bridge_semid_ds semaphore_wire;
    export_semid(&semaphore_wire, &semaphore);
    require(semaphore_wire.otime == 20 && semaphore_wire.ctime == 30 && semaphore_wire.nsems == 4 &&
                semaphore_wire.unused1 == 0,
            "semid_ds uses the guest layout");
    import_semid(&restored, &semaphore_wire);
    require(restored.sem_perm.uid == 1000 && restored.sem_perm.mode == 0640 &&
                restored.sem_otime == 20 && restored.sem_ctime == 30 && restored.sem_nsems == 4,
            "semid_ds round trip");
}

static void realpath_bounds(void) {
    char directory[] = "/tmp/lashos-realpath-XXXXXX";
    require(mkdtemp(directory) != NULL, "create realpath fixture");
    char expected[PATH_MAX];
    require(realpath(directory, expected) != NULL, "resolve fixture natively");
    size_t length = strlen(expected) + 1;
    char buffer[PATH_MAX];
    memset(buffer, 'z', sizeof(buffer));
    errno = 0;
    require(bounded_realpath(directory, buffer, length - 1) == -1 && errno == ENAMETOOLONG,
            "reject a buffer one byte too small");
    require(buffer[0] == 'z', "leave a short buffer untouched");
    require(!bounded_realpath(directory, buffer, length) && !strcmp(buffer, expected),
            "fill an exactly sized buffer");
    require(buffer[length] == 'z', "write no further than the resolved path");
    rmdir(directory);
}

int main(void) {
    flags();
    records();
    realpath_bounds();
    puts("PASS: guest ABI flags, wire records, signal numbers and realpath bounds");
    return 0;
}
