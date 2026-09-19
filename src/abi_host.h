/* Guest/host ABI conversions without loader state, so host tests can use them. */
#pragma once
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sem.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/timex.h>
#include "kernel_control.h"

#ifndef AT_STATX_SYNC_TYPE
#define AT_STATX_SYNC_TYPE 0x6000
#endif
#ifndef SEM_STAT_ANY
#define SEM_STAT_ANY 20
#endif

/* Linux gives access mode 3 its own meaning, so it passes through unchanged. */
static int open_flags(unsigned bits) {
    int f = bits & 3;
    if (bits & BO_CREATE)
        f |= O_CREAT;
    if (bits & BO_TRUNCATE)
        f |= O_TRUNC;
    if (bits & BO_APPEND)
        f |= O_APPEND;
    if (bits & BO_EXCLUSIVE)
        f |= O_EXCL;
    if (bits & BO_NONBLOCK)
        f |= O_NONBLOCK;
    if (bits & BO_CLOEXEC)
        f |= O_CLOEXEC;
    if (bits & BO_NOFOLLOW)
        f |= O_NOFOLLOW;
    if (bits & BO_DIRECTORY)
        f |= O_DIRECTORY;
    if (bits & BO_NOCTTY)
        f |= O_NOCTTY;
    return f;
}
/* Picolibc AT_* values. Unknown bits are rejected rather than passed to Linux. */
#define GUEST_AT_FLAGS UINT64_C(31)
static int at_flags(uint64_t bits) {
    if (bits & ~GUEST_AT_FLAGS) {
        errno = EINVAL;
        return -1;
    }
    int flags = 0;
    if (bits & 1)
        flags |= AT_EACCESS;
    if (bits & 2)
        flags |= AT_SYMLINK_NOFOLLOW;
    if (bits & 4)
        flags |= AT_SYMLINK_FOLLOW;
    if (bits & 8)
        flags |= AT_REMOVEDIR;
    if (bits & 16)
        flags |= AT_EMPTY_PATH;
    return flags;
}
/* Raw statx callers pass either Picolibc AT_* bits or Linux statx controls.
 * The two sets do not overlap, so both are accepted. */
static int statx_flags(uint64_t bits) {
    const uint64_t native =
        AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;
    if (bits & ~(GUEST_AT_FLAGS | native)) {
        errno = EINVAL;
        return -1;
    }
    int flags = at_flags(bits & GUEST_AT_FLAGS);
    return flags < 0 ? -1 : flags | (int)(bits & native);
}

static struct timeval import_timeval(const struct bridge_timeval *in) {
    return (struct timeval){.tv_sec = in->sec, .tv_usec = in->usec};
}
static void export_timeval(struct bridge_timeval *out, const struct timeval *in) {
    *out = (struct bridge_timeval){in->tv_sec, in->tv_usec};
}
/* A guest struct timeval passed as raw bytes: only the low 32 microsecond bits
 * are defined. */
static struct timeval import_guest_timeval(const void *raw) {
    struct bridge_timeval value;
    memcpy(&value, raw, sizeof(value));
    return (struct timeval){.tv_sec = value.sec, .tv_usec = (int32_t)value.usec};
}

static void export_statvfs(struct bridge_statvfs *out, const struct statvfs *s) {
    *out = (struct bridge_statvfs){s->f_bsize,  s->f_frsize, s->f_blocks, s->f_bfree,
                                   s->f_bavail, s->f_files,  s->f_ffree,  s->f_favail,
                                   s->f_fsid,   s->f_flag,   s->f_namemax};
}

static void export_epoll_events(struct bridge_epoll_event *out, const struct epoll_event *in,
                                int count) {
    for (int i = 0; i < count; i++)
        out[i] = (struct bridge_epoll_event){.events = in[i].events, .data = in[i].data.u64};
}

static void import_timex(struct timex *out, const struct bridge_timex *in) {
    memset(out, 0, sizeof(*out));
    out->modes = in->modes;
    out->offset = in->offset;
    out->freq = in->freq;
    out->maxerror = in->maxerror;
    out->esterror = in->esterror;
    out->status = in->status;
    out->constant = in->constant;
    out->precision = in->precision;
    out->tolerance = in->tolerance;
    out->time = import_timeval(&in->time);
    out->tick = in->tick;
    out->ppsfreq = in->ppsfreq;
    out->jitter = in->jitter;
    out->shift = in->shift;
    out->stabil = in->stabil;
    out->jitcnt = in->jitcnt;
    out->calcnt = in->calcnt;
    out->errcnt = in->errcnt;
    out->stbcnt = in->stbcnt;
    out->tai = in->tai;
}
static void export_timex(struct bridge_timex *out, const struct timex *in) {
    memset(out, 0, sizeof(*out));
    out->modes = in->modes;
    out->offset = in->offset;
    out->freq = in->freq;
    out->maxerror = in->maxerror;
    out->esterror = in->esterror;
    out->status = in->status;
    out->constant = in->constant;
    out->precision = in->precision;
    out->tolerance = in->tolerance;
    export_timeval(&out->time, &in->time);
    out->tick = in->tick;
    out->ppsfreq = in->ppsfreq;
    out->jitter = in->jitter;
    out->shift = in->shift;
    out->stabil = in->stabil;
    out->jitcnt = in->jitcnt;
    out->calcnt = in->calcnt;
    out->errcnt = in->errcnt;
    out->stbcnt = in->stbcnt;
    out->tai = in->tai;
}

_Static_assert(sizeof(struct ipc_perm) == sizeof(((struct bridge_semid_ds *)0)->perm),
               "IPC permission layout");
static void import_semid(struct semid_ds *out, const struct bridge_semid_ds *in) {
    memset(out, 0, sizeof(*out));
    memcpy(&out->sem_perm, in->perm, sizeof(in->perm));
    out->sem_otime = in->otime;
    out->sem_ctime = in->ctime;
    out->sem_nsems = in->nsems;
}
static void export_semid(struct bridge_semid_ds *out, const struct semid_ds *in) {
    memset(out, 0, sizeof(*out));
    memcpy(out->perm, &in->sem_perm, sizeof(out->perm));
    out->otime = in->sem_otime;
    out->ctime = in->sem_ctime;
    out->nsems = in->sem_nsems;
}

/* The guest buffer may be smaller than the host's PATH_MAX. */
static int bounded_realpath(const char *path, char *out, uint64_t size) {
    char resolved[PATH_MAX];
    if (!realpath(path, resolved))
        return -1;
    size_t length = strlen(resolved) + 1;
    if (length > size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(out, resolved, length);
    return 0;
}

_Static_assert(sizeof(struct bridge_timeval) == 16, "timeval wire layout");
_Static_assert(sizeof(struct bridge_statvfs) == 88, "statvfs wire layout");
_Static_assert(sizeof(struct bridge_epoll_event) == 16, "epoll wire layout");
_Static_assert(sizeof(struct bridge_timex) == 208, "timex wire layout");
_Static_assert(sizeof(struct bridge_semid_ds) == 104, "semid_ds wire layout");
