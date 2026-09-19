#include <stddef.h>
BRIDGE_RAW_LAYOUTS(BRIDGE_CHECK_LAYOUT)
_Static_assert(sizeof(struct semid_ds) == sizeof(struct bridge_semid_ds) &&
                   offsetof(struct semid_ds, sem_ctime) ==
                       offsetof(struct bridge_semid_ds, ctime) &&
                   offsetof(struct semid_ds, sem_nsems) == offsetof(struct bridge_semid_ds, nsems),
               "semid_ds layout");
static struct bridge_timeval pack_timeval(const struct timeval *value) {
    return (struct bridge_timeval){value->tv_sec, value->tv_usec};
}
static void unpack_timeval(struct timeval *out, const struct bridge_timeval *value) {
    out->tv_sec = value->sec;
    out->tv_usec = value->usec;
}
int openat(int directory, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return posix_bridge(PX_OPENAT, directory, (uintptr_t)path, pack_flags(flags), mode, 0, 0);
}
int fstatat(int directory, const char *path, struct stat *out, int flags) {
    struct bridge_stat info;
    int rc = posix_bridge(PX_FSTATAT, directory, (uintptr_t)path, (uintptr_t)&info, flags, 0, 0);
    if (!rc)
        unpack_stat(out, &info);
    return rc;
}
DIR *fdopendir(int descriptor) {
    int handle = posix_bridge(PX_FDOPENDIR, descriptor, 0, 0, 0, 0, 0);
    if (handle < 0)
        return NULL;
    DIR *out = calloc(1, sizeof(*out));
    if (!out) {
        bridge(BR_CLOSEDIR, handle, 0, 0);
        return NULL;
    }
    out->fd = handle;
    return out;
}
int pipe2(int pair[2], int flags) {
    if (flags & ~(O_CLOEXEC | O_NONBLOCK)) {
        errno = EINVAL;
        return -1;
    }
    if (pipe(pair))
        return -1;
    for (int i = 0; i < 2; i++)
        if (((flags & O_CLOEXEC) && fcntl(pair[i], F_SETFD, FD_CLOEXEC) < 0) ||
            ((flags & O_NONBLOCK) && fcntl(pair[i], F_SETFL, O_NONBLOCK) < 0)) {
            int error = errno;
            close(pair[0]);
            close(pair[1]);
            errno = error;
            return -1;
        }
    return 0;
}
int epoll_ctl(int epoll, int operation, int descriptor, struct epoll_event *event) {
    struct {
        uint32_t events, pad;
        uint64_t data;
    } value = {0};
    if (event) {
        value.events = event->events;
        memcpy(&value.data, &event->data, 8);
    }
    return posix_bridge(PX_EPOLL_CTL, epoll, operation, descriptor, event ? (uintptr_t)&value : 0,
                        0, 0);
}
int epoll_wait(int descriptor, struct epoll_event *events, int count, int timeout) {
    if (count <= 0) {
        errno = EINVAL;
        return -1;
    }
    /* Linux may return fewer events than requested. */
    if (count > BRIDGE_EPOLL_EVENTS)
        count = BRIDGE_EPOLL_EVENTS;
    struct bridge_epoll_event *wire = malloc(count * sizeof(*wire));
    if (!wire) {
        errno = ENOMEM;
        return -1;
    }
    int rc = posix_bridge(PX_EPOLL_WAIT, descriptor, (uintptr_t)wire, count, timeout, 0, 0);
    int error = errno;
    for (int i = 0; i < rc; i++) {
        events[i].events = wire[i].events;
        memcpy(&events[i].data, &wire[i].data, sizeof(wire[i].data));
    }
    free(wire);
    errno = error;
    return rc;
}
static void unpack_statvfs(struct statvfs *out, const struct bridge_statvfs *in) {
    memset(out, 0, sizeof(*out));
    out->f_bsize = in->bsize;
    out->f_frsize = in->frsize;
    out->f_blocks = in->blocks;
    out->f_bfree = in->bfree;
    out->f_bavail = in->bavail;
    out->f_files = in->files;
    out->f_ffree = in->ffree;
    out->f_favail = in->favail;
    out->f_fsid = in->fsid;
    out->f_flag = in->flag;
    out->f_namemax = in->namemax;
}
int statvfs(const char *path, struct statvfs *out) {
    struct bridge_statvfs info;
    int rc = posix_bridge(PX_STATVFS, (uintptr_t)path, (uintptr_t)&info, 0, 0, 0, 0);
    if (!rc)
        unpack_statvfs(out, &info);
    return rc;
}
int fstatvfs(int descriptor, struct statvfs *out) {
    struct bridge_statvfs info;
    int rc = posix_bridge(PX_FSTATVFS, descriptor, (uintptr_t)&info, 0, 0, 0, 0);
    if (!rc)
        unpack_statvfs(out, &info);
    return rc;
}
int utimes(const char *path, const struct timeval *times) {
    struct bridge_timeval wire[2];
    if (times) {
        wire[0] = pack_timeval(&times[0]);
        wire[1] = pack_timeval(&times[1]);
    }
    return posix_bridge(PX_UTIMES, (uintptr_t)path, times ? (uintptr_t)wire : 0, 0, 0, 0, 0);
}
int adjtime(const struct timeval *delta, struct timeval *old) {
    struct bridge_timeval in = delta ? pack_timeval(delta) : (struct bridge_timeval){0}, out = {0};
    int rc =
        posix_bridge(PX_ADJTIME, delta ? (uintptr_t)&in : 0, old ? (uintptr_t)&out : 0, 0, 0, 0, 0);
    if (!rc && old)
        unpack_timeval(old, &out);
    return rc;
}
int setitimer(int which, const struct itimerval *value, struct itimerval *old) {
    struct bridge_timeval in[2] = {0}, out[2] = {0};
    if (value) {
        in[0] = pack_timeval(&value->it_interval);
        in[1] = pack_timeval(&value->it_value);
    }
    int rc = posix_bridge(PX_SETITIMER, which, value ? (uintptr_t)in : 0, old ? (uintptr_t)out : 0,
                          0, 0, 0);
    if (!rc && old) {
        unpack_timeval(&old->it_interval, &out[0]);
        unpack_timeval(&old->it_value, &out[1]);
    }
    return rc;
}
int adjtimex(struct timex *value) {
    struct bridge_timex wire = {.modes = value->modes,
                                .offset = value->offset,
                                .freq = value->freq,
                                .maxerror = value->maxerror,
                                .esterror = value->esterror,
                                .status = value->status,
                                .constant = value->constant,
                                .precision = value->precision,
                                .tolerance = value->tolerance,
                                .time = pack_timeval(&value->time),
                                .tick = value->tick,
                                .ppsfreq = value->ppsfreq,
                                .jitter = value->jitter,
                                .shift = value->shift,
                                .stabil = value->stabil,
                                .jitcnt = value->jitcnt,
                                .calcnt = value->calcnt,
                                .errcnt = value->errcnt,
                                .stbcnt = value->stbcnt,
                                .tai = value->tai};
    int rc = posix_bridge(PX_ADJTIMEX, (uintptr_t)&wire, 0, 0, 0, 0, 0);
    if (rc >= 0) {
        value->modes = wire.modes;
        value->offset = wire.offset;
        value->freq = wire.freq;
        value->maxerror = wire.maxerror;
        value->esterror = wire.esterror;
        value->status = wire.status;
        value->constant = wire.constant;
        value->precision = wire.precision;
        value->tolerance = wire.tolerance;
        unpack_timeval(&value->time, &wire.time);
        value->tick = wire.tick;
        value->ppsfreq = wire.ppsfreq;
        value->jitter = wire.jitter;
        value->shift = wire.shift;
        value->stabil = wire.stabil;
        value->jitcnt = wire.jitcnt;
        value->calcnt = wire.calcnt;
        value->errcnt = wire.errcnt;
        value->stbcnt = wire.stbcnt;
        value->tai = wire.tai;
    }
    return rc;
}
int getrusage(int who, struct rusage *usage) {
    struct bridge_timeval wire[2];
    int rc = posix_bridge(PX_GETRUSAGE, who, (uintptr_t)wire, 0, 0, 0, 0);
    if (!rc) {
        memset(usage, 0, sizeof(*usage));
        unpack_timeval(&usage->ru_utime, &wire[0]);
        unpack_timeval(&usage->ru_stime, &wire[1]);
    }
    return rc;
}
int getgrouplist(const char *user, gid_t group, gid_t *groups, int *count) {
    return posix_bridge(PX_GETGROUPLIST, (uintptr_t)user, group, (uintptr_t)groups,
                        (uintptr_t)count, 0, 0);
}
int getifaddrs(struct ifaddrs **out) {
    return posix_bridge(PX_GETIFADDRS, (uintptr_t)out, 0, 0, 0, 0, 0);
}
void freeifaddrs(struct ifaddrs *list) {
    while (list) {
        struct ifaddrs *next = list->ifa_next;
        free(list->ifa_name);
        free(list->ifa_addr);
        free(list->ifa_netmask);
        free(list->ifa_broadaddr);
        free(list->ifa_data);
        free(list);
        list = next;
    }
}
int signalfd(int descriptor, const sigset_t *mask, int flags) {
    return posix_bridge(PX_SIGNALFD, descriptor, (uintptr_t)mask, pack_flags(flags), 0, 0, 0);
}
int sigtimedwait(const sigset_t *mask, siginfo_t *info, const struct timespec *timeout) {
    struct {
        int number, code, error, pid;
        unsigned uid;
        int status;
        uint64_t value;
    } out = {0};
    int rc = posix_bridge(PX_SIGTIMEDWAIT, (uintptr_t)mask, (uintptr_t)&out, (uintptr_t)timeout, 0,
                          0, 0);
    if (rc >= 0 && info) {
        memset(info, 0, sizeof(*info));
        info->si_signo = out.number;
        info->si_code = out.code;
        info->si_errno = out.error;
        info->si_pid = out.pid;
        info->si_uid = out.uid;
        info->si_status = out.status;
        info->si_value.sival_ptr = (void *)(uintptr_t)out.value;
    }
    return rc;
}
long sysconf(int name) {
    int operation;
    switch (name) {
    case _SC_ARG_MAX:
        return 131072;
    case _SC_OPEN_MAX:
        return 256;
    case _SC_PAGESIZE:
        return 4096;
    case _SC_CLK_TCK:
        operation = 1;
        break;
    case _SC_NPROCESSORS_CONF:
        operation = 2;
        break;
    case _SC_NPROCESSORS_ONLN:
        operation = 3;
        break;
    case _SC_PHYS_PAGES:
        operation = 4;
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    return posix_bridge(PX_SYSCONF, operation, 0, 0, 0, 0, 0);
}
int __sched_cpucount(size_t size, const cpu_set_t *mask) {
    int count = 0;
    const unsigned char *bytes = (const void *)mask;
    for (size_t i = 0; i < size; i++)
        count += __builtin_popcount(bytes[i]);
    return count;
}
int usleep(useconds_t microseconds) {
    struct timespec value = {microseconds / 1000000, (microseconds % 1000000) * 1000};
    return nanosleep(&value, NULL);
}
char *ptsname(int descriptor) {
    static char name[4096];
    int error = ptsname_r(descriptor, name, sizeof(name));
    if (error) {
        errno = error;
        return NULL;
    }
    return name;
}
int clock_nanosleep(clockid_t clock, int flags, const struct timespec *value,
                    struct timespec *remaining) {
    struct timespec duration = *value;
    if (flags & TIMER_ABSTIME) {
        struct timespec now;
        if (clock_gettime(clock, &now))
            return errno;
        duration.tv_sec -= now.tv_sec;
        duration.tv_nsec -= now.tv_nsec;
        if (duration.tv_nsec < 0) {
            duration.tv_sec--;
            duration.tv_nsec += 1000000000;
        }
        if (duration.tv_sec < 0)
            return 0;
    }
    return nanosleep(&duration, remaining) < 0 ? errno : 0;
}
int msgctl(int id, int command, struct msqid_ds *buffer) {
    return posix_bridge(PX_IPCCTL, 1, id, command, (uintptr_t)buffer, 0, 0);
}
int shmctl(int id, int command, struct shmid_ds *buffer) {
    return posix_bridge(PX_IPCCTL, 2, id, command, (uintptr_t)buffer, 0, 0);
}
int semctl(int id, int number, int command, ...) {
    uint64_t argument = 0;
    if (command == IPC_STAT || command == IPC_SET || command == SETVAL || command == GETALL ||
        command == SETALL || command == SEM_STAT || command == SEM_INFO || command == IPC_INFO) {
        va_list ap;
        va_start(ap, command);
        argument = va_arg(ap, uint64_t);
        va_end(ap);
    }
    return posix_bridge(PX_IPCCTL, 3, id, command, argument, number, 0);
}
