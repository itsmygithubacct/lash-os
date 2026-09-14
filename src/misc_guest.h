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
int getrusage(int who, struct rusage *usage) {
    return posix_bridge(PX_GETRUSAGE, who, (uintptr_t)usage, 0, 0, 0, 0);
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
