BRIDGE_RAW_LAYOUTS(BRIDGE_CHECK_LAYOUT)
static void export_stat(struct bridge_stat *out, const struct stat *s) {
    *out = (struct bridge_stat){
        s->st_dev,         s->st_ino,          s->st_mode,        s->st_nlink,
        s->st_uid,         s->st_gid,          s->st_rdev,        s->st_size,
        s->st_blksize,     s->st_blocks,       s->st_atim.tv_sec, s->st_atim.tv_nsec,
        s->st_mtim.tv_sec, s->st_mtim.tv_nsec, s->st_ctim.tv_sec, s->st_ctim.tv_nsec};
}
static void free_interfaces(struct bridge_host *h, struct network_ifaddrs *p) {
    while (p) {
        struct network_ifaddrs *next = (void *)(uintptr_t)p->next;
        bpf_capsule_free(h->capsule, (void *)(uintptr_t)p->name);
        bpf_capsule_free(h->capsule, (void *)(uintptr_t)p->address);
        bpf_capsule_free(h->capsule, (void *)(uintptr_t)p->mask);
        bpf_capsule_free(h->capsule, (void *)(uintptr_t)p->broadcast);
        bpf_capsule_free(h->capsule, p);
        p = next;
    }
}
static uint64_t copy_sockaddr(struct bridge_host *h, const struct sockaddr *p) {
    size_t size;
    if (!p)
        return 0;
    switch (p->sa_family) {
    case AF_INET:
        size = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        size = sizeof(struct sockaddr_in6);
        break;
    case AF_PACKET:
        size = sizeof(struct sockaddr_ll);
        break;
    default:
        size = sizeof(struct sockaddr);
    }
    return (uintptr_t)guest_copy(h, p, size);
}
static int64_t service_raw(struct bridge_host *, struct posix_request *);
static int64_t service_misc(struct bridge_host *h, struct posix_request *request) {
    uint64_t *a = request->args;
    int actual, rc;
    switch (request->operation) {
    case PX_OPENAT:
    case PX_FSTATAT: {
        int flags = request->operation == PX_OPENAT ? 0 : at_flags(a[3]);
        if (flags < 0)
            return -1;
        actual = (int)a[0] == -2 ? AT_FDCWD : fd(h, a[0]);
        char path_storage[BRIDGE_PATH_SIZE];
        int follow = request->operation == PX_OPENAT ? !(a[2] & BO_NOFOLLOW)
                                                     : !(flags & AT_SYMLINK_NOFOLLOW);
        char *path = path_string_mode(h, a[1], path_storage, follow);
        if ((actual < 0 && actual != AT_FDCWD) || !path)
            return -1;
        if (request->operation == PX_OPENAT)
            return save_fd(h, openat(actual, path, open_flags(a[2]), a[3]), 0);
        struct bridge_stat *out = memory(h, a[2], sizeof(*out));
        struct stat info;
        if (!out)
            return -1;
        rc = fstatat(actual, path, &info, flags);
        if (!rc)
            export_stat(out, &info);
        return rc;
    }
    case PX_FDOPENDIR: {
        actual = fd(h, a[0]);
        if (actual < 0)
            return -1;
        for (int i = 0; i < MAX_DIRS; i++)
            if (!h->dirs[i]) {
                int copy = dup(actual);
                if (copy < 0)
                    return -1;
                DIR *dir = fdopendir(copy);
                if (!dir) {
                    close(copy);
                    return -1;
                }
                h->dirs[i] = dir;
                h->dir_fds[i] = a[0];
                return i;
            }
        errno = EMFILE;
        return -1;
    }
    case PX_EPOLL_CTL: {
        actual = fd(h, a[0]);
        int target = fd(h, a[2]);
        if (actual < 0 || target < 0)
            return -1;
        struct {
            uint32_t events, pad;
            uint64_t data;
        } *in = a[3] ? memory(h, a[3], 16) : NULL;
        if (a[3] && !in)
            return -1;
        struct epoll_event event = {0};
        if (in) {
            event.events = in->events;
            event.data.u64 = in->data;
        }
        return epoll_ctl(actual, a[1], target, in ? &event : NULL);
    }
    case PX_EPOLL_WAIT: {
        actual = fd(h, a[0]);
        if (actual < 0)
            return -1;
        int count = (int)a[2];
        if (count <= 0 || count > BRIDGE_EPOLL_EVENTS) {
            errno = EINVAL;
            return -1;
        }
        struct bridge_epoll_event *out = memory(h, a[1], (uint64_t)count * sizeof(*out));
        if (!out)
            return -1;
        struct epoll_event events[BRIDGE_EPOLL_EVENTS];
        rc = epoll_wait(actual, events, count, (int)a[3]);
        if (rc > 0)
            export_epoll_events(out, events, rc);
        return rc;
    }
    case PX_STATVFS:
    case PX_FSTATVFS: {
        struct bridge_statvfs *out = memory(h, a[1], sizeof(*out));
        struct statvfs info;
        if (!out)
            return -1;
        if (request->operation == PX_STATVFS) {
            char path_storage[BRIDGE_PATH_SIZE];
            char *path = path_string(h, a[0], path_storage);
            rc = path ? statvfs(path, &info) : -1;
        } else {
            actual = fd(h, a[0]);
            rc = actual < 0 ? -1 : fstatvfs(actual, &info);
        }
        if (!rc)
            export_statvfs(out, &info);
        return rc;
    }
    case PX_UTIMES: {
        char path_storage[BRIDGE_PATH_SIZE];
        char *path = path_string(h, a[0], path_storage);
        const struct bridge_timeval *in = a[1] ? memory(h, a[1], 2 * sizeof(*in)) : NULL;
        if (!path || (a[1] && !in))
            return -1;
        struct timeval times[2];
        if (in) {
            times[0] = import_timeval(&in[0]);
            times[1] = import_timeval(&in[1]);
        }
        return utimes(path, in ? times : NULL);
    }
    case PX_ADJTIME: {
        const struct bridge_timeval *in = a[0] ? memory(h, a[0], sizeof(*in)) : NULL;
        struct bridge_timeval *out = a[1] ? memory(h, a[1], sizeof(*out)) : NULL;
        if ((a[0] && !in) || (a[1] && !out))
            return -1;
        struct timeval delta = in ? import_timeval(in) : (struct timeval){0}, old;
        rc = adjtime(in ? &delta : NULL, out ? &old : NULL);
        if (!rc && out)
            export_timeval(out, &old);
        return rc;
    }
    case PX_SETITIMER: {
        const struct bridge_timeval *in = a[1] ? memory(h, a[1], 2 * sizeof(*in)) : NULL;
        struct bridge_timeval *out = a[2] ? memory(h, a[2], 2 * sizeof(*out)) : NULL;
        if ((a[1] && !in) || (a[2] && !out))
            return -1;
        struct itimerval value = {0}, old;
        if (in) {
            value.it_interval = import_timeval(&in[0]);
            value.it_value = import_timeval(&in[1]);
        }
        rc = setitimer((int)a[0], in ? &value : NULL, out ? &old : NULL);
        if (!rc && out) {
            export_timeval(&out[0], &old.it_interval);
            export_timeval(&out[1], &old.it_value);
        }
        return rc;
    }
    case PX_ADJTIMEX: {
        struct bridge_timex *wire = memory(h, a[0], sizeof(*wire));
        if (!wire)
            return -1;
        struct timex value;
        import_timex(&value, wire);
        rc = adjtimex(&value);
        if (rc >= 0)
            export_timex(wire, &value);
        return rc;
    }
    case PX_SETSOCKOPT: {
        actual = fd(h, a[0]);
        socklen_t length = (socklen_t)a[4];
        const void *value = memory(h, a[3], length);
        if (actual < 0 || (!value && length))
            return -1;
        int level = (int)a[1], option = (int)a[2];
        if (level == SOL_SOCKET && (option == SO_RCVTIMEO || option == SO_SNDTIMEO) &&
            length == sizeof(struct bridge_timeval)) {
            struct timeval timeout = import_guest_timeval(value);
            return setsockopt(actual, level, option, &timeout, sizeof(timeout));
        }
        return setsockopt(actual, level, option, value, length);
    }
    case PX_GETRUSAGE: {
        struct bridge_timeval *out = memory(h, a[1], 2 * sizeof(*out));
        struct rusage value;
        if (!out)
            return -1;
        rc = getrusage(a[0], &value);
        if (!rc) {
            export_timeval(&out[0], &value.ru_utime);
            export_timeval(&out[1], &value.ru_stime);
        }
        return rc;
    }
    case PX_GETGROUPLIST: {
        char *name = string(h, a[0]);
        int *count = memory(h, a[3], sizeof(*count));
        if (!name || !count)
            return -1;
        if (*count < 0 || *count > 65536) {
            errno = EINVAL;
            return -1;
        }
        gid_t *groups = *count ? memory(h, a[2], *count * sizeof(gid_t)) : NULL;
        if (*count && !groups)
            return -1;
        return getgrouplist(name, a[1], groups, count);
    }
    case PX_GETIFADDRS: {
        uint64_t *out = memory(h, a[0], 8);
        if (!out)
            return -1;
        *out = 0;
        struct ifaddrs *list;
        if (getifaddrs(&list))
            return -1;
        struct network_ifaddrs *first = NULL, *last = NULL;
        for (struct ifaddrs *p = list; p; p = p->ifa_next) {
            struct network_ifaddrs value = {.flags = p->ifa_flags};
            struct network_ifaddrs *item = guest_copy(h, &value, sizeof(value));
            if (!item)
                goto interfaces_failed;
            if (last)
                last->next = (uintptr_t)item;
            else
                first = item;
            last = item;
            item->name = (uintptr_t)guest_copy(h, p->ifa_name, strlen(p->ifa_name) + 1);
            item->address = copy_sockaddr(h, p->ifa_addr);
            item->mask = copy_sockaddr(h, p->ifa_netmask);
            item->broadcast = copy_sockaddr(h, p->ifa_broadaddr);
            if (!item->name || (p->ifa_addr && !item->address) || (p->ifa_netmask && !item->mask) ||
                (p->ifa_broadaddr && !item->broadcast))
                goto interfaces_failed;
        }
        freeifaddrs(list);
        *out = (uintptr_t)first;
        return 0;
    interfaces_failed:
        freeifaddrs(list);
        free_interfaces(h, first);
        errno = ENOMEM;
        return -1;
    }
    case PX_SIGNALFD: {
        uint64_t *bits = memory(h, a[1], 8);
        if (!bits)
            return -1;
        sigset_t mask;
        unpack_signal_mask(*bits, &mask);
        actual = (int)a[0] < 0 ? -1 : fd(h, a[0]);
        if ((int)a[0] >= 0 && actual < 0)
            return -1;
        rc = signalfd(actual, &mask, open_flags(a[2]));
        return actual < 0 ? save_fd(h, rc, 0) : rc < 0 ? -1 : (int)a[0];
    }
    case PX_SIGTIMEDWAIT: {
        uint64_t *bits = memory(h, a[0], 8);
        struct {
            int number, code, error, pid;
            unsigned uid;
            int status;
            uint64_t value;
        } *out = memory(h, a[1], 32);
        const struct timespec *timeout = a[2] ? memory(h, a[2], sizeof(*timeout)) : NULL;
        if (!bits || !out || (a[2] && !timeout))
            return -1;
        sigset_t mask;
        unpack_signal_mask(*bits, &mask);
        siginfo_t info;
        rc = sigtimedwait(&mask, &info, timeout);
        if (rc >= 0) {
            out->number = info.si_signo;
            out->code = info.si_code;
            out->error = info.si_errno;
            out->pid = info.si_pid;
            out->uid = info.si_uid;
            out->status = info.si_status;
            out->value = (uintptr_t)info.si_value.sival_ptr;
        }
        return rc;
    }
    case PX_SYSCONF: {
        const int names[] = {0, _SC_CLK_TCK, _SC_NPROCESSORS_CONF, _SC_NPROCESSORS_ONLN,
                             _SC_PHYS_PAGES};
        if (a[0] < 1 || a[0] > 4) {
            errno = EINVAL;
            return -1;
        }
        return sysconf(names[a[0]]);
    }
    case PX_IPCCTL: {
        int command = a[2];
        /* Command numbers overlap between the three IPC kinds. */
        int semaphore_record = a[0] == 3 && (command == IPC_STAT || command == IPC_SET ||
                                             command == SEM_STAT || command == SEM_STAT_ANY);
        size_t size;
        if (a[0] == 1)
            size = command == IPC_INFO || command == MSG_INFO ? sizeof(struct msginfo)
                                                              : sizeof(struct msqid_ds);
        else if (a[0] == 2)
            size = command == IPC_INFO   ? sizeof(struct shminfo)
                   : command == SHM_INFO ? sizeof(struct shm_info)
                                         : sizeof(struct shmid_ds);
        else
            size = command == IPC_INFO || command == SEM_INFO ? sizeof(struct seminfo)
                                                              : sizeof(struct bridge_semid_ds);
        void *buffer = a[3] && command != SETVAL ? memory(h, a[3], size) : NULL;
        if (a[3] && command != SETVAL && !buffer)
            return -1;
        if (a[0] == 1)
            return msgctl(a[1], command, buffer);
        if (a[0] == 2)
            return shmctl(a[1], command, buffer);
        if (command == GETALL || command == SETALL) {
            errno = ENOTSUP;
            return -1;
        }
        union {
            int val;
            struct semid_ds *buf;
            void *array;
        } arg = {.buf = buffer};
        struct semid_ds native;
        if (semaphore_record && buffer) {
            import_semid(&native, buffer);
            arg.buf = &native;
        }
        if (command == SETVAL)
            arg.val = a[3];
        rc = semctl(a[1], a[4], command, arg);
        if (rc >= 0 && semaphore_record && buffer && command != IPC_SET)
            export_semid(buffer, &native);
        return rc;
    }
    default:
        return service_raw(h, request);
    }
}
