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
        actual = (int)a[0] == -2 ? AT_FDCWD : fd(h, a[0]);
        char path_storage[BRIDGE_PATH_SIZE];
        int follow = request->operation == PX_OPENAT ? !(a[2] & BO_NOFOLLOW)
                                                     : !(at_flags(a[3]) & AT_SYMLINK_NOFOLLOW);
        char *path = path_string_mode(h, a[1], path_storage, follow);
        if ((actual < 0 && actual != AT_FDCWD) || !path)
            return -1;
        if (request->operation == PX_OPENAT)
            return save_fd(h, openat(actual, path, open_flags(a[2]), a[3]), 0);
        struct bridge_stat *out = memory(h, a[2], sizeof(*out));
        struct stat info;
        if (!out)
            return -1;
        rc = fstatat(actual, path, &info, at_flags(a[3]));
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
    case PX_GETRUSAGE: {
        struct timeval *out = memory(h, a[1], 2 * sizeof(*out));
        struct rusage value;
        if (!out)
            return -1;
        rc = getrusage(a[0], &value);
        if (!rc) {
            out[0] = value.ru_utime;
            out[1] = value.ru_stime;
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
        size_t size = a[0] == 1   ? sizeof(struct msqid_ds)
                      : a[0] == 2 ? sizeof(struct shmid_ds)
                                  : sizeof(struct semid_ds);
        if (command == IPC_INFO || command == MSG_INFO || command == SHM_INFO ||
            command == SEM_INFO)
            size = 128;
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
        if (command == SETVAL)
            arg.val = a[3];
        return semctl(a[1], a[4], command, arg);
    }
    default:
        return service_raw(h, request);
    }
}
