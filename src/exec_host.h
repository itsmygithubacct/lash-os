/* Preserve the loader's descriptor namespace if Linux rejects execve. */
static char **exec_strings(struct bridge_host *h, uint64_t pointer) {
    char **result = calloc(4097, sizeof(char *));
    if (!result)
        return NULL;
    for (unsigned i = 0; i < 4096; i++) {
        uint64_t *item = memory(h, pointer + i * sizeof(uint64_t), sizeof(uint64_t));
        if (!item) {
            free(result);
            return NULL;
        }
        if (!*item)
            return result;
        size_t left = available(h, *item);
        if (left > 131072)
            left = 131072;
        result[i] = left ? memory(h, *item, left) : NULL;
        if (result[i] && !memchr(result[i], 0, left)) {
            errno = E2BIG;
            result[i] = NULL;
        }
        if (!result[i]) {
            free(result);
            return NULL;
        }
    }
    free(result);
    errno = E2BIG;
    return NULL;
}
struct exec_fd {
    int number, flags;
};
struct posix_lock {
    dev_t dev;
    ino_t ino;
    off_t start, len;
    short type;
    int fd;
};
static int remember_lock(struct posix_lock **locks, size_t *count, size_t *capacity,
                         struct posix_lock item) {
    for (size_t i = 0; i < *count; i++) {
        struct posix_lock *old = &(*locks)[i];
        if (old->dev == item.dev && old->ino == item.ino && old->type == item.type &&
            old->start == item.start && old->len == item.len)
            return 0;
    }
    if (*count == *capacity) {
        size_t next = *capacity ? *capacity * 2 : 8;
        struct posix_lock *grown = realloc(*locks, next * sizeof(*grown));
        if (!grown)
            return -1;
        *locks = grown;
        *capacity = next;
    }
    (*locks)[(*count)++] = item;
    return 0;
}
/* fdinfo end is inclusive. EOF is the fcntl length 0, meaning through EOF. */
static int lock_length(long long start, const char *end_text, off_t *length) {
    if (start < 0)
        return -1;
    if (!strcmp(end_text, "EOF")) {
        *length = 0;
        return 0;
    }
    errno = 0;
    char *end = NULL;
    long long last = strtoll(end_text, &end, 10);
    if (!end || *end || errno || last < start)
        return -1;
    unsigned long long span = (unsigned long long)(last - start) + 1;
    if (span > (unsigned long long)LLONG_MAX)
        return -1;
    *length = (off_t)span;
    return 0;
}
static int parse_fdinfo_locks(int fd, const struct stat *st, struct posix_lock **locks,
                              size_t *count, size_t *capacity) {
    char path[64], *text = NULL;
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    int info = open(path, O_RDONLY | O_CLOEXEC);
    if (info < 0)
        return errno == ENOENT ? 0 : -1;
    size_t used = 0, room = 4096;
    text = malloc(room);
    if (!text) {
        close(info);
        return -1;
    }
    int failed = 0;
    while (!failed) {
        if (used + 1 >= room) {
            size_t next = room * 2;
            char *grown = realloc(text, next);
            if (!grown) {
                failed = 1;
                break;
            }
            text = grown;
            room = next;
        }
        ssize_t n = read(info, text + used, room - used - 1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            failed = 1;
            break;
        }
        if (!n)
            break;
        used += (size_t)n;
    }
    close(info);
    if (failed) {
        free(text);
        return -1;
    }
    text[used] = 0;
    for (char *line = text; *line;) {
        char *next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        else
            next = line + strlen(line);
        if (!strncmp(line, "lock:", 5)) {
            int id, fields;
            char kind[16], advisory[16], mode[16], end_text[32];
            long owner;
            unsigned major, minor;
            unsigned long inode;
            long long start;
            fields = sscanf(line, "lock: %d: %15s %15s %15s %ld %x:%x:%lu %lld %31s", &id, kind,
                            advisory, mode, &owner, &major, &minor, &inode, &start, end_text);
            (void)id;
            (void)advisory;
            (void)major;
            (void)minor;
            (void)inode;
            if (fields != 10) {
                free(text);
                errno = EIO;
                return -1;
            }
            if (!strcmp(kind, "POSIX") && owner == getpid()) {
                off_t length;
                short type;
                if (!strcmp(mode, "READ"))
                    type = F_RDLCK;
                else if (!strcmp(mode, "WRITE"))
                    type = F_WRLCK;
                else
                    type = 0;
                if (!type || lock_length(start, end_text, &length)) {
                    free(text);
                    errno = EIO;
                    return -1;
                }
                if (remember_lock(locks, count, capacity,
                                  (struct posix_lock){.dev = st->st_dev,
                                                      .ino = st->st_ino,
                                                      .start = (off_t)start,
                                                      .len = length,
                                                      .type = type,
                                                      .fd = fd})) {
                    free(text);
                    return -1;
                }
            }
        }
        line = next;
    }
    free(text);
    return 0;
}
/* Record locks before any dup. close() of a duplicate releases them. */
static int snapshot_posix_locks(struct posix_lock **locks, size_t *count) {
    *locks = NULL;
    *count = 0;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory)
        return -1;
    size_t capacity = 0;
    int error = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        long number = strtol(entry->d_name, &end, 10);
        if (*end || number < 0 || number > INT_MAX || number == dirfd(directory))
            continue;
        struct stat st;
        if (fstat((int)number, &st))
            continue;
        if (parse_fdinfo_locks((int)number, &st, locks, count, &capacity)) {
            error = errno ? errno : EIO;
            break;
        }
    }
    closedir(directory);
    if (error) {
        free(*locks);
        *locks = NULL;
        *count = 0;
        errno = error;
        return -1;
    }
    return 0;
}
static int find_lock_fd(const struct posix_lock *lock) {
    struct stat st;
    if (lock->fd >= 0 && !fstat(lock->fd, &st) && st.st_dev == lock->dev && st.st_ino == lock->ino)
        return lock->fd;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory)
        return -2;
    int found = -1;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        long number = strtol(entry->d_name, &end, 10);
        if (*end || number < 0 || number > INT_MAX || number == dirfd(directory))
            continue;
        if (fstat((int)number, &st))
            continue;
        if (st.st_dev == lock->dev && st.st_ino == lock->ino) {
            found = (int)number;
            break;
        }
    }
    closedir(directory);
    return found;
}
static int reapply_posix_locks(struct posix_lock *locks, size_t count) {
    for (size_t i = 0; i < count; i++) {
        int target = find_lock_fd(&locks[i]);
        if (target == -1)
            continue;
        if (target < 0)
            return -1;
        struct flock region = {.l_type = locks[i].type,
                               .l_whence = SEEK_SET,
                               .l_start = locks[i].start,
                               .l_len = locks[i].len};
        if (fcntl(target, F_SETLK, &region))
            return -1;
    }
    return 0;
}
static int service_exec(struct bridge_host *h, uint64_t path_address, uint64_t arguments_address,
                        uint64_t environment_address) {
    char *path = string(h, path_address);
    char **arguments = NULL, **environment = NULL;
    struct exec_fd *original = NULL;
    struct posix_lock *locks = NULL;
    size_t count = 0, capacity = 0, nlocks = 0;
    int saved[MAX_FDS], sources[MAX_FDS], flags[MAX_FDS], error = 0, changed = 0;
    for (int i = 0; i < MAX_FDS; i++)
        saved[i] = sources[i] = flags[i] = -1;
    if (!path || !(arguments = exec_strings(h, arguments_address)) ||
        !(environment = exec_strings(h, environment_address)))
        goto cleanup;
    DIR *directory = opendir("/proc/self/fd");
    if (!directory)
        goto cleanup;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        long number = strtol(entry->d_name, &end, 10);
        if (*end || number < 0 || number > INT_MAX || number == dirfd(directory))
            continue;
        int f = fcntl(number, F_GETFD);
        if (f < 0)
            continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 64;
            void *p = realloc(original, next * sizeof(*original));
            if (!p) {
                closedir(directory);
                goto cleanup;
            }
            original = p;
            capacity = next;
        }
        original[count++] = (struct exec_fd){number, f};
    }
    closedir(directory);
    if (snapshot_posix_locks(&locks, &nlocks))
        goto cleanup;
    /* Back up only native slots that the guest projection will overwrite.
     * Private descriptors stay open with CLOEXEC until execve succeeds; a
     * full BPF image can already occupy most of the native descriptor limit. */
    for (size_t j = 0; j < count; j++) {
        int number = original[j].number;
        if (number < MAX_FDS && h->fds[number] >= 0) {
            saved[number] = fcntl(number, F_DUPFD_CLOEXEC, MAX_FDS);
            if (saved[number] < 0)
                goto cleanup;
        }
    }
    for (int i = 0; i < MAX_FDS; i++) {
        if (h->fds[i] < 0)
            continue;
        flags[i] = fcntl(h->fds[i], F_GETFD);
        sources[i] = fcntl(h->fds[i], F_DUPFD_CLOEXEC, MAX_FDS);
        if (flags[i] < 0 || sources[i] < 0)
            goto cleanup;
    }
    changed = 1;
    for (size_t j = 0; j < count; j++) {
        int number = original[j].number;
        if (fcntl(number, F_SETFD, original[j].flags | FD_CLOEXEC))
            goto cleanup;
    }
    for (int i = 0; i < MAX_FDS; i++) {
        if (sources[i] >= 0 && (dup2(sources[i], i) < 0 || fcntl(i, F_SETFD, flags[i])))
            goto cleanup;
    }
    execve(path, arguments, environment);
cleanup:
    error = errno ? errno : EIO;
    if (changed) {
        int restore_failed = 0;
        for (int i = 0; i < MAX_FDS; i++) {
            if (sources[i] < 0)
                continue;
            if (saved[i] < 0)
                close(i);
            else if (dup2(saved[i], i) < 0)
                restore_failed = 1;
        }
        for (size_t j = 0; j < count; j++) {
            if (fcntl(original[j].number, F_SETFD, original[j].flags))
                restore_failed = 1;
        }
        /* Continuing with a damaged descriptor table could redirect user I/O. */
        if (restore_failed)
            _exit(125);
    }
    for (int i = 0; i < MAX_FDS; i++) {
        if (saved[i] >= 0)
            close(saved[i]);
        if (sources[i] >= 0)
            close(sources[i]);
    }
    /* Temps are closed, so re-acquire record locks on whatever descriptors remain. */
    if (locks && reapply_posix_locks(locks, nlocks))
        _exit(125);
    free(locks);
    free(original);
    free(arguments);
    free(environment);
    errno = error;
    return -1;
}
