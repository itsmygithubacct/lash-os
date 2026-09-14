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
static int service_exec(struct bridge_host *h, uint64_t path_address, uint64_t arguments_address,
                        uint64_t environment_address) {
    char *path = string(h, path_address);
    char **arguments = NULL, **environment = NULL;
    struct exec_fd *original = NULL;
    size_t count = 0, capacity = 0;
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
    free(original);
    free(arguments);
    free(environment);
    errno = error;
    return -1;
}
