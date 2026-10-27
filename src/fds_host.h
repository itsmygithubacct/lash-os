#pragma once
#include <sys/mman.h>
#include <sys/resource.h>

/* Capture before opening BPF objects or other private loader descriptors.
 * Keep the original descriptors so their flags and open-file state survive. */
static int inherit_descriptors(int descriptors[MAX_FDS]) {
    int saved_errno = errno;
    for (int i = 0; i < MAX_FDS; i++)
        descriptors[i] = -1;
    for (int i = 0; i < MAX_FDS; i++) {
        int flags;
        do {
            flags = fcntl(i, F_GETFD);
        } while (flags < 0 && errno == EINTR);
        if (flags >= 0)
            descriptors[i] = i;
        else if (errno != EBADF)
            return -1;
    }
    errno = saved_errno;
    return 0;
}

/* Keep loader descriptors out of the guest range. Reserve its vacant slots
 * while loading (or reloading after fork), then release only the placeholders.
 * Guest descriptors can consequently keep their native numbers through exec:
 * even closing a temporary duplicate would release POSIX record locks. */
struct descriptor_reservation {
    int slots[MAX_FDS], raised_limit;
    struct rlimit limit;
};
static int release_descriptor_slots(struct descriptor_reservation *reserved) {
    int saved_errno = errno;
    for (int i = 0; i < MAX_FDS; i++) {
        if (reserved->slots[i])
            close(i);
        reserved->slots[i] = 0;
    }
    if (reserved->raised_limit) {
        if (setrlimit(RLIMIT_NOFILE, &reserved->limit))
            return -1;
        reserved->raised_limit = 0;
    }
    errno = saved_errno;
    return 0;
}
static int reserve_descriptor_slots(struct descriptor_reservation *reserved) {
    memset(reserved, 0, sizeof(*reserved));
    if (getrlimit(RLIMIT_NOFILE, &reserved->limit))
        return -1;
    /* Reserving the guest range must not consume the loader's original fd
     * budget. Raise only the soft limit, within the caller's hard limit, and
     * restore it before returning to the guest. */
    struct rlimit expanded = reserved->limit;
    rlim_t extra = expanded.rlim_max - expanded.rlim_cur;
    if (extra > MAX_FDS)
        extra = MAX_FDS;
    if (extra) {
        expanded.rlim_cur += extra;
        if (setrlimit(RLIMIT_NOFILE, &expanded))
            return -1;
        reserved->raised_limit = 1;
    }
    /* A memfd has a distinct inode. Closing an eventfd placeholder can drop
     * locks on another eventfd because anonymous-inode descriptors share one. */
    int placeholder = memfd_create("lashos-fd-slots", MFD_CLOEXEC);
    if (placeholder < 0)
        goto failed;
    if (placeholder < MAX_FDS)
        reserved->slots[placeholder] = 1;
    for (int i = 0; i < MAX_FDS; i++) {
        if (fcntl(i, F_GETFD) >= 0)
            continue;
        if (errno != EBADF || fcntl(placeholder, F_DUPFD_CLOEXEC, i) < 0) {
            int error = errno;
            if (placeholder >= MAX_FDS)
                close(placeholder);
            errno = error;
            goto failed;
        }
        reserved->slots[i] = 1;
    }
    if (placeholder >= MAX_FDS)
        close(placeholder);
    return 0;
failed:
    release_descriptor_slots(reserved);
    return -1;
}
static int adopt_descriptor(int descriptors[MAX_FDS], int real, int minimum) {
    if (real < 0)
        return -1;
    if (real >= minimum && real < MAX_FDS && descriptors[real] < 0) {
        descriptors[real] = real;
        return real;
    }
    close(real);
    errno = EMFILE;
    return -1;
}
