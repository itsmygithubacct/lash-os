#pragma once

static int poll_descriptors(volatile struct kernel_control *c, const int descriptors[MAX_FDS],
                            struct pollfd *in, nfds_t count, const struct timespec *timeout,
                            const uint64_t *mask) {
    if (count > MAX_FDS) {
        errno = EINVAL;
        return -1;
    }
    struct pollfd items[MAX_FDS];
    int invalid = 0;
    for (nfds_t i = 0; i < count; i++) {
        items[i] = in[i];
        in[i].revents = items[i].revents = 0;
        if (in[i].fd < 0)
            items[i].fd = -1;
        else if (in[i].fd >= MAX_FDS || descriptors[in[i].fd] < 0) {
            items[i].fd = -1;
            in[i].revents = POLLNVAL;
            invalid++;
        } else
            items[i].fd = descriptors[in[i].fd];
    }
    struct timespec immediate = {0};
    if (invalid)
        timeout = &immediate;

    /* Queue inspection and mask installation must be atomic with respect to
     * native delivery: a signal already recorded cannot interrupt ppoll. */
    sigset_t all, previous, desired;
    sigfillset(&all);
    if (sigprocmask(SIG_BLOCK, &all, &previous))
        return -1;
    if (mask)
        unpack_signal_mask(*mask, &desired);
    else
        desired = previous;
    publish_signals(c);
    int rc;
    if (c->pending_signals & ~pack_signal_mask(&desired)) {
        errno = EINTR;
        rc = -1;
    } else
        rc = ppoll(items, count, timeout, &desired);
    int error = errno;
    publish_signals(c);
    if (sigprocmask(SIG_SETMASK, &previous, NULL))
        return -1;
    errno = error;
    if (rc < 0)
        return rc;
    for (nfds_t i = 0; i < count; i++)
        in[i].revents |= items[i].revents;
    return rc + invalid;
}
