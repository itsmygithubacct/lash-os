int ppoll(struct pollfd *fds, nfds_t count, const struct timespec *timeout, const sigset_t *mask) {
    if (count > 256 || (timeout && (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
                                    timeout->tv_nsec >= 1000000000))) {
        errno = EINVAL;
        return -1;
    }
    int64_t ns = timeout ? (int64_t)timeout->tv_sec * 1000000000 + timeout->tv_nsec : -1;
    sigset_t previous = guest_signal_mask, effective;
    /* Signals held by a running handler must not interrupt the host wait. */
    if (dispatch_blocked) {
        effective = (mask ? *mask : guest_signal_mask) | dispatch_blocked;
        mask = &effective;
    }
    if (mask)
        guest_signal_mask = *mask;
    control.args[3] = mask ? (uintptr_t)mask : 0;
    int rc = bridge(BR_POLL, (uintptr_t)fds, count, ns);
    guest_signal_mask = previous;
    return rc;
}
int poll(struct pollfd *fds, nfds_t count, int milliseconds) {
    struct timespec timeout = {.tv_sec = milliseconds / 1000,
                               .tv_nsec = (milliseconds % 1000) * 1000000};
    return ppoll(fds, count, milliseconds < 0 ? NULL : &timeout, NULL);
}
int pselect(int n, fd_set *r, fd_set *w, fd_set *e, const struct timespec *t, const sigset_t *s) {
    if (n < 0 || n > 256 || n > FD_SETSIZE) {
        errno = EINVAL;
        return -1;
    }
    struct pollfd fds[256];
    nfds_t count = 0;
    for (int i = 0; i < n; i++) {
        short events = 0;
        if (r && FD_ISSET(i, r))
            events |= POLLIN;
        if (w && FD_ISSET(i, w))
            events |= POLLOUT;
        if (e && FD_ISSET(i, e))
            events |= POLLPRI;
        if (events)
            fds[count++] = (struct pollfd){.fd = i, .events = events};
    }
    int rc = ppoll(fds, count, t, s);
    if (rc < 0)
        return rc;
    if (r)
        FD_ZERO(r);
    if (w)
        FD_ZERO(w);
    if (e)
        FD_ZERO(e);
    rc = 0;
    for (nfds_t i = 0; i < count; i++) {
        short ready = fds[i].revents;
        if (ready & POLLNVAL) {
            errno = EBADF;
            return -1;
        }
        if (r && (fds[i].events & POLLIN) && (ready & (POLLIN | POLLHUP | POLLERR))) {
            FD_SET(fds[i].fd, r);
            rc++;
        }
        if (w && (fds[i].events & POLLOUT) && (ready & (POLLOUT | POLLERR))) {
            FD_SET(fds[i].fd, w);
            rc++;
        }
        if (e && (ready & POLLPRI)) {
            FD_SET(fds[i].fd, e);
            rc++;
        }
    }
    return rc;
}
int select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t) {
    struct timespec timeout;
    if (t) {
        timeout.tv_sec = t->tv_sec;
        timeout.tv_nsec = t->tv_usec * 1000;
    }
    return pselect(n, r, w, e, t ? &timeout : NULL, NULL);
}
