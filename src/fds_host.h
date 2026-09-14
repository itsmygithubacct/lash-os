#pragma once

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
