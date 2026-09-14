/* SPDX-License-Identifier: MIT
 * Local, Linux-only raw PTY service. No terminal parser or implicit replay.
 */
#ifndef BOS_PTYBROKER_H
#define BOS_PTYBROKER_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PB_CHUNK 16384u
#define PB_HISTORY (1024u * 1024u)
#define PB_ID_MAX 48
#define PB_TIMEOUT 3000
#define PB_CONTROL 1
#define PB_OBSERVE 2
enum pb_event_type { PB_OUTPUT = 64, PB_ATTACHED, PB_GEOMETRY, PB_EXIT, PB_GAP };
struct pb_status {
    int32_t broker_pid, child_pid, running, stopping, exit_status;
    uint32_t rows, cols, controller, observers;
    uint64_t oldest, next;
};
struct pb_event {
    uint32_t type, size;
    uint64_t offset;
    unsigned char data[PB_CHUNK];
};
struct pb_start_options {
    const char *root, *id, *cwd;
    char *const *argv;
    unsigned rows, cols;
    /* NULL selects the current executable. A shared loadable creator supplies
     * its absolute .so path; compiled-in clients leave loadable NULL. */
    const char *shell, *loadable;
};
/* All calls return zero on success or -1 with errno. Deadlines are bounded;
 * EINTR is returned to the caller. FDs returned by attach are NONBLOCK/CLOEXEC.
 * Session directories remain until explicit termination, even after exit. */
int pb_start(const struct pb_start_options *, struct pb_status *);
int pb_serve(const struct pb_start_options *, int ready_fd);
int pb_status(const char *root, const char *id, struct pb_status *);
int pb_resize(const char *root, const char *id, unsigned rows, unsigned cols);
int pb_send(const char *root, const char *id, const void *data, size_t size);
int pb_capture(const char *root, const char *id, int out_fd);
int pb_terminate(const char *root, const char *id);
int pb_attach(const char *root, const char *id, int role, int *fd,
              struct pb_status *);
int pb_receive(int fd, struct pb_event *, int timeout_ms);
int pb_valid_id(const char *);
int pb_check_root(const char *root, int create);
/* Used by screen as well as the loadable. Resolves the current bash-os binary
 * and the wrapper's shared-object path, then starts a fresh service process. */
int bos_ptybroker_create(const char *root, const char *id, char *const *argv,
                        const char *cwd, unsigned rows, unsigned cols,
                        struct pb_status *);
#endif
