/* SPDX-License-Identifier: MIT */
/* Bash control surface for the local raw PTY broker. Bytes stay in native
   buffers; history capture is explicit and is never terminal-state replay. */
#include <config.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "loadables.h"
#include "trap.h"
#if __has_include ("_ptybroker_ptybroker.h")
# include "_ptybroker_ptybroker.h"
# include "_ptybroker_transport.h"
#else
# include "_ptybroker/ptybroker.h"
# include "_ptybroker/transport.h"
#endif

#define BW_HANDLES 32
struct bw_handle {
    pid_t owner;
    uint64_t generation;
    int active, fd, pending;
    struct pb_event event;
    size_t written;
};
static struct bw_handle bw_handles[BW_HANDLES];
static uint64_t bw_generation;
static int bw_exit_registered;
int ptybroker_builtin(WORD_LIST *);

static void bw_clear(void)
{
    for (int i = 0; i < BW_HANDLES; i++) {
        if (bw_handles[i].active) close(bw_handles[i].fd);
        memset(&bw_handles[i], 0, sizeof bw_handles[i]);
    }
}

void ptybroker_builtin_unload(char *name)
{
    (void)name;
    bw_clear();
}

static int bw_initialize(void)
{
    /* The child may discard its own copies, but must never read a packet
       from a connection still owned by its parent. */
    for (int i = 0; i < BW_HANDLES; i++)
        if (bw_handles[i].active && bw_handles[i].owner != getpid()) {
            close(bw_handles[i].fd);
            memset(&bw_handles[i], 0, sizeof bw_handles[i]);
        }
    if (!bw_exit_registered) {
        /* A new module load must not recreate a token retained by the
           caller before enable -d/enable -f in this same process. */
        uint64_t seed;
        if (getrandom(&seed, sizeof seed, GRND_NONBLOCK) != sizeof seed) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
            seed = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
        }
        bw_generation = seed & (UINT64_MAX >> 1);
        if (atexit(bw_clear)) { errno = ENOMEM; return -1; }
        bw_exit_registered = 1;
    }
    return 0;
}

static int bw_failure(const char *operation)
{
    int saved = errno;
    if (saved == ETIMEDOUT) return 124;
    builtin_error("%s: %s", operation, strerror(saved));
    if (saved == EINTR) {
        int sig = terminating_signal ? terminating_signal :
                  interrupt_state ? SIGINT : first_pending_trap();
        return sig > 0 ? 128 + sig : EXECUTION_FAILURE;
    }
    return EXECUTION_FAILURE;
}

static int bw_number(const char *word, unsigned long limit, unsigned long *value)
{
    char *end;
    if (!word || word[0] < '0' || word[0] > '9') return -1;
    errno = 0;
    unsigned long n = strtoul(word, &end, 10);
    if (errno || *end || n > limit) return -1;
    *value = n;
    return 0;
}

static int bw_fd(const char *word, int writing)
{
    unsigned long n;
    if (bw_number(word, INT_MAX, &n)) { errno = EINVAL; return -1; }
    int flags = fcntl((int)n, F_GETFL);
    if (flags < 0) return -1;
    if ((writing && (flags & O_ACCMODE) == O_RDONLY) ||
        (!writing && (flags & O_ACCMODE) == O_WRONLY)) { errno = EBADF; return -1; }
    return (int)n;
}

/* Scalar validation cannot evaluate an array subscript or command
   substitution. Copy resolved nameref names before changing any bindings. */
static char *bw_variable(const char *name, int text)
{
    const char *target = name;
    for (int depth = 0; depth < 64; depth++) {
        if (!target || !legal_identifier(target)) break;
        SHELL_VAR *v = find_variable_noref(target);
        if (v && (readonly_p(v) || noassign_p(v) || array_p(v) || assoc_p(v) ||
                  v->dynamic_value || v->assign_func ||
                  (text && (integer_p(v) || uppercase_p(v) || lowercase_p(v) || capcase_p(v))))) break;
        if (v && nameref_p(v)) { target = nameref_cell(v); continue; }
        char *copy = strdup(target);
        if (!copy) builtin_error("variable: %s", strerror(errno));
        return copy;
    }
    builtin_error("expected a writable %sscalar variable: %s", text ? "text " : "", name);
    return NULL;
}

static int bw_bind(char *name, const char *value)
{
    SHELL_VAR *v = builtin_bind_variable(name, (char *)value, 0);
    if (!v || readonly_p(v) || noassign_p(v)) { errno = EINVAL; return -1; }
    return 0;
}

static int bw_bind_number(char *name, uint64_t n)
{
    char value[32];
    snprintf(value, sizeof value, "%" PRIu64, n);
    return bw_bind(name, value);
}

static struct bw_handle *bw_find(const char *name)
{
    unsigned long owner, slot;
    unsigned long long generation;
    int used = 0;
    if (!name || sscanf(name, "pb:%lu:%llu:%lu%n", &owner, &generation, &slot, &used) != 3 ||
        name[used] || slot >= BW_HANDLES || owner != (unsigned long)getpid()) {
        errno = EINVAL; return NULL;
    }
    struct bw_handle *h = &bw_handles[slot];
    if (!h->active || h->owner != getpid() || h->generation != generation) {
        errno = EINVAL; return NULL;
    }
    return h;
}

static void bw_status_line(const char *id, const struct pb_status *s)
{
    printf("id=%s broker_pid=%d child_pid=%d running=%d stopping=%d exit_status=%d "
           "rows=%u cols=%u controller=%u observers=%u oldest=%" PRIu64 " next=%" PRIu64
           " capability=raw-pty history=raw-only replay=none\n",
           id, s->broker_pid, s->child_pid, s->running, s->stopping, s->exit_status,
           s->rows, s->cols, s->controller, s->observers, s->oldest, s->next);
}

/* Use the loaded mapping when dladdr retained a relative path and the
   caller has since changed directory. readlink also preserves spaces. */
static char *bw_mapping_path(void *address)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return NULL;
    char line[PATH_MAX + 256], link[128], path[PATH_MAX];
    unsigned long start, end;
    char *result = NULL;
    while (fgets(line, sizeof line, maps)) {
        if (sscanf(line, "%lx-%lx", &start, &end) != 2 ||
            (uintptr_t)address < start || (uintptr_t)address >= end) continue;
        snprintf(link, sizeof link, "/proc/self/map_files/%lx-%lx", start, end);
        ssize_t n = readlink(link, path, sizeof path - 1);
        if (n > 0 && (size_t)n < sizeof path - 1) {
            path[n] = 0;
            result = realpath(path, NULL);
        }
        break;
    }
    fclose(maps);
    return result;
}

int bos_ptybroker_create(const char *root, const char *id, char *const *argv,
                        const char *cwd, unsigned rows, unsigned cols,
                        struct pb_status *status)
{
    Dl_info info;
    char *loadable = NULL;
    const char *override = getenv("BASH_PTYBROKER_LOADABLE");
    struct stat executable, object;
    if (override && *override) {
        loadable = realpath(override, NULL);
        if (!loadable) return -1;
        if (stat(loadable, &object) < 0 || !S_ISREG(object.st_mode)) {
            int saved = errno ? errno : EINVAL; free(loadable); errno = saved; return -1;
        }
    } else if (dladdr((void *)&ptybroker_builtin, &info) && info.dli_fname) {
        if (stat("/proc/self/exe", &executable) < 0) return -1;
        loadable = bw_mapping_path((void *)&ptybroker_builtin);
        if (!loadable) loadable = realpath(info.dli_fname, NULL);
        if (!loadable) return -1;
        if (stat(loadable, &object) < 0) { int saved = errno; free(loadable); errno = saved; return -1; }
        if (object.st_dev == executable.st_dev && object.st_ino == executable.st_ino) {
            free(loadable); loadable = NULL;
        }
    } /* A fully static executable has no dladdr object: use compiled self. */
    struct pb_start_options options = {.root = root, .id = id, .cwd = cwd,
        .argv = argv, .rows = rows, .cols = cols, .loadable = loadable};
    int rc = pb_start(&options, status), saved = errno;
    free(loadable);
    errno = saved;
    return rc;
}

struct bw_pipe_guard { sigset_t set; int changed, pending, generated; };
static int bw_pipe_begin(struct bw_pipe_guard *g)
{
    sigset_t old, pending;
    g->generated = 0;
    sigemptyset(&g->set); sigaddset(&g->set, SIGPIPE);
    if (sigprocmask(SIG_BLOCK, &g->set, &old) < 0) return -1;
    g->changed = sigismember(&old, SIGPIPE) == 0;
    if (sigpending(&pending) < 0) {
        int saved = errno;
        if (g->changed) sigprocmask(SIG_UNBLOCK, &g->set, NULL);
        errno = saved; return -1;
    }
    g->pending = sigismember(&pending, SIGPIPE) == 1;
    return 0;
}

static void bw_pipe_end(struct bw_pipe_guard *g)
{
    int saved = errno;
    if (g->generated && !g->pending) {
        struct timespec zero = {0, 0};
        (void)sigtimedwait(&g->set, NULL, &zero);
    }
    if (g->changed) (void)sigprocmask(SIG_UNBLOCK, &g->set, NULL);
    errno = saved;
}

/* A timed-out or interrupted write retains the event and its exact output
   offset. The next receive resumes it before reading another broker packet. */
static int bw_deliver(struct bw_handle *h, int fd, int64_t deadline)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    struct bw_pipe_guard guard;
    if (bw_pipe_begin(&guard) < 0) return -1;
    int rc = -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) goto done;
    while (h->written < h->event.size) {
        if (interrupt_state || terminating_signal || first_pending_trap() > 0) { errno = EINTR; goto restore; }
        ssize_t n = write(fd, h->event.data + h->written, h->event.size - h->written);
        if (n > 0) { h->written += (size_t)n; continue; }
        if (n < 0 && errno == EPIPE) guard.generated = 1;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!pb_wait(fd, POLLOUT, deadline)) continue;
        } else if (!n) errno = EIO;
        goto restore;
    }
    rc = 0;
restore: {
        int saved = errno;
        if (fcntl(fd, F_SETFL, flags) < 0 && !rc) { saved = errno; rc = -1; }
        errno = saved;
    }
done:
    bw_pipe_end(&guard);
    return rc;
}

static int bw_receive(struct bw_handle *h, int fd, char *variable, int timeout)
{
    int64_t deadline = pb_now() + timeout;
    if (!h->pending) {
        if (pb_receive(h->fd, &h->event, timeout) < 0) return -1;
        h->pending = 1; h->written = 0;
    }
    char event[256];
    if (h->event.type == PB_OUTPUT) {
        if (bw_deliver(h, fd, deadline) < 0) return -1;
        snprintf(event, sizeof event, "output size=%u offset=%" PRIu64, h->event.size, h->event.offset);
    } else {
        struct pb_status status;
        if (h->event.size != sizeof status) { errno = EPROTO; return -1; }
        memcpy(&status, h->event.data, sizeof status);
        const char *kind = h->event.type == PB_ATTACHED ? "attached" :
                           h->event.type == PB_GAP ? "gap" :
                           h->event.type == PB_GEOMETRY ? "geometry" :
                           h->event.type == PB_EXIT ? "exit" : NULL;
        if (!kind) { errno = EPROTO; return -1; }
        snprintf(event, sizeof event, "%s rows=%u cols=%u exit_status=%d oldest=%" PRIu64
                 " next=%" PRIu64, kind, status.rows, status.cols, status.exit_status, status.oldest, status.next);
    }
    if (bw_bind(variable, event) < 0) return -1;
    h->pending = 0; h->written = 0;
    return 0;
}

static int bw_create(int argc, char **argv, int service)
{
    unsigned long rows = 24, cols = 80;
    const char *directory = NULL;
    int command = 3;
    if (service) {
        const char *flag = getenv("BASH_PTYBROKER_SERVICE");
        struct stat ready;
        int type = 0;
        socklen_t type_size = sizeof type;
        if (!flag || strcmp(flag, "1") || interactive || interactive_shell ||
            fstat(3, &ready) < 0 || !S_ISSOCK(ready.st_mode) ||
            getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &type_size) < 0 || type != SOCK_SEQPACKET) {
            builtin_error("serve is reserved for a fresh broker service process"); return EXECUTION_FAILURE;
        }
        if (argc < 7 || bw_number(argv[3], 65535, &rows) || !rows ||
            bw_number(argv[4], 65535, &cols) || !cols) return EX_USAGE;
        directory = argv[5]; command = 6;
    } else {
        if (argc < 5) return EX_USAGE;
        while (command < argc && strcmp(argv[command], "--")) {
            if (command + 1 >= argc) return EX_USAGE;
            if (!strcmp(argv[command], "--rows")) {
                if (bw_number(argv[command + 1], 65535, &rows) || !rows) return EX_USAGE;
            } else if (!strcmp(argv[command], "--cols")) {
                if (bw_number(argv[command + 1], 65535, &cols) || !cols) return EX_USAGE;
            } else if (!strcmp(argv[command], "--cwd")) directory = argv[command + 1];
            else return EX_USAGE;
            command += 2;
        }
        if (++command >= argc) return EX_USAGE;
    }
    if (!pb_valid_id(argv[2])) { errno = EINVAL; return bw_failure("session ID"); }
    char *cwd = directory ? realpath(directory, NULL) : getcwd(NULL, 0);
    if (!cwd) return bw_failure("cwd");
    struct stat st;
    if (stat(cwd, &st) < 0 || !S_ISDIR(st.st_mode)) {
        int saved = errno ? errno : ENOTDIR; free(cwd); errno = saved; return bw_failure("cwd");
    }
    struct pb_status status;
    int rc;
    if (service) {
        struct pb_start_options options = {.root = argv[1], .id = argv[2], .cwd = cwd,
            .argv = argv + command, .rows = (unsigned)rows, .cols = (unsigned)cols};
        rc = pb_serve(&options, 3);
    } else rc = bos_ptybroker_create(argv[1], argv[2], argv + command, cwd,
                                    (unsigned)rows, (unsigned)cols, &status);
    int saved = errno;
    free(cwd); errno = saved;
    if (rc < 0) return bw_failure(service ? "serve" : "create");
    if (!service) bw_status_line(argv[2], &status);
    return EXECUTION_SUCCESS;
}

static int bw_send_fd(const char *root, const char *id, int fd, char *variable)
{
    unsigned char bytes[PB_CHUNK];
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    ssize_t size;
    int64_t until = pb_now() + PB_TIMEOUT;
    for (;;) {
        size = read(fd, bytes, sizeof bytes);
        if (size >= 0) break;
        if ((errno != EAGAIN && errno != EWOULDBLOCK) || pb_wait(fd, POLLIN, until) < 0) break;
    }
    int saved = errno;
    if (fcntl(fd, F_SETFL, flags) < 0 && size >= 0) { size = -1; saved = errno; }
    errno = saved;
    if (size < 0) return -1;
    if (size && pb_send(root, id, bytes, (size_t)size) < 0) return -1;
    return variable ? bw_bind_number(variable, (uint64_t)size) : 0;
}

int ptybroker_builtin(WORD_LIST *list)
{
    if (bw_initialize() < 0) return bw_failure("initialize");
    char *argv[1040]; int argc = 0;
    for (; list && argc < 1039; list = list->next) argv[argc++] = list->word->word;
    argv[argc] = NULL;
    if (!argc || list) { builtin_usage(); return EX_USAGE; }
    const char *command = argv[0];
    int rc = -1;
    if (!strcmp(command, "create") || !strcmp(command, "serve"))
        return bw_create(argc, argv, !strcmp(command, "serve"));
    if (!strcmp(command, "status") && argc == 3) {
        struct pb_status status;
        rc = pb_status(argv[1], argv[2], &status);
        if (!rc) bw_status_line(argv[2], &status);
    } else if (!strcmp(command, "list") && argc == 2) {
        if (pb_check_root(argv[1], 0) < 0) return bw_failure(command);
        DIR *dir = opendir(argv[1]);
        if (!dir) return bw_failure(command);
        struct dirent *entry;
        while ((entry = readdir(dir))) {
            struct stat st;
            if (pb_valid_id(entry->d_name) &&
                !fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) &&
                S_ISDIR(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 0777) == 0700)
                puts(entry->d_name);
        }
        closedir(dir); rc = 0;
    } else if (!strcmp(command, "attach") && argc == 5) {
        int role = !strcmp(argv[3], "control") ? PB_CONTROL : !strcmp(argv[3], "observe") ? PB_OBSERVE : 0;
        if (!role) return EX_USAGE;
        char *variable = bw_variable(argv[4], 1);
        if (!variable) return EXECUTION_FAILURE;
        int slot;
        for (slot = 0; slot < BW_HANDLES && bw_handles[slot].active; slot++);
        if (slot == BW_HANDLES || bw_generation == UINT64_MAX) {
            free(variable); errno = EMFILE; return bw_failure(command);
        }
        struct bw_handle *h = &bw_handles[slot];
        struct pb_status status;
        rc = pb_attach(argv[1], argv[2], role, &h->fd, &status);
        if (!rc) {
            char handle[96];
            h->owner = getpid(); h->generation = ++bw_generation; h->active = 1;
            snprintf(handle, sizeof handle, "pb:%lu:%" PRIu64 ":%d", (unsigned long)getpid(), h->generation, slot);
            rc = bw_bind(variable, handle);
            if (rc < 0) { close(h->fd); memset(h, 0, sizeof *h); }
        }
        int saved = errno; free(variable); errno = saved;
    } else if (!strcmp(command, "fd") && argc == 3) {
        char *variable = bw_variable(argv[2], 0);
        if (!variable) return EXECUTION_FAILURE;
        struct bw_handle *h = bw_find(argv[1]);
        rc = h ? bw_bind_number(variable, (uint64_t)h->fd) : -1;
        int saved = errno; free(variable); errno = saved;
    } else if (!strcmp(command, "detach") && argc == 2) {
        struct bw_handle *h = bw_find(argv[1]);
        if (!h) return bw_failure(command);
        rc = close(h->fd); memset(h, 0, sizeof *h);
    } else if (!strcmp(command, "receive") && (argc == 4 || argc == 5)) {
        unsigned long timeout = 100;
        if (argc == 5 && bw_number(argv[4], 60000, &timeout)) return EX_USAGE;
        char *variable = bw_variable(argv[3], 1);
        if (!variable) return EXECUTION_FAILURE;
        struct bw_handle *h = bw_find(argv[1]);
        int fd = bw_fd(argv[2], 1);
        if (h && fd == h->fd) { errno = EINVAL; fd = -1; }
        rc = h && fd >= 0 ? bw_receive(h, fd, variable, (int)timeout) : -1;
        int saved = errno; free(variable); errno = saved;
    } else if (!strcmp(command, "send") && argc == 4) {
        rc = pb_send(argv[1], argv[2], argv[3], strlen(argv[3]));
    } else if (!strcmp(command, "send-fd") && (argc == 4 || argc == 5)) {
        char *variable = argc == 5 ? bw_variable(argv[4], 0) : NULL;
        if (argc == 5 && !variable) return EXECUTION_FAILURE;
        int fd = bw_fd(argv[3], 0);
        /* Check the destination before consuming any bytes from INFD. */
        struct pb_status status;
        rc = fd >= 0 ? pb_status(argv[1], argv[2], &status) : -1;
        if (!rc) rc = bw_send_fd(argv[1], argv[2], fd, variable);
        int saved = errno; free(variable); errno = saved;
    } else if (!strcmp(command, "resize") && argc == 5) {
        unsigned long rows, cols;
        if (bw_number(argv[3], 65535, &rows) || !rows || bw_number(argv[4], 65535, &cols) || !cols) return EX_USAGE;
        rc = pb_resize(argv[1], argv[2], (unsigned)rows, (unsigned)cols);
    } else if (!strcmp(command, "capture") && argc == 4) {
        int fd = bw_fd(argv[3], 1);
        if (fd < 0) return bw_failure(command);
        /* The shared native writer handles its own SIGPIPE generation. */
        rc = pb_capture(argv[1], argv[2], fd);
    } else if (!strcmp(command, "terminate") && argc == 3) {
        rc = pb_terminate(argv[1], argv[2]);
    } else { builtin_usage(); return EX_USAGE; }
    return rc < 0 ? bw_failure(command) : EXECUTION_SUCCESS;
}

char *ptybroker_doc[] = {
    "Local durable raw PTYs owned by a fresh native broker service.",
    "  ptybroker create ROOT ID [--rows N --cols N --cwd DIR] -- CMD...",
    "  ptybroker status ROOT ID | list ROOT",
    "  ptybroker attach ROOT ID control|observe HANDLEVAR",
    "  ptybroker fd HANDLE FDVAR | detach HANDLE",
    "  ptybroker receive HANDLE OUTFD EVENTVAR [TIMEOUT_MS]",
    "  ptybroker send ROOT ID TEXT | send-fd ROOT ID INFD [COUNT_VAR]",
    "  ptybroker resize ROOT ID ROWS COLS | capture ROOT ID OUTFD",
    "  ptybroker terminate ROOT ID",
    "ROOT is an absolute, owner-only directory. Handles belong to this process.",
    "Receive defaults to 100 ms (maximum 60000); timeout returns 124. Events:",
    "attached, gap, output, geometry, exit. Bytes go only to OUTFD. Partial",
    "writes retain the remaining event bytes for the next receive call.",
    "send-fd reads at most 16384 bytes; COUNT_VAR reports a successful chunk.",
    "A failed send may have consumed input; delivery acknowledgement is not",
    "a transaction. Output variables must be writable scalars, not arrays.",
    "Attach starts with live output. Capture explicitly writes bounded raw",
    "history; it is not a terminal or graphics checkpoint. Detach keeps the",
    "PTY alive. Terminate waits for descendant cleanup before acknowledging.",
    (char *)NULL
};

struct builtin ptybroker_struct = {
    "ptybroker", ptybroker_builtin, BUILTIN_ENABLED, ptybroker_doc,
    "ptybroker create|status|list|attach|fd|receive|detach|send|send-fd|resize|capture|terminate ARGS...", 0
};
