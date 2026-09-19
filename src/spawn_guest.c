#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
struct spawn_action {
    struct spawn_action *next;
    int type, fd, other, flags;
    mode_t mode;
    char *path;
};
struct __posix_spawn_file_actions {
    struct spawn_action *first, *last;
};
struct __posix_spawnattr {
    short flags;
    pid_t group;
    sigset_t mask, defaults;
};
int posix_spawnattr_init(posix_spawnattr_t *out) {
    *out = calloc(1, sizeof(**out));
    return *out ? 0 : ENOMEM;
}
int posix_spawnattr_destroy(posix_spawnattr_t *out) {
    free(*out);
    *out = NULL;
    return 0;
}
int posix_spawnattr_setflags(posix_spawnattr_t *out, short flags) {
    if (flags & ~(POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF |
                  POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSID))
        return ENOTSUP;
    (*out)->flags = flags;
    return 0;
}
int posix_spawnattr_setpgroup(posix_spawnattr_t *out, pid_t group) {
    (*out)->group = group;
    return 0;
}
int posix_spawnattr_setsigmask(posix_spawnattr_t *out, const sigset_t *mask) {
    (*out)->mask = *mask;
    return 0;
}
int posix_spawnattr_setsigdefault(posix_spawnattr_t *out, const sigset_t *mask) {
    (*out)->defaults = *mask;
    return 0;
}
int posix_spawn_file_actions_init(posix_spawn_file_actions_t *out) {
    *out = calloc(1, sizeof(**out));
    return *out ? 0 : ENOMEM;
}
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *out) {
    struct spawn_action *a = (*out)->first;
    while (a) {
        struct spawn_action *next = a->next;
        free(a->path);
        free(a);
        a = next;
    }
    free(*out);
    *out = NULL;
    return 0;
}
static int add_action(posix_spawn_file_actions_t *out, int type, int fd, int other,
                      const char *path, int flags, mode_t mode) {
    if (fd < 0 || fd >= 256)
        return EBADF;
    struct spawn_action *a = calloc(1, sizeof(*a));
    if (!a)
        return ENOMEM;
    a->type = type;
    a->fd = fd;
    a->other = other;
    a->flags = flags;
    a->mode = mode;
    if (path && !(a->path = strdup(path))) {
        free(a);
        return ENOMEM;
    }
    if ((*out)->last)
        (*out)->last->next = a;
    else
        (*out)->first = a;
    (*out)->last = a;
    return 0;
}
int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *out, int from, int to) {
    if (to < 0 || to >= 256)
        return EBADF;
    return add_action(out, 1, from, to, NULL, 0, 0);
}
int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *out, int fd, const char *path,
                                     int flags, mode_t mode) {
    return add_action(out, 2, fd, 0, path, flags, mode);
}
int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *out, int fd) {
    return add_action(out, 3, fd, 0, NULL, 0, 0);
}
int posix_spawn_file_actions_addclosefrom_np(posix_spawn_file_actions_t *out, int fd) {
    return add_action(out, 4, fd, 0, NULL, 0, 0);
}
/* Failed exec is reported over a close-on-exec pipe, as required by posix_spawn. */
int posix_spawn(pid_t *result, const char *path, const posix_spawn_file_actions_t *actions,
                const posix_spawnattr_t *attributes, char *const argv[], char *const envp[]) {
    int pair[2];
    if (pipe(pair))
        return errno;
    int report = fcntl(pair[1], F_DUPFD_CLOEXEC, 128);
    close(pair[1]);
    if (report < 0) {
        int error = errno;
        close(pair[0]);
        return error;
    }
    pid_t child = fork();
    if (child < 0) {
        int error = errno;
        close(pair[0]);
        close(report);
        return error;
    }
    if (!child) {
        close(pair[0]);
        int error = 0;
        if (attributes && *attributes) {
            const struct __posix_spawnattr *a = *attributes;
            if ((a->flags & POSIX_SPAWN_SETSID) && setsid() < 0)
                goto failed;
            if ((a->flags & POSIX_SPAWN_SETPGROUP) && setpgid(0, a->group))
                goto failed;
            if ((a->flags & POSIX_SPAWN_RESETIDS) && (setgid(getgid()) || setuid(getuid())))
                goto failed;
            /* Like glibc, skip signals that cannot be caught and the two
             * realtime signals reserved by the C library. */
            if (a->flags & POSIX_SPAWN_SETSIGDEF)
                for (int i = 1; i < 65; i++)
                    if (i != SIGKILL && i != SIGSTOP && i != 32 && i != 33 &&
                        sigismember(&a->defaults, i) == 1 && signal(i, SIG_DFL) == SIG_ERR)
                        goto failed;
            if ((a->flags & POSIX_SPAWN_SETSIGMASK) && sigprocmask(SIG_SETMASK, &a->mask, NULL))
                goto failed;
        }
        if (actions && *actions)
            for (struct spawn_action *a = (*actions)->first; a; a = a->next) {
                if (a->fd == report || (a->type == 1 && a->other == report)) {
                    errno = ENOTSUP;
                    goto failed;
                }
                /* POSIX: duplicating a descriptor onto itself clears FD_CLOEXEC. */
                if (a->type == 1 && a->fd == a->other) {
                    int flags = fcntl(a->fd, F_GETFD);
                    if (flags < 0 || fcntl(a->fd, F_SETFD, flags & ~FD_CLOEXEC) < 0)
                        goto failed;
                } else if (a->type == 1 && dup2(a->fd, a->other) < 0)
                    goto failed;
                if (a->type == 2) {
                    int f = open(a->path, a->flags, a->mode);
                    if (f < 0)
                        goto failed;
                    if (f != a->fd) {
                        int rc = dup2(f, a->fd);
                        close(f);
                        if (rc < 0)
                            goto failed;
                    }
                }
                if (a->type == 3)
                    close(a->fd);
                if (a->type == 4)
                    for (int f = a->fd; f < 256; f++)
                        if (f != report)
                            close(f);
            }
        execve(path, argv, envp);
    failed:
        error = errno;
        while (write(report, &error, sizeof(error)) < 0 && errno == EINTR) {
        }
        _exit(127);
    }
    close(report);
    int error = 0;
    ssize_t n;
    do {
        n = read(pair[0], &error, sizeof(error));
    } while (n < 0 && errno == EINTR);
    close(pair[0]);
    if (n > 0) {
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
        }
        return error;
    }
    if (n < 0)
        return errno;
    *result = child;
    return 0;
}
int execlp(const char *file, const char *first, ...) {
    va_list ap;
    va_start(ap, first);
    size_t count = 1;
    while (va_arg(ap, const char *))
        count++;
    va_end(ap);
    char **argv = calloc(count + 1, sizeof(char *));
    if (!argv)
        return -1;
    argv[0] = (char *)first;
    va_start(ap, first);
    for (size_t i = 1; i < count; i++)
        argv[i] = va_arg(ap, char *);
    va_end(ap);
    execvp(file, argv);
    int error = errno;
    free(argv);
    errno = error;
    return -1;
}
