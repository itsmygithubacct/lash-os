#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <asm/ioctl.h>
#include <linux/sockios.h>
#include <linux/keyctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/epoll.h>
#include <sys/timex.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <sys/signalfd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <sys/xattr.h>
#include <sys/random.h>
#include <sys/inotify.h>
#include <sys/file.h>
#include <sys/reboot.h>
#include <sys/swap.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sched.h>
#include "bpf_capsule_host.h"
#include "kernel_control.h"
#include "bash.skel.h"
#include "sandbox_host.h"

#define MAX_FDS 256
#define MAX_DIRS 64
#include "fds_host.h"
struct bridge_host {
    struct bpf_capsule *capsule;
    const void *image;
    size_t image_size;
    int fds[MAX_FDS];
    DIR *dirs[MAX_DIRS];
    int dir_fds[MAX_DIRS];
};
#include "process_host.h"
#include "signal_host.h"
#include "poll_host.h"
static int bridge_error(int error) {
    switch (error) {
    case 0:
        return BE_OK;
#define HOST_ERROR(e)                                                                              \
    case e:                                                                                        \
        return BE_##e;
        BRIDGE_ERRORS(HOST_ERROR)
#undef HOST_ERROR
    default:
        return BE_EIO;
    }
}

static uint64_t available(struct bridge_host *h, uint64_t address) {
    uint64_t base = (uintptr_t)bpf_capsule_memory_start(h->capsule);
    uint64_t total = bpf_capsule_memory_size(h->capsule);
    if (address >= base + 4096 && address - base < total)
        return total - (address - base);
    /* Initialized globals occupy the arena image before the sparse heap. */
    base = (uintptr_t)h->image;
    total = h->image_size;
    if (base && address >= base && address - base < total)
        return total - (address - base);
    return 0;
}
static void *memory(struct bridge_host *h, uint64_t address, uint64_t size) {
    uint64_t remaining = available(h, address);
    if (!remaining || size > remaining) {
        errno = EFAULT;
        return NULL;
    }
    return (void *)(uintptr_t)address;
}
static char *string(struct bridge_host *h, uint64_t address) {
    size_t left = available(h, address);
    if (!left) {
        errno = EFAULT;
        return NULL;
    }
    if (left > 4096)
        left = 4096;
    char *p = memory(h, address, left);
    if (!p || !memchr(p, 0, left)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return p;
}
static int fd(struct bridge_host *h, int guest) {
    if (guest < 0 || guest >= MAX_FDS || h->fds[guest] < 0) {
        errno = EBADF;
        return -1;
    }
    return h->fds[guest];
}
#include "paths_host.h"
static int save_fd(struct bridge_host *h, int real, int minimum) {
    if (real < 0)
        return -1;
    if (minimum >= 0)
        for (int i = minimum; i < MAX_FDS; i++)
            if (h->fds[i] < 0) {
                h->fds[i] = real;
                return i;
            }
    close(real);
    errno = EMFILE;
    return -1;
}
static int open_flags(unsigned bits) {
    int f = bits & 3;
    if (bits & BO_CREATE)
        f |= O_CREAT;
    if (bits & BO_TRUNCATE)
        f |= O_TRUNC;
    if (bits & BO_APPEND)
        f |= O_APPEND;
    if (bits & BO_EXCLUSIVE)
        f |= O_EXCL;
    if (bits & BO_NONBLOCK)
        f |= O_NONBLOCK;
    if (bits & BO_CLOEXEC)
        f |= O_CLOEXEC;
    if (bits & BO_NOFOLLOW)
        f |= O_NOFOLLOW;
    if (bits & BO_DIRECTORY)
        f |= O_DIRECTORY;
    if (bits & BO_NOCTTY)
        f |= O_NOCTTY;
    return f;
}
static int at_flags(unsigned bits) {
    int flags = bits & ~31u;
    if (bits & 1)
        flags |= AT_EACCESS;
    if (bits & 2)
        flags |= AT_SYMLINK_NOFOLLOW;
    if (bits & 4)
        flags |= AT_SYMLINK_FOLLOW;
    if (bits & 8)
        flags |= AT_REMOVEDIR;
    if (bits & 16)
        flags |= AT_EMPTY_PATH;
    return flags;
}
static unsigned pack_flags(int flags) {
    unsigned bits = flags & O_ACCMODE;
    if (flags & O_APPEND)
        bits |= BO_APPEND;
    if (flags & O_NONBLOCK)
        bits |= BO_NONBLOCK;
    return bits;
}
static void copy_string(char *dst, size_t size, const char *src) {
    snprintf(dst, size, "%s", src ? src : "");
}
static clockid_t native_clock(unsigned id) {
    switch (id) {
    case 0:
        return CLOCK_REALTIME_COARSE;
    case 1:
        return CLOCK_REALTIME;
    case 2:
    case 10:
        return CLOCK_PROCESS_CPUTIME_ID;
    case 3:
    case 11:
        return CLOCK_THREAD_CPUTIME_ID;
    case 4:
        return CLOCK_MONOTONIC;
    case 5:
        return CLOCK_MONOTONIC_RAW;
    case 6:
        return CLOCK_MONOTONIC_COARSE;
    case 7:
        return CLOCK_BOOTTIME;
    case 8:
        return CLOCK_REALTIME_ALARM;
    case 9:
        return CLOCK_BOOTTIME_ALARM;
    default:
        return -1;
    }
}
#include "network_host.h"
#include "misc_host.h"
#include "raw_host.h"
#include "posix_generated_host.h"
#include "exec_host.h"

static int64_t service(struct bridge_host *h, volatile struct kernel_control *c) {
    uint64_t a = c->args[0], b = c->args[1], n = c->args[2];
    int actual, rc;
    char *path, *other;
    char path_storage[BRIDGE_PATH_SIZE], other_storage[BRIDGE_PATH_SIZE];
    void *buffer;
    switch (c->operation) {
    case BR_EXEC:
        return service_exec(h, a, b, n);
    case BR_POSIX: {
        struct posix_request *request = memory(h, a, sizeof(*request));
        return request ? service_posix(h, request) : -1;
    }
    case BR_POLL: {
        if (b > MAX_FDS) {
            errno = EINVAL;
            return -1;
        }
        struct pollfd *in = b ? memory(h, a, b * sizeof(*in)) : NULL;
        uint64_t *mask = c->args[3] ? memory(h, c->args[3], sizeof(*mask)) : NULL;
        if ((b && !in) || (c->args[3] && !mask))
            return -1;
        struct timespec timeout = {.tv_sec = (int64_t)n / 1000000000,
                                   .tv_nsec = (int64_t)n % 1000000000};
        return poll_descriptors(c, h->fds, in, b, (int64_t)n < 0 ? NULL : &timeout, mask);
    }
    case BR_STATX: {
        struct statx *out = memory(h, c->args[4], sizeof(*out));
        path = path_string_mode(h, b, path_storage, !(n & AT_SYMLINK_NOFOLLOW));
        actual = (int)a == -2 ? AT_FDCWD : fd(h, (int)a);
        if (!out || !path || (actual < 0 && actual != AT_FDCWD))
            return -1;
        return statx(actual, path, n, c->args[3], out);
    }
    case BR_GETPGID:
        return getpgid((int)a);
    case BR_SETPGID:
        return setpgid((int)a, (int)b);
    case BR_SETSID:
        return setsid();
    case BR_TCGETPGRP:
        actual = fd(h, a);
        return actual < 0 ? -1 : tcgetpgrp(actual);
    case BR_TCSETPGRP:
        actual = fd(h, a);
        return actual < 0 ? -1 : tcsetpgrp(actual, (int)b);
    case BR_TCGETATTR:
    case BR_TCSETATTR: {
        struct bridge_termios *out = memory(h, b, sizeof(*out));
        struct termios t = {0};
        actual = fd(h, a);
        if (!out || actual < 0)
            return -1;
        if (c->operation == BR_TCSETATTR) {
            t.c_iflag = out->iflag;
            t.c_oflag = out->oflag;
            t.c_cflag = out->cflag;
            t.c_lflag = out->lflag;
            t.c_line = out->line;
            memcpy(t.c_cc, out->cc, NCCS);
            if (cfsetospeed(&t, out->ospeed) || cfsetispeed(&t, out->ispeed))
                return -1;
            return tcsetattr(actual, (int)n, &t);
        }
        if (tcgetattr(actual, &t))
            return -1;
        out->iflag = t.c_iflag;
        out->oflag = t.c_oflag;
        out->cflag = t.c_cflag;
        out->lflag = t.c_lflag;
        out->line = t.c_line;
        memcpy(out->cc, t.c_cc, NCCS);
        out->ispeed = cfgetispeed(&t);
        out->ospeed = cfgetospeed(&t);
        return 0;
    }
    case BR_TTYNAME:
        actual = fd(h, a);
        buffer = memory(h, b, n);
        if (actual < 0 || !buffer)
            return -1;
        rc = ttyname_r(actual, buffer, n);
        if (rc) {
            errno = rc;
            return -1;
        }
        return 0;
    case BR_KILL: {
        int number = native_signal((int)b);
        if (number < 0) {
            errno = EINVAL;
            return -1;
        }
        return kill((int)a, number);
    }
    case BR_ALARM:
        return alarm(a);
    case BR_SIGACTION: {
        int number = native_signal((int)a);
        struct bridge_signal_action *in = b ? memory(h, b, sizeof(*in)) : NULL;
        struct bridge_signal_action *out = n ? memory(h, n, sizeof(*out)) : NULL;
        if (number <= 0 || (b && !in) || (n && !out)) {
            errno = EINVAL;
            return -1;
        }
        struct sigaction action = {0}, old;
        if (in) {
            unpack_signal_mask(in->mask, &action.sa_mask);
            action.sa_flags = native_action_flags(in->flags);
            if (in->mode == 0)
                action.sa_handler = SIG_DFL;
            else if (in->mode == 1)
                action.sa_handler = SIG_IGN;
            else {
                action.sa_sigaction = record_signal;
                action.sa_flags |= SA_SIGINFO;
            }
        }
        if (sigaction(number, in ? &action : NULL, &old))
            return -1;
        if (out) {
            out->mask = pack_signal_mask(&old.sa_mask);
            out->flags = old.sa_sigaction == record_signal ? installed_signal_flags[a]
                                                           : guest_action_flags(old.sa_flags);
            out->mode = old.sa_handler == SIG_DFL ? 0 : old.sa_handler == SIG_IGN ? 1 : 2;
        }
        if (in)
            installed_signal_flags[a] = in->flags;
        return 0;
    }
    case BR_SIGMASK: {
        uint64_t *in = b ? memory(h, b, sizeof(*in)) : NULL,
                 *out = n ? memory(h, n, sizeof(*out)) : NULL;
        if ((b && !in) || (n && !out))
            return -1;
        sigset_t set, old;
        int how = a == 0 ? SIG_SETMASK : a == 1 ? SIG_BLOCK : a == 2 ? SIG_UNBLOCK : -1;
        if (in)
            unpack_signal_mask(*in, &set);
        if (sigprocmask(how, in ? &set : NULL, &old))
            return -1;
        if (out)
            *out = pack_signal_mask(&old);
        return 0;
    }
    case BR_SIGSUSPEND:
        return suspend_signals(c, a);
    case BR_PIPE: {
        int *out = memory(h, a, 2 * sizeof(int));
        if (!out)
            return -1;
        int pair[2];
        if (pipe(pair))
            return -1;
        int first = save_fd(h, pair[0], 0);
        if (first < 0) {
            close(pair[1]);
            return -1;
        }
        int second = save_fd(h, pair[1], 0);
        if (second < 0) {
            close(h->fds[first]);
            h->fds[first] = -1;
            return -1;
        }
        out[0] = first;
        out[1] = second;
        return 0;
    }
    case BR_WAITPID: {
        int status = 0;
        int *out = b ? memory(h, b, sizeof(int)) : NULL;
        if (b && !out)
            return -1;
        pid_t pid = waitpid((int)a, &status, ((int)n & ~4) | ((n & 4) ? WCONTINUED : 0));
        if (pid > 0 && out)
            *out = guest_wait_status(status);
        return pid;
    }
    case BR_WRITE:
    case BR_READ:
        actual = fd(h, (int)a);
        buffer = memory(h, b, n);
        if (actual < 0 || !buffer || n > SSIZE_MAX)
            return -1;
        return c->operation == BR_WRITE ? write(actual, buffer, n) : read(actual, buffer, n);
    case BR_OPEN:
        path = path_string_mode(h, a, path_storage, !(b & BO_NOFOLLOW));
        if (!path)
            return -1;
        return save_fd(h, open(path, open_flags(b), (mode_t)n), 0);
    case BR_CLOSE:
        actual = fd(h, (int)a);
        if (actual < 0)
            return -1;
        rc = close(actual);
        h->fds[a] = -1;
        return rc;
    case BR_LSEEK:
        actual = fd(h, (int)a);
        return actual < 0 ? -1 : lseek(actual, (int64_t)b, (int)n);
    case BR_FCNTL:
        actual = fd(h, (int)a);
        if (actual < 0)
            return -1;
        switch (b) {
        case BF_GETLK:
        case BF_SETLK:
        case BF_SETLKW: {
            struct bridge_lock *wire = memory(h, n, sizeof(*wire));
            if (!wire)
                return -1;
            struct flock lock = {.l_type = wire->type,
                                 .l_whence = wire->whence,
                                 .l_pid = wire->pid,
                                 .l_start = wire->start,
                                 .l_len = wire->length};
            int rc = fcntl(actual,
                           b == BF_GETLK   ? F_GETLK
                           : b == BF_SETLK ? F_SETLK
                                           : F_SETLKW,
                           &lock);
            if (!rc && b == BF_GETLK) {
                wire->type = lock.l_type;
                wire->whence = lock.l_whence;
                wire->pid = lock.l_pid;
                wire->start = lock.l_start;
                wire->length = lock.l_len;
            }
            return rc;
        }
        case BF_GETFD:
            return fcntl(actual, F_GETFD);
        case BF_SETFD:
            return fcntl(actual, F_SETFD, (int)n);
        case BF_GETFL:
            rc = fcntl(actual, F_GETFL);
            return rc < 0 ? -1 : (int64_t)pack_flags(rc);
        case BF_SETFL:
            return fcntl(actual, F_SETFL, open_flags(n));
        case BF_DUPFD:
        case BF_DUPFD_CLOEXEC:
            return save_fd(h, fcntl(actual, b == BF_DUPFD ? F_DUPFD : F_DUPFD_CLOEXEC, 3), (int)n);
        default:
            errno = EINVAL;
            return -1;
        }
    case BR_DUP2:
        actual = fd(h, (int)a);
        if (actual < 0)
            return -1;
        if (b >= MAX_FDS) {
            errno = EBADF;
            return -1;
        }
        if (a == b)
            return b;
        rc = dup(actual);
        if (rc < 0)
            return -1;
        if (h->fds[b] >= 0)
            close(h->fds[b]);
        h->fds[b] = rc;
        return b;
    case BR_STAT:
    case BR_LSTAT:
    case BR_FSTAT: {
        struct bridge_stat *out = memory(h, b, sizeof(*out));
        struct stat s;
        if (!out)
            return -1;
        if (c->operation == BR_FSTAT) {
            actual = fd(h, (int)a);
            rc = actual < 0 ? -1 : fstat(actual, &s);
        } else {
            path = path_string_mode(h, a, path_storage, c->operation == BR_STAT);
            if (!path)
                return -1;
            rc = c->operation == BR_STAT ? stat(path, &s) : lstat(path, &s);
        }
        if (rc < 0)
            return -1;
        *out = (struct bridge_stat){
            s.st_dev,         s.st_ino,          s.st_mode,        s.st_nlink,
            s.st_uid,         s.st_gid,          s.st_rdev,        s.st_size,
            s.st_blksize,     s.st_blocks,       s.st_atim.tv_sec, s.st_atim.tv_nsec,
            s.st_mtim.tv_sec, s.st_mtim.tv_nsec, s.st_ctim.tv_sec, s.st_ctim.tv_nsec};
        return 0;
    }
    case BR_ACCESS:
        path = path_string(h, a, path_storage);
        return path ? access(path, (int)b) : -1;
    case BR_CHDIR:
        path = path_string(h, a, path_storage);
        return path ? chdir(path) : -1;
    case BR_GETCWD:
        buffer = memory(h, a, b);
        return buffer && getcwd(buffer, b) ? 0 : -1;
    case BR_MKDIR:
        path = path_string_nofollow(h, a, path_storage);
        return path ? mkdir(path, (mode_t)b) : -1;
    case BR_RMDIR:
        path = path_string_nofollow(h, a, path_storage);
        return path ? rmdir(path) : -1;
    case BR_UNLINK:
        path = path_string_nofollow(h, a, path_storage);
        return path ? unlink(path) : -1;
    case BR_LINK:
    case BR_SYMLINK:
        path = c->operation == BR_SYMLINK ? string(h, a) : path_string_nofollow(h, a, path_storage);
        other = path_string_nofollow(h, b, other_storage);
        if (!path || !other)
            return -1;
        return c->operation == BR_LINK ? link(path, other) : symlink(path, other);
    case BR_READLINK:
        path = path_string_nofollow(h, a, path_storage);
        buffer = memory(h, b, n);
        return path && buffer ? readlink(path, buffer, n) : -1;
    case BR_CHMOD:
        path = path_string(h, a, path_storage);
        return path ? chmod(path, (mode_t)b) : -1;
    case BR_FCHMOD:
        actual = fd(h, (int)a);
        return actual < 0 ? -1 : fchmod(actual, (mode_t)b);
    case BR_FCHDIR:
        actual = fd(h, (int)a);
        return actual < 0 ? -1 : fchdir(actual);
    case BR_FSYNC:
        actual = fd(h, (int)a);
        return actual < 0 ? -1 : fsync(actual);
    case BR_ISATTY:
        actual = fd(h, (int)a);
        return actual < 0 ? 0 : isatty(actual);
    case BR_MKFIFO:
        path = path_string_nofollow(h, a, path_storage);
        return path ? mkfifo(path, (mode_t)b) : -1;
    case BR_UMASK:
        return umask((mode_t)a);
    case BR_UNAME:
        buffer = memory(h, a, sizeof(struct utsname));
        return buffer ? uname(buffer) : -1;
    case BR_GETTIME: {
        struct timespec t;
        if (clock_gettime(native_clock(a), &t))
            return -1;
        return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
    }
    case BR_SLEEP: {
        struct timespec t = {.tv_sec = a, .tv_nsec = b}, remaining = {0};
        int64_t *out = n ? memory(h, n, 2 * sizeof(int64_t)) : NULL;
        if (n && !out)
            return -1;
        int rc = nanosleep(&t, &remaining);
        if (out) {
            out[0] = remaining.tv_sec;
            out[1] = remaining.tv_nsec;
        }
        return rc;
    }
    case BR_GETPWUID:
    case BR_GETPWNAM:
    case BR_GETGRGID:
    case BR_GETGRNAM: {
        struct bridge_identity *out = memory(h, b, sizeof(*out));
        if (!out)
            return -1;
        memset(out, 0, sizeof(*out));
        if (c->operation == BR_GETPWUID || c->operation == BR_GETPWNAM) {
            struct passwd *p;
            if (c->operation == BR_GETPWUID)
                p = getpwuid(a);
            else {
                path = string(h, a);
                if (!path)
                    return -1;
                p = getpwnam(path);
            }
            if (!p)
                return 0;
            out->uid = p->pw_uid;
            out->gid = p->pw_gid;
            copy_string(out->name, sizeof(out->name), p->pw_name);
            copy_string(out->password, sizeof(out->password), p->pw_passwd);
            copy_string(out->gecos, sizeof(out->gecos), p->pw_gecos);
            copy_string(out->directory, sizeof(out->directory), p->pw_dir);
            copy_string(out->shell, sizeof(out->shell), p->pw_shell);
        } else {
            struct group *g;
            if (c->operation == BR_GETGRGID)
                g = getgrgid(a);
            else {
                path = string(h, a);
                if (!path)
                    return -1;
                g = getgrnam(path);
            }
            if (!g)
                return 0;
            out->gid = g->gr_gid;
            copy_string(out->name, sizeof(out->name), g->gr_name);
        }
        return 1;
    }
    case BR_GETGROUPS:
        if (a > MAX_FDS) {
            errno = EINVAL;
            return -1;
        }
        buffer = a ? memory(h, b, a * sizeof(gid_t)) : NULL;
        return a && !buffer ? -1 : getgroups((int)a, buffer);
    case BR_OPENDIR:
        path = path_string(h, a, path_storage);
        if (!path)
            return -1;
        for (int i = 0; i < MAX_DIRS; i++)
            if (!h->dirs[i]) {
                h->dirs[i] = opendir(path);
                if (!h->dirs[i])
                    return -1;
                h->dir_fds[i] = save_fd(h, dup(dirfd(h->dirs[i])), 0);
                if (h->dir_fds[i] < 0) {
                    closedir(h->dirs[i]);
                    h->dirs[i] = NULL;
                    return -1;
                }
                return i;
            }
        errno = EMFILE;
        return -1;
    case BR_DIRFD:
        if (a >= MAX_DIRS || !h->dirs[a]) {
            errno = EBADF;
            return -1;
        }
        return h->dir_fds[a];
    case BR_READDIR: {
        if (a >= MAX_DIRS || !h->dirs[a]) {
            errno = EBADF;
            return -1;
        }
        struct bridge_dirent *out = memory(h, b, sizeof(*out));
        if (!out)
            return -1;
        struct dirent *entry = readdir(h->dirs[a]);
        if (!entry)
            return 0;
        out->ino = entry->d_ino;
        switch (entry->d_type) {
        case DT_BLK:
            out->type = 1;
            break;
        case DT_CHR:
            out->type = 2;
            break;
        case DT_DIR:
            out->type = 3;
            break;
        case DT_FIFO:
            out->type = 4;
            break;
        case DT_LNK:
            out->type = 5;
            break;
        case DT_REG:
            out->type = 6;
            break;
        case DT_SOCK:
            out->type = 7;
            break;
        default:
            out->type = 0;
        }
        copy_string(out->name, sizeof(out->name), entry->d_name);
        return 1;
    }
    case BR_CLOSEDIR:
        if (a >= MAX_DIRS || !h->dirs[a]) {
            errno = EBADF;
            return -1;
        }
        actual = h->dir_fds[a];
        close(h->fds[actual]);
        h->fds[actual] = -1;
        rc = closedir(h->dirs[a]);
        h->dirs[a] = NULL;
        return rc;
    case BR_IOCTL:
        actual = fd(h, (int)a);
        if (actual < 0)
            return -1;
        {
            size_t size = _IOC_SIZE(b);
            if (b == TIOCGWINSZ || b == TIOCSWINSZ)
                size = sizeof(struct winsize);
            else if (b == FIONREAD || b == FIONBIO || b == TIOCGPTN || b == TIOCSPTLCK)
                size = sizeof(int);
            else if (b == TIOCSCTTY || b == TIOCNOTTY || b == TIOCCONS)
                return ioctl(actual, b, n);
            else if (b >= SIOCGIFNAME && b <= SIOCSIFMAP)
                size = sizeof(struct ifreq);
            if (!size || b == SIOCGIFCONF || b == SIOCETHTOOL) {
                errno = ENOTSUP;
                return -1;
            }
            buffer = memory(h, n, size);
            return buffer ? ioctl(actual, b, buffer) : -1;
        }
    case BR_GETRLIMIT:
    case BR_SETRLIMIT: {
        const int limits[] = {RLIMIT_CPU,    RLIMIT_FSIZE, RLIMIT_DATA,  RLIMIT_STACK,  RLIMIT_CORE,
                              RLIMIT_NOFILE, RLIMIT_AS,    RLIMIT_NPROC, RLIMIT_MEMLOCK};
        uint64_t *pair = memory(h, b, 2 * sizeof(uint64_t));
        if (!pair)
            return -1;
        if (a >= sizeof(limits) / sizeof(limits[0])) {
            errno = EINVAL;
            return -1;
        }
        struct rlimit limit;
        if (c->operation == BR_GETRLIMIT) {
            if (getrlimit(limits[a], &limit))
                return -1;
            pair[0] = a == 5 ? MAX_FDS : limit.rlim_cur;
            pair[1] = a == 5 ? MAX_FDS : limit.rlim_max;
            return 0;
        }
        limit = (struct rlimit){pair[0], pair[1]};
        return setrlimit(limits[a], &limit);
    }
    case BR_REALPATH:
        path = path_string(h, a, path_storage);
        buffer = memory(h, b, n);
        return path && buffer && realpath(path, buffer) ? 0 : -1;
    case BR_SYNC:
        sync();
        return 0;
    case BR_MKDTEMP:
        path = string(h, a);
        return path && mkdtemp(path) ? 0 : -1;
    default:
        errno = ENOSYS;
        return -1;
    }
}

/* A fork-like namespace clone uses the same independent Capsule snapshot.
 * Sharing a native stack, address space, or thread group is unsupported. */
static unsigned long namespace_clone_request(struct bridge_host *h,
                                             volatile struct kernel_control *c) {
    if (c->operation != BR_POSIX)
        return 0;
    struct posix_request *r = memory(h, c->args[0], sizeof(*r));
    if (!r || r->operation != PX_RAW_SYSCALL)
        return 0;
    uint64_t *v = memory(h, r->args[0], 7 * sizeof(uint64_t));
    if (!v || v[0] != SYS_clone)
        return 0;
    unsigned long allowed = CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS |
                            CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS;
    if ((v[1] & 255) != SIGCHLD || (v[1] & ~(allowed | 255UL)) || v[2] || v[3] || v[4] || v[5] ||
        v[6])
        return 0;
    return v[1];
}
static int changes_credentials(struct bridge_host *h, volatile struct kernel_control *c) {
    if (c->operation != BR_POSIX)
        return 0;
    struct posix_request *r = memory(h, c->args[0], sizeof(*r));
    if (!r)
        return 0;
    return r->operation == PX_SETUID || r->operation == PX_SETGID || r->operation == PX_SETRESUID ||
           r->operation == PX_SETRESGID;
}

static char **guest_strings(struct bpf_capsule *capsule, int count, char **strings) {
    char **result = bpf_capsule_malloc(capsule, (count + 1) * sizeof(char *));
    if (!result)
        return NULL;
    memset(result, 0, (count + 1) * sizeof(char *));
    for (int i = 0; i < count; i++) {
        size_t bytes = strlen(strings[i]) + 1;
        result[i] = bpf_capsule_malloc(capsule, bytes);
        if (!result[i])
            return NULL;
        memcpy(result[i], strings[i], bytes);
    }
    return result;
}

static int mount_working_directory_as_home(void) {
    const char *step = "checking the /home mount point";
    struct stat target;
    if (lstat("/home", &target))
        goto fail;
    if (!S_ISDIR(target.st_mode)) {
        errno = ENOTDIR;
        goto fail;
    }
    step = "creating a private mount namespace (requires CAP_SYS_ADMIN)";
    if (unshare(CLONE_NEWNS))
        goto fail;
    /* Cloned shared mounts still propagate until explicitly made private. */
    step = "disabling mount propagation";
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
        goto fail;
    /* Resolve the original cwd directly, including when it lies under /home. */
    step = "bind-mounting the working directory at /home";
    if (mount(".", "/home", NULL, MS_BIND | MS_REC, NULL))
        goto fail;
    step = "entering /home";
    if (chdir("/home"))
        goto fail;
    step = "setting the home environment";
    if (setenv("HOME", "/home", 1) || setenv("PWD", "/home", 1) || unsetenv("OLDPWD"))
        goto fail;
    return 0;
fail:
    fprintf(stderr, "--mount-cwd: %s: %s\n", step, strerror(errno));
    return -1;
}

int main(int argc, char **argv) {
    pid_t owner = getpid();
    int show_stats = 0, mount_cwd = 0;
    struct sandbox_options sandbox = {.memory_mib = 4096, .cpus = 2, .network = 1};
    int sandbox_tuning = 0;
    while (argc > 1) {
        if (!strcmp(argv[1], "--stats"))
            show_stats = 1;
        else if (!strcmp(argv[1], "--mount-cwd"))
            mount_cwd = 1;
        else if (!strcmp(argv[1], "--sandbox") || !strcmp(argv[1], "--host")) {
            int mode = !strcmp(argv[1], "--sandbox") ? 1 : -1;
            if (sandbox.mode && sandbox.mode != mode) {
                fprintf(stderr, "--sandbox and --host are mutually exclusive\n");
                return 2;
            }
            sandbox.mode = mode;
        } else if (!strncmp(argv[1], "--sandbox-memory=", 17)) {
            if (sandbox_number(argv[1] + 17, 1024, 65536, &sandbox.memory_mib)) {
                fprintf(stderr, "--sandbox-memory requires 1024..65536 MiB\n");
                return 2;
            }
            sandbox_tuning = 1;
        } else if (!strncmp(argv[1], "--sandbox-cpus=", 15)) {
            if (sandbox_number(argv[1] + 15, 1, 64, &sandbox.cpus)) {
                fprintf(stderr, "--sandbox-cpus requires 1..64\n");
                return 2;
            }
            sandbox_tuning = 1;
        } else if (!strncmp(argv[1], "--sandbox-network=", 18)) {
            if (strcmp(argv[1] + 18, "user") && strcmp(argv[1] + 18, "none")) {
                fprintf(stderr, "--sandbox-network requires user or none\n");
                return 2;
            }
            sandbox.network = !strcmp(argv[1] + 18, "user");
            sandbox_tuning = 1;
        }
        else if (!strcmp(argv[1], "--help")) {
            puts("Usage: linux-bash-os [loader options] [Bash arguments...]\n"
                 "  --sandbox    Run in the bundled KVM VM (default on other operating systems).\n"
                 "  --host       Run directly in this kernel; requires BPF loading privileges.\n"
                 "  --sandbox-memory=N     Guest RAM in MiB (default 4096, range 1024..65536).\n"
                 "  --sandbox-cpus=N       Guest CPUs (default 2, range 1..64).\n"
                 "  --sandbox-network=user Outbound network, no inbound forwards (default).\n"
                 "  --sandbox-network=none Offline VM.\n"
                 "  --mount-cwd  Share the launch directory at /home (automatic in sandbox mode).\n"
                 "               In host mode: private bind mount, requires CAP_SYS_ADMIN.\n"
                 "  --stats      Print kernel execution statistics on exit.\n"
                 "  --help       Show this help without loading BPF.\n"
                 "Loader options must precede Bash arguments. Use -- to end option parsing.\n"
                 "Bash runs with --noprofile --norc; accepts -c COMMAND, a script, or -i.\n"
                 "Sandbox: x86_64 Linux, KVM access and Landlock ABI 6 required; run without sudo.\n"
                 "The launch folder is writable /home; the remaining guest filesystem is temporary.\n"
                 "Installed systems with trusted os-release ID=linux-bash-os default to host mode.");
            return 0;
        } else
            break;
        argc--;
        argv++;
    }
    if (sandbox_tuning && sandbox.mode == -1) {
        fprintf(stderr, "--sandbox-* options cannot be used with --host\n");
        return 2;
    }
    if (sandbox.mode == 1 || sandbox_tuning || (!sandbox.mode && !sandbox_installed_os())) {
        sandbox.stats = show_stats;
        return sandbox_run(argc, argv, &sandbox);
    }
    if (mount_cwd && mount_working_directory_as_home())
        return 1;
    int status = 1, stats = -1;
    struct bash *skel = NULL;
    struct bpf_capsule capsule = {0};
    struct bridge_host host = {.capsule = &capsule};
    if (inherit_descriptors(host.fds)) {
        perror("inherited descriptors");
        goto cleanup;
    }
    skel = bash__open();
    if (!skel) {
        fprintf(stderr, "cannot open BPF object\n");
        goto cleanup;
    }
    if (bpf_capsule_configure(
            &capsule, skel->obj,
            (struct bpf_capsule_config){.fiber_count = 2, .heap_bytes = 64ULL << 20}) ||
        bpf_object__load_skeleton(skel->skeleton) ||
        bpf_capsule_attach_freplace(&capsule, skel->skeleton->data, skel->skeleton->data_sz) ||
        bpf_capsule_initialize(&capsule)) {
        fprintf(stderr, "cannot load kernel Bash: %s\n", strerror(errno));
        goto cleanup;
    }
    volatile struct kernel_control *c = &skel->data_ctrl->control;
    host.image = bpf_map__initial_value(skel->maps.arena, &host.image_size);
    char **arguments = calloc(argc + 3, sizeof(char *));
    if (!arguments) {
        perror("arguments");
        goto cleanup;
    }
    arguments[0] = "linux-bash-os";
    arguments[1] = "--noprofile";
    arguments[2] = "--norc";
    for (int i = 1; i < argc; i++)
        arguments[i + 2] = argv[i];
    c->argc = argc + 2;
    c->argv = guest_strings(&capsule, c->argc, arguments);
    free(arguments);
    extern char **environ;
    int env_count = 0;
    while (environ[env_count])
        env_count++;
    char **environment = calloc(env_count + 4, sizeof(char *));
    if (!environment) {
        perror("environment");
        goto cleanup;
    }
    int used = 0;
    for (int i = 0; i < env_count; i++)
        if (strncmp(environ[i], "LC_ALL=", 7) && strncmp(environ[i], "PS1=", 4))
            environment[used++] = environ[i];
    environment[used++] = "LC_ALL=C";
    environment[used++] = "PS1=kernel-bash\\$ ";
    if (!getenv("TERM"))
        environment[used++] = "TERM=dumb";
    c->envp = guest_strings(&capsule, used, environment);
    free(environment);
    if (!c->argv || !c->envp) {
        perror("guest arguments");
        goto cleanup;
    }
    c->uid = getuid();
    c->euid = geteuid();
    c->gid = getgid();
    c->egid = getegid();
    c->pid = getpid();
    c->ppid = getppid();
    if (show_stats)
        stats = bpf_enable_stats(BPF_STATS_RUN_TIME);
    int start = bpf_program__fd(skel->progs.bash_start),
        next = bpf_program__fd(skel->progs.bash_continue);
    int current = start;
    int trace = getenv("LINUX_BASH_TRACE") != NULL;
    unsigned long calls = 0, invocation_limit = 0;
    const char *limit_text = getenv("LINUX_BASH_MAX_STEPS");
    if (limit_text && *limit_text) {
        char *end;
        invocation_limit = strtoul(limit_text, &end, 10);
        if (*end) {
            fprintf(stderr, "invalid LINUX_BASH_MAX_STEPS\n");
            goto cleanup;
        }
    }
    for (; !invocation_limit || calls < invocation_limit; calls++) {
        publish_signals(c);
        if (trace && (calls < 100 || calls % 10000 == 0))
            fprintf(stderr, "run[%d]: call=%lu status=%d\n", getpid(), calls, c->result.status);
        struct bpf_test_run_opts options = {.sz = sizeof(options)};
        if (bpf_prog_test_run_opts(current, &options)) {
            perror("BPF run");
            goto cleanup;
        }
        if (c->result.status == CAPSULE_EXITED) {
            if (c->result.code < 0) {
                fprintf(stderr, "Capsule: %s (%lld)\n", bpf_capsule_error_string(c->result.code),
                        (long long)c->result.code);
                goto cleanup;
            }
            status = (unsigned)c->result.code & 255;
            break;
        }
        if (c->result.status == CAPSULE_OK) {
            status = 0;
            break;
        }
        if (c->result.status == CAPSULE_YIELD) {
            if (trace)
                fprintf(stderr, "bridge[%d]: op=%u arg=%lld\n", getpid(), c->operation,
                        (long long)c->args[0]);
            if (c->operation == BR_EXIT) {
                status = (unsigned)c->args[0] & 255;
                break;
            }
            unsigned long clone_flags = namespace_clone_request(&host, c);
            int refresh_credentials =
                c->operation == BR_FORK || clone_flags || changes_credentials(&host, c);
            errno = 0;
            int64_t response;
            int error;
            if (c->operation == BR_FORK || clone_flags) {
                response = fork_process(&host, &skel, clone_flags);
                error = errno;
                c = &skel->data_ctrl->control;
                if (response == 0) {
                    memset((void *)pending_signals, 0, sizeof(pending_signals));
                    c->pending_signals = 0;
                }
                start = bpf_program__fd(skel->progs.bash_start);
                next = bpf_program__fd(skel->progs.bash_continue);
            } else {
                response = service(&host, c);
                error = errno;
            }
            if (trace)
                fprintf(stderr, "result[%d]: op=%u rc=%lld error=%d\n", getpid(), c->operation,
                        (long long)response, error);
            if (refresh_credentials) {
                c->uid = getuid();
                c->euid = geteuid();
                c->gid = getgid();
                c->egid = getegid();
            }
            c->response = response;
            c->error = bridge_error(error);
            c->operation = BR_NONE;
        } else if (c->result.status != CAPSULE_PENDING) {
            fprintf(stderr, "unexpected Capsule state\n");
            goto cleanup;
        }
        current = next;
    }
    if (invocation_limit && calls == invocation_limit) {
        fprintf(stderr, "execution budget exceeded\n");
        status = 124;
    }
    if (stats >= 0 && getpid() == owner) {
        uint64_t ns = 0;
        for (int i = 0; i < 2; i++) {
            struct bpf_prog_info info = {0};
            unsigned n = sizeof(info);
            if (!bpf_prog_get_info_by_fd(i ? next : start, &info, &n))
                ns += info.run_time_ns;
        }
        fprintf(stderr, "kernel execution: %.3f ms; %lu invocations; %llu I/O calls\n", ns / 1e6,
                calls + 1, (unsigned long long)c->io_calls);
    }
cleanup:
    for (int i = 0; i < MAX_FDS; i++)
        if (host.fds[i] >= 0)
            close(host.fds[i]);
    for (int i = 0; i < MAX_DIRS; i++)
        if (host.dirs[i])
            closedir(host.dirs[i]);
    if (stats >= 0)
        close(stats);
    bpf_capsule_release(&capsule);
    if (skel)
        bash__destroy(skel);
    return status;
}
