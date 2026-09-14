#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdio-bufio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <termios.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/epoll.h>
#include <sys/timex.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/signalfd.h>
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
#include "bpf_capsule.h"
#include "kernel_control.h"

char **environ;

pid_t fork(void);

void __fpurge(FILE *stream) {
    stream->unget = 0;
    if (stream->flags & __SBUF) {
        struct __file_bufio *buffer = (struct __file_bufio *)stream;
        buffer->off = 0;
        buffer->len = 0;
    }
}

static int guest_error(unsigned error) {
    switch (error) {
    case BE_OK:
        return 0;
#define GUEST_ERROR(e)                                                                             \
    case BE_##e:                                                                                   \
        return e;
        BRIDGE_ERRORS(GUEST_ERROR)
#undef GUEST_ERROR
    default:
        return EIO;
    }
}
void linux_bash_poll_signals(void);
static int64_t bridge(unsigned op, uint64_t a, uint64_t b, uint64_t c) {
    control.args[0] = a;
    control.args[1] = b;
    control.args[2] = c;
    control.operation = op;
    control.io_calls++;
    capsule_yield();
    int error = guest_error(control.error);
    int64_t response = control.response;
    if (op != BR_SIGACTION && op != BR_SIGMASK)
        linux_bash_poll_signals();
    errno = error;
    return response;
}

__attribute__((noreturn)) void linux_bash_process_exit(int status) {
    bridge(BR_EXIT, status, 0, 0);
    capsule_exit(status);
}
pid_t fork(void) {
    return bridge(BR_FORK, 0, 0, 0);
}
int pipe(int fds[2]) {
    return bridge(BR_PIPE, (uintptr_t)fds, 0, 0);
}
pid_t waitpid(pid_t pid, int *status, int options) {
    return bridge(BR_WAITPID, pid, (uintptr_t)status, options);
}

ssize_t write(int fd, const void *data, size_t count) {
    return bridge(BR_WRITE, fd, (uintptr_t)data, count);
}
ssize_t read(int fd, void *data, size_t count) {
    return bridge(BR_READ, fd, (uintptr_t)data, count);
}
pid_t getpid(void) {
    return control.pid;
}
pid_t getppid(void) {
    return control.ppid;
}
uid_t getuid(void) {
    return control.uid;
}
uid_t geteuid(void) {
    return control.euid;
}
gid_t getgid(void) {
    return control.gid;
}
gid_t getegid(void) {
    return control.egid;
}

#include "signal_guest.h"
#include "terminal_guest.h"

static unsigned pack_flags(int flags) {
    unsigned f = flags & O_ACCMODE;
    if (flags & O_CREAT)
        f |= BO_CREATE;
    if (flags & O_TRUNC)
        f |= BO_TRUNCATE;
    if (flags & O_APPEND)
        f |= BO_APPEND;
    if (flags & O_EXCL)
        f |= BO_EXCLUSIVE;
    if (flags & O_NONBLOCK)
        f |= BO_NONBLOCK;
    if (flags & O_CLOEXEC)
        f |= BO_CLOEXEC;
    if (flags & O_NOFOLLOW)
        f |= BO_NOFOLLOW;
    if (flags & O_DIRECTORY)
        f |= BO_DIRECTORY;
    if (flags & O_NOCTTY)
        f |= BO_NOCTTY;
    return f;
}
static int unpack_flags(unsigned f) {
    int flags = f & 3;
    if (f & BO_APPEND)
        flags |= O_APPEND;
    if (f & BO_NONBLOCK)
        flags |= O_NONBLOCK;
    return flags;
}
int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return bridge(BR_OPEN, (uintptr_t)path, pack_flags(flags), mode);
}
int close(int fd) {
    return bridge(BR_CLOSE, fd, 0, 0);
}
off_t lseek(int fd, off_t offset, int whence) {
    return bridge(BR_LSEEK, fd, offset, whence);
}
int fcntl(int fd, int command, ...) {
    int value = 0, op;
    if (command == F_GETLK || command == F_SETLK || command == F_SETLKW) {
        va_list ap;
        va_start(ap, command);
        struct flock *lock = va_arg(ap, struct flock *);
        va_end(ap);
        if (!lock) {
            errno = EFAULT;
            return -1;
        }
        struct bridge_lock wire = {.type = lock->l_type == F_RDLCK   ? 0
                                           : lock->l_type == F_WRLCK ? 1
                                           : lock->l_type == F_UNLCK ? 2
                                                                     : -1,
                                   .whence = lock->l_whence,
                                   .pid = lock->l_pid,
                                   .start = lock->l_start,
                                   .length = lock->l_len};
        int rc = bridge(BR_FCNTL, fd,
                        command == F_GETLK   ? BF_GETLK
                        : command == F_SETLK ? BF_SETLK
                                             : BF_SETLKW,
                        (uintptr_t)&wire);
        if (!rc && command == F_GETLK) {
            lock->l_type = wire.type == 0 ? F_RDLCK : wire.type == 1 ? F_WRLCK : F_UNLCK;
            lock->l_whence = wire.whence;
            lock->l_pid = wire.pid;
            lock->l_start = wire.start;
            lock->l_len = wire.length;
        }
        return rc;
    }
    switch (command) {
    case F_GETFD:
        op = BF_GETFD;
        break;
    case F_GETFL:
        op = BF_GETFL;
        break;
    case F_SETFD:
        op = BF_SETFD;
        break;
    case F_SETFL:
        op = BF_SETFL;
        break;
    case F_DUPFD:
        op = BF_DUPFD;
        break;
    case F_DUPFD_CLOEXEC:
        op = BF_DUPFD_CLOEXEC;
        break;
    default:
        errno = ENOSYS;
        return -1;
    }
    if (command != F_GETFD && command != F_GETFL) {
        va_list ap;
        va_start(ap, command);
        value = va_arg(ap, int);
        va_end(ap);
    }
    if (command == F_SETFL)
        value = pack_flags(value);
    int rc = bridge(BR_FCNTL, fd, op, value);
    return command == F_GETFL && rc >= 0 ? unpack_flags(rc) : rc;
}
int dup(int fd) {
    return fcntl(fd, F_DUPFD, 0);
}
int dup2(int oldfd, int newfd) {
    return bridge(BR_DUP2, oldfd, newfd, 0);
}
int fsync(int fd) {
    return bridge(BR_FSYNC, fd, 0, 0);
}
int fdatasync(int fd) {
    return fsync(fd);
}
int isatty(int fd) {
    return bridge(BR_ISATTY, fd, 0, 0);
}
int access(const char *p, int mode) {
    return bridge(BR_ACCESS, (uintptr_t)p, mode, 0);
}
int chdir(const char *p) {
    return bridge(BR_CHDIR, (uintptr_t)p, 0, 0);
}
int fchdir(int fd) {
    return bridge(BR_FCHDIR, fd, 0, 0);
}
char *getcwd(char *buffer, size_t size) {
    int allocated = !buffer;
    if (!buffer) {
        if (!size)
            size = 4096;
        buffer = malloc(size);
    }
    if (!buffer)
        return NULL;
    if (bridge(BR_GETCWD, (uintptr_t)buffer, size, 0) < 0) {
        if (allocated)
            free(buffer);
        return NULL;
    }
    return buffer;
}
int mkdir(const char *p, mode_t m) {
    return bridge(BR_MKDIR, (uintptr_t)p, m, 0);
}
int rmdir(const char *p) {
    return bridge(BR_RMDIR, (uintptr_t)p, 0, 0);
}
int unlink(const char *p) {
    return bridge(BR_UNLINK, (uintptr_t)p, 0, 0);
}
int link(const char *p, const char *q) {
    return bridge(BR_LINK, (uintptr_t)p, (uintptr_t)q, 0);
}
int symlink(const char *p, const char *q) {
    return bridge(BR_SYMLINK, (uintptr_t)p, (uintptr_t)q, 0);
}
ssize_t readlink(const char *p, char *b, size_t n) {
    return bridge(BR_READLINK, (uintptr_t)p, (uintptr_t)b, n);
}
int chmod(const char *p, mode_t m) {
    return bridge(BR_CHMOD, (uintptr_t)p, m, 0);
}
int fchmod(int fd, mode_t m) {
    return bridge(BR_FCHMOD, fd, m, 0);
}
int mkfifo(const char *p, mode_t m) {
    return bridge(BR_MKFIFO, (uintptr_t)p, m, 0);
}
mode_t umask(mode_t mask) {
    return bridge(BR_UMASK, mask, 0, 0);
}

static void unpack_stat(struct stat *out, const struct bridge_stat *value) {
    struct bridge_stat s = *value;
    memset(out, 0, sizeof(*out));
    out->st_dev = s.dev;
    out->st_ino = s.ino;
    out->st_mode = s.mode;
    out->st_nlink = s.nlink;
    out->st_uid = s.uid;
    out->st_gid = s.gid;
    out->st_rdev = s.rdev;
    out->st_size = s.size;
    out->st_blksize = s.blksize;
    out->st_blocks = s.blocks;
    out->st_atim.tv_sec = s.atime_sec;
    out->st_atim.tv_nsec = s.atime_nsec;
    out->st_mtim.tv_sec = s.mtime_sec;
    out->st_mtim.tv_nsec = s.mtime_nsec;
    out->st_ctim.tv_sec = s.ctime_sec;
    out->st_ctim.tv_nsec = s.ctime_nsec;
}
static int read_stat(unsigned op, uintptr_t p, struct stat *out) {
    struct bridge_stat s;
    if (bridge(op, p, (uintptr_t)&s, 0) < 0)
        return -1;
    unpack_stat(out, &s);
    return 0;
}

int stat(const char *p, struct stat *s) {
    return read_stat(BR_STAT, (uintptr_t)p, s);
}
int lstat(const char *p, struct stat *s) {
    return read_stat(BR_LSTAT, (uintptr_t)p, s);
}
int fstat(int fd, struct stat *s) {
    return read_stat(BR_FSTAT, fd, s);
}

int uname(struct utsname *u) {
    return bridge(BR_UNAME, (uintptr_t)u, sizeof(*u), 0);
}
int gethostname(char *name, size_t n) {
    struct utsname u;
    if (uname(&u) < 0)
        return -1;
    if (strlen(u.nodename) >= n) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(name, u.nodename);
    return 0;
}

static struct bridge_identity identity;
static struct passwd passwd_record;
static struct group group_record;
static char *empty_members[1];
static struct passwd *password_lookup(unsigned op, uint64_t key) {
    int rc = bridge(op, key, (uintptr_t)&identity, 0);
    if (rc <= 0)
        return NULL;
    passwd_record = (struct passwd){.pw_name = identity.name,
                                    .pw_uid = identity.uid,
                                    .pw_gid = identity.gid,
                                    .pw_dir = identity.directory,
                                    .pw_shell = identity.shell};
    return &passwd_record;
}
struct passwd *getpwuid(uid_t uid) {
    return password_lookup(BR_GETPWUID, uid);
}
struct passwd *getpwnam(const char *name) {
    return password_lookup(BR_GETPWNAM, (uintptr_t)name);
}
static struct group *group_lookup(unsigned op, uint64_t key) {
    if (bridge(op, key, (uintptr_t)&identity, 0) <= 0)
        return NULL;
    group_record =
        (struct group){.gr_name = identity.name, .gr_gid = identity.gid, .gr_mem = empty_members};
    return &group_record;
}
struct group *getgrgid(gid_t gid) {
    return group_lookup(BR_GETGRGID, gid);
}
struct group *getgrnam(const char *name) {
    return group_lookup(BR_GETGRNAM, (uintptr_t)name);
}
int getgroups(int size, gid_t *groups) {
    return bridge(BR_GETGROUPS, size, (uintptr_t)groups, 0);
}

DIR *opendir(const char *path) {
    int handle = bridge(BR_OPENDIR, (uintptr_t)path, 0, 0);
    if (handle < 0)
        return NULL;
    DIR *dir = calloc(1, sizeof(*dir));
    if (!dir) {
        bridge(BR_CLOSEDIR, handle, 0, 0);
        return NULL;
    }
    dir->fd = handle;
    return dir;
}
struct dirent *readdir(DIR *dir) {
    struct bridge_dirent e;
    if (bridge(BR_READDIR, dir->fd, (uintptr_t)&e, 0) <= 0)
        return NULL;
    dir->dirent.d_ino = e.ino;
    dir->dirent.d_type = e.type;
    memcpy(dir->dirent.d_name, e.name, sizeof(e.name));
    return &dir->dirent;
}
int closedir(DIR *dir) {
    int rc = bridge(BR_CLOSEDIR, dir->fd, 0, 0);
    free(dir);
    return rc;
}
int dirfd(DIR *dir) {
    return bridge(BR_DIRFD, dir->fd, 0, 0);
}

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return bridge(BR_IOCTL, fd, request, (uintptr_t)arg);
}
int gettimeofday(struct timeval *tv, void *zone) {
    (void)zone;
    int64_t ns = bridge(BR_GETTIME, CLOCK_REALTIME, 0, 0);
    if (ns < 0)
        return -1;
    tv->tv_sec = ns / 1000000000;
    tv->tv_usec = ns % 1000000000 / 1000;
    return 0;
}
int clock_gettime(clockid_t clock, struct timespec *tv) {
    int64_t ns = bridge(BR_GETTIME, clock, 0, 0);
    if (ns < 0)
        return -1;
    tv->tv_sec = ns / 1000000000;
    tv->tv_nsec = ns % 1000000000;
    return 0;
}
int nanosleep(const struct timespec *ts, struct timespec *remaining) {
    if (remaining)
        memset(remaining, 0, sizeof(*remaining));
    return bridge(BR_SLEEP, ts->tv_sec, ts->tv_nsec, (uintptr_t)remaining);
}
unsigned sleep(unsigned seconds) {
    struct timespec ts = {.tv_sec = seconds};
    return nanosleep(&ts, NULL) < 0 ? seconds : 0;
}

int getresuid(uid_t *r, uid_t *e, uid_t *s) {
    *r = getuid();
    *e = geteuid();
    *s = *e;
    return 0;
}
int getresgid(gid_t *r, gid_t *e, gid_t *s) {
    *r = getgid();
    *e = getegid();
    *s = *e;
    return 0;
}

int getrlimit(int resource, struct rlimit *limit) {
    uint64_t pair[2];
    if (bridge(BR_GETRLIMIT, resource, (uintptr_t)pair, 0) < 0)
        return -1;
    limit->rlim_cur = pair[0] == UINT64_MAX ? RLIM_INFINITY : pair[0];
    limit->rlim_max = pair[1] == UINT64_MAX ? RLIM_INFINITY : pair[1];
    return 0;
}
int setrlimit(int resource, const struct rlimit *limit) {
    uint64_t pair[2] = {limit->rlim_cur == RLIM_INFINITY ? UINT64_MAX : limit->rlim_cur,
                        limit->rlim_max == RLIM_INFINITY ? UINT64_MAX : limit->rlim_max};
    return bridge(BR_SETRLIMIT, resource, (uintptr_t)pair, 0);
}
int getdtablesize(void) {
    return 256;
}
char *realpath(const char *path, char *buffer) {
    int allocated = !buffer;
    if (!buffer)
        buffer = malloc(4096);
    if (!buffer)
        return NULL;
    if (bridge(BR_REALPATH, (uintptr_t)path, (uintptr_t)buffer, 4096) < 0) {
        if (allocated)
            free(buffer);
        return NULL;
    }
    return buffer;
}
void sync(void) {
    (void)bridge(BR_SYNC, 0, 0, 0);
}
long pathconf(const char *path, int name) {
    (void)path;
    if (name == _PC_PATH_MAX)
        return 4096;
    if (name == _PC_NAME_MAX)
        return 255;
    if (name == _PC_PIPE_BUF)
        return 4096;
    errno = EINVAL;
    return -1;
}
size_t confstr(int name, char *buffer, size_t size) {
    if (name != _CS_PATH) {
        errno = EINVAL;
        return 0;
    }
    if (size)
        buffer[0] = 0;
    return 1;
}
char *mkdtemp(char *pattern) {
    return bridge(BR_MKDTEMP, (uintptr_t)pattern, 0, 0) < 0 ? NULL : pattern;
}

#include "poll_guest.h"

/* Picolibc owns this optional enumeration stream; it is not a pathname. */
FILE *__passwd_file;

int linux_bash_xsi_strerror_r(int error, char *out, size_t size) {
    const char *message = strerror(error);
    size_t length = strlen(message);
    if (!size || length >= size)
        return ERANGE;
    memcpy(out, message, length + 1);
    return 0;
}

static int64_t posix_bridge(unsigned operation, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                            uint64_t e, uint64_t f) {
    struct posix_request request = {.operation = operation, .args = {a, b, c, d, e, f}};
    return bridge(BR_POSIX, (uintptr_t)&request, 0, 0);
}
#include "posix_generated_guest.h"
#include "network_guest.h"
#include "misc_guest.h"
#include "raw_guest.h"

int execve(const char *path, char *const arguments[], char *const environment[]) {
    return bridge(BR_EXEC, (uintptr_t)path, (uintptr_t)arguments, (uintptr_t)environment);
}
int getentropy(void *buffer, size_t count) {
    if (count > 256) {
        errno = EIO;
        return -1;
    }
    size_t done = 0;
    while (done < count) {
        ssize_t n = getrandom((char *)buffer + done, count - done, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        done += n;
    }
    return 0;
}
