#pragma once
#include <stdint.h>
#include "posix_generated.h"
#include "posix_extra.h"
#include "bpf_capsule_types.h"

enum bridge_operation {
    BR_NONE,
    BR_WRITE,
    BR_READ,
    BR_OPEN,
    BR_CLOSE,
    BR_LSEEK,
    BR_FCNTL,
    BR_DUP2,
    BR_STAT,
    BR_LSTAT,
    BR_FSTAT,
    BR_ACCESS,
    BR_CHDIR,
    BR_GETCWD,
    BR_MKDIR,
    BR_RMDIR,
    BR_UNLINK,
    BR_LINK,
    BR_SYMLINK,
    BR_READLINK,
    BR_CHMOD,
    BR_FCHMOD,
    BR_FSYNC,
    BR_ISATTY,
    BR_UNAME,
    BR_SLEEP,
    BR_GETTIME,
    BR_GETPWUID,
    BR_GETPWNAM,
    BR_GETGRGID,
    BR_GETGRNAM,
    BR_GETGROUPS,
    BR_OPENDIR,
    BR_READDIR,
    BR_CLOSEDIR,
    BR_IOCTL,
    BR_UMASK,
    BR_FCHDIR,
    BR_MKFIFO,
    BR_GETRLIMIT,
    BR_SETRLIMIT,
    BR_REALPATH,
    BR_SYNC,
    BR_DIRFD,
    BR_MKDTEMP,
    BR_FORK,
    BR_PIPE,
    BR_WAITPID,
    BR_EXIT,
    BR_GETPGID,
    BR_SETPGID,
    BR_SETSID,
    BR_TCGETPGRP,
    BR_TCSETPGRP,
    BR_TCGETATTR,
    BR_TCSETATTR,
    BR_TTYNAME,
    BR_KILL,
    BR_SIGACTION,
    BR_SIGMASK,
    BR_SIGSUSPEND,
    BR_ALARM,
    BR_STATX,
    BR_POLL,
    BR_POSIX,
    BR_EXEC
};

struct kernel_control {
    struct capsule_result result;
    char **argv, **envp;
    uint32_t argc;
    uint32_t uid, gid, euid, egid, pid, ppid;
    uint32_t operation;
    int32_t error;
    int64_t response;
    uint64_t args[6];
    uint64_t io_calls;
    uint64_t pending_signals;
};
extern volatile struct kernel_control control;

struct bridge_stat {
    uint64_t dev, ino, mode, nlink, uid, gid, rdev;
    int64_t size, blksize, blocks, atime_sec, atime_nsec, mtime_sec, mtime_nsec, ctime_sec,
        ctime_nsec;
};
struct bridge_identity {
    uint32_t uid, gid;
    char name[256], password[128], gecos[512], directory[4096], shell[256];
};
struct bridge_dirent {
    uint64_t ino;
    uint32_t type;
    char name[256];
};
enum bridge_open_flag {
    BO_WRITE = 1,
    BO_RDWR = 2,
    BO_CREATE = 4,
    BO_TRUNCATE = 8,
    BO_APPEND = 16,
    BO_EXCLUSIVE = 32,
    BO_NONBLOCK = 64,
    BO_CLOEXEC = 128,
    BO_NOFOLLOW = 256,
    BO_DIRECTORY = 512,
    BO_NOCTTY = 1024
};
enum bridge_fcntl {
    BF_GETFD,
    BF_SETFD,
    BF_GETFL,
    BF_SETFL,
    BF_DUPFD,
    BF_DUPFD_CLOEXEC,
    BF_GETLK,
    BF_SETLK,
    BF_SETLKW
};

/* Linux and Picolibc assign different numbers to several POSIX errors. */
#define BRIDGE_ERRORS(X)                                                                           \
    X(EPERM)                                                                                       \
    X(ENOENT)                                                                                      \
    X(ESRCH) X(EINTR) X(EIO) X(ENXIO) X(E2BIG) X(ENOEXEC) X(EBADF) X(ECHILD) X(EAGAIN) X(ENOMEM)   \
        X(EACCES) X(EFAULT) X(EBUSY) X(EEXIST) X(EXDEV) X(ENODEV) X(ENOTDIR) X(EISDIR) X(EINVAL)   \
            X(ENFILE) X(EMFILE) X(ENOTTY) X(ETXTBSY) X(EFBIG) X(ENOSPC) X(ESPIPE) X(EROFS)         \
                X(EMLINK) X(EPIPE) X(EDOM) X(ERANGE) X(EDEADLK) X(ENAMETOOLONG) X(ENOLCK)          \
                    X(ENOSYS) X(ENOTEMPTY) X(ELOOP) X(EOVERFLOW) X(ETIMEDOUT) X(ECANCELED)         \
                        X(ENOTSOCK) X(EDESTADDRREQ) X(EMSGSIZE) X(EPROTOTYPE) X(ENOPROTOOPT)       \
                            X(EPROTONOSUPPORT) X(ESOCKTNOSUPPORT) X(EOPNOTSUPP) X(EAFNOSUPPORT)    \
                                X(EADDRINUSE) X(EADDRNOTAVAIL) X(ENETDOWN) X(ENETUNREACH)          \
                                    X(ENETRESET) X(ECONNABORTED) X(ECONNRESET) X(ENOBUFS)          \
                                        X(EISCONN) X(ENOTCONN) X(ECONNREFUSED) X(EHOSTUNREACH)     \
                                            X(EALREADY) X(EINPROGRESS) X(ENODATA) X(ENOMSG)        \
                                                X(EIDRM) X(EILSEQ)
#define BRIDGE_ERROR_ENUM(e) BE_##e,
enum bridge_error { BE_OK, BRIDGE_ERRORS(BRIDGE_ERROR_ENUM) };
#undef BRIDGE_ERROR_ENUM

struct bridge_signal_action {
    uint64_t mask;
    int32_t mode, flags;
};
struct bridge_termios {
    uint32_t iflag, oflag, cflag, lflag;
    uint8_t line, cc[32];
    uint32_t ispeed, ospeed;
};

struct bridge_lock {
    int32_t type, whence, pid, pad;
    int64_t start, length;
};

/* Picolibc's timeval has a 32-bit microsecond field followed by padding. */
struct bridge_timeval {
    int64_t sec, usec;
};
struct bridge_statvfs {
    uint64_t bsize, frsize, blocks, bfree, bavail, files, ffree, favail, fsid, flag, namemax;
};
/* The guest epoll_event is packed like x86-64; ARM64 and RISC-V64 are not. */
struct bridge_epoll_event {
    uint32_t events, pad;
    uint64_t data;
};
#define BRIDGE_EPOLL_EVENTS 1024
struct bridge_timex {
    uint32_t modes, pad0;
    int64_t offset, freq, maxerror, esterror;
    int32_t status, pad1;
    int64_t constant, precision, tolerance;
    struct bridge_timeval time;
    int64_t tick, ppsfreq, jitter;
    int32_t shift, pad2;
    int64_t stabil, jitcnt, calcnt, errcnt, stbcnt;
    int32_t tai, pad3[11];
};
/* The guest uses the x86-64 semid64_ds layout; the generic 64-bit layout omits
 * the reserved words after each timestamp. */
struct bridge_semid_ds {
    uint8_t perm[48];
    int64_t otime, unused1, ctime, unused2;
    uint64_t nsems, unused3, unused4;
};

/* Structures that cross the bridge unchanged have one 64-bit Linux layout on
 * the guest and on every supported host. Both sides assert these sizes. */
#define BRIDGE_RAW_LAYOUTS(X)                                                                      \
    X(struct ipc_perm, 48)                                                                         \
    X(struct msqid_ds, 120)                                                                        \
    X(struct shmid_ds, 112)                                                                        \
    X(struct msginfo, 32)                                                                          \
    X(struct shminfo, 72)                                                                          \
    X(struct shm_info, 48)                                                                         \
    X(struct seminfo, 40)                                                                          \
    X(struct utsname, 390)                                                                         \
    X(struct winsize, 8)                                                                           \
    X(struct pollfd, 8)                                                                            \
    X(struct ifreq, 40)                                                                            \
    X(struct sockaddr_in, 16)                                                                      \
    X(struct sockaddr_in6, 28)                                                                     \
    X(struct linger, 8)                                                                            \
    X(struct ucred, 12)                                                                            \
    X(struct signalfd_siginfo, 128)                                                                \
    X(struct inotify_event, 16)                                                                    \
    X(gid_t, 4)
#define BRIDGE_CHECK_LAYOUT(type, size) _Static_assert(sizeof(type) == size, "Linux ABI layout");
