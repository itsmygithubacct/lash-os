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
