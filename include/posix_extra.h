#pragma once
#include <stdint.h>
enum posix_extra_operation {
    PX_SOCKETPAIR = 1000,
    PX_ACCEPT,
    PX_GETSOCKNAME,
    PX_GETPEERNAME,
    PX_GETSOCKOPT,
    PX_RECVFROM,
    PX_SENDMSG,
    PX_RECVMSG,
    PX_GETADDRINFO,
    PX_GETNAMEINFO,
    PX_IF_NAMETOINDEX,
    PX_IF_INDEXTONAME,
    PX_OPENAT,
    PX_FSTATAT,
    PX_FDOPENDIR,
    PX_EPOLL_CTL,
    PX_GETRUSAGE,
    PX_GETGROUPLIST,
    PX_GETIFADDRS,
    PX_SIGNALFD,
    PX_SIGTIMEDWAIT,
    PX_SYSCONF,
    PX_IPCCTL,
    PX_RAW_SYSCALL,
    PX_PRCTL,
    PX_PTRACE,
    PX_SEM_OPEN,
    PX_SEM_CLOSE,
    PX_SEM_UNLINK,
    PX_GIT_STRFTIME
};
struct network_msghdr {
    uint64_t name;
    uint32_t namelen, pad0;
    uint64_t iov;
    uint32_t iovlen, pad1;
    uint64_t control;
    uint32_t controllen, pad2;
    int32_t flags, pad3;
};
struct network_iovec {
    uint64_t base, length;
};
struct network_cmsghdr {
    uint32_t length, pad;
    int32_t level, type;
};
struct network_addrinfo {
    int32_t flags, family, socktype, protocol;
    uint32_t addrlen, pad;
    uint64_t address, canonname, next;
};

struct network_ifaddrs {
    uint64_t next, name;
    uint32_t flags, pad;
    uint64_t address, mask, broadcast, data;
};

struct bridge_calendar {
    int32_t sec, min, hour, mday, mon, year, wday, yday, isdst, pad;
    int64_t gmtoff;
    uint64_t zone;
};
