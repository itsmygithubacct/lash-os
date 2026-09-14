_Static_assert(sizeof(struct msghdr) == sizeof(struct network_msghdr), "message layout");
_Static_assert(sizeof(struct addrinfo) == sizeof(struct network_addrinfo), "addrinfo layout");
int socketpair(int family, int type, int protocol, int pair[2]) {
    return posix_bridge(PX_SOCKETPAIR, family, type, protocol, (uintptr_t)pair, 0, 0);
}
int accept4(int descriptor, struct sockaddr *address, socklen_t *length, int flags) {
    return posix_bridge(PX_ACCEPT, descriptor, (uintptr_t)address, (uintptr_t)length, flags, 0, 0);
}
int accept(int descriptor, struct sockaddr *address, socklen_t *length) {
    return accept4(descriptor, address, length, 0);
}
int getsockname(int descriptor, struct sockaddr *address, socklen_t *length) {
    return posix_bridge(PX_GETSOCKNAME, descriptor, (uintptr_t)address, (uintptr_t)length, 0, 0, 0);
}
int getpeername(int descriptor, struct sockaddr *address, socklen_t *length) {
    return posix_bridge(PX_GETPEERNAME, descriptor, (uintptr_t)address, (uintptr_t)length, 0, 0, 0);
}
int getsockopt(int descriptor, int level, int option, void *value, socklen_t *length) {
    return posix_bridge(PX_GETSOCKOPT, descriptor, level, option, (uintptr_t)value,
                        (uintptr_t)length, 0);
}
ssize_t recvfrom(int descriptor, void *buffer, size_t size, int flags, struct sockaddr *address,
                 socklen_t *length) {
    return posix_bridge(PX_RECVFROM, descriptor, (uintptr_t)buffer, size, flags, (uintptr_t)address,
                        (uintptr_t)length);
}
ssize_t sendmsg(int descriptor, const struct msghdr *message, int flags) {
    return posix_bridge(PX_SENDMSG, descriptor, (uintptr_t)message, flags, 0, 0, 0);
}
ssize_t recvmsg(int descriptor, struct msghdr *message, int flags) {
    return posix_bridge(PX_RECVMSG, descriptor, (uintptr_t)message, flags, 0, 0, 0);
}
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **result) {
    return posix_bridge(PX_GETADDRINFO, (uintptr_t)node, (uintptr_t)service, (uintptr_t)hints,
                        (uintptr_t)result, 0, 0);
}
void freeaddrinfo(struct addrinfo *list) {
    while (list) {
        struct addrinfo *next = list->ai_next;
        free(list->ai_addr);
        free(list->ai_canonname);
        free(list);
        list = next;
    }
}
const char *gai_strerror(int error) {
    switch (error) {
    case 0:
        return "Success";
    case EAI_AGAIN:
        return "Temporary failure in name resolution";
    case EAI_NONAME:
        return "Name or service not known";
    case EAI_MEMORY:
        return "Memory allocation failure";
    case EAI_FAMILY:
        return "Address family not supported";
    case EAI_SOCKTYPE:
        return "Socket type not supported";
    case EAI_SERVICE:
        return "Service not supported for socket type";
    case EAI_SYSTEM:
        return "System error";
    default:
        return "Name resolution error";
    }
}
int getnameinfo(const struct sockaddr *address, socklen_t size, char *node, socklen_t node_size,
                char *service, socklen_t service_size, int flags) {
    struct {
        uint64_t node, service;
        uint32_t node_size, service_size;
    } out = {(uintptr_t)node, (uintptr_t)service, node_size, service_size};
    return posix_bridge(PX_GETNAMEINFO, (uintptr_t)address, size, (uintptr_t)&out, flags, 0, 0);
}
unsigned if_nametoindex(const char *name) {
    int64_t result = posix_bridge(PX_IF_NAMETOINDEX, (uintptr_t)name, 0, 0, 0, 0, 0);
    return result < 0 ? 0 : result;
}
char *if_indextoname(unsigned index, char *name) {
    return posix_bridge(PX_IF_INDEXTONAME, index, (uintptr_t)name, 0, 0, 0, 0) < 0 ? NULL : name;
}
