/* Socket structures are marshalled explicitly across the libc boundary. */
static void *guest_copy(struct bridge_host *h, const void *data, size_t size) {
    void *out = bpf_capsule_malloc(h->capsule, size);
    if (!out) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(out, data, size);
    return out;
}
static void free_address_list(struct bridge_host *h, struct network_addrinfo *item) {
    while (item) {
        struct network_addrinfo *next = (void *)(uintptr_t)item->next;
        bpf_capsule_free(h->capsule, (void *)(uintptr_t)item->address);
        bpf_capsule_free(h->capsule, (void *)(uintptr_t)item->canonname);
        bpf_capsule_free(h->capsule, item);
        item = next;
    }
}
static int network_addresses(struct bridge_host *h, uint64_t *a) {
    const char *node = a[0] ? string(h, a[0]) : NULL, *service = a[1] ? string(h, a[1]) : NULL;
    struct network_addrinfo *hint = a[2] ? memory(h, a[2], sizeof(*hint)) : NULL;
    uint64_t *out = memory(h, a[3], sizeof(*out));
    if ((a[0] && !node) || (a[1] && !service) || (a[2] && !hint) || !out)
        return EAI_SYSTEM;
    *out = 0;
    struct addrinfo hints = {0}, *list = NULL;
    if (hint) {
        hints.ai_flags = hint->flags;
        hints.ai_family = hint->family;
        hints.ai_socktype = hint->socktype;
        hints.ai_protocol = hint->protocol;
    }
    int rc = getaddrinfo(node, service, hint ? &hints : NULL, &list);
    if (rc)
        return rc;
    struct network_addrinfo *first = NULL, *previous = NULL;
    for (struct addrinfo *p = list; p; p = p->ai_next) {
        struct network_addrinfo value = {.flags = p->ai_flags,
                                         .family = p->ai_family,
                                         .socktype = p->ai_socktype,
                                         .protocol = p->ai_protocol,
                                         .addrlen = p->ai_addrlen};
        struct network_addrinfo *item = guest_copy(h, &value, sizeof(value));
        if (!item)
            goto nomem;
        if (previous)
            previous->next = (uintptr_t)item;
        else
            first = item;
        previous = item;
        if (p->ai_addr) {
            item->address = (uintptr_t)guest_copy(h, p->ai_addr, p->ai_addrlen);
            if (!item->address)
                goto nomem;
        }
        if (p->ai_canonname) {
            item->canonname =
                (uintptr_t)guest_copy(h, p->ai_canonname, strlen(p->ai_canonname) + 1);
            if (!item->canonname)
                goto nomem;
        }
    }
    freeaddrinfo(list);
    *out = (uintptr_t)first;
    return 0;
nomem:
    freeaddrinfo(list);
    free_address_list(h, first);
    return EAI_MEMORY;
}
static ssize_t network_message(struct bridge_host *h, uint64_t *a, int receiving) {
    int actual = fd(h, a[0]);
    struct network_msghdr *wire = memory(h, a[1], sizeof(*wire));
    if (actual < 0 || !wire)
        return -1;
    if (wire->iovlen > 1024 || wire->controllen > 65536) {
        errno = EMSGSIZE;
        return -1;
    }
    struct network_iovec *vectors =
        wire->iovlen ? memory(h, wire->iov, wire->iovlen * sizeof(*vectors)) : NULL;
    if (wire->iovlen && !vectors)
        return -1;
    struct iovec *iov = calloc(wire->iovlen ?: 1, sizeof(*iov));
    if (!iov)
        return -1;
    struct msghdr msg = {.msg_iov = iov,
                         .msg_iovlen = wire->iovlen,
                         .msg_namelen = wire->namelen,
                         .msg_controllen = wire->controllen};
    void *ancillary = NULL, *guest_control = NULL;
    ssize_t rc = -1;
    int saved;
    for (unsigned i = 0; i < wire->iovlen; i++) {
        iov[i].iov_len = vectors[i].length;
        iov[i].iov_base = memory(h, vectors[i].base, vectors[i].length);
        if (vectors[i].length && !iov[i].iov_base)
            goto done;
    }
    if (wire->name) {
        msg.msg_name = memory(h, wire->name, wire->namelen);
        if (!msg.msg_name)
            goto done;
    }
    if (wire->controllen) {
        guest_control = memory(h, wire->control, wire->controllen);
        if (!guest_control)
            goto done;
        ancillary = calloc(1, wire->controllen);
        if (!ancillary)
            goto done;
        msg.msg_control = ancillary;
        if (!receiving) {
            memcpy(ancillary, guest_control, wire->controllen);
            size_t offset = 0;
            while (offset + sizeof(struct network_cmsghdr) <= wire->controllen) {
                struct network_cmsghdr *w = (void *)((char *)ancillary + offset);
                size_t length = w->length;
                if (length < sizeof(*w) || length > wire->controllen - offset) {
                    errno = EINVAL;
                    goto done;
                }
                w->pad = 0;
                struct cmsghdr *c = (void *)w;
                if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                    if ((length - sizeof(*w)) % sizeof(int)) {
                        errno = EINVAL;
                        goto done;
                    }
                    int *rights = (void *)(w + 1);
                    for (size_t j = 0; j < (length - sizeof(*w)) / sizeof(int); j++) {
                        rights[j] = fd(h, rights[j]);
                        if (rights[j] < 0)
                            goto done;
                    }
                }
                offset += (length + 7) & ~(size_t)7;
            }
        }
    }
    rc = receiving ? recvmsg(actual, &msg, (int)a[2]) : sendmsg(actual, &msg, (int)a[2]);
    if (rc >= 0 && receiving) {
        int installed[MAX_FDS], count = 0, failed = 0;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                int *rights = (void *)CMSG_DATA(c);
                size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t j = 0; j < n; j++) {
                    if (failed) {
                        close(rights[j]);
                        continue;
                    }
                    int logical = save_fd(h, rights[j], 0);
                    if (logical < 0) {
                        failed = 1;
                        continue;
                    }
                    rights[j] = logical;
                    installed[count++] = logical;
                }
            }
        }
        if (failed) {
            for (int j = 0; j < count; j++) {
                close(h->fds[installed[j]]);
                h->fds[installed[j]] = -1;
            }
            errno = EMFILE;
            rc = -1;
            goto done;
        }
        wire->namelen = msg.msg_namelen;
        wire->controllen = msg.msg_controllen;
        wire->flags = msg.msg_flags;
        if (msg.msg_controllen)
            memcpy(guest_control, ancillary, msg.msg_controllen);
    }
done:
    saved = errno;
    free(ancillary);
    free(iov);
    errno = saved;
    return rc;
}
static int64_t service_misc(struct bridge_host *, struct posix_request *);
static int64_t service_posix_extra(struct bridge_host *h, struct posix_request *request) {
    uint64_t *a = request->args;
    int actual, rc;
    switch (request->operation) {
    case PX_SOCKETPAIR: {
        int *out = memory(h, a[3], 2 * sizeof(int)), pair[2];
        if (!out)
            return -1;
        if (socketpair(a[0], a[1], a[2], pair))
            return -1;
        out[0] = save_fd(h, pair[0], 0);
        if (out[0] < 0) {
            close(pair[1]);
            return -1;
        }
        out[1] = save_fd(h, pair[1], 0);
        if (out[1] < 0) {
            close(h->fds[out[0]]);
            h->fds[out[0]] = -1;
            return -1;
        }
        return 0;
    }
    case PX_ACCEPT:
    case PX_GETSOCKNAME:
    case PX_GETPEERNAME: {
        actual = fd(h, a[0]);
        if (actual < 0)
            return -1;
        socklen_t *length = a[2] ? memory(h, a[2], sizeof(*length)) : NULL;
        if (a[2] && !length)
            return -1;
        void *address = a[1] && length ? memory(h, a[1], *length) : NULL;
        if (a[1] && !address) {
            errno = EFAULT;
            return -1;
        }
        if (request->operation == PX_ACCEPT)
            return save_fd(h, accept4(actual, address, length, a[3]), 0);
        return request->operation == PX_GETSOCKNAME ? getsockname(actual, address, length)
                                                    : getpeername(actual, address, length);
    }
    case PX_GETSOCKOPT: {
        actual = fd(h, a[0]);
        socklen_t *size = memory(h, a[4], sizeof(*size));
        if (actual < 0 || !size)
            return -1;
        void *out = memory(h, a[3], *size);
        if (!out && *size)
            return -1;
        return getsockopt(actual, a[1], a[2], out, size);
    }
    case PX_RECVFROM: {
        actual = fd(h, a[0]);
        void *buffer = memory(h, a[1], a[2]);
        socklen_t *size = a[5] ? memory(h, a[5], sizeof(*size)) : NULL;
        if (actual < 0 || (a[2] && !buffer) || (a[5] && !size))
            return -1;
        void *address = a[4] && size ? memory(h, a[4], *size) : NULL;
        if (a[4] && !address) {
            errno = EFAULT;
            return -1;
        }
        return recvfrom(actual, buffer, a[2], a[3], address, size);
    }
    case PX_SENDMSG:
        return network_message(h, a, 0);
    case PX_RECVMSG:
        return network_message(h, a, 1);
    case PX_GETADDRINFO:
        return network_addresses(h, a);
    case PX_GETNAMEINFO: {
        void *address = memory(h, a[0], a[1]);
        struct {
            uint64_t node, service;
            uint32_t node_size, service_size;
        } *out = memory(h, a[2], sizeof(*out));
        if (!address || !out)
            return EAI_SYSTEM;
        char *node = out->node ? memory(h, out->node, out->node_size) : NULL;
        char *service = out->service ? memory(h, out->service, out->service_size) : NULL;
        if ((out->node && !node) || (out->service && !service))
            return EAI_SYSTEM;
        return getnameinfo(address, a[1], node, out->node_size, service, out->service_size, a[3]);
    }
    case PX_IF_NAMETOINDEX: {
        char *name = string(h, a[0]);
        if (!name)
            return -1;
        rc = if_nametoindex(name);
        return rc ? rc : -1;
    }
    case PX_IF_INDEXTONAME: {
        char *name = memory(h, a[1], IF_NAMESIZE);
        return name && if_indextoname(a[0], name) ? 0 : -1;
    }
    default:
        return service_misc(h, request);
    }
}
