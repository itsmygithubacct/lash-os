/* Only declared Linux ABI calls cross this boundary. Pointers and logical file
 * descriptors are checked here; Linux continues to enforce process privileges. */
static int64_t service_raw(struct bridge_host *h, struct posix_request *request) {
    uint64_t *a = request->args;
    if (request->operation == PX_PRCTL) {
        switch (a[0]) {
        case PR_GET_PDEATHSIG:
        case PR_GET_CHILD_SUBREAPER:
            if (!memory(h, a[1], 4))
                return -1;
            break;
        case PR_SET_NAME:
        case PR_GET_NAME:
            if (!memory(h, a[1], 16))
                return -1;
            break;
        case PR_SET_PDEATHSIG:
        case PR_SET_CHILD_SUBREAPER:
        case PR_GET_DUMPABLE:
        case PR_SET_DUMPABLE:
        case PR_GET_KEEPCAPS:
        case PR_SET_KEEPCAPS:
        case PR_CAPBSET_READ:
        case PR_CAPBSET_DROP:
        case PR_GET_SECUREBITS:
        case PR_SET_SECUREBITS:
        case PR_CAP_AMBIENT:
        case PR_SET_NO_NEW_PRIVS:
        case PR_GET_NO_NEW_PRIVS:
            break;
        default:
            errno = ENOTSUP;
            return -1;
        }
        return prctl(a[0], a[1], a[2], a[3], a[4]);
    }
    if (request->operation == PX_PTRACE) {
        switch (a[0]) {
#if defined(__x86_64__)
        case PTRACE_GETREGS:
            if (!memory(h, a[3], sizeof(struct user_regs_struct)))
                return -1;
            break;
#endif
        case PTRACE_GETEVENTMSG:
            if (!memory(h, a[3], sizeof(unsigned long)))
                return -1;
            break;
        case PTRACE_TRACEME:
        case PTRACE_ATTACH:
        case PTRACE_DETACH:
        case PTRACE_SYSCALL:
        case PTRACE_CONT:
        case PTRACE_SETOPTIONS:
        case PTRACE_PEEKDATA:
        case PTRACE_PEEKTEXT:
            break;
        default:
            errno = ENOTSUP;
            return -1;
        }
        return ptrace(a[0], (pid_t)a[1], (void *)(uintptr_t)a[2], (void *)(uintptr_t)a[3]);
    }
    if (request->operation != PX_RAW_SYSCALL) {
        errno = ENOSYS;
        return -1;
    }
    uint64_t *in = memory(h, a[0], 7 * sizeof(uint64_t));
    if (!in)
        return -1;
    long n = native_syscall_number(in[0]);
    if (n < 0) {
        errno = ENOTSUP;
        return -1;
    }
    uint64_t v[6];
    memcpy(v, in + 1, sizeof(v));
    switch (n) {
    case SYS_getrandom:
        if (v[1] && !memory(h, v[0], v[1]))
            return -1;
        break;
    case SYS_add_key:
        if (!string(h, v[0]) || !string(h, v[1]) || (v[3] && !memory(h, v[2], v[3])))
            return -1;
        break;
    case SYS_keyctl:
        switch (v[0]) {
        case KEYCTL_JOIN_SESSION_KEYRING:
            if (v[1] && !string(h, v[1]))
                return -1;
            break;
        case KEYCTL_SEARCH:
            if (!string(h, v[2]) || !string(h, v[3]))
                return -1;
            break;
        case KEYCTL_READ:
            if (v[3] && !memory(h, v[2], v[3]))
                return -1;
            break;
        case KEYCTL_REVOKE:
        case KEYCTL_CLEAR:
            break;
        default:
            errno = ENOTSUP;
            return -1;
        }
        break;
    case SYS_seccomp: {
        if (v[0] != SECCOMP_SET_MODE_FILTER) {
            errno = ENOTSUP;
            return -1;
        }
        struct sock_fprog *program = memory(h, v[2], sizeof(*program));
        if (!program || program->len > 4096 ||
            !memory(h, (uintptr_t)program->filter, program->len * sizeof(struct sock_filter)))
            return -1;
        break;
    }
    case SYS_pidfd_open:
        return save_fd(h, syscall(n, v[0], v[1]), 0);
    case SYS_pidfd_send_signal: {
        int real = fd(h, v[0]);
        if (real < 0)
            return -1;
        v[0] = real;
        if (v[2]) {
            errno = ENOTSUP;
            return -1;
        }
        break;
    }
    case SYS_capget:
    case SYS_capset:
        if (!memory(h, v[0], 8) || !memory(h, v[1], 24))
            return -1;
        break;
    case SYS_sched_getscheduler:
    case SYS_ioprio_get:
    case SYS_ioprio_set:
        break;
    case SYS_sched_getparam:
        if (!memory(h, v[1], 4))
            return -1;
        break;
    case SYS_sched_setscheduler:
        if (!memory(h, v[2], 4))
            return -1;
        break;
    case SYS_sched_getattr:
        if (!memory(h, v[1], v[2]))
            return -1;
        break;
    case SYS_sched_setattr: {
        uint32_t *size = memory(h, v[1], 4);
        if (!size || !memory(h, v[1], *size))
            return -1;
        break;
    }
    case SYS_prlimit64:
        if ((v[2] && !memory(h, v[2], 16)) || (v[3] && !memory(h, v[3], 16)))
            return -1;
        break;
    case SYS_pivot_root:
        if (!string(h, v[0]) || !string(h, v[1]))
            return -1;
        break;
    case SYS_finit_module: {
        int real = fd(h, v[0]);
        if (real < 0 || !string(h, v[1]))
            return -1;
        v[0] = real;
        break;
    }
    case SYS_delete_module:
        if (!string(h, v[0]))
            return -1;
        break;
    case SYS_syslog:
        if (v[1] && v[2] && !memory(h, v[1], v[2]))
            return -1;
        break;
    /* Namespace creation is handled by the process snapshot path. Unlisted
     * calls need explicit pointer and descriptor translation before use. */
    default:
        errno = ENOTSUP;
        return -1;
    }
    return syscall(n, v[0], v[1], v[2], v[3], v[4], v[5]);
}
