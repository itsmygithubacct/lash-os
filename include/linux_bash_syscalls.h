/* Stable wire identifiers, using the original x86-64 guest ABI. These are not
 * native syscall numbers on other hosts. Only calls with bridge validation
 * belong here; clone is handled by the process snapshot path. */
#ifndef LINUX_BASH_SYSCALLS_H
#define LINUX_BASH_SYSCALLS_H
#define LINUX_BASH_SYSCALLS(X) \
    X(clone, 56) \
    X(syslog, 103) \
    X(capget, 125) \
    X(capset, 126) \
    X(sched_getparam, 143) \
    X(sched_setscheduler, 144) \
    X(sched_getscheduler, 145) \
    X(pivot_root, 155) \
    X(delete_module, 176) \
    X(add_key, 248) \
    X(keyctl, 250) \
    X(ioprio_set, 251) \
    X(ioprio_get, 252) \
    X(prlimit64, 302) \
    X(finit_module, 313) \
    X(sched_setattr, 314) \
    X(sched_getattr, 315) \
    X(seccomp, 317) \
    X(getrandom, 318) \
    X(pidfd_send_signal, 424) \
    X(pidfd_open, 434)
enum {
#define LASH_SYSCALL_ID(name, number) LASH_SYS_##name = number,
    LINUX_BASH_SYSCALLS(LASH_SYSCALL_ID)
#undef LASH_SYSCALL_ID
};
#endif
