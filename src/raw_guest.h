long linux_bash_syscall(long number, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e,
                        uint64_t f) {
    if (number == SYS_statx) {
        control.args[3] = d;
        control.args[4] = e;
        return bridge(BR_STATX, a, b, c);
    }
    uint64_t values[7] = {number, a, b, c, d, e, f};
    return posix_bridge(PX_RAW_SYSCALL, (uintptr_t)values, 0, 0, 0, 0, 0);
}
int linux_bash_prctl(long operation, uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    return posix_bridge(PX_PRCTL, operation, a, b, c, d, 0);
}
long linux_bash_ptrace(long operation, uint64_t pid, uint64_t address, uint64_t data) {
    return posix_bridge(PX_PTRACE, operation, pid, address, data, 0, 0);
}
