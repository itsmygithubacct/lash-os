/* Async handlers only record delivery. Guest handlers execute inside BPF. */
static volatile sig_atomic_t pending_signals[65];
static int installed_signal_flags[65];
static int native_signal(int number) {
    return number >= 0 && number <= 64 ? number : -1;
}
static int guest_signal(int number) {
    return number >= 0 && number <= 64 ? number : 0;
}
static void unpack_signal_mask(uint64_t packed, sigset_t *set) {
    sigemptyset(set);
    for (int i = 1; i <= 64; i++) {
        int number = native_signal(i);
        if (number > 0 && (packed & (UINT64_C(1) << (i - 1))))
            sigaddset(set, number);
    }
}
static uint64_t pack_signal_mask(const sigset_t *set) {
    uint64_t packed = 0;
    for (int i = 1; i <= 64; i++) {
        int number = native_signal(i);
        if (number > 0 && sigismember(set, number) == 1)
            packed |= UINT64_C(1) << (i - 1);
    }
    return packed;
}
static void record_signal(int number, siginfo_t *info, void *context) {
    (void)info;
    (void)context;
    int guest = guest_signal(number);
    if (guest)
        pending_signals[guest] = 1;
}
static void publish_signals(volatile struct kernel_control *c) {
    sigset_t all, previous;
    sigfillset(&all);
    sigprocmask(SIG_BLOCK, &all, &previous);
    for (unsigned i = 1; i <= 64; i++) {
        if (pending_signals[i]) {
            c->pending_signals |= UINT64_C(1) << (i - 1);
            pending_signals[i] = 0;
        }
    }
    sigprocmask(SIG_SETMASK, &previous, NULL);
}

static int suspend_signals(volatile struct kernel_control *c, uint64_t mask) {
    sigset_t all, previous, desired;
    sigfillset(&all);
    unpack_signal_mask(mask, &desired);
    /* A signal may already have reached the bridge while Bash was running.
     * Block delivery across the queue check and let sigsuspend atomically
     * install the requested mask, so neither queued nor new signals get lost. */
    if (sigprocmask(SIG_BLOCK, &all, &previous))
        return -1;
    publish_signals(c);
    int rc;
    if (c->pending_signals & ~mask) {
        errno = EINTR;
        rc = -1;
    } else
        rc = sigsuspend(&desired);
    int saved = errno;
    if (sigprocmask(SIG_SETMASK, &previous, NULL))
        return -1;
    errno = saved;
    return rc;
}
static int guest_wait_status(int status) {
    if (WIFSTOPPED(status))
        return (guest_signal(WSTOPSIG(status)) << 8) | 0x7f;
    if (WIFSIGNALED(status))
        return (status & 0x80) | guest_signal(WTERMSIG(status));
    return status;
}
static int native_action_flags(int flags) {
    int result = 0;
    if (flags & 1)
        result |= SA_NOCLDSTOP;
    if (flags & 2)
        result |= SA_ONSTACK;
    if (flags & 4)
        result |= SA_RESETHAND;
    if (flags & 8)
        result |= SA_RESTART;
    if (flags & 16)
        result |= SA_SIGINFO;
    if (flags & 32)
        result |= SA_NOCLDWAIT;
    if (flags & 64)
        result |= SA_NODEFER;
    return result;
}
static int guest_action_flags(int flags) {
    int result = 0;
    if (flags & SA_NOCLDSTOP)
        result |= 1;
    if (flags & SA_ONSTACK)
        result |= 2;
    if (flags & SA_RESETHAND)
        result |= 4;
    if (flags & SA_RESTART)
        result |= 8;
    if (flags & SA_SIGINFO)
        result |= 16;
    if (flags & SA_NOCLDWAIT)
        result |= 32;
    if (flags & SA_NODEFER)
        result |= 64;
    return result;
}
