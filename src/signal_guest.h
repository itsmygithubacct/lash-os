/* Linux signals are collected by the bridge and dispatched as managed calls. */
static struct sigaction guest_actions[128];
static sigset_t guest_signal_mask;

void linux_bash_poll_signals(void) {
    int saved_errno = errno;
    uint64_t ready = control.pending_signals & ~(uint64_t)guest_signal_mask;
    for (unsigned number = 1; number <= 64; number++) {
        uint64_t bit = UINT64_C(1) << (number - 1);
        if (!(ready & bit))
            continue;
        control.pending_signals &= ~bit;
        struct sigaction action = guest_actions[number];
        if (action.sa_handler != SIG_DFL && action.sa_handler != SIG_IGN) {
            if (action.sa_flags & SA_SIGINFO) {
                siginfo_t info = {.si_signo = (int)number, .si_code = SI_USER};
                action.sa_sigaction(number, &info, NULL);
            } else
                action.sa_handler(number);
        }
    }
    errno = saved_errno;
}

int sigaction(int number, const struct sigaction *action, struct sigaction *old) {
    if (number < 1 || number > 64) {
        errno = EINVAL;
        return -1;
    }
    struct bridge_signal_action packed = {0}, previous = {0};
    if (action) {
        packed.mask = action->sa_mask;
        packed.flags = action->sa_flags;
        packed.mode = action->sa_handler == SIG_DFL ? 0 : action->sa_handler == SIG_IGN ? 1 : 2;
    }
    int rc = bridge(BR_SIGACTION, number, action ? (uintptr_t)&packed : 0, (uintptr_t)&previous);
    if (rc < 0)
        return rc;
    if (old) {
        *old = guest_actions[number];
        old->sa_mask = previous.mask;
        old->sa_flags = previous.flags;
        if (previous.mode == 0)
            old->sa_handler = SIG_DFL;
        else if (previous.mode == 1)
            old->sa_handler = SIG_IGN;
    }
    if (action)
        guest_actions[number] = *action;
    return 0;
}

_sig_func_ptr signal(int number, _sig_func_ptr handler) {
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_RESTART}, old;
    return sigaction(number, &action, &old) ? SIG_ERR : old.sa_handler;
}
int siginterrupt(int number, int interrupt) {
    struct sigaction action;
    if (sigaction(number, NULL, &action))
        return -1;
    if (interrupt)
        action.sa_flags &= ~SA_RESTART;
    else
        action.sa_flags |= SA_RESTART;
    return sigaction(number, &action, NULL);
}
int sigprocmask(int how, const sigset_t *set, sigset_t *old) {
    uint64_t packed = set ? *set : 0, previous;
    int rc = bridge(BR_SIGMASK, how, set ? (uintptr_t)&packed : 0, (uintptr_t)&previous);
    if (rc < 0)
        return rc;
    if (old)
        *old = previous;
    guest_signal_mask = previous;
    if (set) {
        if (how == SIG_SETMASK)
            guest_signal_mask = *set;
        else if (how == SIG_BLOCK)
            guest_signal_mask |= *set;
        else if (how == SIG_UNBLOCK)
            guest_signal_mask &= ~*set;
    }
    return 0;
}
int sigpending(sigset_t *set) {
    *set = control.pending_signals;
    return 0;
}
int sigsuspend(const sigset_t *set) {
    sigset_t previous = guest_signal_mask;
    guest_signal_mask = *set;
    int rc = bridge(BR_SIGSUSPEND, *set, 0, 0);
    guest_signal_mask = previous;
    return rc;
}
int kill(pid_t pid, int number) {
    return bridge(BR_KILL, pid, number, 0);
}
int killpg(pid_t group, int number) {
    return kill(-group, number);
}
int raise(int number) {
    return kill(getpid(), number);
}
unsigned alarm(unsigned seconds) {
    return bridge(BR_ALARM, seconds, 0, 0);
}

char *strsignal(int number) {
    static char realtime[40];
    switch (number) {
    case 1:
        return "Hangup";
    case 2:
        return "Interrupt";
    case 3:
        return "Quit";
    case 4:
        return "Illegal instruction";
    case 5:
        return "Trace/breakpoint trap";
    case 6:
        return "Aborted";
    case 7:
        return "Bus error";
    case 8:
        return "Floating point exception";
    case 9:
        return "Killed";
    case 10:
        return "User defined signal 1";
    case 11:
        return "Segmentation fault";
    case 12:
        return "User defined signal 2";
    case 13:
        return "Broken pipe";
    case 14:
        return "Alarm clock";
    case 15:
        return "Terminated";
    case 16:
        return "Stack fault";
    case 17:
        return "Child exited";
    case 18:
        return "Continued";
    case 19:
        return "Stopped (signal)";
    case 20:
        return "Stopped";
    case 21:
        return "Stopped (tty input)";
    case 22:
        return "Stopped (tty output)";
    case 23:
        return "Urgent I/O condition";
    case 24:
        return "CPU time limit exceeded";
    case 25:
        return "File size limit exceeded";
    case 26:
        return "Virtual timer expired";
    case 27:
        return "Profiling timer expired";
    case 28:
        return "Window changed";
    case 29:
        return "I/O possible";
    case 30:
        return "Power failure";
    case 31:
        return "Bad system call";
    default:
        snprintf(realtime, sizeof(realtime),
                 number >= SIGRTMIN && number <= SIGRTMAX ? "Real-time signal %d"
                                                          : "Unknown signal %d",
                 number >= SIGRTMIN && number <= SIGRTMAX ? number - SIGRTMIN : number);
        return realtime;
    }
}
