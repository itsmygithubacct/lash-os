#pragma once
#include_next <signal.h>
#include <errno.h>
/* Linux signal ABI; guest sigset_t is the 64-bit kernel mask. */
#undef SIGHUP
#define SIGHUP 1
#undef SIGINT
#define SIGINT 2
#undef SIGQUIT
#define SIGQUIT 3
#undef SIGILL
#define SIGILL 4
#undef SIGTRAP
#define SIGTRAP 5
#undef SIGABRT
#define SIGABRT 6
#undef SIGBUS
#define SIGBUS 7
#undef SIGFPE
#define SIGFPE 8
#undef SIGKILL
#define SIGKILL 9
#undef SIGUSR1
#define SIGUSR1 10
#undef SIGSEGV
#define SIGSEGV 11
#undef SIGUSR2
#define SIGUSR2 12
#undef SIGPIPE
#define SIGPIPE 13
#undef SIGALRM
#define SIGALRM 14
#undef SIGTERM
#define SIGTERM 15
#undef SIGSTKFLT
#define SIGSTKFLT 16
#undef SIGCHLD
#define SIGCHLD 17
#undef SIGCONT
#define SIGCONT 18
#undef SIGSTOP
#define SIGSTOP 19
#undef SIGTSTP
#define SIGTSTP 20
#undef SIGTTIN
#define SIGTTIN 21
#undef SIGTTOU
#define SIGTTOU 22
#undef SIGURG
#define SIGURG 23
#undef SIGXCPU
#define SIGXCPU 24
#undef SIGXFSZ
#define SIGXFSZ 25
#undef SIGVTALRM
#define SIGVTALRM 26
#undef SIGPROF
#define SIGPROF 27
#undef SIGWINCH
#define SIGWINCH 28
#undef SIGIO
#define SIGIO 29
#undef SIGPWR
#define SIGPWR 30
#undef SIGSYS
#define SIGSYS 31
#undef NSIG
#define NSIG 65
#undef _NSIG
#define _NSIG NSIG
#define SIGRTMIN 34
#define SIGRTMAX 64
#undef SIGEMT
#undef SIGLOST
#undef sigaddset
#undef sigdelset
#undef sigismember
static inline int linux_sigaddset(sigset_t *set, int number) {
    if (number < 1 || number > 64) { errno = EINVAL; return -1; }
    *set |= (sigset_t)1 << (number - 1); return 0;
}
static inline int linux_sigdelset(sigset_t *set, int number) {
    if (number < 1 || number > 64) { errno = EINVAL; return -1; }
    *set &= ~((sigset_t)1 << (number - 1)); return 0;
}
static inline int linux_sigismember(const sigset_t *set, int number) {
    if (number < 1 || number > 64) { errno = EINVAL; return -1; }
    return (*set >> (number - 1)) & 1;
}
#define sigaddset linux_sigaddset
#define sigdelset linux_sigdelset
#define sigismember linux_sigismember
int siginterrupt(int, int);
