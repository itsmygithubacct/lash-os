/* SPDX-License-Identifier: MIT */
/* Preserve the shell's SIGCHLD handler and pending background-job signals
   while a raw-fork wrapper waits for its own child. */
#ifndef BASHOS_CHILD_WAIT_H
#define BASHOS_CHILD_WAIT_H

#include <errno.h>
#include <signal.h>

typedef struct {
    sigset_t previous_mask;
    struct sigaction previous_action;
} bos_child_wait;

static inline int
bos_child_wait_begin (bos_child_wait *state)
{
    sigset_t blocked;
    sigemptyset (&blocked);
    sigaddset (&blocked, SIGCHLD);
    if (sigprocmask (SIG_BLOCK, &blocked, &state->previous_mask) < 0)
        return -1;
    struct sigaction action = {0};
    action.sa_handler = SIG_DFL;
    sigemptyset (&action.sa_mask);
    if (sigaction (SIGCHLD, &action, &state->previous_action) < 0) {
        int saved = errno;
        sigprocmask (SIG_SETMASK, &state->previous_mask, NULL);
        errno = saved;
        return -1;
    }
    return 0;
}

static inline void
bos_child_wait_child (const bos_child_wait *state)
{
    sigprocmask (SIG_SETMASK, &state->previous_mask, NULL);
}

static inline void
bos_child_wait_end (const bos_child_wait *state)
{
    int saved = errno;
    /* Restore the handler before unblocking. Reversing this order discards
       pending SIGCHLD with SIG_DFL and strands unrelated Bash jobs. */
    sigaction (SIGCHLD, &state->previous_action, NULL);
    sigprocmask (SIG_SETMASK, &state->previous_mask, NULL);
    errno = saved;
}

#endif
