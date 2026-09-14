#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include "kernel_control.h"
#include "../src/signal_host.h"

static void timeout_handler(int signal_number) {
    (void)signal_number;
    _exit(99);
}

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void) {
    struct kernel_control mailbox = {0};
    uint64_t first = UINT64_C(1) << (SIGUSR1 - 1);
    uint64_t second = UINT64_C(1) << (SIGUSR2 - 1);
    struct sigaction action = {.sa_sigaction = record_signal, .sa_flags = SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    require(!sigaction(SIGUSR1, &action, NULL), "install SIGUSR1 recorder");
    require(!sigaction(SIGUSR2, &action, NULL), "install SIGUSR2 recorder");
    signal(SIGALRM, timeout_handler);
    alarm(3);

    /* Delivery before a bridge wait must wake it even though the native
     * handler has already returned. */
    require(!raise(SIGUSR1), "queue native signal");
    require(suspend_signals(&mailbox, 0) == -1 && errno == EINTR,
            "native queued signal wakes suspension");
    require(mailbox.pending_signals == first, "native signal reaches mailbox");
    mailbox.pending_signals = 0;

    require(!raise(SIGUSR1), "queue mailbox signal");
    publish_signals(&mailbox);
    require(suspend_signals(&mailbox, 0) == -1 && errno == EINTR,
            "mailbox signal wakes suspension");
    require(mailbox.pending_signals == first, "mailbox event survives suspension");

    /* An already queued masked event must not consume the wait for another
     * signal; that later delivery exercises atomic mask installation. */
    pid_t child = fork();
    require(child >= 0, "start delayed sender");
    if (!child) {
        usleep(20000);
        kill(getppid(), SIGUSR2);
        _exit(0);
    }
    require(suspend_signals(&mailbox, first) == -1 && errno == EINTR,
            "later unmasked signal wakes suspension");
    publish_signals(&mailbox);
    require(mailbox.pending_signals == (first | second), "both pending events survive");
    sigset_t mask;
    require(!sigprocmask(SIG_SETMASK, NULL, &mask), "query restored mask");
    require(!sigismember(&mask, SIGUSR1), "restore mask after suspension");
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "delayed sender exits");
    alarm(0);
    puts("PASS: queued and delayed signals wake bridge suspension");
    return 0;
}
