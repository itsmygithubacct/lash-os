#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
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

static long long elapsed_ms(struct timespec start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start.tv_sec) * 1000LL + (now.tv_nsec - start.tv_nsec) / 1000000;
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

    int pipes[2];
    char byte = 0;
    require(!pipe(pipes), "create pipe");
    mailbox.pending_signals = 0;
    require(!raise(SIGUSR1), "queue signal before blocking read");
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int64_t rc = interruptible_transfer(&mailbox, pipes[0], &byte, 1, 0);
    require(rc == -1 && errno == EINTR, "queued signal interrupts an empty read");
    require(elapsed_ms(start) < 500, "empty read notices the queued signal promptly");
    require(mailbox.pending_signals == first, "empty read publishes the queued signal");

    mailbox.pending_signals = 0;
    require(write(pipes[1], "Q", 1) == 1, "preload one byte");
    require(!raise(SIGUSR1), "queue signal ahead of readable data");
    rc = interruptible_transfer(&mailbox, pipes[0], &byte, 1, 0);
    require(rc == -1 && errno == EINTR, "pending signal wins over a ready byte");
    require(mailbox.pending_signals == first, "ready descriptor still publishes the signal");
    require(byte != 'Q', "interrupted read does not consume the byte");
    mailbox.pending_signals = 0;
    rc = interruptible_transfer(&mailbox, pipes[0], &byte, 1, 0);
    require(rc == 1 && byte == 'Q' && !errno, "retry reads the byte after the signal is cleared");

    mailbox.pending_signals = first;
    rc = interruptible_transfer(&mailbox, pipes[0], &byte, 0, 0);
    require(rc == 0 && mailbox.pending_signals == first, "zero-length read does not wait or fail");
    rc = interruptible_transfer(&mailbox, pipes[1], &byte, 0, 1);
    require(rc == 0, "zero-length write returns immediately");

    mailbox.pending_signals = 0;
    child = fork();
    require(child >= 0, "start signal during read");
    if (!child) {
        usleep(20000);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    rc = interruptible_transfer(&mailbox, pipes[0], &byte, 1, 0);
    require(rc == -1 && errno == EINTR, "signal during a blocking read returns EINTR");
    require(elapsed_ms(start) < 1000, "in-flight read returns within a second");
    require(mailbox.pending_signals == first, "in-flight signal is published");
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "in-flight sender exits");

    sigset_t blocked, saved_mask;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    require(!sigprocmask(SIG_BLOCK, &blocked, &saved_mask), "block SIGUSR1");
    require(!raise(SIGUSR1), "queue a blocked SIGUSR1");
    mailbox.pending_signals = 0;
    child = fork();
    require(child >= 0, "start writer while signal is blocked");
    if (!child) {
        usleep(20000);
        if (write(pipes[1], "Z", 1) != 1)
            _exit(1);
        _exit(0);
    }
    clock_gettime(CLOCK_MONOTONIC, &start);
    byte = 0;
    rc = interruptible_transfer(&mailbox, pipes[0], &byte, 1, 0);
    require(rc == 1 && byte == 'Z' && !errno, "a blocked signal does not interrupt the read");
    require(elapsed_ms(start) < 1000, "blocked-signal read returns with the byte");
    require(!(mailbox.pending_signals & first), "blocked signal stays out of the mailbox");
    require(!sigprocmask(SIG_SETMASK, &saved_mask, NULL), "unblock SIGUSR1");
    publish_signals(&mailbox);
    require(mailbox.pending_signals == first, "drained signal reaches the mailbox");
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "blocked-signal writer exits");
    close(pipes[0]);
    close(pipes[1]);
    alarm(0);
    puts("PASS: queued signals wake suspension and blocking reads");
    return 0;
}
