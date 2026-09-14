#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "kernel_control.h"

#define MAX_FDS 256
#include "../src/signal_host.h"
#include "../src/poll_host.h"

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void timeout_handler(int number) {
    (void)number;
    _exit(99);
}

int main(void) {
    struct kernel_control mailbox = {0};
    int descriptors[MAX_FDS];
    for (int i = 0; i < MAX_FDS; i++)
        descriptors[i] = -1;
    uint64_t first = UINT64_C(1) << (SIGUSR1 - 1);
    uint64_t second = UINT64_C(1) << (SIGUSR2 - 1), unmasked = 0;
    struct timespec immediate = {0};
    struct sigaction action = {.sa_sigaction = record_signal, .sa_flags = SA_SIGINFO};
    sigemptyset(&action.sa_mask);
    require(!sigaction(SIGUSR1, &action, NULL) && !sigaction(SIGUSR2, &action, NULL),
            "install recorders");
    sigset_t tested, original, current;
    sigemptyset(&tested);
    sigaddset(&tested, SIGUSR1);
    sigaddset(&tested, SIGUSR2);
    require(!sigprocmask(SIG_UNBLOCK, &tested, &original), "unblock test signals");
    signal(SIGALRM, timeout_handler);
    alarm(3);

    require(!raise(SIGUSR1), "queue native signal");
    require(poll_descriptors(&mailbox, descriptors, NULL, 0, NULL, NULL) == -1 && errno == EINTR,
            "queued native signal interrupts an indefinite poll");
    require(mailbox.pending_signals == first, "publish native queued signal");
    require(poll_descriptors(&mailbox, descriptors, NULL, 0, NULL, NULL) == -1 && errno == EINTR,
            "queued mailbox signal interrupts an indefinite poll");
    require(poll_descriptors(&mailbox, descriptors, NULL, 0, &immediate, &first) == 0,
            "masked mailbox signal does not interrupt poll");
    require(mailbox.pending_signals == first, "retain masked mailbox signal");

    /* A native signal still pending in the OS is delivered by ppoll's atomic
     * mask switch and published before the original blocked mask is restored. */
    mailbox.pending_signals = 0;
    require(!sigprocmask(SIG_BLOCK, &tested, NULL), "block native delivery");
    require(!raise(SIGUSR1), "queue blocked native signal");
    require(poll_descriptors(&mailbox, descriptors, NULL, 0, NULL, &unmasked) == -1 &&
                errno == EINTR && mailbox.pending_signals == first,
            "temporary poll mask permits pending native delivery");
    require(!sigprocmask(SIG_SETMASK, NULL, &current) && sigismember(&current, SIGUSR1) == 1,
            "restore caller's blocked native mask");
    require(poll_descriptors(&mailbox, descriptors, NULL, 0, &immediate, NULL) == 0,
            "null poll mask respects caller's blocked mask");
    require(!sigprocmask(SIG_UNBLOCK, &tested, NULL), "restore unblocked test signals");

    pid_t child = fork();
    require(child >= 0, "start delayed signal sender");
    if (!child) {
        usleep(20000);
        kill(getppid(), SIGUSR2);
        _exit(0);
    }
    require(poll_descriptors(&mailbox, descriptors, NULL, 0, NULL, &first) == -1 && errno == EINTR,
            "later unmasked signal interrupts poll");
    require(mailbox.pending_signals == (first | second),
            "publish later signal and retain masked one");
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "reap delayed signal sender");
    mailbox.pending_signals = 0;
    require(!sigprocmask(SIG_SETMASK, NULL, &current) && sigismember(&current, SIGUSR1) == 0,
            "restore caller's unblocked native mask");

    int pair[2], empty[2];
    require(!pipe(pair) && !pipe(empty), "create ready and idle pipes");
    require(write(pair[1], "x", 1) == 1, "make input ready");
    descriptors[11] = pair[0];
    descriptors[12] = empty[0];
    struct pollfd items[] = {{.fd = 10, .events = POLLIN, .revents = POLLHUP},
                             {.fd = 11, .events = POLLIN, .revents = POLLHUP},
                             {.fd = 12, .events = POLLIN, .revents = POLLHUP},
                             {.fd = MAX_FDS, .events = POLLIN, .revents = POLLHUP},
                             {.fd = -1, .events = POLLIN, .revents = POLLHUP}};
    require(poll_descriptors(&mailbox, descriptors, items, 5, NULL, NULL) == 3,
            "count every invalid and ready descriptor without blocking");
    require(items[0].revents == POLLNVAL && items[1].revents == POLLIN && items[2].revents == 0 &&
                items[3].revents == POLLNVAL && items[4].revents == 0,
            "combine readiness and invalid entries and clear stale events");
    char value;
    require(read(pair[0], &value, 1) == 1, "consume ready input");
    require(poll_descriptors(&mailbox, descriptors, items, 5, NULL, NULL) == 2 &&
                items[1].revents == 0,
            "invalid descriptors still return immediately with otherwise idle input");
    require(poll_descriptors(&mailbox, descriptors, items + 1, 2, &immediate, NULL) == 0,
            "ordinary idle descriptors time out without events");
    close(pair[0]);
    close(pair[1]);
    close(empty[0]);
    close(empty[1]);
    require(!sigprocmask(SIG_SETMASK, &original, NULL), "restore original test-process mask");
    alarm(0);
    puts("PASS: queued, masked, delayed signals and complete poll readiness");
    return 0;
}
