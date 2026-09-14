#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int terminal;
static char transcript[65536];
static size_t used;
/* A full-profile child must verify its image before resuming Bash. */
static long long step_timeout_ms = 60000;
static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}
static int expect(const char *needle) {
    long long deadline = now_ms() + step_timeout_ms;
    for (;;) {
        char *found = strstr(transcript, needle);
        if (found) {
            size_t consumed = found + strlen(needle) - transcript;
            memmove(transcript, transcript + consumed, used - consumed);
            used -= consumed;
            transcript[used] = 0;
            return 0;
        }
        int remaining = deadline - now_ms();
        if (remaining <= 0)
            break;
        struct pollfd p = {.fd = terminal, .events = POLLIN};
        int rc = poll(&p, 1, remaining);
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc <= 0 || used >= sizeof(transcript) - 1)
            break;
        ssize_t count = read(terminal, transcript + used, sizeof(transcript) - used - 1);
        if (count <= 0)
            break;
        fwrite(transcript + used, 1, count, stdout);
        fflush(stdout);
        used += count;
        transcript[used] = 0;
    }
    fprintf(stderr, "terminal test: did not receive <%s>\n", needle);
    return -1;
}
static int send_text(const char *s) {
    size_t left = strlen(s);
    while (left) {
        ssize_t n = write(terminal, s, left);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        s += n;
        left -= n;
    }
    return 0;
}
static int await_job_foreground(pid_t shell) {
    long long deadline = now_ms() + step_timeout_ms;
    while (now_ms() < deadline) {
        pid_t group = tcgetpgrp(terminal);
        if (group > 0 && group != shell)
            return 0;
        struct timespec pause = {.tv_nsec = 10000000};
        nanosleep(&pause, NULL);
    }
    fprintf(stderr, "terminal test: job never acquired the terminal\n");
    return -1;
}
#define EXPECT(s)                                                                                  \
    do {                                                                                           \
        if (expect(s))                                                                             \
            goto fail;                                                                             \
    } while (0)
#define SEND(s)                                                                                    \
    do {                                                                                           \
        if (send_text(s))                                                                          \
            goto fail;                                                                             \
    } while (0)
int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    const char *timeout = getenv("LASHOS_TEST_STEP_TIMEOUT_MS");
    if (timeout) {
        char *end;
        errno = 0;
        long long value = strtoll(timeout, &end, 10);
        if (errno || !*timeout || *end || value < 1000 || value > 1800000)
            return 2;
        step_timeout_ms = value;
    }
    const char *prompt = geteuid() == 0 ? "# " : "$ ";
    int slave;
    if (openpty(&terminal, &slave, NULL, NULL, NULL)) {
        perror("openpty");
        return 1;
    }
    struct termios t;
    tcgetattr(slave, &t);
    t.c_lflag &= ~ECHO;
    tcsetattr(slave, TCSANOW, &t);
    pid_t shell = fork();
    if (shell < 0)
        return 1;
    if (!shell) {
        close(terminal);
        setsid();
        ioctl(slave, TIOCSCTTY, 0);
        for (int i = 0; i < 3; i++)
            dup2(slave, i);
        if (slave > 2)
            close(slave);
        setenv("PS1", "kernel-bash\\$ ", 1);
        execl(argv[1], argv[1], "--noprofile", "--norc", "-i", NULL);
        _exit(127);
    }
    close(slave);
    EXPECT(prompt);
    SEND("( printf 'job-ready\\n'; sleep 30 )\n");
    EXPECT("job-ready\r\n");
    SEND("\032");
    EXPECT("Stopped");
    EXPECT(prompt);
    SEND("jobs\n");
    EXPECT("Stopped");
    EXPECT(prompt);
    SEND("bg\n");
    EXPECT(prompt);
    SEND("fg\n");
    EXPECT("sleep 30");
    if (await_job_foreground(shell))
        goto fail;
    SEND("\003");
    EXPECT(prompt);
    SEND("printf 'interrupt-status=%s\\n' \"$?\"\n");
    EXPECT("interrupt-status=130\r\n");
    EXPECT(prompt);
    SEND("trap 'printf signal-delivered\\\\n' USR1; kill -USR1 $$\n");
    EXPECT("signal-delivered");
    EXPECT(prompt);
    SEND("exit\n");
    int status;
    waitpid(shell, &status, 0);
    close(terminal);
    if (!WIFEXITED(status) || WEXITSTATUS(status))
        return 1;
    puts("JOB_CONTROL_PASSED");
    return 0;
fail:
    kill(-shell, SIGKILL);
    kill(shell, SIGKILL);
    waitpid(shell, NULL, 0);
    close(terminal);
    return 1;
}
