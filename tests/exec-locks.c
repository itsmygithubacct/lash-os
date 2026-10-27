/* Exec must preserve record locks continuously, without descriptor aliases. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_FDS 256
struct bridge_host {
    int fds[MAX_FDS];
};
static char arena[256 * 1024] __attribute__((aligned(16)));
static uint64_t available(struct bridge_host *h, uint64_t address) {
    (void)h;
    uintptr_t base = (uintptr_t)arena;
    if (address >= base && address - base < sizeof(arena))
        return sizeof(arena) - (address - base);
    return 0;
}
static void *memory(struct bridge_host *h, uint64_t address, uint64_t size) {
    if (!size || size > available(h, address)) {
        errno = EFAULT;
        return NULL;
    }
    return (void *)(uintptr_t)address;
}
static char *string(struct bridge_host *h, uint64_t address) {
    size_t left = available(h, address);
    if (!left) {
        errno = EFAULT;
        return NULL;
    }
    if (left > 4096)
        left = 4096;
    char *text = memory(h, address, left);
    if (!text || !memchr(text, 0, left)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return text;
}
#include "../src/fds_host.h"
#include "../src/exec_host.h"

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}
static int attempt_exec(struct bridge_host *host, const char *path, char *const arguments[]) {
    char *cursor = arena + 4096;
    uint64_t name = (uintptr_t)cursor;
    strcpy(cursor, path);
    cursor += strlen(cursor) + 1;
    uint64_t *argv = (uint64_t *)arena;
    size_t count = 0;
    for (; arguments[count]; count++) {
        argv[count] = (uintptr_t)cursor;
        strcpy(cursor, arguments[count]);
        cursor += strlen(cursor) + 1;
    }
    argv[count] = 0;
    uint64_t *envp = (uint64_t *)(arena + 1024);
    strcpy(cursor, "LASHOS_EXEC_TEST=ready");
    envp[0] = (uintptr_t)cursor;
    envp[1] = 0;
    return service_exec(host, name, (uintptr_t)argv, (uintptr_t)envp);
}

static void check_locks(int reading, int writing) {
    pid_t parent = getpid(), child = fork();
    require(child >= 0, "start independent lock query");
    if (!child) {
        struct flock read_range = {
            .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 5, .l_len = 10};
        struct flock whole_file = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        struct flock outside = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 20, .l_len = 1};
        require(!fcntl(reading, F_GETLK, &read_range) && read_range.l_type == F_RDLCK &&
                    read_range.l_pid == parent && read_range.l_start == 5 && read_range.l_len == 10,
                "parent retains its exact read lock");
        require(!fcntl(writing, F_GETLK, &whole_file) && whole_file.l_type == F_WRLCK &&
                    whole_file.l_pid == parent && whole_file.l_start == 0 && !whole_file.l_len,
                "parent retains its whole-file write lock");
        require(!fcntl(reading, F_GETLK, &outside) && outside.l_type == F_UNLCK,
                "bytes outside the locked range remain unlocked");
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "independent lock query succeeds");
}

static int locked_file(struct bridge_host *host, short type, off_t start, off_t length) {
    char path[] = "/tmp/lashos-exec-lock-XXXXXX";
    int descriptor = adopt_descriptor(host->fds, mkstemp(path), 0);
    require(descriptor >= 0, "create guest file in its native slot");
    require(!unlink(path), "unlink temporary lock file");
    struct flock region = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = length};
    require(!fcntl(descriptor, F_SETLK, &region), "take record lock");
    return descriptor;
}

static void failed_exec(struct bridge_host *host, int private, int cloexec) {
    char *arguments[] = {"missing-program", NULL};
    errno = 0;
    int rc = attempt_exec(host, "/no/such/lashos-exec", arguments);
    require(rc == -1 && errno == ENOENT, "missing program returns ENOENT even with a read lock");
    require(fcntl(private, F_GETFD) == FD_CLOEXEC,
            "private descriptor remains usable and close-on-exec after failure");
    require(fcntl(cloexec, F_GETFD) == FD_CLOEXEC, "failed exec preserves guest close-on-exec");
}

static void contended_exec(struct bridge_host *host, int writing, int private, int cloexec) {
    int notice[2];
    require(!pipe2(notice, O_NONBLOCK | O_CLOEXEC), "create contender notification pipe");
    pid_t child = fork();
    require(child >= 0, "start waiting contender");
    if (!child) {
        close(notice[0]);
        require(write(notice[1], "R", 1) == 1, "announce waiting contender");
        struct flock region = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        require(!fcntl(writing, F_SETLKW, &region), "wait for parent lock");
        require(write(notice[1], "L", 1) == 1, "report any interruption in lock ownership");
        usleep(100000);
        _exit(0);
    }
    close(notice[1]);
    struct pollfd event = {.fd = notice[0], .events = POLLIN};
    char byte;
    require(poll(&event, 1, 1000) == 1 && read(notice[0], &byte, 1) == 1 && byte == 'R',
            "contender is ready before exec attempts");
    for (int i = 0; i < 200; i++)
        failed_exec(host, private, cloexec);
    require(poll(&event, 1, 20) == 0, "contender never acquires the lock during failed exec");
    require(!kill(child, SIGKILL), "stop blocked contender");
    int status;
    require(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                WTERMSIG(status) == SIGKILL,
            "contender stayed blocked until stopped");
    close(notice[0]);
}

int main(int argc, char **argv) {
    if (argc == 7 && !strcmp(argv[1], "--after-exec")) {
        int reading = atoi(argv[2]), writing = atoi(argv[3]);
        require(getpid() == (pid_t)atoi(argv[6]), "exec keeps the process and lock owner");
        require(getenv("LASHOS_EXEC_TEST") && !strcmp(getenv("LASHOS_EXEC_TEST"), "ready"),
                "exec passes its environment");
        check_locks(reading, writing);
        require(fcntl(atoi(argv[4]), F_GETFD) == -1 && errno == EBADF,
                "successful exec closes private descriptors");
        require(fcntl(atoi(argv[5]), F_GETFD) == -1 && errno == EBADF,
                "successful exec honors guest close-on-exec");
        require(fcntl(reading, F_GETFD) == 0 && fcntl(writing, F_GETFD) == 0,
                "successful exec retains guest descriptor flags");
        puts("PASS: read/write locks, contended failed exec, successful exec and private "
             "descriptors");
        return 0;
    }
    alarm(4);
    struct bridge_host host;
    require(!inherit_descriptors(host.fds), "capture inherited descriptors");
    struct descriptor_reservation reserved;
    require(!reserve_descriptor_slots(&reserved), "reserve loader descriptor slots");
    int private = open("/dev/null", O_RDONLY);
    require(private >= MAX_FDS, "private loader file is outside the guest range");
    release_descriptor_slots(&reserved);
    int reading = locked_file(&host, F_RDLCK, 5, 10);
    int writing = locked_file(&host, F_WRLCK, 0, 0);
    int cloexec = adopt_descriptor(host.fds, open("/dev/null", O_RDONLY | O_CLOEXEC), 0);
    require(cloexec >= 0, "create guest close-on-exec descriptor");
    check_locks(reading, writing);
    failed_exec(&host, private, cloexec);
    check_locks(reading, writing);
    int directory = adopt_descriptor(host.fds, open("/proc/self/fd", O_RDONLY | O_DIRECTORY), 0);
    require(directory >= 0, "open a guest proc directory");
    struct flock range = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 5, .l_len = 10};
    require(!fcntl(directory, F_SETLK, &range), "lock a guest proc directory");
    failed_exec(&host, private, cloexec);
    check_locks(directory, writing);
    require(!close(directory), "close the guest proc directory");
    host.fds[directory] = -1;
    contended_exec(&host, writing, private, cloexec);
    check_locks(reading, writing);

    char read_text[16], write_text[16], private_text[16], close_text[16], pid_text[16];
    snprintf(read_text, sizeof(read_text), "%d", reading);
    snprintf(write_text, sizeof(write_text), "%d", writing);
    snprintf(private_text, sizeof(private_text), "%d", private);
    snprintf(close_text, sizeof(close_text), "%d", cloexec);
    snprintf(pid_text, sizeof(pid_text), "%d", getpid());
    /* Cross tests explicitly re-enter their emulator; native tests exec this
     * binary directly. Both paths replace the same process while it owns locks. */
    char *emulator = getenv("LASHOS_TEST_EXEC_EMULATOR");
    char *arguments[] = {emulator,     argv[0],    "--after-exec", read_text, write_text,
                         private_text, close_text, pid_text,       NULL};
    alarm(0);
    attempt_exec(&host, emulator ? emulator : argv[0], arguments + (emulator ? 0 : 1));
    perror("successful exec");
    return 1;
}
