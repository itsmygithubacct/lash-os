/* A failed exec must not drop POSIX record locks while restoring descriptors. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include "../src/exec_host.h"

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}
static int fdinfo_has_write_lock(int fd, const char *range) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    FILE *file = fopen(path, "r");
    if (!file)
        return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (!strncmp(line, "lock:", 5) && strstr(line, "POSIX") && strstr(line, "WRITE") &&
            strstr(line, range))
            found = 1;
    }
    fclose(file);
    return found;
}
int main(void) {
    char path[] = "/tmp/lashos-exec-lock-XXXXXX";
    int temporary = mkstemp(path);
    require(temporary >= 0, "create locked file");
    int held = fcntl(temporary, F_DUPFD_CLOEXEC, 200);
    require(held >= 200 && held != 3, "move the locked descriptor off the guest slot");
    require(!close(temporary), "close the original descriptor before locking");
    struct flock region = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};
    require(!fcntl(held, F_SETLK, &region), "take a whole-file write lock");
    require(fdinfo_has_write_lock(held, "EOF"), "fdinfo shows the write lock before exec");
    char range_path[] = "/tmp/lashos-exec-range-XXXXXX";
    int range_temporary = mkstemp(range_path);
    require(range_temporary >= 0, "create range-locked file");
    int range_held = fcntl(range_temporary, F_DUPFD_CLOEXEC, 200);
    require(range_held >= 200 && range_held != 4, "move the range descriptor off its guest slot");
    require(!close(range_temporary), "close the range file's original descriptor");
    struct flock range = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 5, .l_len = 10};
    require(!fcntl(range_held, F_SETLK, &range), "take a ten-byte write lock");
    require(fdinfo_has_write_lock(range_held, "5 14"), "fdinfo shows the inclusive range");

    struct bridge_host host = {0};
    for (int i = 0; i < MAX_FDS; i++)
        host.fds[i] = -1;
    host.fds[3] = held;
    host.fds[4] = range_held;
    char *base = arena;
    strcpy(base + 256, "/no/such/lashos-exec");
    strcpy(base + 512, "lashos-exec");
    uint64_t *arguments = (uint64_t *)(base + 1024);
    arguments[0] = (uintptr_t)(base + 512);
    arguments[1] = 0;
    uint64_t *environment = (uint64_t *)(base + 2048);
    environment[0] = 0;
    errno = 0;
    int rc = service_exec(&host, (uintptr_t)(base + 256), (uintptr_t)arguments,
                          (uintptr_t)environment);
    require(rc == -1 && errno == ENOENT, "missing program returns ENOENT");
    require(host.fds[3] == held && host.fds[4] == range_held, "guest slots still name both descriptors");
    require(fdinfo_has_write_lock(held, "EOF"), "fdinfo still shows the whole-file lock");
    require(fdinfo_has_write_lock(range_held, "5 14"), "fdinfo still shows the inclusive range");

    pid_t child = fork();
    require(child >= 0, "start lock contender");
    if (!child) {
        int probe = open(path, O_RDWR);
        int ranged = open(range_path, O_RDWR);
        if (probe < 0 || ranged < 0)
            _exit(2);
        struct flock attempt = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
        struct flock attempt_range = {
            .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 5, .l_len = 10};
        int whole = fcntl(probe, F_SETLK, &attempt);
        int whole_error = errno;
        int partial = fcntl(ranged, F_SETLK, &attempt_range);
        int partial_error = errno;
        if (!whole || !partial)
            _exit(0);
        if ((whole_error == EAGAIN || whole_error == EACCES) &&
            (partial_error == EAGAIN || partial_error == EACCES))
            _exit(1);
        _exit(2);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status), "contender exits");
    require(WEXITSTATUS(status) == 1, "contender cannot take the preserved locks");
    require(!close(held) && !close(range_held) && !unlink(path) && !unlink(range_path),
            "remove the locked files");
    puts("PASS: failed exec preserves POSIX record locks");
    return 0;
}
