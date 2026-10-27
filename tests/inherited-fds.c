#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_FDS 256
#include "../src/fds_host.h"

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void) {
    int pair[2], descriptors[MAX_FDS];
    require(!pipe(pair), "create inherited input");
    require(dup2(pair[0], 9) == 9 && dup2(pair[0], 200) == 200,
            "install low and high inherited descriptors");
    require(!fcntl(200, F_SETFD, FD_CLOEXEC), "set descriptor flag");
    close(STDIN_FILENO);
    require(!inherit_descriptors(descriptors), "capture descriptors");
    require(descriptors[0] == -1, "closed stdin remains logically closed");
    require(descriptors[9] == 9 && descriptors[200] == 200, "adopt inherited descriptors");
    require(fcntl(descriptors[200], F_GETFD) == FD_CLOEXEC, "preserve descriptor flags");
    int private = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(private == 0 && descriptors[private] == -1, "do not adopt later private descriptors");
    close(private);
    struct descriptor_reservation reserved;
    require(!reserve_descriptor_slots(&reserved), "reserve vacant guest descriptor slots");
    private = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(private >= MAX_FDS, "allocate loader descriptors outside the guest range");
    release_descriptor_slots(&reserved);
    require(fcntl(0, F_GETFD) == -1 && errno == EBADF, "release the stdin placeholder");
    require(fcntl(200, F_GETFD) == FD_CLOEXEC, "reservation preserves inherited descriptors");
    int guest = adopt_descriptor(descriptors, open("/dev/null", O_RDONLY), 0);
    require(guest == 0 && descriptors[guest] == guest, "guest open keeps its native number");
    int copy = adopt_descriptor(descriptors, fcntl(guest, F_DUPFD_CLOEXEC, 100), 100);
    require(copy == 100 && descriptors[copy] == copy, "duplication honors its minimum slot");
    require(fcntl(copy, F_GETFD) == FD_CLOEXEC, "duplication preserves close-on-exec");
    require(!reserve_descriptor_slots(&reserved), "reserve slots for a fork reload");
    int reloaded = open("/dev/null", O_RDONLY | O_CLOEXEC);
    require(reloaded >= MAX_FDS, "fork reload also keeps loader descriptors private");
    release_descriptor_slots(&reserved);
    require(fcntl(guest, F_GETFD) == 0 && fcntl(copy, F_GETFD) == FD_CLOEXEC,
            "fork reservation preserves guest flags");
    pid_t child = fork();
    require(child >= 0, "start reservation failure test");
    if (!child) {
        int original[MAX_FDS];
        for (int i = 0; i < MAX_FDS; i++)
            original[i] = fcntl(i, F_GETFD);
        struct rlimit limit;
        require(!getrlimit(RLIMIT_NOFILE, &limit), "read descriptor limit");
        limit.rlim_cur = 512;
        require(!setrlimit(RLIMIT_NOFILE, &limit), "set initial loader descriptor budget");
        require(!reserve_descriptor_slots(&reserved), "reserve slots with a limited loader budget");
        struct rlimit expanded;
        require(!getrlimit(RLIMIT_NOFILE, &expanded) && expanded.rlim_cur == 512 + MAX_FDS,
                "reservation adds temporary loader headroom");
        require(!release_descriptor_slots(&reserved), "release loader descriptor headroom");
        require(!getrlimit(RLIMIT_NOFILE, &expanded) && expanded.rlim_cur == 512,
                "reservation restores the caller's descriptor limit");
        limit.rlim_cur = limit.rlim_max = 64;
        require(!setrlimit(RLIMIT_NOFILE, &limit), "limit placeholder allocation");
        require(reserve_descriptor_slots(&reserved) == -1 && (errno == EMFILE || errno == EINVAL),
                "reservation reports allocation failure");
        for (int i = 0; i < MAX_FDS; i++)
            require(fcntl(i, F_GETFD) == original[i], "failed reservation restores every slot");
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "reservation failure test exits");
    require(write(pair[1], "ab", 2) == 2, "provide inherited data");
    char first, second;
    require(read(descriptors[9], &first, 1) == 1 && first == 'a', "read inherited descriptor");
    require(read(descriptors[200], &second, 1) == 1 && second == 'b',
            "retain shared open-file state");
    close(private);
    close(reloaded);
    close(guest);
    close(copy);
    close(pair[0]);
    close(pair[1]);
    close(9);
    close(200);
    puts("PASS: inherited descriptors, flags, and private-descriptor isolation");
    return 0;
}
