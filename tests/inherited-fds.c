#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    require(write(pair[1], "ab", 2) == 2, "provide inherited data");
    char first, second;
    require(read(descriptors[9], &first, 1) == 1 && first == 'a', "read inherited descriptor");
    require(read(descriptors[200], &second, 1) == 1 && second == 'b',
            "retain shared open-file state");
    close(private);
    close(pair[0]);
    close(pair[1]);
    close(9);
    close(200);
    puts("PASS: inherited descriptors, flags, and private-descriptor isolation");
    return 0;
}
