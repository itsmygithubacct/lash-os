/* Remove a required host facility in this child only, then check fail-closed startup. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3 || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return 99;
    if (!strcmp(argv[1], "deny-kvm")) {
        struct landlock_ruleset_attr rule = {.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE};
        int fd = syscall(SYS_landlock_create_ruleset, &rule, sizeof(rule), 0);
        if (fd < 0 || syscall(SYS_landlock_restrict_self, fd, 0))
            return 99;
        close(fd);
    } else if (!strcmp(argv[1], "deny-landlock")) {
        struct sock_filter instructions[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_landlock_create_ruleset, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog program = {.len = sizeof(instructions) / sizeof(*instructions),
                                     .filter = instructions};
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program))
            return 99;
    } else
        return 99;
    execv(argv[2], argv + 2);
    perror("exec test binary");
    return 99;
}
