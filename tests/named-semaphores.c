#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../src/named_sem_host.h"

int main(void) {
    struct named_semaphores table = {0};
    char name[80];
    snprintf(name, sizeof(name), "/lashos-test-%ld", (long)getpid());
    int first = open_named_semaphore(&table, name, O_CREAT | O_EXCL, 0600, 2);
    assert(first > 0);
    int second = open_named_semaphore(&table, name, 0, 0, 0);
    assert(second == first);
    assert(open_named_semaphore(&table, name, O_CREAT | O_EXCL, 0600, 0) == -1);
    assert(errno == EEXIST);
    assert(!sem_unlink(name));
    assert(open_named_semaphore(&table, name, 0, 0, 0) == -1 && errno == ENOENT);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(!close_named_semaphore(&table, first));
        close_named_semaphores(&table);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    int value;
    assert(!sem_getvalue(table.objects[first - 1], &value) && value == 2);
    assert(!close_named_semaphore(&table, first));
    assert(!close_named_semaphore(&table, second));
    assert(close_named_semaphore(&table, first) == -1 && errno == EINVAL);
    assert(close_named_semaphore(&table, UINT64_MAX) == -1 && errno == EINVAL);
    for (int i = 0; i <= MAX_NAMED_SEMAPHORES; i++) {
        snprintf(name, sizeof(name), "/lashos-test-%ld-%d", (long)getpid(), i);
        int handle = open_named_semaphore(&table, name, O_CREAT | O_EXCL, 0600, 0);
        int error = errno;
        assert(!sem_unlink(name));
        if (i == MAX_NAMED_SEMAPHORES)
            assert(handle == -1 && error == EMFILE);
        else
            assert(handle > 0);
    }
    close_named_semaphores(&table);
    for (int i = 0; i < MAX_NAMED_SEMAPHORES; i++)
        assert(!table.references[i]);
    puts("named semaphore identity, lifetime, fork and bounds: passed");
}
