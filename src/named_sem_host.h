#pragma once
#include <errno.h>
#include <limits.h>
#include <semaphore.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* Guest handles are table indices, never native pointers. Native mappings and
 * reference counts survive fork and are released when the loader exits. */
#define MAX_NAMED_SEMAPHORES 64
struct named_semaphores {
    sem_t *objects[MAX_NAMED_SEMAPHORES];
    unsigned references[MAX_NAMED_SEMAPHORES];
};
static int open_named_semaphore(struct named_semaphores *table, const char *name, int flags,
                                mode_t mode, unsigned value) {
    sem_t *object = sem_open(name, flags, mode, value);
    if (object == SEM_FAILED)
        return -1;
    int free_slot = -1;
    for (int i = 0; i < MAX_NAMED_SEMAPHORES; i++) {
        if (!table->references[i]) {
            if (free_slot < 0)
                free_slot = i;
        } else if (table->objects[i] == object) {
            if (table->references[i] == UINT_MAX) {
                sem_close(object);
                errno = EOVERFLOW;
                return -1;
            }
            table->references[i]++;
            return i + 1;
        }
    }
    if (free_slot < 0) {
        sem_close(object);
        errno = EMFILE;
        return -1;
    }
    table->objects[free_slot] = object;
    table->references[free_slot] = 1;
    return free_slot + 1;
}
static int close_named_semaphore(struct named_semaphores *table, uint64_t handle) {
    if (!handle || handle > MAX_NAMED_SEMAPHORES || !table->references[handle - 1]) {
        errno = EINVAL;
        return -1;
    }
    int rc = sem_close(table->objects[handle - 1]);
    if (!rc && !--table->references[handle - 1])
        table->objects[handle - 1] = NULL;
    return rc;
}
static void close_named_semaphores(struct named_semaphores *table) {
    for (int i = 0; i < MAX_NAMED_SEMAPHORES; i++)
        while (table->references[i])
            if (close_named_semaphore(table, i + 1))
                break;
}
