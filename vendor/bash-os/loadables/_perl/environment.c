/* SPDX-License-Identifier: MIT */
/* Perl's environment API, independent of Bash's exported libc replacements.
   The original snapshot stays owned by Bash's wrapper. Replacement vectors and
   values are reclaimed during the call, and the remainder on return to Bash. */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "engine.h"

extern char **environ;
typedef struct bp_allocation {
    void *data;
    struct bp_allocation *next;
} bp_allocation;
static bp_allocation *allocations;
static char **private_vector;

static void
bp_free_allocations(bp_allocation *list)
{
    while (list) {
        bp_allocation *next = list->next;
        free(list->data);
        free(list);
        list = next;
    }
}

static void
bp_retire(void *data, bp_allocation **retired)
{
    for (bp_allocation **p = &allocations; *p; p = &(*p)->next) {
        if ((*p)->data == data) {
            bp_allocation *node = *p;
            *p = node->next;
            node->next = *retired;
            *retired = node;
            return;
        }
    }
}

static void *
bp_alloc(size_t size)
{
    bp_allocation *node = malloc(sizeof(*node));
    void *data = malloc(size);
    if (!node || !data) {
        free(node);
        free(data);
        errno = ENOMEM;
        return NULL;
    }
    node->data = data;
    node->next = allocations;
    allocations = node;
    return data;
}

static int
bp_name(const char *name)
{
    if (!name || !*name || strchr(name, '=')) {
        errno = EINVAL;
        return 0;
    }
    return 1;
}

char *
bos_perl_env_getenv(const char *name)
{
    size_t n;
    if (!name || !*name || strchr(name, '='))
        return NULL;
    n = strlen(name);
    for (char **p = environ; p && *p; p++)
        if (!strncmp(*p, name, n) && (*p)[n] == '=')
            return *p + n + 1;
    return NULL;
}

static int
bp_store(const char *name, size_t n, char *value)
{
    size_t count = 0, used = 0;
    char **copy;
    bp_allocation *retired = NULL;
    while (environ && environ[count])
        count++;
    if (count > SIZE_MAX / sizeof(*copy) - 2) {
        errno = ENOMEM;
        return -1;
    }
    copy = malloc((count + 2) * sizeof(*copy));
    if (!copy)
        return -1;
    for (size_t i = 0; i < count; i++) {
        if (strncmp(environ[i], name, n) || environ[i][n] != '=')
            copy[used++] = environ[i];
        else if (environ[i] != value)
            bp_retire(environ[i], &retired);
    }
    if (value)
        copy[used++] = value;
    copy[used] = NULL;
    environ = copy;
    free(private_vector);
    private_vector = copy;
    /* name/value may point into the old environment until the copy is done. */
    bp_free_allocations(retired);
    return 0;
}

int
bos_perl_env_setenv(const char *name, const char *value, int overwrite)
{
    size_t n, size;
    char *entry;
    if (!bp_name(name))
        return -1;
    if (!overwrite && bos_perl_env_getenv(name))
        return 0;
    n = strlen(name);
    size = strlen(value);
    if (n > SIZE_MAX - size - 2) {
        errno = ENOMEM;
        return -1;
    }
    entry = bp_alloc(n + size + 2);
    if (!entry)
        return -1;
    memcpy(entry, name, n);
    entry[n] = '=';
    memcpy(entry + n + 1, value, size + 1);
    if (bp_store(name, n, entry) < 0) {
        bp_allocation *retired = NULL;
        bp_retire(entry, &retired);
        bp_free_allocations(retired);
        return -1;
    }
    return 0;
}

int
bos_perl_env_unsetenv(const char *name)
{
    return bp_name(name) ? bp_store(name, strlen(name), NULL) : -1;
}

int
bos_perl_env_putenv(char *entry)
{
    char *eq = strchr(entry, '=');
    if (!eq)
        return bos_perl_env_unsetenv(entry);
    if (eq == entry) {
        errno = EINVAL;
        return -1;
    }
    return bp_store(entry, (size_t)(eq - entry), entry);
}

int
bos_perl_env_clearenv(void)
{
    environ = NULL;
    bos_perl_env_cleanup();
    return 0;
}

void
bos_perl_env_cleanup(void)
{
    bp_free_allocations(allocations);
    allocations = NULL;
    free(private_vector);
    private_vector = NULL;
}
