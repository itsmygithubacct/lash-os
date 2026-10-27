/* SPDX-License-Identifier: MIT */
/* Python's environment calls, kept away from Bash's exported replacements.
   Bash defines getenv, setenv, unsetenv and putenv over shell variables; the
   Python archives are rewritten to call these, which use environ like libc.
   They run only in the child created for one invocation, which never returns
   to Bash, so replaced vectors and strings are not reclaimed. */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "engine.h"

extern char **environ;

static int
bos_env_name(const char *name)
{
    if (!name || !*name || strchr(name, '=')) {
        errno = EINVAL;
        return 0;
    }
    return 1;
}

char *
bos_python_env_getenv(const char *name)
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
bos_env_store(const char *name, size_t n, char *entry)
{
    size_t count = 0, used = 0;
    char **copy;
    while (environ && environ[count])
        count++;
    if (count > SIZE_MAX / sizeof(*copy) - 2) {
        errno = ENOMEM;
        return -1;
    }
    copy = malloc((count + 2) * sizeof(*copy));
    if (!copy)
        return -1;
    for (size_t i = 0; i < count; i++)
        if (strncmp(environ[i], name, n) || environ[i][n] != '=')
            copy[used++] = environ[i];
    if (entry)
        copy[used++] = entry;
    copy[used] = NULL;
    environ = copy;
    return 0;
}

int
bos_python_env_setenv(const char *name, const char *value, int overwrite)
{
    size_t n, size;
    char *entry;
    if (!bos_env_name(name))
        return -1;
    if (!overwrite && bos_python_env_getenv(name))
        return 0;
    n = strlen(name);
    size = strlen(value);
    if (n > SIZE_MAX - size - 2) {
        errno = ENOMEM;
        return -1;
    }
    entry = malloc(n + size + 2);
    if (!entry)
        return -1;
    memcpy(entry, name, n);
    entry[n] = '=';
    memcpy(entry + n + 1, value, size + 1);
    return bos_env_store(name, n, entry);
}

int
bos_python_env_unsetenv(const char *name)
{
    return bos_env_name(name) ? bos_env_store(name, strlen(name), NULL) : -1;
}

int
bos_python_env_putenv(char *entry)
{
    char *eq = strchr(entry, '=');
    if (!eq)
        return bos_python_env_unsetenv(entry);
    if (eq == entry) {
        errno = EINVAL;
        return -1;
    }
    return bos_env_store(entry, (size_t)(eq - entry), entry);
}

int
bos_python_env_clearenv(void)
{
    environ = NULL;
    return 0;
}
