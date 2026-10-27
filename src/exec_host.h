#include <linux/close_range.h>
#include <sys/syscall.h>

/* Preserve the loader's descriptor namespace if Linux rejects execve. */
static char **exec_strings(struct bridge_host *h, uint64_t pointer) {
    char **result = calloc(4097, sizeof(char *));
    if (!result)
        return NULL;
    for (unsigned i = 0; i < 4096; i++) {
        uint64_t *item = memory(h, pointer + i * sizeof(uint64_t), sizeof(uint64_t));
        if (!item) {
            free(result);
            return NULL;
        }
        if (!*item)
            return result;
        size_t left = available(h, *item);
        if (left > 131072)
            left = 131072;
        result[i] = left ? memory(h, *item, left) : NULL;
        if (result[i] && !memchr(result[i], 0, left)) {
            errno = E2BIG;
            result[i] = NULL;
        }
        if (!result[i]) {
            free(result);
            return NULL;
        }
    }
    free(result);
    errno = E2BIG;
    return NULL;
}
/* Guest descriptors already occupy their native slots. Mark the private
 * range close-on-exec without opening or closing any file. Even opening and
 * closing /proc/self/fd to enumerate it could drop a guest lock on that inode.
 * Private handles stay usable after failure and never escape a successful exec. */
static int service_exec(struct bridge_host *h, uint64_t path_address, uint64_t arguments_address,
                        uint64_t environment_address) {
    char *path = string(h, path_address);
    char **arguments = NULL, **environment = NULL;
    int error;
    if (!path || !(arguments = exec_strings(h, arguments_address)) ||
        !(environment = exec_strings(h, environment_address)))
        goto cleanup;
    for (int i = 0; i < MAX_FDS; i++) {
        if (h->fds[i] >= 0 && h->fds[i] != i) {
            errno = EIO;
            goto cleanup;
        }
    }
    if (syscall(SYS_close_range, (unsigned)MAX_FDS, ~0U, CLOSE_RANGE_CLOEXEC))
        goto cleanup;
    execve(path, arguments, environment);
cleanup:
    error = errno ? errno : EIO;
    free(arguments);
    free(environment);
    errno = error;
    return -1;
}
