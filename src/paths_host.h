/* Direct descriptor paths refer to Bash's logical descriptor table. */
#pragma once
#define BRIDGE_PATH_SIZE (PATH_MAX + 32)

static char *path_string_mode(struct bridge_host *h, uint64_t address,
                              char translated[BRIDGE_PATH_SIZE], int follow_streams) {
    char *path = string(h, address);
    if (!path)
        return NULL;
    const char *number = NULL, *suffix = "";
    int logical = -1;
    if (!strncmp(path, "/dev/fd/", 8))
        number = path + 8;
    else if (!strncmp(path, "/proc/self/fd/", 14))
        number = path + 14;
    else if (!strncmp(path, "/proc/thread-self/fd/", 21))
        number = path + 21;
    else {
        const char *aliases[] = {"/dev/stdin", "/dev/stdout", "/dev/stderr"};
        for (int i = 0; i < 3; ++i) {
            size_t length = strlen(aliases[i]);
            if (!strncmp(path, aliases[i], length) &&
                (path[length] == '\0' || path[length] == '/')) {
                if (!follow_streams && path[length] == '\0')
                    return path;
                logical = i;
                suffix = path + length;
                break;
            }
        }
    }
    if (number) {
        if (*number < '0' || *number > '9')
            return path;
        if (*number == '0' && number[1] >= '0' && number[1] <= '9') {
            errno = ENOENT;
            return NULL;
        }
        logical = 0;
        do {
            logical = logical * 10 + *number++ - '0';
            if (logical >= MAX_FDS) {
                errno = ENOENT;
                return NULL;
            }
        } while (*number >= '0' && *number <= '9');
        if (*number && *number != '/')
            return path;
        suffix = number;
    }
    if (logical < 0)
        return path;
    int actual = fd(h, logical);
    if (actual < 0) {
        errno = ENOENT;
        return NULL;
    }
    int length = snprintf(translated, BRIDGE_PATH_SIZE, "/proc/self/fd/%d%s", actual, suffix);
    if (length < 0 || length >= BRIDGE_PATH_SIZE) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    return translated;
}

static char *path_string(struct bridge_host *h, uint64_t address,
                         char translated[BRIDGE_PATH_SIZE]) {
    return path_string_mode(h, address, translated, 1);
}

static char *path_string_nofollow(struct bridge_host *h, uint64_t address,
                                  char translated[BRIDGE_PATH_SIZE]) {
    return path_string_mode(h, address, translated, 0);
}
