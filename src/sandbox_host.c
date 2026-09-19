#define _GNU_SOURCE
#include <dirent.h>
#include <grp.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/kvm.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <zstd.h>
#include "sandbox_host.h"
#include "sandbox_protocol.h"
#include "sandbox_platform.h"

#ifndef ST_NOEXEC
#define ST_NOEXEC 8
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

#define SB_MAX_ARCHIVE (512ULL << 20)
#define SB_LOG_TAIL 4096
static const unsigned char bundle_magic[16] = "LASHOS-VM-v1";
static volatile sig_atomic_t interrupted, resized, suspended, continued;

int sandbox_number(const char *text, unsigned minimum, unsigned maximum, unsigned *value) {
    if (!*text)
        return -1;
    unsigned long n = 0;
    for (const unsigned char *p = (const void *)text; *p; p++) {
        if (*p < '0' || *p > '9' || n > maximum / 10)
            return -1;
        n = n * 10 + *p - '0';
        if (n > maximum)
            return -1;
    }
    if (n < minimum)
        return -1;
    *value = n;
    return 0;
}
static int os_identity(FILE *file) {
    char line[512];
    int matched = 0, seen = 0;
    while (fgets(line, sizeof(line), file)) {
        if (!strchr(line, '\n') && !feof(file))
            return 0;
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "ID=", 3)) {
            if (seen++)
                return 0;
            matched = !strcmp(line + 3, "linux-bash-os") ||
                      !strcmp(line + 3, "\"linux-bash-os\"") ||
                      !strcmp(line + 3, "'linux-bash-os'");
        }
    }
    return !ferror(file) && matched;
}
int sandbox_installed_os(void) {
    const char *paths[] = {"/etc/os-release", "/usr/lib/os-release"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(*paths); i++) {
        int fd = open(paths[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
            continue;
        struct stat st;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 022) ||
            st.st_size > 16384) {
            close(fd);
            return 0;
        }
        FILE *file = fdopen(fd, "r");
        if (!file) {
            close(fd);
            return 0;
        }
        int result = os_identity(file);
        fclose(file);
        /* /etc overrides /usr/lib, including a different distribution ID. */
        return result;
    }
    return 0;
}
static int drop_sudo(void) {
    if (geteuid() != 0) {
        if (getuid() == geteuid() && getgid() == getegid())
            return 0;
        errno = EPERM;
        return -1;
    }
    const char *uid_text = getenv("SUDO_UID"), *gid_text = getenv("SUDO_GID");
    unsigned uid, gid;
    if (!uid_text || !gid_text || sandbox_number(uid_text, 1, UINT_MAX - 1, &uid) ||
        sandbox_number(gid_text, 1, UINT_MAX - 1, &gid)) {
        fprintf(stderr, "Sandbox mode must run as a regular user with /dev/kvm access.\n");
        errno = EPERM;
        return -1;
    }
    struct passwd *pw = getpwuid(uid);
    if (!pw || pw->pw_gid != gid) {
        errno = EPERM;
        return -1;
    }
    if (prctl(PR_SET_KEEPCAPS, 0) || initgroups(pw->pw_name, gid) || setresgid(gid, gid, gid) ||
        setresuid(uid, uid, uid))
        return -1;
    return 0;
}
static int pread_all(int fd, void *buffer, size_t size, off_t position) {
    unsigned char *p = buffer;
    while (size) {
        ssize_t n = pread(fd, p, size, position);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            errno = EINVAL;
            return -1;
        }
        p += n;
        position += n;
        size -= n;
    }
    return 0;
}
static int safe_name(const char *name) {
    if (!*name || *name == '/')
        return 0;
    for (const char *p = name; *p;) {
        size_t n = strcspn(p, "/");
        if (!n || (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.'))
            return 0;
        p += n;
        if (*p && !*++p)
            return 0;
    }
    return 1;
}
static int extract_file(int root, char *name, unsigned mode, const void *data, size_t size) {
    int directory = dup(root), result = -1;
    if (directory < 0)
        return -1;
    char *part = name, *slash;
    while ((slash = strchr(part, '/'))) {
        *slash = 0;
        if (mkdirat(directory, part, 0700) && errno != EEXIST)
            goto done;
        int next = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
            goto done;
        close(directory);
        directory = next;
        part = slash + 1;
    }
    int fd = openat(directory, part, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0)
        goto done;
    result = sb_write_all(fd, data, size);
    if (close(fd))
        result = -1;
done:
    close(directory);
    return result;
}
static int extract_bundle(int root) {
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC), result = -1;
    unsigned char footer[40], *compressed = NULL, *archive = NULL;
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size < 40 ||
        pread_all(fd, footer, sizeof(footer), st.st_size - sizeof(footer)))
        goto done;
    uint64_t offset, packed, size;
    memcpy(&offset, footer + 16, 8);
    memcpy(&packed, footer + 24, 8);
    memcpy(&size, footer + 32, 8);
    if (memcmp(footer, bundle_magic, 16) || !size || size > SB_MAX_ARCHIVE || !packed ||
        packed > SB_MAX_ARCHIVE || offset > (uint64_t)st.st_size - 40 ||
        packed != (uint64_t)st.st_size - 40 - offset) {
        fprintf(stderr,
                "No valid bundled VM. Use the executable produced by make or make portable.\n");
        errno = EINVAL;
        goto done;
    }
    compressed = malloc(packed);
    archive = malloc(size);
    if (!compressed || !archive || pread_all(fd, compressed, packed, offset))
        goto done;
    size_t unpacked = ZSTD_decompress(archive, size, compressed, packed);
    if (ZSTD_isError(unpacked) || unpacked != size) {
        errno = EINVAL;
        goto done;
    }
    size_t pos = 0;
    unsigned count = 0;
    while (size - pos >= 16) {
        if (interrupted) {
            errno = EINTR;
            goto done;
        }
        uint32_t namesize, mode;
        uint64_t bytes;
        memcpy(&namesize, archive + pos, 4);
        memcpy(&mode, archive + pos + 4, 4);
        memcpy(&bytes, archive + pos + 8, 8);
        pos += 16;
        if (!namesize && !mode && !bytes && pos == size) {
            result = 0;
            goto done;
        }
        if (!namesize || namesize > 1023 || namesize > size - pos ||
            bytes > size - pos - namesize || (mode != 0600 && mode != 0700) || ++count > 1024)
            break;
        char name[1024];
        memcpy(name, archive + pos, namesize);
        name[namesize] = 0;
        if (memchr(name, 0, namesize) || !safe_name(name))
            break;
        pos += namesize;
        if (extract_file(root, name, mode, archive + pos, bytes))
            goto done;
        pos += bytes;
    }
    errno = EINVAL;
done:
    free(archive);
    free(compressed);
    if (fd >= 0)
        close(fd);
    return result;
}
/* Traversal is fd-relative and never follows a symlink, including during cleanup. */
static void remove_contents(int root) {
    DIR *dir = fdopendir(dup(root));
    if (!dir)
        return;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        int sub = openat(root, entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sub >= 0) {
            remove_contents(sub);
            close(sub);
            unlinkat(root, entry->d_name, AT_REMOVEDIR);
        } else
            unlinkat(root, entry->d_name, 0);
    }
    closedir(dir);
}
static int contains_directory(int ancestor, int directory) {
    struct stat target, current, parent;
    if (fstat(ancestor, &target))
        return -1;
    int fd = dup(directory);
    if (fd < 0)
        return -1;
    int result = -1;
    for (;;) {
        if (fstat(fd, &current))
            break;
        if (current.st_dev == target.st_dev && current.st_ino == target.st_ino) {
            result = 1;
            break;
        }
        int up = openat(fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (up < 0)
            break;
        if (fstat(up, &parent)) {
            close(up);
            break;
        }
        close(fd);
        fd = up;
        if (current.st_dev == parent.st_dev && current.st_ino == parent.st_ino) {
            result = 0;
            break;
        }
    }
    close(fd);
    return result;
}
/* Component-wise prefix test for absolute paths. */
static int path_under(const char *path, const char *prefix) {
    size_t n = strlen(prefix);
    if (n == 1 && prefix[0] == '/')
        return path[0] == '/';
    return n && !strncmp(path, prefix, n) && (path[n] == 0 || path[n] == '/');
}
/* Decode mountinfo's \ooo escapes in place. Returns -1 for malformed or NUL escapes. */
static int mountinfo_unescape(char *text) {
    char *out = text;
    for (char *in = text; *in; in++) {
        if (*in != '\\') {
            *out++ = *in;
            continue;
        }
        int value = 0;
        for (int i = 1; i <= 3; i++) {
            if (in[i] < '0' || in[i] > '7')
                return -1;
            value = value * 8 + in[i] - '0';
        }
        if (!value || value > 255)
            return -1;
        *out++ = (char)value;
        in += 3;
    }
    *out = 0;
    return 0;
}
/* Joins a mount-relative remainder (empty or starting with /) to a base path. */
static int join_path(char *out, size_t size, const char *base, const char *rest) {
    int n = !strcmp(base, "/") ? snprintf(out, size, "%s", *rest ? rest : "/")
                               : snprintf(out, size, "%s%s", base, rest);
    return n < 0 || (size_t)n >= size ? -1 : 0;
}
struct sb_mount {
    unsigned long id;
    char device[32], *root, *point;
};
/*
 * Decides whether an object at namespace path target, on mount target_mount, can also be
 * reached through a namespace path below share. Bind mounts expose one filesystem location
 * at several paths, so compare filesystem-relative locations on the same device and map them
 * back through every mount of that device. Returns 1 reachable, 0 unreachable, -1 unknown.
 */
static int mount_reachable(FILE *mountinfo, const char *share, const char *target,
                           unsigned long target_mount) {
    struct sb_mount *mounts = NULL, *found = NULL;
    size_t count = 0, capacity = 0, line_capacity = 0;
    char *line = NULL, location[2 * PATH_MAX], candidate[2 * PATH_MAX];
    int result = -1;
    while (getline(&line, &line_capacity, mountinfo) > 0) {
        line[strcspn(line, "\n")] = 0;
        char *save = NULL, *id = strtok_r(line, " ", &save), *parent = strtok_r(NULL, " ", &save),
             *device = strtok_r(NULL, " ", &save), *root = strtok_r(NULL, " ", &save),
             *point = strtok_r(NULL, " ", &save), *end;
        if (!id || !parent || !device || !root || !point || strlen(device) >= 32)
            goto done;
        if (count == capacity) {
            capacity = capacity ? capacity * 2 : 64;
            struct sb_mount *grown = realloc(mounts, capacity * sizeof(*mounts));
            if (!grown)
                goto done;
            mounts = grown;
        }
        struct sb_mount *entry = &mounts[count];
        entry->id = strtoul(id, &end, 10);
        entry->root = strdup(root);
        entry->point = strdup(point);
        if (*end || !entry->root || !entry->point) {
            free(entry->root);
            free(entry->point);
            goto done;
        }
        count++;
        snprintf(entry->device, sizeof(entry->device), "%s", device);
        if (mountinfo_unescape(entry->root) || mountinfo_unescape(entry->point))
            goto done;
    }
    if (ferror(mountinfo))
        goto done;
    for (size_t i = 0; i < count; i++)
        if (mounts[i].id == target_mount)
            found = &mounts[i];
    if (!found || found->root[0] != '/' || !path_under(target, found->point))
        goto done;
    const char *rest = !strcmp(found->point, "/") ? target : target + strlen(found->point);
    if (join_path(location, sizeof(location), found->root, rest))
        goto done;
    result = 0;
    for (size_t i = 0; i < count && !result; i++) {
        struct sb_mount *mount = &mounts[i];
        if (strcmp(mount->device, found->device) || mount->root[0] != '/' ||
            !path_under(location, mount->root))
            continue;
        const char *below = !strcmp(mount->root, "/") ? location : location + strlen(mount->root);
        if (join_path(candidate, sizeof(candidate), mount->point, below))
            result = -1;
        else if (path_under(candidate, share))
            result = 1;
    }
done:
    for (size_t i = 0; i < count; i++) {
        free(mounts[i].root);
        free(mounts[i].point);
    }
    free(mounts);
    free(line);
    return result;
}
static int descriptor_location(int fd, char *path, size_t size, unsigned long *mount) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, size);
    if (n <= 0 || (size_t)n >= size || path[0] != '/')
        return -1;
    path[n] = 0;
    if (!mount)
        return 0;
    snprintf(link, sizeof(link), "/proc/self/fdinfo/%d", fd);
    FILE *info = fopen(link, "re");
    if (!info)
        return -1;
    char line[256];
    int result = -1;
    while (fgets(line, sizeof(line), info))
        if (sscanf(line, "mnt_id: %lu", mount) == 1) {
            result = 0;
            break;
        }
    fclose(info);
    return result;
}
/* Fails closed: anything that cannot be proven outside the share counts as reachable. */
static int reachable_from_share(int share, int directory) {
    if (contains_directory(share, directory) != 0)
        return 1;
    char share_path[PATH_MAX], path[PATH_MAX];
    unsigned long mount;
    if (descriptor_location(share, share_path, sizeof(share_path), NULL) ||
        descriptor_location(directory, path, sizeof(path), &mount))
        return 1;
    FILE *mountinfo = fopen("/proc/self/mountinfo", "re");
    if (!mountinfo)
        return 1;
    int result = mount_reachable(mountinfo, share_path, path, mount);
    fclose(mountinfo);
    return result != 0;
}
static int usable_runtime(int share, int directory) {
    struct statvfs fs;
    return !fstatvfs(directory, &fs) && !(fs.f_flag & ST_NOEXEC) &&
           !reachable_from_share(share, directory);
}
static int private_directory(char *name, size_t size, int share) {
    const char *bases[] = {"/tmp", "/var/tmp"};
    for (unsigned i = 0; i < 2; i++) {
        int base = open(bases[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (base < 0)
            continue;
        int usable = usable_runtime(share, base);
        close(base);
        if (!usable)
            continue;
        snprintf(name, size, "%s/lash-os-XXXXXX", bases[i]);
        if (!mkdtemp(name))
            continue;
        /* Check the directory itself too; a mount can appear below the base. */
        int created = open(name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        usable = created >= 0 && usable_runtime(share, created);
        if (created >= 0)
            close(created);
        if (usable)
            return 0;
        rmdir(name);
    }
    name[0] = 0;
    errno = EACCES;
    return -1;
}
static int cpio_entry(int fd, const char *name, const void *data, uint32_t size) {
    char header[111];
    unsigned namesize = strlen(name) + 1;
    snprintf(header, sizeof(header), "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
             1, !strcmp(name, "TRAILER!!!") ? 0 : S_IFREG | 0600, 0, 0, 1, 0, size, 0, 0, 0, 0,
             namesize, 0);
    const char zero[4] = {0};
    return sb_write_all(fd, header, 110) || sb_write_all(fd, name, namesize) ||
                   sb_write_all(fd, zero, -(110 + namesize) & 3) || sb_write_all(fd, data, size) ||
                   sb_write_all(fd, zero, -size & 3)
               ? -1
               : 0;
}
static int configure_guest(int root, int argc, char **argv, const struct sandbox_options *options,
                           int terminal) {
    struct sb_config config = {.magic = SB_CONFIG_MAGIC,
                               .argc = argc + 2 + options->stats,
                               .terminal = terminal,
                               .network = options->network,
                               .rows = 24,
                               .cols = 80};
    struct winsize window;
    if (!ioctl(0, TIOCGWINSZ, &window)) {
        config.rows = window.ws_row;
        config.cols = window.ws_col;
    }
    const char *term = getenv("TERM");
    snprintf(config.term, sizeof(config.term), "%s", term ? term : "xterm");
    size_t size = sizeof(config) + sizeof("linux-bash-os") + sizeof("--host") + sizeof("--");
    if (options->stats)
        size += sizeof("--stats");
    for (int i = 1; i < argc; i++)
        size += strlen(argv[i]) + 1;
    if (size > (1 << 20) || config.argc > 4096) {
        errno = E2BIG;
        return -1;
    }
    char *buffer = malloc(size), *p;
    if (!buffer)
        return -1;
    memcpy(buffer, &config, sizeof(config));
    p = buffer + sizeof(config);
#define SB_ARG(text)                                                                               \
    do {                                                                                           \
        size_t n = strlen(text) + 1;                                                               \
        memcpy(p, text, n);                                                                        \
        p += n;                                                                                    \
    } while (0)
    SB_ARG("linux-bash-os");
    SB_ARG("--host");
    if (options->stats)
        SB_ARG("--stats");
    /* The inner loader must forward Bash arguments without parsing them again. */
    SB_ARG("--");
    for (int i = 1; i < argc; i++)
        SB_ARG(argv[i]);
#undef SB_ARG
    int fd = openat(root, "initramfs", O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW), result = -1;
    if (fd >= 0) {
        result = cpio_entry(fd, "run/config", buffer, size) || cpio_entry(fd, "TRAILER!!!", NULL, 0)
                     ? -1
                     : 0;
        close(fd);
    }
    free(buffer);
    return result;
}
static int landlock_rule(int rules, int fd, uint64_t rights) {
    struct landlock_path_beneath_attr path = {.allowed_access = rights, .parent_fd = fd};
    return syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH, &path, 0);
}
static int allow_path(int rules, const char *name, uint64_t rights, int optional) {
    int fd = open(name, O_PATH | O_CLOEXEC);
    if (fd < 0)
        return optional && errno == ENOENT ? 0 : -1;
    struct stat st;
    int result = fstat(fd, &st);
    if (!result) {
        if (!S_ISDIR(st.st_mode))
            rights &= LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
                      LANDLOCK_ACCESS_FS_IOCTL_DEV;
        result = landlock_rule(rules, fd, rights);
    }
    close(fd);
    return result;
}
#if defined(__x86_64__)
#define SB_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SB_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#define SB_AUDIT_ARCH AUDIT_ARCH_RISCV64
#endif
#define SB_FILTER_MAX 24
#define SB_DENY(error) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ((error) & SECCOMP_RET_DATA))
/*
 * QEMU receives its console and serial sockets already connected, so it never needs to create
 * a UNIX socket; denying that prevents connecting to host D-Bus, agent or daemon sockets.
 * Offline VMs also cannot create IP sockets, and user networking gets only IPv4/IPv6.
 * io_uring is denied because its socket operations would bypass these checks.
 */
static size_t socket_filter(int network, struct sock_filter *program) {
    const struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SB_AUDIT_ARCH, 1, 0),
        SB_DENY(ENOSYS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        /* x32 system calls use a separate table. */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
        SB_DENY(ENOSYS),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
        SB_DENY(ENOSYS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 6, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        /* socket(2): the kernel truncates the family to int, so compare the low word. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 1, 0),
        SB_DENY(EAFNOSUPPORT),
        network ? (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
                : (struct sock_filter)SB_DENY(EAFNOSUPPORT),
        /* socketpair(2) cannot reach named sockets; keep only the UNIX family. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        SB_DENY(EAFNOSUPPORT),
    };
    _Static_assert(sizeof(instructions) / sizeof(*instructions) <= SB_FILTER_MAX,
                   "socket filter exceeds its buffer");
    memcpy(program, instructions, sizeof(instructions));
    return sizeof(instructions) / sizeof(*instructions);
}
static int install_socket_filter(int network) {
    struct sock_filter instructions[SB_FILTER_MAX];
    struct sock_fprog program = {.len = socket_filter(network, instructions),
                                 .filter = instructions};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
static int restrict_qemu(int root, int share, int network) {
    /* Require ABI 6: device ioctls, signals, and abstract sockets are covered. */
    struct landlock_ruleset_attr ruleset = {
        .handled_access_fs = (1ULL << 16) - 1,
        .handled_access_net =
            network ? 0 : LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
        .scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
    };
#ifdef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
    /* Newer kernels can also refuse pathname UNIX socket lookups; no rule grants them. */
    ruleset.handled_access_fs |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
#endif
    int rules = syscall(SYS_landlock_create_ruleset, &ruleset, sizeof(ruleset), 0);
#ifdef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
    if (rules < 0 && errno == EINVAL) {
        ruleset.handled_access_fs &= ~(uint64_t)LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
        rules = syscall(SYS_landlock_create_ruleset, &ruleset, sizeof(ruleset), 0);
    }
#endif
    if (rules < 0)
        return -1;
    uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t write = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SYM |
                     LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_REFER |
                     LANDLOCK_ACCESS_FS_TRUNCATE;
    int result = -1;
    if (landlock_rule(rules, root, read | LANDLOCK_ACCESS_FS_EXECUTE) ||
        landlock_rule(rules, share, read | write) ||
        allow_path(rules, "/dev/kvm",
                   LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                       LANDLOCK_ACCESS_FS_IOCTL_DEV,
                   0) ||
        allow_path(rules, "/dev/null", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
                   0) ||
        allow_path(rules, "/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE, 0) ||
        allow_path(rules, "/dev/random", LANDLOCK_ACCESS_FS_READ_FILE, 0) ||
        allow_path(rules, "/proc/self", read, 0) || allow_path(rules, "/proc/cpuinfo", read, 0) ||
        allow_path(rules, "/proc/meminfo", read, 0) ||
        allow_path(rules, "/sys/devices/system/cpu", read, 0) ||
        allow_path(rules, "/sys/devices/system/node", read, 1) ||
        allow_path(rules, "/etc/resolv.conf", read, 1) ||
        allow_path(rules, "/etc/hosts", read, 1) ||
        allow_path(rules, "/etc/nsswitch.conf", read, 1) ||
        allow_path(rules, "/etc/gai.conf", read, 1) ||
        allow_path(rules, "/etc/localtime", read, 1) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        syscall(SYS_landlock_restrict_self, rules, 0) || install_socket_filter(network))
        goto done;
    result = 0;
done:
    close(rules);
    return result;
}
static void launch_qemu(const char *directory, int share, int channel, int serial, int errors,
                        const struct sandbox_options *options, pid_t parent) {
    /* Only the filesystem export, console, serial log and diagnostics cross exec. */
    int kept_share = fcntl(share, F_DUPFD_CLOEXEC, 10);
    int kept_channel = fcntl(channel, F_DUPFD_CLOEXEC, 10);
    int kept_serial = fcntl(serial, F_DUPFD_CLOEXEC, 10);
    int kept_errors = fcntl(errors, F_DUPFD_CLOEXEC, 10);
    if (kept_share < 0 || kept_channel < 0 || kept_serial < 0 || kept_errors < 0)
        goto fail;
    if (dup2(kept_share, 3) < 0 || dup2(kept_channel, 4) < 0 || dup2(kept_serial, 5) < 0 ||
        dup2(kept_errors, 2) < 0)
        goto fail;
    /* The launcher's root fd might have been 2..5, so reopen it after reserving them. */
    int root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0)
        goto fail;
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || chdir(directory))
        goto fail;
    struct rlimit limit = {.rlim_cur = 0, .rlim_max = 0};
    if (setrlimit(RLIMIT_CORE, &limit))
        goto fail;
    limit.rlim_cur = limit.rlim_max = ((uint64_t)options->memory_mib * 3 + 2048) << 20;
    if (setrlimit(RLIMIT_AS, &limit) || restrict_qemu(root, 3, options->network))
        goto fail;
    if (syscall(SYS_close_range, 6U, ~0U, 0))
        goto fail;
    int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null < 0 || dup2(null, 0) < 0 || dup2(null, 1) < 0)
        goto fail;
    close(null);
    char memory[32], cpus[32], modules[PATH_MAX], home[PATH_MAX];
    snprintf(memory, sizeof(memory), "%u", options->memory_mib);
    snprintf(cpus, sizeof(cpus), "%u", options->cpus);
    snprintf(modules, sizeof(modules), "QEMU_MODULE_DIR=%s/modules", directory);
    snprintf(home, sizeof(home), "HOME=%s", directory);
    char *environment[] = {home, modules, "LC_ALL=C", "PATH=/nonexistent", NULL};
    char *arguments[96];
    unsigned n = 0;
#define QA(x) arguments[n++] = (char *)(x)
    QA("ld.so");
    QA("--inhibit-cache");
    QA("--library-path");
    QA("lib");
    QA("./qemu");
    QA("-accel");
    QA("kvm");
    QA("-machine");
    QA(SB_MACHINE);
    QA("-cpu");
    QA("host");
    QA("-m");
    QA(memory);
    QA("-smp");
    QA(cpus);
    QA("-nodefaults");
    QA("-no-user-config");
    QA("-display");
    QA("none");
    QA("-monitor");
    QA("none");
    QA("-no-reboot");
    QA("-L");
    QA("firmware");
#ifdef SB_BIOS
    QA("-bios");
    QA(SB_BIOS);
#endif
    QA("-kernel");
    QA("kernel");
    QA("-initrd");
    QA("initramfs");
    QA("-append");
    QA("console=" SB_CONSOLE " rdinit=/init quiet loglevel=0 panic=-1 net.ifnames=0");
    /* The launcher drains the serial console and keeps only a bounded tail in memory. */
    QA("-chardev");
    QA("socket,id=boot,fd=5");
    QA("-serial");
    QA("chardev:boot");
    QA("-chardev");
    QA("socket,id=io,fd=4");
    QA("-device");
    QA("virtio-serial-pci");
    QA("-device");
    QA("virtserialport,chardev=io,name=lash.io");
    QA("-fsdev");
    QA("local,id=work,path=/proc/self/fd/3,security_model=none,multidevs=remap");
    QA("-device");
    QA("virtio-9p-pci,fsdev=work,mount_tag=work");
    if (options->network) {
        QA("-netdev");
        QA("user,id=net,ipv6=off");
        QA("-device");
        QA("virtio-net-pci,netdev=net,romfile=");
    } else {
        QA("-nic");
        QA("none");
    }
    QA("-sandbox");
    QA("on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny");
    arguments[n] = NULL;
#undef QA
    execve("./ld.so", arguments, environment);
fail:
    dprintf(2, "lash-os: starting confined QEMU: %s\n", strerror(errno));
    _exit(125);
}

/* A bounded in-memory tail of QEMU diagnostics or guest serial output. */
struct sb_log {
    int fd;
    size_t length, next;
    char data[SB_LOG_TAIL];
};
static void log_keep(struct sb_log *log, const char *data, size_t size) {
    if (size >= SB_LOG_TAIL) {
        memcpy(log->data, data + size - SB_LOG_TAIL, SB_LOG_TAIL);
        log->length = SB_LOG_TAIL;
        log->next = 0;
        return;
    }
    while (size) {
        size_t n = SB_LOG_TAIL - log->next < size ? SB_LOG_TAIL - log->next : size;
        memcpy(log->data + log->next, data, n);
        log->next = (log->next + n) % SB_LOG_TAIL;
        log->length = log->length + n > SB_LOG_TAIL ? SB_LOG_TAIL : log->length + n;
        data += n;
        size -= n;
    }
}
/* Reads what is available without blocking; closes the log at end of file or error. */
static void log_drain(struct sb_log *log) {
    char buffer[SB_CHUNK];
    for (int i = 0; log->fd >= 0 && i < 64; i++) {
        ssize_t n = read(log->fd, buffer, sizeof(buffer));
        if (n > 0)
            log_keep(log, buffer, n);
        else if (n < 0 && errno == EINTR)
            continue;
        else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        else {
            close(log->fd);
            log->fd = -1;
        }
    }
}
static void log_print(const struct sb_log *log) {
    if (log->length < SB_LOG_TAIL)
        sb_write_all(2, log->data, log->length);
    else {
        sb_write_all(2, log->data + log->next, SB_LOG_TAIL - log->next);
        sb_write_all(2, log->data, log->next);
    }
}

/*
 * Standard streams share open file descriptions with the caller, so O_NONBLOCK is never set
 * on them. Pipes and terminals get a private nonblocking description, sockets use
 * MSG_DONTWAIT, and regular files never block. Anything else is used only after poll reports
 * readiness, with writes no larger than PIPE_BUF.
 */
enum { SB_STREAM_DIRECT, SB_STREAM_SOCKET, SB_STREAM_PRIVATE, SB_STREAM_GATED };
struct sb_stream {
    int fd, kind;
};
static void stream_open(struct sb_stream *stream, int fd, int writing) {
    struct stat st;
    stream->fd = fd;
    stream->kind = SB_STREAM_GATED;
    if (fstat(fd, &st))
        return;
    if (S_ISREG(st.st_mode) || S_ISBLK(st.st_mode) || S_ISDIR(st.st_mode)) {
        stream->kind = SB_STREAM_DIRECT;
        return;
    }
    if (S_ISSOCK(st.st_mode)) {
        stream->kind = SB_STREAM_SOCKET;
        return;
    }
    if (!S_ISFIFO(st.st_mode) && !isatty(fd))
        return;
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    int copy = open(path, (writing ? O_WRONLY : O_RDONLY) | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (copy < 0)
        return;
    struct stat reopened;
    if (!fstat(copy, &reopened) && reopened.st_dev == st.st_dev && reopened.st_ino == st.st_ino &&
        reopened.st_rdev == st.st_rdev) {
        stream->fd = copy;
        stream->kind = SB_STREAM_PRIVATE;
    } else
        close(copy);
}
static void stream_close(struct sb_stream *stream) {
    if (stream->kind == SB_STREAM_PRIVATE && stream->fd >= 0)
        close(stream->fd);
    stream->fd = -1;
}
static ssize_t stream_read(const struct sb_stream *stream, void *buffer, size_t size) {
    if (stream->kind == SB_STREAM_SOCKET)
        return recv(stream->fd, buffer, size, MSG_DONTWAIT);
    return read(stream->fd, buffer, size);
}
static int stream_flush(const struct sb_stream *stream, struct sb_queue *q) {
    size_t size = sb_size(q);
    if (!size)
        return 0;
    if (stream->kind == SB_STREAM_GATED && size > PIPE_BUF)
        size = PIPE_BUF;
    ssize_t n = stream->kind == SB_STREAM_SOCKET
                    ? send(stream->fd, q->data + q->start, size, MSG_DONTWAIT | MSG_NOSIGNAL)
                    : write(stream->fd, q->data + q->start, size);
    if (n > 0) {
        sb_consume(q, n);
        return 0;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    return -1;
}

struct sb_terminal {
    int active, raw;
    struct termios saved;
};
static int terminal_foreground(void) {
    /* A terminal that is not the controlling terminal cannot stop this process. */
    pid_t group = tcgetpgrp(0);
    return group < 0 || group == getpgrp();
}
static int terminal_raw(struct sb_terminal *terminal) {
    struct termios tty = terminal->saved;
    cfmakeraw(&tty);
    if (tcsetattr(0, TCSANOW, &tty))
        return -1;
    terminal->raw = 1;
    return 0;
}
static void terminal_restore(struct sb_terminal *terminal) {
    if (terminal->raw && !tcsetattr(0, TCSANOW, &terminal->saved))
        terminal->raw = 0;
}

static const int handled_signals[] = {SIGINT,  SIGTERM,  SIGHUP,  SIGQUIT, SIGUSR1,
                                      SIGUSR2, SIGALRM,  SIGXCPU, SIGXFSZ, SIGVTALRM,
                                      SIGPROF, SIGWINCH, SIGTSTP, SIGCONT, SIGPIPE};
#define SB_SIGNALS (sizeof(handled_signals) / sizeof(*handled_signals))
struct sb_handlers {
    unsigned count;
    struct sigaction old[SB_SIGNALS];
};
static void caught_signal(int signo) {
    if (signo == SIGWINCH)
        resized = 1;
    else if (signo == SIGTSTP)
        suspended = 1;
    else if (signo == SIGCONT)
        continued = 1;
    else if (!interrupted)
        interrupted = signo;
}
static int install_handlers(struct sb_handlers *handlers) {
    interrupted = resized = suspended = continued = 0;
    for (unsigned i = 0; i < SB_SIGNALS; i++) {
        /* EPIPE is reported by write; the relay maps it to status 141. */
        struct sigaction action = {.sa_handler =
                                       handled_signals[i] == SIGPIPE ? SIG_IGN : caught_signal};
        sigemptyset(&action.sa_mask);
        if (sigaction(handled_signals[i], &action, &handlers->old[i]))
            return -1;
        handlers->count++;
    }
    return 0;
}
static void restore_handlers(struct sb_handlers *handlers) {
    for (unsigned i = 0; i < handlers->count; i++)
        sigaction(handled_signals[i], &handlers->old[i], NULL);
    handlers->count = 0;
}
static double monotonic_seconds(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec + now.tv_nsec / 1e9;
}

static int console_relay(int channel, struct sb_terminal *terminal, const struct sb_stream *streams,
                         struct sb_log *logs, int *failed) {
    struct sb_queue *rx = calloc(1, sizeof(*rx)), *tx = calloc(1, sizeof(*tx)),
                    *out = calloc(1, sizeof(*out)), *err = calloc(1, sizeof(*err));
    int result = 125, eof = 0, received_exit = 0, ready = 0, connected = 1;
    double started = monotonic_seconds();
    if (!rx || !tx || !out || !err || sb_nonblock(channel))
        goto done;
    for (;;) {
        if (interrupted) {
            result = 128 + interrupted;
            break;
        }
        if (suspended) {
            /* Give the caller its terminal back while stopped. */
            suspended = 0;
            terminal_restore(terminal);
            raise(SIGSTOP);
            continued = 1;
        }
        if (continued) {
            continued = 0;
            if (terminal->active && terminal_foreground() && !terminal_raw(terminal))
                resized = 1;
        }
        if (resized && terminal->active && sb_room(tx) >= 8 + sizeof(struct winsize)) {
            struct winsize window;
            if (!ioctl(0, TIOCGWINSZ, &window))
                sb_packet(tx, SB_WINDOW, &window, sizeof(window));
            resized = 0;
        }
        uint32_t type, size;
        void *data;
        int frame;
        while ((frame = sb_peek(rx, &type, &size, &data)) > 0) {
            if ((type == SB_OUTPUT || type == SB_ERROR) && !received_exit) {
                struct sb_queue *to = type == SB_OUTPUT ? out : err;
                if (sb_room(to) < size)
                    break;
                sb_append(to, data, size);
            } else if (type == SB_READY && !size && !ready && !received_exit)
                ready = 1;
            else if (type == SB_EXIT && size == 4 && !received_exit) {
                uint32_t code;
                memcpy(&code, data, 4);
                if (code > 255)
                    goto protocol_error;
                received_exit = 1;
                result = code;
                tx->start = tx->end = 0;
            } else
                goto protocol_error;
            sb_consume(rx, 8 + size);
        }
        if (frame < 0)
            goto protocol_error;
        if (received_exit && !sb_size(out) && !sb_size(err))
            break;
        if (!connected && frame == 0 && !received_exit) {
            fprintf(stderr, "lash-os: VM disconnected without an exit status\n");
            break;
        }
        if (!ready && monotonic_seconds() - started > 120) {
            fprintf(stderr, "lash-os: VM startup timed out\n");
            break;
        }
        short channel_events = (sb_room(rx) >= SB_CHUNK ? POLLIN : 0) | (sb_size(tx) ? POLLOUT : 0);
        /* Hang-ups are reported even without requested events; skip idle entries. */
        struct pollfd fds[] = {
            {connected && !received_exit && channel_events ? channel : -1, channel_events, 0},
            {!eof && !received_exit && sb_room(tx) >= SB_CHUNK + 8 ? streams[0].fd : -1, POLLIN, 0},
            {sb_size(out) ? streams[1].fd : -1, POLLOUT, 0},
            {sb_size(err) ? streams[2].fd : -1, POLLOUT, 0},
            {logs[0].fd, POLLIN, 0},
            {logs[1].fd, POLLIN, 0},
        };
        if (poll(fds, 6, 100) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < 2; i++)
            if (fds[4 + i].revents)
                log_drain(&logs[i]);
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            int got = sb_receive(channel, rx);
            if (got <= 0) {
                connected = 0;
                tx->start = tx->end = 0;
            }
        }
        if (connected && (fds[0].revents & POLLOUT) && sb_flush(channel, tx))
            break;
        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            unsigned char buffer[SB_CHUNK];
            ssize_t n = stream_read(&streams[0], buffer, sizeof(buffer));
            if (n > 0)
                sb_packet(tx, SB_INPUT, buffer, n);
            else if (!n || (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                sb_packet(tx, SB_EOF, NULL, 0);
                eof = 1;
            }
        }
        if (((fds[2].revents & (POLLOUT | POLLHUP | POLLERR)) && stream_flush(&streams[1], out)) ||
            ((fds[3].revents & (POLLOUT | POLLHUP | POLLERR)) && stream_flush(&streams[2], err))) {
            result = 141;
            break;
        }
    }
    goto done;
protocol_error:
    fprintf(stderr, "lash-os: invalid VM console message\n");
    result = 125;
    received_exit = 0;
done:
    /* A guest exit status of 125 is ordinary; only launcher failures print diagnostics. */
    if (!received_exit && result == 125)
        *failed = 1;
    free(rx);
    free(tx);
    free(out);
    free(err);
    return result;
}

int sandbox_run(int argc, char **argv, const struct sandbox_options *options) {
    int result = 125, failed = 0, root = -1, share = -1, kvm = -1;
    int channel[2] = {-1, -1}, serial[2] = {-1, -1}, errors[2] = {-1, -1};
    struct sb_handlers handlers = {0};
    struct sb_terminal terminal = {0};
    struct sb_stream streams[3] = {
        {-1, SB_STREAM_DIRECT}, {-1, SB_STREAM_DIRECT}, {-1, SB_STREAM_DIRECT}};
    struct sb_log *logs = calloc(2, sizeof(*logs));
    pid_t child = -1;
    char directory[64] = {0};
    const char *step = "allocating launcher state";
    if (!logs)
        goto fail;
    logs[0].fd = logs[1].fd = -1;
    step = "dropping host privileges";
    if (drop_sudo())
        goto fail;
    struct __user_cap_header_struct cap_header = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct cap_data[2] = {{0}, {0}};
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
        syscall(SYS_capset, &cap_header, cap_data) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        goto fail;
    step = "checking KVM access (enable virtualization and grant this user /dev/kvm access)";
    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0 || ioctl(kvm, KVM_GET_API_VERSION, 0) != KVM_API_VERSION)
        goto fail;
    close(kvm);
    kvm = -1;
    step = "checking Landlock ABI 6 support (required for sandbox mode)";
    if (syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) < 6) {
        errno = ENOTSUP;
        goto fail;
    }
    /* Handle termination before creating private files, so they are always removed. */
    step = "installing signal handlers";
    if (install_handlers(&handlers))
        goto fail;
    step = "opening the launch directory";
    share = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat here, slash;
    if (share < 0 || fstat(share, &here) || stat("/", &slash))
        goto fail;
    if (here.st_dev == slash.st_dev && here.st_ino == slash.st_ino) {
        fprintf(stderr, "lash-os: choose a working folder; sharing the host root is refused\n");
        goto done;
    }
    step = "creating private VM files outside the launch folder (tried /tmp and /var/tmp)";
    if (interrupted || private_directory(directory, sizeof(directory), share))
        goto fail;
    root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0)
        goto fail;
    step = "extracting the bundled VM";
    if (interrupted || extract_bundle(root))
        goto fail;
    /* Disable implicit module lookup; all required devices are built into QEMU. */
    if (mkdirat(root, "modules", 0700))
        goto fail;
    terminal.active = isatty(0) && isatty(1) && isatty(2);
    step = "preparing VM arguments";
    if (interrupted || configure_guest(root, argc, argv, options, terminal.active) ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channel) ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, serial) || pipe2(errors, O_CLOEXEC) ||
        sb_nonblock(serial[0]) || sb_nonblock(errors[0]))
        goto fail;
    logs[0].fd = serial[0];
    logs[1].fd = errors[0];
    serial[0] = errors[0] = -1;
    step = "configuring the terminal";
    if (terminal.active) {
        if (tcgetattr(0, &terminal.saved))
            goto fail;
        /* A background launch becomes raw when continued in the foreground. */
        if (terminal_foreground() && terminal_raw(&terminal))
            goto fail;
    }
    for (int i = 0; i < 3; i++)
        stream_open(&streams[i], i, i != 0);
    step = "starting the VM";
    pid_t parent = getpid();
    if (interrupted)
        goto fail;
    child = fork();
    if (child < 0)
        goto fail;
    if (!child)
        launch_qemu(directory, share, channel[1], serial[1], errors[1], options, parent);
    close(serial[1]);
    close(errors[1]);
    close(channel[1]);
    channel[1] = serial[1] = errors[1] = -1;
    result = console_relay(channel[0], &terminal, streams, logs, &failed);
    goto done;
fail:
    if (interrupted)
        result = 128 + interrupted;
    else {
        failed = 1;
        fprintf(stderr, "lash-os: %s: %s\n", step, strerror(errno));
    }
done:
    if (child > 0) {
        /* QEMU exits after guest poweroff; terminate on errors and broken pipes too. */
        kill(child, SIGTERM);
        int status;
        for (int i = 0; i < 50; i++) {
            if (waitpid(child, &status, WNOHANG) == child) {
                child = -1;
                break;
            }
            struct timespec delay = {.tv_nsec = 20000000};
            nanosleep(&delay, NULL);
        }
        if (child > 0) {
            kill(child, SIGKILL);
            while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
            }
        }
    }
    terminal_restore(&terminal);
    restore_handlers(&handlers);
    for (int i = 0; i < 3; i++)
        stream_close(&streams[i]);
    for (int i = 0; i < 2; i++) {
        if (channel[i] >= 0)
            close(channel[i]);
        if (serial[i] >= 0)
            close(serial[i]);
        if (errors[i] >= 0)
            close(errors[i]);
    }
    if (logs) {
        for (int i = 0; i < 2; i++) {
            /* QEMU has exited and every writer is closed, so this reaches end of file. */
            for (int round = 0; logs[i].fd >= 0 && round < 16; round++)
                log_drain(&logs[i]);
            if (logs[i].fd >= 0)
                close(logs[i].fd);
            if (failed)
                log_print(&logs[i]);
        }
        free(logs);
    }
    if (root >= 0) {
        remove_contents(root);
        close(root);
    }
    if (directory[0])
        rmdir(directory);
    if (share >= 0)
        close(share);
    if (kvm >= 0)
        close(kvm);
    return result;
}
