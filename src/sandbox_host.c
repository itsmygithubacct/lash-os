#define _GNU_SOURCE
#include <dirent.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/kvm.h>
#include <linux/landlock.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <zstd.h>
#include "sandbox_host.h"
#include "sandbox_protocol.h"

#define SB_MAX_ARCHIVE (512ULL << 20)
static const unsigned char bundle_magic[16] = "LASHOS-VM-v1";
static volatile sig_atomic_t interrupted, resized;

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
    if (geteuid() != 0)
        return getuid() == geteuid() && getgid() == getegid() ? 0 : -1;
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
static int private_directory(char *name, size_t size, int share) {
    const char *bases[] = {"/tmp", "/var/tmp"};
    for (unsigned i = 0; i < 2; i++) {
        int base = open(bases[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (base < 0)
            continue;
        int inside = contains_directory(share, base);
        close(base);
        if (inside)
            continue;
        snprintf(name, size, "%s/lash-os-XXXXXX", bases[i]);
        if (mkdtemp(name))
            return 0;
    }
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
                               .argc = argc + 1 + options->stats,
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
    size_t size = sizeof(config) + sizeof("linux-bash-os") + sizeof("--host");
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
static int restrict_qemu(int root, int share) {
    /* Require ABI 6: device ioctls, signals, and abstract sockets are covered. */
    struct landlock_ruleset_attr ruleset = {
        .handled_access_fs = (1ULL << 16) - 1,
        .scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
    };
    int rules = syscall(SYS_landlock_create_ruleset, &ruleset, sizeof(ruleset), 0);
    if (rules < 0)
        return -1;
    uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t write = LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SYM |
                     LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_REFER |
                     LANDLOCK_ACCESS_FS_TRUNCATE;
    int result = -1;
    if (landlock_rule(rules, root,
                      read | LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE) ||
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
        syscall(SYS_landlock_restrict_self, rules, 0))
        goto done;
    result = 0;
done:
    close(rules);
    return result;
}
static void launch_qemu(const char *directory, int root, int share, int channel,
                        const struct sandbox_options *options, pid_t parent) {
    /* Only the filesystem export and the console socket cross exec. */
    int kept_share = fcntl(share, F_DUPFD_CLOEXEC, 10);
    int kept_channel = fcntl(channel, F_DUPFD_CLOEXEC, 10);
    if (kept_share < 0 || kept_channel < 0)
        goto fail;
    if (dup2(kept_share, 3) < 0 || dup2(kept_channel, 4) < 0)
        goto fail;
    /* The original root fd might be 3 or 4, so reopen it after reserving them. */
    root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0)
        goto fail;
    int diagnostics = openat(root, "qemu.log", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (diagnostics < 0 || dup2(diagnostics, 2) < 0)
        goto fail;
    close(diagnostics);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || chdir(directory))
        goto fail;
    struct rlimit limit = {.rlim_cur = 0, .rlim_max = 0};
    if (setrlimit(RLIMIT_CORE, &limit))
        goto fail;
    limit.rlim_cur = limit.rlim_max = ((uint64_t)options->memory_mib * 3 + 2048) << 20;
    if (setrlimit(RLIMIT_AS, &limit) || restrict_qemu(root, 3))
        goto fail;
    if (syscall(SYS_close_range, 5U, ~0U, 0))
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
    QA("pc");
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
    QA("-bios");
    QA("firmware/bios-256k.bin");
    QA("-kernel");
    QA("kernel");
    QA("-initrd");
    QA("initramfs");
    QA("-append");
    QA("console=ttyS0 rdinit=/init quiet loglevel=0 panic=-1 net.ifnames=0");
    QA("-chardev");
    QA("file,id=boot,path=boot.log,append=on");
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
static void caught_signal(int signo) {
    if (signo == SIGWINCH)
        resized = 1;
    else
        interrupted = signo;
}
static int console_relay(int channel, int terminal) {
    struct sb_queue *rx = calloc(1, sizeof(*rx)), *tx = calloc(1, sizeof(*tx)),
                    *out = calloc(1, sizeof(*out)), *err = calloc(1, sizeof(*err));
    int result = 125, eof = 0, received_exit = 0, ready = 0, connected = 1;
    time_t started = time(NULL);
    if (!rx || !tx || !out || !err || sb_nonblock(channel))
        goto done;
    for (;;) {
        if (interrupted) {
            result = 128 + interrupted;
            break;
        }
        if (resized && terminal && sb_room(tx) >= 8 + sizeof(struct winsize)) {
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
        if (!ready && time(NULL) - started > 120) {
            fprintf(stderr, "lash-os: VM startup timed out\n");
            break;
        }
        struct pollfd fds[] = {
            {connected && !received_exit ? channel : -1,
             (sb_room(rx) >= SB_CHUNK ? POLLIN : 0) | (sb_size(tx) ? POLLOUT : 0), 0},
            {!eof && !received_exit && sb_room(tx) >= SB_CHUNK + 8 ? 0 : -1, POLLIN, 0},
            {sb_size(out) ? 1 : -1, POLLOUT, 0},
            {sb_size(err) ? 2 : -1, POLLOUT, 0},
        };
        if (poll(fds, 4, 100) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
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
            ssize_t n = read(0, buffer, sizeof(buffer));
            if (n > 0)
                sb_packet(tx, SB_INPUT, buffer, n);
            else if (!n || (n < 0 && errno != EINTR && errno != EAGAIN)) {
                sb_packet(tx, SB_EOF, NULL, 0);
                eof = 1;
            }
        }
        if (((fds[2].revents & (POLLOUT | POLLHUP | POLLERR)) && sb_flush(1, out)) ||
            ((fds[3].revents & (POLLOUT | POLLHUP | POLLERR)) && sb_flush(2, err))) {
            result = 141;
            break;
        }
    }
    goto done;
protocol_error:
    fprintf(stderr, "lash-os: invalid VM console message\n");
    result = 125;
done:
    free(rx);
    free(tx);
    free(out);
    free(err);
    return result;
}

int sandbox_run(int argc, char **argv, const struct sandbox_options *options) {
    int result = 125, root = -1, share = -1, channel[2] = {-1, -1}, kvm = -1;
    int flags[3] = {-1, -1, -1}, raw = 0, handlers = 0;
    pid_t child = -1;
    char directory[64] = {0};
    struct termios saved;
    struct sigaction old[5];
    const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGWINCH, SIGPIPE};
    const char *logs[] = {"boot.log", "qemu.log"};
    const char *step = "dropping host privileges";
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
    step = "opening the launch directory";
    share = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat here, slash;
    if (share < 0 || fstat(share, &here) || stat("/", &slash))
        goto fail;
    if (here.st_dev == slash.st_dev && here.st_ino == slash.st_ino) {
        fprintf(stderr, "lash-os: choose a working folder; sharing the host root is refused\n");
        goto done;
    }
    step = "creating private VM files";
    if (private_directory(directory, sizeof(directory), share))
        goto fail;
    root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0)
        goto fail;
    step = "extracting the bundled VM";
    if (extract_bundle(root))
        goto fail;
    /* Disable implicit module lookup; all required devices are built into QEMU. */
    if (mkdirat(root, "modules", 0700))
        goto fail;
    for (unsigned i = 0; i < 2; i++) {
        int log = openat(root, logs[i], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (log < 0)
            goto fail;
        close(log);
    }
    int terminal = isatty(0) && isatty(1) && isatty(2);
    step = "preparing VM arguments";
    if (configure_guest(root, argc, argv, options, terminal) ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, channel))
        goto fail;
    step = "installing terminal handlers";
    interrupted = resized = 0;
    for (unsigned i = 0; i < sizeof(signals) / sizeof(*signals); i++) {
        struct sigaction action = {.sa_handler = signals[i] == SIGPIPE ? SIG_IGN : caught_signal};
        sigemptyset(&action.sa_mask);
        if (sigaction(signals[i], &action, &old[i]))
            goto fail;
        handlers++;
    }
    if (terminal) {
        if (tcgetattr(0, &saved))
            goto fail;
        struct termios tty = saved;
        cfmakeraw(&tty);
        if (tcsetattr(0, TCSANOW, &tty))
            goto fail;
        raw = 1;
    }
    for (int i = 0; i < 3; i++) {
        flags[i] = fcntl(i, F_GETFL);
        if (flags[i] < 0)
            goto fail;
    }
    for (int i = 0; i < 3; i++) {
        if (sb_nonblock(i))
            goto fail;
    }
    step = "starting the VM";
    pid_t parent = getpid();
    child = fork();
    if (child < 0)
        goto fail;
    if (!child) {
        launch_qemu(directory, root, share, channel[1], options, parent);
    }
    close(channel[1]);
    channel[1] = -1;
    result = console_relay(channel[0], terminal);
    goto done;
fail:
    fprintf(stderr, "lash-os: %s: %s\n", step, strerror(errno));
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
    for (int i = 0; i < 3; i++)
        if (flags[i] >= 0)
            fcntl(i, F_SETFL, flags[i]);
    if (raw)
        tcsetattr(0, TCSANOW, &saved);
    for (int i = 0; i < handlers; i++)
        sigaction(signals[i], &old[i], NULL);
    for (int i = 0; i < 2; i++)
        if (channel[i] >= 0)
            close(channel[i]);
    if (root >= 0) {
        for (unsigned i = 0; result == 125 && i < 2; i++) {
            int log = openat(root, logs[i], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (log >= 0) {
                char buffer[4096];
                struct stat st;
                if (!fstat(log, &st) && st.st_size > (off_t)sizeof(buffer))
                    lseek(log, st.st_size - sizeof(buffer), SEEK_SET);
                ssize_t n = read(log, buffer, sizeof(buffer));
                if (n > 0)
                    sb_write_all(2, buffer, n);
                close(log);
            }
        }
        remove_contents(root);
        close(root);
        rmdir(directory);
    }
    if (share >= 0)
        close(share);
    if (kvm >= 0)
        close(kvm);
    return result;
}
