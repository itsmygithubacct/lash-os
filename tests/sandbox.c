#define _GNU_SOURCE
#include <assert.h>
#include "../src/sandbox_host.c"

static int identity(const char *text) {
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    assert(f);
    int result = os_identity(f);
    fclose(f);
    return result;
}
static void guest_arguments(void) {
    for (int stats = 0; stats <= 1; stats++) {
        char directory[] = "/tmp/lashos-config-test-XXXXXX";
        assert(mkdtemp(directory));
        int root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        assert(root >= 0);
        int fd = openat(root, "initramfs", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        assert(fd >= 0);
        struct sandbox_options options = {.stats = stats, .network = 0};
        char *arguments[] = {"launcher", "--version", "script with spaces", ""};
        assert(!configure_guest(root, 4, arguments, &options, 0));
        /* Read the first newc entry as the guest would: a config followed by
         * NUL-terminated argv strings, including the final empty argument. */
        off_t offset = (110 + sizeof("run/config") + 3) & ~(off_t)3;
        struct sb_config config;
        assert(!pread_all(fd, &config, sizeof(config), offset));
        assert(config.magic == SB_CONFIG_MAGIC && config.argc == (unsigned)(6 + stats));
        assert(!config.terminal && !config.network);
        const char plain[] = "linux-bash-os\0--host\0--\0--version\0script with spaces\0";
        const char with_stats[] =
            "linux-bash-os\0--host\0--stats\0--\0--version\0script with spaces\0";
        char actual[sizeof(with_stats)];
        size_t size = stats ? sizeof(with_stats) : sizeof(plain);
        assert(!pread_all(fd, actual, size, offset + sizeof(config)));
        assert(!memcmp(actual, stats ? with_stats : plain, size));
        close(fd);
        assert(!unlinkat(root, "initramfs", 0));
        close(root);
        assert(!rmdir(directory));
    }
}
static int reachable(const char *mountinfo, const char *share, const char *target,
                     unsigned long mount) {
    FILE *f = fmemopen((void *)mountinfo, strlen(mountinfo), "r");
    assert(f);
    int result = mount_reachable(f, share, target, mount);
    fclose(f);
    return result;
}
static void mounts(void) {
    char text[] = "a\\040b\\134c\\011d";
    assert(!mountinfo_unescape(text) && !strcmp(text, "a b\\c\td"));
    char short_escape[] = "a\\09", nul_escape[] = "a\\000";
    assert(mountinfo_unescape(short_escape) && mountinfo_unescape(nul_escape));
    assert(path_under("/home/u/x", "/home/u") && path_under("/home/u", "/home/u"));
    assert(!path_under("/home/user", "/home/u") && path_under("/x", "/"));
    /* /tmp is a bind mount of a directory inside the shared home. */
    const char *bind = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                       "30 22 8:1 /home/u/tmp /tmp rw,nosuid - ext4 /dev/sda1 rw\n"
                       "31 22 0:40 / /run rw - tmpfs tmpfs rw\n";
    assert(reachable(bind, "/home/u", "/tmp/lash-os-1", 30) == 1);
    assert(reachable(bind, "/home/other", "/tmp/lash-os-1", 30) == 0);
    assert(reachable(bind, "/home/u", "/run/lash-os-1", 31) == 0);
    assert(reachable(bind, "/run", "/run/lash-os-1", 31) == 1);
    assert(reachable(bind, "/home/u", "/tmp/lash-os-1", 99) == -1);
    /* A second filesystem is mounted inside the share and also provides /tmp. */
    const char *nested = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                         "40 22 0:50 / /home/u/data rw - xfs /dev/sdb1 rw\n"
                         "41 22 0:50 /scratch /tmp rw - xfs /dev/sdb1 rw\n";
    assert(reachable(nested, "/home/u", "/tmp/lash-os-1", 41) == 1);
    assert(reachable(nested, "/home/u/elsewhere", "/tmp/lash-os-1", 41) == 0);
    const char *escaped = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                          "50 22 8:1 /srv/my\\040share/t /tmp rw - ext4 /dev/sda1 rw\n";
    assert(reachable(escaped, "/srv/my share", "/tmp/lash-os-1", 50) == 1);
    assert(reachable("garbage\n", "/home/u", "/tmp/x", 1) == -1);

    char base[] = "/tmp/lashos-reach-XXXXXX", share[64], inner[64], other[64];
    assert(mkdtemp(base));
    snprintf(share, sizeof(share), "%s/share", base);
    snprintf(inner, sizeof(inner), "%s/share/inner", base);
    snprintf(other, sizeof(other), "%s/other", base);
    assert(!mkdir(share, 0700) && !mkdir(inner, 0700) && !mkdir(other, 0700));
    int share_fd = open(share, O_RDONLY | O_DIRECTORY | O_CLOEXEC),
        inner_fd = open(inner, O_RDONLY | O_DIRECTORY | O_CLOEXEC),
        other_fd = open(other, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    assert(share_fd >= 0 && inner_fd >= 0 && other_fd >= 0);
    assert(reachable_from_share(share_fd, inner_fd) == 1);
    assert(reachable_from_share(share_fd, other_fd) == 0);
    close(share_fd);
    close(inner_fd);
    close(other_fd);
    assert(!rmdir(inner) && !rmdir(share) && !rmdir(other) && !rmdir(base));
}
static void log_tail(void) {
    struct sb_log *log = calloc(1, sizeof(*log));
    assert(log);
    log_keep(log, "abc", 3);
    assert(log->length == 3 && !memcmp(log->data, "abc", 3));
    char big[SB_LOG_TAIL + 10];
    for (size_t i = 0; i < sizeof(big); i++)
        big[i] = 'a' + i % 26;
    log_keep(log, big, sizeof(big));
    assert(log->length == SB_LOG_TAIL && log->next == 0 &&
           !memcmp(log->data, big + 10, SB_LOG_TAIL));
    log_keep(log, "XYZ", 3);
    assert(log->next == 3 && !memcmp(log->data, "XYZ", 3));
    int p[2];
    assert(!pipe(p) && !sb_nonblock(p[0]));
    log->fd = p[0];
    assert(write(p[1], "tail\n", 5) == 5);
    log_drain(log);
    assert(log->fd == p[0] && log->next == 8 && !memcmp(log->data + 3, "tail\n", 5));
    close(p[1]);
    log_drain(log);
    assert(log->fd == -1);
    free(log);
}
static void socket_policy(void) {
    for (int network = 0; network <= 1; network++) {
        pid_t pid = fork();
        assert(pid >= 0);
        if (!pid) {
            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || install_socket_filter(network))
                _exit(10);
            if (socket(AF_UNIX, SOCK_STREAM, 0) != -1 || errno != EAFNOSUPPORT)
                _exit(11);
            /* The family argument is an int; high bits must not bypass the filter. */
            if (syscall(SYS_socket, (long)((1ULL << 32) | AF_UNIX), SOCK_STREAM, 0) != -1 ||
                errno != EAFNOSUPPORT)
                _exit(12);
            if (socket(AF_NETLINK, SOCK_RAW, 0) != -1 || errno != EAFNOSUPPORT)
                _exit(13);
            int pair[2];
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair))
                _exit(14);
            int inet = socket(AF_INET, SOCK_DGRAM, 0);
            if (network ? inet < 0 : inet != -1 || errno != EAFNOSUPPORT)
                _exit(15);
            if (syscall(__NR_io_uring_setup, 1, NULL) != -1 || errno != ENOSYS)
                _exit(16);
            _exit(0);
        }
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        if (!WIFEXITED(status) || WEXITSTATUS(status))
            fprintf(stderr, "socket policy network=%d status=%#x\n", network, status);
        assert(WIFEXITED(status) && !WEXITSTATUS(status));
    }
}
static void private_streams(void) {
    struct sb_queue *q = calloc(1, sizeof(*q));
    int p[2];
    assert(q && !pipe(p));
    int flags = fcntl(p[0], F_GETFL);
    struct sb_stream in, out;
    stream_open(&in, p[0], 0);
    stream_open(&out, p[1], 1);
    assert(in.kind == SB_STREAM_PRIVATE && in.fd != p[0] && (fcntl(in.fd, F_GETFL) & O_NONBLOCK));
    assert(out.kind == SB_STREAM_PRIVATE && out.fd != p[1]);
    assert(fcntl(p[0], F_GETFL) == flags && !(fcntl(p[1], F_GETFL) & O_NONBLOCK));
    char c;
    assert(stream_read(&in, &c, 1) == -1 && errno == EAGAIN);
    assert(!sb_append(q, "x", 1) && !stream_flush(&out, q) && !sb_size(q));
    assert(stream_read(&in, &c, 1) == 1 && c == 'x');
    stream_close(&in);
    stream_close(&out);
    close(p[0]);
    close(p[1]);
    int pair[2];
    assert(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair));
    stream_open(&in, pair[0], 0);
    assert(in.kind == SB_STREAM_SOCKET && in.fd == pair[0]);
    assert(stream_read(&in, &c, 1) == -1 && errno == EAGAIN);
    assert(!(fcntl(pair[0], F_GETFL) & O_NONBLOCK));
    stream_close(&in);
    close(pair[0]);
    close(pair[1]);
    FILE *file = tmpfile();
    assert(file);
    stream_open(&in, fileno(file), 0);
    assert(in.kind == SB_STREAM_DIRECT && in.fd == fileno(file));
    fclose(file);
    int null = open("/dev/null", O_RDWR | O_CLOEXEC);
    assert(null >= 0);
    stream_open(&in, null, 0);
    assert(in.kind == SB_STREAM_GATED && in.fd == null);
    close(null);
    free(q);
}
int main(void) {
    guest_arguments();
    mounts();
    log_tail();
    socket_policy();
    private_streams();
    assert(identity("NAME=other\nID=linux-bash-os\n"));
    assert(identity("ID=\"linux-bash-os\"\n"));
    assert(identity("ID='linux-bash-os'"));
    assert(!identity("ID=debian\nID_LIKE=linux-bash-os\n"));
    assert(!identity("ID=linux-bash-os-more\n"));
    assert(!identity("ID=linux-bash-os\nID=debian\n"));
    assert(!identity("# ID=linux-bash-os\n"));
    unsigned value;
    assert(!sandbox_number("4096", 1024, 65536, &value) && value == 4096);
    assert(sandbox_number("0", 1024, 65536, &value));
    assert(sandbox_number("65537", 1024, 65536, &value));
    assert(sandbox_number("999999999999999999999", 1024, 65536, &value));
    assert(sandbox_number("-1", 1, 64, &value));
    assert(sandbox_number("2x", 1, 64, &value));
    assert(safe_name("firmware/bios-256k.bin"));
    assert(!safe_name("/kernel"));
    assert(!safe_name("../kernel"));
    assert(!safe_name("lib/../kernel"));
    assert(!safe_name("lib//kernel"));
    assert(!safe_name("lib/"));
    assert(!safe_name("lib/./kernel"));
    struct sb_queue *q = calloc(1, sizeof(*q));
    assert(q);
    uint32_t type, size;
    void *data;
    uint32_t header[] = {SB_INPUT, 4};
    assert(!sb_append(q, header, 3));
    assert(sb_peek(q, &type, &size, &data) == 0);
    assert(!sb_append(q, (char *)header + 3, 5));
    assert(sb_peek(q, &type, &size, &data) == 0);
    assert(!sb_append(q, "a\0bc", 4));
    assert(sb_peek(q, &type, &size, &data) == 1);
    assert(type == SB_INPUT && size == 4 && !memcmp(data, "a\0bc", 4));
    sb_consume(q, 12);
    assert(sb_size(q) == 0);
    for (unsigned i = 0; i < SB_QUEUE / 12; i++)
        assert(!sb_packet(q, SB_OUTPUT, "test", 4));
    assert(sb_packet(q, SB_OUTPUT, "test", 4));
    while (sb_peek(q, &type, &size, &data) == 1)
        sb_consume(q, size + 8);
    assert(sb_size(q) == 0);
    header[1] = SB_CHUNK + 1;
    assert(!sb_append(q, header, sizeof(header)));
    assert(sb_peek(q, &type, &size, &data) == -1);
    free(q);
    puts("PASS: guest arguments, mount reachability, log tails, QEMU socket policy, private "
         "streams, OS identity, numeric limits, archive names, console framing and backpressure");
    return 0;
}
