#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include "sandbox_protocol.h"

static void power_down(void) {
    sync();
    reboot(RB_POWER_OFF);
    _exit(125);
}
static void die(const char *step) {
    dprintf(2, "lash-os VM: %s: %s\n", step, strerror(errno));
    power_down();
}
static void mount_fs(const char *source, const char *target, const char *type, unsigned long flags,
                     const char *data) {
    if (mount(source, target, type, flags, data))
        die(target);
}
static void modules(void) {
    FILE *list = fopen("/modules/load", "r");
    if (!list)
        die("module list");
    char path[256];
    while (fgets(path, sizeof(path), list)) {
        path[strcspn(path, "\n")] = 0;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0 || syscall(SYS_finit_module, fd, "", 0))
            die(path);
        close(fd);
    }
    fclose(list);
}
static void address(struct sockaddr *out, const char *ip) {
    struct sockaddr_in *v4 = (void *)out;
    v4->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &v4->sin_addr) != 1)
        die("network address");
}
static void network(int enabled) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        die("network socket");
    struct ifreq req = {0};
    strcpy(req.ifr_name, "lo");
    req.ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &req))
        die("loopback");
    if (enabled) {
        strcpy(req.ifr_name, "eth0");
        address(&req.ifr_addr, "10.0.2.15");
        if (ioctl(fd, SIOCSIFADDR, &req))
            die("network address");
        address(&req.ifr_netmask, "255.255.255.0");
        if (ioctl(fd, SIOCSIFNETMASK, &req))
            die("network netmask");
        req.ifr_flags = IFF_UP | IFF_RUNNING;
        if (ioctl(fd, SIOCSIFFLAGS, &req))
            die("network link");
        struct rtentry route = {0};
        address(&route.rt_dst, "0.0.0.0");
        address(&route.rt_genmask, "0.0.0.0");
        address(&route.rt_gateway, "10.0.2.2");
        route.rt_flags = RTF_UP | RTF_GATEWAY;
        if (ioctl(fd, SIOCADDRT, &route))
            die("network route");
    }
    close(fd);
}
static int console_channel(void) {
    DIR *dir = opendir("/sys/class/virtio-ports");
    if (!dir)
        die("console transport");
    struct dirent *entry;
    int fd = -1;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;
        char path[512], name[64];
        snprintf(path, sizeof(path), "/sys/class/virtio-ports/%s/name", entry->d_name);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        int matches = fgets(name, sizeof(name), f) && !strcmp(name, "lash.io\n");
        fclose(f);
        if (matches) {
            snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
            fd = open(path, O_RDWR | O_CLOEXEC);
            break;
        }
    }
    closedir(dir);
    if (fd < 0)
        die("opening console transport");
    return fd;
}
static void relay(int channel, int input, int output, int errors, pid_t child, int terminal) {
    struct sb_queue *rx = calloc(1, sizeof(*rx)), *tx = calloc(1, sizeof(*tx)),
                    *in = calloc(1, sizeof(*in));
    if (!rx || !tx || !in || sb_nonblock(channel) || sb_nonblock(input) || sb_nonblock(output) ||
        (errors >= 0 && sb_nonblock(errors)))
        die("console setup");
    int eof = 0, exited = 0, status = 125 << 8, sent_exit = 0;
    sb_packet(tx, SB_READY, NULL, 0);
    for (;;) {
        if (!exited) {
            int result;
            pid_t reaped;
            while ((reaped = waitpid(-1, &result, WNOHANG)) > 0)
                if (reaped == child) {
                    status = result;
                    exited = 1;
                    /* PID 1 and kernel threads are excluded. A VM session owns all
                     * other guest processes, including disowned/background jobs. */
                    kill(-1, SIGKILL);
                }
        }
        uint32_t type, size;
        void *data;
        int frame;
        while ((frame = sb_peek(rx, &type, &size, &data)) > 0) {
            if (type == SB_INPUT && !eof) {
                if (sb_room(in) < size)
                    break;
                if (input >= 0)
                    sb_append(in, data, size);
            } else if (type == SB_EOF && !size && !eof) {
                if (terminal && input >= 0) {
                    if (!sb_room(in))
                        break;
                    sb_append(in, "\004", 1);
                }
                eof = 1;
            } else if (type == SB_WINDOW && size == sizeof(struct winsize)) {
                if (terminal && output >= 0)
                    ioctl(output, TIOCSWINSZ, data);
            } else {
                errno = EPROTO;
                die("console packet");
            }
            sb_consume(rx, 8 + size);
        }
        if (frame < 0)
            die("console framing");
        if (eof && !terminal && input >= 0 && !sb_size(in)) {
            close(input);
            input = -1;
        }
        if (exited && output < 0 && errors < 0 && !sent_exit && sb_room(tx) >= 12) {
            uint32_t code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            sb_packet(tx, SB_EXIT, &code, sizeof(code));
            sent_exit = 1;
        }
        if (sent_exit && !sb_size(tx))
            break;
        struct pollfd fds[] = {
            {channel, (sb_room(rx) >= SB_CHUNK ? POLLIN : 0) | (sb_size(tx) ? POLLOUT : 0), 0},
            {input, sb_size(in) ? POLLOUT : 0, 0},
            {output, sb_room(tx) >= SB_CHUNK + 8 ? POLLIN : 0, 0},
            {errors, sb_room(tx) >= SB_CHUNK + 8 ? POLLIN : 0, 0},
        };
        if (poll(fds, 4, 50) < 0) {
            if (errno == EINTR)
                continue;
            die("console poll");
        }
        if ((fds[0].revents & (POLLIN | POLLHUP | POLLERR)) && sb_receive(channel, rx) <= 0)
            power_down();
        if ((fds[0].revents & POLLOUT) && sb_flush(channel, tx))
            power_down();
        if ((fds[1].revents & (POLLOUT | POLLERR | POLLHUP)) && sb_size(in) &&
            sb_flush(input, in)) {
            if (!terminal)
                close(input);
            input = -1;
            in->start = in->end = 0;
        }
        for (int i = 2; i < 4; i++) {
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)) || sb_room(tx) < SB_CHUNK + 8)
                continue;
            unsigned char bytes[SB_CHUNK];
            ssize_t n = read(fds[i].fd, bytes, sizeof(bytes));
            if (n > 0)
                sb_packet(tx, i == 2 ? SB_OUTPUT : SB_ERROR, bytes, n);
            else if (!n || (n < 0 && errno != EINTR && errno != EAGAIN)) {
                close(fds[i].fd);
                if (i == 2) {
                    output = -1;
                    if (terminal)
                        input = -1;
                } else
                    errors = -1;
            }
        }
    }
    struct timespec delay = {.tv_nsec = 200000000};
    nanosleep(&delay, NULL);
}

int main(void) {
    if (getpid() != 1)
        return 125;
    umask(022);
    signal(SIGPIPE, SIG_IGN);
    mount_fs("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    mount_fs("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
    mount_fs("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
    int console = open("/dev/console", O_RDWR);
    if (console >= 0) {
        for (int i = 0; i < 3; i++)
            dup2(console, i);
        if (console > 2)
            close(console);
    }
    mkdir("/dev/pts", 0755);
    mount_fs("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "mode=0620,ptmxmode=0666");
    unlink("/dev/ptmx");
    symlink("pts/ptmx", "/dev/ptmx");
    symlink("/proc/self/fd", "/dev/fd");
    symlink("/proc/self/fd/0", "/dev/stdin");
    symlink("/proc/self/fd/1", "/dev/stdout");
    symlink("/proc/self/fd/2", "/dev/stderr");
    sethostname("lash-os", 7);
    modules();
    int channel = console_channel();
    int fd = open("/run/config", O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size < (off_t)sizeof(struct sb_config) ||
        st.st_size > (1 << 20))
        die("launch configuration");
    char *config_data = malloc(st.st_size);
    if (!config_data)
        die("launch configuration memory");
    size_t offset = 0;
    while (offset < (size_t)st.st_size) {
        ssize_t n = read(fd, config_data + offset, st.st_size - offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            die("reading launch configuration");
        offset += n;
    }
    close(fd);
    struct sb_config *config = (void *)config_data;
    if (config->magic != SB_CONFIG_MAGIC || config->argc > 4096 || !config->argc ||
        config->terminal > 1 || config->network > 1 ||
        !memchr(config->term, 0, sizeof(config->term)))
        die("invalid launch configuration");
    char **args = calloc(config->argc + 1, sizeof(char *));
    if (!args)
        die("launch arguments");
    offset = sizeof(*config);
    for (unsigned i = 0; i < config->argc; i++) {
        if (offset >= (size_t)st.st_size || !memchr(config_data + offset, 0, st.st_size - offset))
            die("invalid argument");
        args[i] = config_data + offset;
        offset += strlen(args[i]) + 1;
    }
    if (offset != (size_t)st.st_size)
        die("configuration trailing bytes");
    network(config->network);
    mount_fs("work", "/home", "9p", MS_NOSUID | MS_NODEV,
             "trans=virtio,version=9p2000.L,msize=262144,cache=none,access=any");
    if (chdir("/home"))
        die("working directory");
    clearenv();
    setenv("HOME", "/home", 1);
    setenv("PWD", "/home", 1);
    setenv("PATH", "/bin:/usr/bin:/sbin", 1);
    setenv("SHELL", "/bin/bash", 1);
    setenv("USER", "root", 1);
    setenv("LOGNAME", "root", 1);
    setenv("LC_ALL", "C", 1);
    setenv("TERM", config->term[0] ? config->term : "xterm", 1);
    int in[2], out[2], err[2], master = -1, slave = -1;
    if (config->terminal) {
        master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (master < 0 || grantpt(master) || unlockpt(master))
            die("terminal master");
        slave = open(ptsname(master), O_RDWR | O_NOCTTY | O_CLOEXEC);
        struct winsize window = {.ws_row = config->rows, .ws_col = config->cols};
        if (slave < 0 || ioctl(slave, TIOCSWINSZ, &window))
            die("terminal slave");
    } else if (pipe2(in, O_CLOEXEC) || pipe2(out, O_CLOEXEC) || pipe2(err, O_CLOEXEC))
        die("console pipes");
    pid_t child = fork();
    if (child < 0)
        die("fork shell");
    if (!child) {
        signal(SIGPIPE, SIG_DFL);
        if (setsid() < 0)
            die("shell session");
        if (config->terminal) {
            if (ioctl(slave, TIOCSCTTY, 0))
                die("controlling terminal");
            for (int i = 0; i < 3; i++)
                if (dup2(slave, i) < 0)
                    die("shell terminal");
        } else if (dup2(in[0], 0) < 0 || dup2(out[1], 1) < 0 || dup2(err[1], 2) < 0)
            die("shell descriptors");
        execv("/bin/linux-bash-os", args);
        dprintf(2, "lash-os: exec shell: %s\n", strerror(errno));
        _exit(125);
    }
    if (config->terminal) {
        close(slave);
        relay(channel, master, master, -1, child, 1);
    } else {
        close(in[0]);
        close(out[1]);
        close(err[1]);
        relay(channel, in[1], out[0], err[0], child, 0);
    }
    power_down();
}
