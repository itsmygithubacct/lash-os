/* SPDX-License-Identifier: MIT */
/* A persistent canvas and synchronous Kitty presenter inside Bash.
   Pixel buffers remain in C. No threads, shell evaluation, or graphics SDK
   dependency. Sessions belong to the process that opened them. */
#include <config.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "loadables.h"
#include "_soft_raster_soft_raster.h"
#include "gpu-native.h"

#define BG_ESC "\033"
#define BG_MAX_PIXELS (16u * 1024u * 1024u)
#define BG_TIMEOUT 1000
typedef struct { int x, y, w, h; } bg_rect;
typedef enum { BG_AUTO, BG_SHM, BG_INLINE, BG_DMABUF } bg_transport;
typedef enum { BG_PROBE_SETUP, BG_PROBE_SEND, BG_PROBE_WAIT, BG_PROBE_REJECTED } bg_probe_phase;
static const char *bg_transports[] = {"auto", "shm", "inline", "dmabuf"};

static struct {
    pid_t owner;
    sr_canvas canvas, previous, output;
    unsigned char *rgba;
    int active, tty, fullscreen, displayed, image_slot, gpu_valid, output_valid;
    int tmux, remote;
    int scroll_pending, scroll_x, scroll_y, sync_active, broken_packet;
    bg_rect scroll_rect;
    bg_transport requested, transport;
    bg_probe_phase probe_phase;
    uint32_t image, probes;
    uint64_t nonce, serial, frames, bytes, patches, composes, fallbacks, readbacks, uploads;
    char shm[3][96], directory[108], socket_path[108], device[PATH_MAX];
    char fallback[512], pending[4096], probe_detail[160];
    size_t pending_len;
    struct winsize size;
    char *fragment;
    bg_native native;
} bg = {.tty = -1, .native = {.fd = -1}};
static int bg_exit_registered;
static int bg_cleaning;
static void bg_wait_shm(void);

static int bg_env_set(const char *name)
{
    const char *value = getenv(name);
    return value && *value;
}

/* Bound and sanitize both environment hints and terminal-supplied errors.
   All callers provide at least four bytes for a terminator and ellipsis. */
static void bg_label(const char *value, size_t length, char *label, size_t size)
{
    size_t count = length < size ? length : size - 4;
    for (size_t i = 0; i < count; i++) {
        unsigned char c = value[i];
        label[i] = c >= 32 && c <= 126 ? c : '?';
    }
    if (count < length) { memcpy(label + count, "...", 3); count += 3; }
    label[count] = 0;
}

static int64_t bg_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int bg_poll(int fd, short events, int64_t deadline)
{
    for (;;) {
        int64_t remaining = deadline - bg_now();
        if (remaining < 0) remaining = 0;
        struct pollfd p = {.fd = fd, .events = events};
        int rc = poll(&p, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
        if (rc < 0 && errno == EINTR && !interrupt_state && !terminating_signal) continue;
        if (rc <= 0) { if (!rc) errno = ETIMEDOUT; return -1; }
        if (p.revents & events) return 0;
        errno = EIO; return -1;
    }
}

static int bg_write(const void *data, size_t length)
{
    const char *p = data;
    int64_t deadline = bg_now() + BG_TIMEOUT;
    while (length) {
        if (!bg_cleaning && (interrupt_state || terminating_signal)) { errno = EINTR; return -1; }
        ssize_t n = write(bg.tty, p, length);
        if (n > 0) { p += n; length -= n; bg.bytes += n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!bg_poll(bg.tty, POLLOUT, deadline)) continue;
        }
        return -1;
    }
    return 0;
}

static int bg_emit(const char *text)
{
    size_t length = strlen(text);
    int graphics = strstr(text, BG_ESC "_G") != NULL;
    if (!bg.tmux || !graphics) {
        int rc = bg_write(text, length);
        if (rc && graphics) bg.broken_packet = 1;
        return rc;
    }
    /* tmux passthrough doubles embedded escapes; terminal-mode changes remain
       local to the pane. The user's tmux must permit passthrough. */
    char wrapped[16400];
    if (length > 8192) { errno = EOVERFLOW; return -1; }
    size_t at = 7;
    memcpy(wrapped, BG_ESC "Ptmux;", at);
    for (size_t i = 0; i < length; i++) {
        if (text[i] == 27) wrapped[at++] = 27;
        wrapped[at++] = text[i];
    }
    wrapped[at++] = 27; wrapped[at++] = '\\';
    int rc = bg_write(wrapped, at);
    if (rc) bg.broken_packet = 1;
    return rc;
}

static size_t bg_base64(const unsigned char *p, size_t len, char *out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16;
        if (i + 1 < len) v |= (uint32_t)p[i+1] << 8;
        if (i + 2 < len) v |= p[i+2];
        out[j++] = alphabet[v >> 18]; out[j++] = alphabet[(v >> 12) & 63];
        out[j++] = i + 1 < len ? alphabet[(v >> 6) & 63] : '=';
        out[j++] = i + 2 < len ? alphabet[v & 63] : '=';
    }
    out[j] = 0; return j;
}

static int bg_packet(const char *control, const unsigned char *payload, size_t length)
{
    char encoded[4097], packet[4608];
    if (length > 3072) { errno = EOVERFLOW; return -1; }
    bg_base64(payload, length, encoded);
    int n = snprintf(packet, sizeof(packet), BG_ESC "_G%s;%s" BG_ESC "\\", control, encoded);
    if (n < 0 || (size_t)n >= sizeof(packet)) { errno = EOVERFLOW; return -1; }
    return bg_emit(packet);
}

static void bg_delete(uint32_t id)
{
    char text[96];
    snprintf(text, sizeof(text), BG_ESC "_Ga=d,d=I,i=%u,q=2;" BG_ESC "\\", id);
    (void)bg_emit(text);
}

static void bg_close(void)
{
    if (!bg.active || bg.owner != getpid()) return;
    bg_cleaning = 1;
    bg_wait_shm();
    if (bg.tty >= 0) {
        if (bg.broken_packet) (void)bg_emit(BG_ESC "\\");
        if (bg.sync_active) (void)bg_emit(BG_ESC "[?2026l");
        bg_delete(bg.image); bg_delete(bg.image + 1);
        if (bg.fullscreen)
            (void)bg_emit(BG_ESC "[?1000l" BG_ESC "[?1006l" BG_ESC "[?25h" BG_ESC "[?1049l");
        close(bg.tty);
    }
    for (int i = 0; i < 3; i++) if (bg.shm[i][0]) shm_unlink(bg.shm[i]);
    if (bg.socket_path[0]) unlink(bg.socket_path);
    if (bg.directory[0]) rmdir(bg.directory);
    bg_native_close(&bg.native);
    sr_canvas_free(&bg.canvas); sr_canvas_free(&bg.previous); sr_canvas_free(&bg.output);
    free(bg.rgba); free(bg.fragment);
    memset(&bg, 0, sizeof(bg)); bg.tty = bg.native.fd = -1;
    bg_cleaning = 0;
}

/* Called for enable -d and for dlclose as well as a statically linked exit. */
void gpu_builtin_unload(char *name) { (void)name; bg_close(); }

static int bg_number(const char *s, int min, int max, int *out)
{
    char *end;
    errno = 0;
    long n = strtol(s, &end, 10);
    if (!*s || *end || errno || n < min || n > max) return -1;
    *out = (int)n; return 0;
}

static int bg_color(const char *s, uint32_t *out)
{
    if (*s == '#') s++;
    else if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (strlen(s) != 6) return -1;
    for (int i = 0; i < 6; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') ||
              (s[i] >= 'A' && s[i] <= 'F'))) return -1;
    char *end; errno = 0;
    unsigned long n = strtoul(s, &end, 16);
    if (*end || errno || n > 0xffffff) return -1;
    *out = (uint32_t)n; return 0;
}

static int bg_dimensions(int width, int height)
{
    return width > 0 && height > 0 && width <= 10000 && height <= 10000 &&
        (uint64_t)width * height <= BG_MAX_PIXELS;
}

static int bg_output(void)
{
    if (!bg.gpu_valid || bg.output_valid) return 0;
    if (!bg.native.context) { errno = EIO; return -1; }
    if (bg_native_read(&bg.native, &bg.output, bg.rgba)) return -1;
    bg.output_valid = 1; bg.readbacks++;
    return 0;
}

static int bg_cpu(void)
{
    if (!bg.gpu_valid) return 0;
    if (bg_output()) return -1;
    memcpy(bg.canvas.px, bg.output.px, (size_t)bg.canvas.w*bg.canvas.h*4);
    bg.gpu_valid = bg.output_valid = 0;
    bg.native.input_valid = 0;
    return 0;
}

static int bg_resize(int width, int height)
{
    sr_canvas canvas = {0}, previous = {0}, output = {0};
    if (!bg_dimensions(width, height)) { errno = EINVAL; return -1; }
    unsigned char *rgba = malloc((size_t)width * height * 4);
    if (!rgba || !sr_canvas_init(&canvas, width, height) ||
        !sr_canvas_init(&previous, width, height) || !sr_canvas_init(&output, width, height)) {
        free(rgba); sr_canvas_free(&canvas); sr_canvas_free(&previous); sr_canvas_free(&output); errno = ENOMEM; return -1;
    }
    if (bg_cpu()) { free(rgba); sr_canvas_free(&canvas); sr_canvas_free(&previous); sr_canvas_free(&output); return -1; }
    sr_clear(&canvas, 0);
    if (bg.canvas.px) sr_blit(&canvas, &bg.canvas, 0, 0);
    sr_canvas_free(&bg.canvas); sr_canvas_free(&bg.previous); free(bg.rgba);
    sr_canvas_free(&bg.output);
    bg_native_close(&bg.native);
    bg.canvas = canvas; bg.previous = previous; bg.output = output; bg.rgba = rgba;
    bg.displayed = bg.scroll_pending = 0;
    return 0;
}

/* Validate an edit before committing the rendered output as its input. */
static int bg_edit(void)
{
    if (bg_cpu()) return -1;
    bg.native.input_valid = 0;
    return 0;
}

static int bg_read_pending(int64_t deadline)
{
    size_t used = bg.pending_len;
    if (used >= sizeof(bg.pending)) { errno = ENOBUFS; return -1; }
    if (bg_poll(bg.tty, POLLIN, deadline)) return -1;
    ssize_t n = read(bg.tty, bg.pending + used, sizeof(bg.pending) - used);
    if (n <= 0) { if (!n) errno = EIO; return -1; }
    bg.pending_len = used + (size_t)n; return 0;
}

static void bg_consume(size_t at, size_t length)
{
    memmove(bg.pending + at, bg.pending + at + length, bg.pending_len - at - length);
    bg.pending_len -= length;
}

/* Remove only our completed probe replies. A late shared-memory response
   must neither satisfy the next inline probe nor become keyboard input. */
static int bg_take_reply(uint32_t id)
{
    for (size_t i = 0; i + 3 < bg.pending_len;) {
        if (memcmp(bg.pending + i, BG_ESC "_G", 3)) { i++; continue; }
        int removed = 0;
        for (size_t j = i + 3; j + 1 < bg.pending_len; j++) {
            if (memcmp(bg.pending + j, BG_ESC "\\", 2)) continue;
            char reply[1024];
            size_t len = j - i - 3;
            if (len >= sizeof(reply)) break;
            memcpy(reply, bg.pending + i + 3, len); reply[len] = 0;
            unsigned got = 0; int offset = 0;
            if (sscanf(reply, "i=%u;%n", &got, &offset) == 1 && offset &&
                got >= bg.image + 2 && got < bg.image + 2 + bg.probes) {
                size_t detail_len = len - (size_t)offset;
                int ok = detail_len == 2 && !memcmp(reply + offset, "OK", 2);
                bg_consume(i, j + 2 - i);
                if (got == id) {
                    if (!ok) {
                        bg_label(detail_len ? reply + offset : "(empty reply)",
                            detail_len ? detail_len : strlen("(empty reply)"),
                            bg.probe_detail, sizeof(bg.probe_detail));
                        bg.probe_phase = BG_PROBE_REJECTED;
                        errno = ENOTSUP;
                    }
                    return ok ? 1 : -1;
                }
                removed = 1;
            }
            break;
        }
        if (!removed) i++;
    }
    return 0;
}

static int bg_reply(uint32_t id)
{
    int64_t deadline = bg_now() + BG_TIMEOUT;
    for (;;) {
        int rc = bg_take_reply(id);
        if (rc) return rc == 1 ? 0 : -1;
        if (bg_read_pending(deadline)) return -1;
    }
}

static int bg_raw(struct termios *saved, int input)
{
    if (tcgetattr(bg.tty, saved)) return -1;
    struct termios t = *saved;
    t.c_lflag &= ~(ICANON | ECHO);
    if (input) t.c_lflag &= ~ISIG;
    t.c_iflag &= ~(ICRNL | IXON);
    t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
    return tcsetattr(bg.tty, TCSANOW, &t);
}

static int bg_shm_available(int slot)
{
    if (!bg.shm[slot][0]) return 1;
    int fd = shm_open(bg.shm[slot], O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0) { close(fd); return 0; }
    if (errno == ENOENT) { bg.shm[slot][0] = 0; return 1; }
    return -1;
}

static void bg_wait_shm(void)
{
    int64_t deadline = bg_now() + BG_TIMEOUT;
    for (;;) {
        int pending = 0;
        for (int i = 0; i < 3; i++) if (bg.shm[i][0] && bg_shm_available(i) != 1) pending = 1;
        if (!pending || bg_now() >= deadline) return;
        struct timespec pause = {.tv_nsec = 1000000};
        nanosleep(&pause, NULL);
    }
}

static int bg_shm_create(const unsigned char *data, size_t length, int *slot_out)
{
    int slot = -1;
    for (int attempt = 0; attempt < 3 && slot < 0; attempt++) {
        for (int i = 0; i < 3; i++) if (bg_shm_available(i) == 1) { slot = i; break; }
        if (slot < 0 && attempt < 2 && !interrupt_state && !terminating_signal) {
            struct timespec pause = {.tv_nsec = 1000000};
            nanosleep(&pause, NULL);
        }
    }
    if (slot < 0) { errno = EAGAIN; return -1; }
    snprintf(bg.shm[slot], sizeof(bg.shm[slot]), "/bashos-gpu-%ld-%016llx-%llu",
        (long)bg.owner, (unsigned long long)bg.nonce, (unsigned long long)++bg.serial);
    int fd = shm_open(bg.shm[slot], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { bg.shm[slot][0] = 0; return -1; }
    int error = posix_fallocate(fd, 0, length);
    void *mapping = MAP_FAILED;
    if (!error) mapping = mmap(NULL, length, PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping != MAP_FAILED) { memcpy(mapping, data, length); munmap(mapping, length); }
    else if (!error) error = errno;
    close(fd);
    if (error) { shm_unlink(bg.shm[slot]); bg.shm[slot][0] = 0; errno = error; return -1; }
    *slot_out = slot; return 0;
}

static int bg_probe(bg_transport transport)
{
    unsigned char pixel[4] = {0, 0, 0, 255};
    char control[160];
    int slot = -1, rc;
    struct termios saved;
    bg.probe_phase = BG_PROBE_SETUP; bg.probe_detail[0] = 0;
    if (bg_raw(&saved, 0)) return -1;
    uint32_t id = bg.image + 2 + bg.probes++;
    if (transport == BG_SHM) {
        rc = bg_shm_create(pixel, sizeof(pixel), &slot);
        if (!rc) {
            snprintf(control, sizeof(control), "a=q,t=s,f=32,s=1,v=1,i=%u", id);
            bg.probe_phase = BG_PROBE_SEND;
            rc = bg_packet(control, (unsigned char *)bg.shm[slot], strlen(bg.shm[slot]));
        }
    } else {
        snprintf(control, sizeof(control), "a=q,t=d,f=32,s=1,v=1,i=%u", id);
        bg.probe_phase = BG_PROBE_SEND;
        rc = bg_packet(control, pixel, sizeof(pixel));
    }
    if (!rc) { bg.probe_phase = BG_PROBE_WAIT; rc = bg_reply(id); }
    int error = errno;
    tcsetattr(bg.tty, TCSANOW, &saved);
    if (slot >= 0) { shm_unlink(bg.shm[slot]); bg.shm[slot][0] = 0; }
    errno = error; return rc;
}

static int bg_fallback(void)
{
    bg.fallbacks++;
    if (!bg.tmux && !bg.remote && !bg_probe(BG_SHM)) { bg.transport = BG_SHM; return 0; }
    if (!bg_probe(BG_INLINE)) { bg.transport = BG_INLINE; return 0; }
    return -1;
}

static int bg_graphics(void)
{
    if (bg.native.context) return 0;
    if (bg.device[0]) {
        if (bg_native_open(&bg.native, bg.device, bg.canvas.w, bg.canvas.h)) return -1;
    } else {
        char path[64]; int found = 0;
        for (int i = 128; i < 192; i++) {
            snprintf(path, sizeof(path), "/dev/dri/renderD%d", i);
            if (access(path, R_OK | W_OK)) continue;
            if (!bg_native_open(&bg.native, path, bg.canvas.w, bg.canvas.h)) { found = 1; break; }
        }
        if (!found) {
            if (!bg.native.error[0]) snprintf(bg.native.error, sizeof(bg.native.error), "no usable render node");
            return -1;
        }
    }
    if (bg.fragment) {
        bg.native.program = bg_program(&bg.native, bg.fragment);
        if (!bg.native.program) return -1;
    }
    return 0;
}

static int bg_socket(void)
{
    if (!bg.directory[0]) {
        const char *root = getenv("KILIX_SESSION_HOME");
        struct stat st;
        if (!root || *root != '/' || lstat(root, &st) || !S_ISDIR(st.st_mode) ||
            st.st_uid != geteuid() || (st.st_mode & 0077)) { errno = EACCES; return -1; }
        int n = snprintf(bg.directory, sizeof(bg.directory), "%s/gpu-XXXXXX", root);
        if (n < 0 || (size_t)n + 7 >= sizeof(bg.directory)) { bg.directory[0] = 0; errno = ENAMETOOLONG; return -1; }
        if (!mkdtemp(bg.directory)) { bg.directory[0] = 0; return -1; }
        size_t length = strlen(bg.directory);
        memcpy(bg.socket_path, bg.directory, length);
        memcpy(bg.socket_path + length, "/frame", 7);
    }
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, bg.socket_path, strlen(bg.socket_path) + 1);
    unlink(bg.socket_path);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) || chmod(bg.socket_path, 0600) || listen(fd, 1)) {
        int error = errno; close(fd); unlink(bg.socket_path); errno = error; return -1;
    }
    return fd;
}

static int bg_draw(float time, int custom)
{
    int upload = !bg.native.input_valid;
    if (upload) sr_pack_rgba(&bg.canvas, bg.rgba, (size_t)bg.canvas.w * bg.canvas.h * 4);
    if (bg_native_draw(&bg.native, upload ? bg.rgba : NULL, time, custom)) return -1;
    bg.uploads += upload;
    return 0;
}

static int bg_dmabuf(uint32_t id)
{
    int listener = -1, peer = -1, frame_fd = -1, rc = -1, handed_off = 0;
    if (bg_graphics()) { snprintf(bg.fallback, sizeof(bg.fallback), "%s", bg.native.error); return -1; }
    if (!bg.gpu_valid && bg_draw(0, 0)) return -1;
    listener = bg_socket();
    if (listener < 0) goto done;
    frame_fd = bg.native.gbm_bo_get_fd(bg.native.bo);
    if (frame_fd < 0) goto done;
    char control[128];
    snprintf(control, sizeof(control), "a=g,t=g,i=%u,q=2", id);
    if (bg_packet(control, (unsigned char *)bg.socket_path, strlen(bg.socket_path))) goto done;
    int64_t deadline = bg_now() + BG_TIMEOUT;
    if (bg_poll(listener, POLLIN, deadline)) goto done;
    peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (peer < 0) goto done;
    struct ucred credentials;
    socklen_t size = sizeof(credentials);
    if (getsockopt(peer, SOL_SOCKET, SO_PEERCRED, &credentials, &size) ||
        size != sizeof(credentials) || credentials.uid != geteuid()) { errno = EACCES; goto done; }
    uint64_t modifier = bg.native.gbm_bo_get_modifier(bg.native.bo);
    /* Native-endian v2 wire record, GLES framebuffer has a bottom-left origin.
       Transform 6 is the fork's vertical inversion (flipped-180). */
    uint32_t frame[10] = {0x4b444d41, 2, bg.canvas.w, bg.canvas.h,
        bg.native.gbm_bo_get_stride(bg.native.bo), bg.native.gbm_bo_get_offset(bg.native.bo, 0),
        BG_XRGB, modifier >> 32, (uint32_t)modifier, 6};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct iovec iov = {.iov_base = frame, .iov_len = sizeof(frame)};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &frame_fd, sizeof(frame_fd));
    if (bg_poll(peer, POLLOUT, deadline)) goto done;
    if (sendmsg(peer, &message, MSG_NOSIGNAL) != sizeof(frame)) goto done;
    handed_off = 1;
    if (bg_poll(peer, POLLIN, deadline)) goto done;
    unsigned char ack = 0;
    if (recv(peer, &ack, 1, 0) != 1 || ack != 1) { errno = EIO; goto done; }
    rc = 0;
done:
    if (rc && !bg.fallback[0]) snprintf(bg.fallback, sizeof(bg.fallback), "DMA-BUF: %s", strerror(errno));
    if (rc && handed_off) {
        /* A missing ACK does not return the receiver's lease. Preserve the
           result, then retire this allocation before any later render can
           overwrite it. The receiver's FD keeps the old buffer alive. */
        (void)bg_output();
        bg_native_close(&bg.native);
    }
    if (frame_fd >= 0) close(frame_fd);
    if (peer >= 0) close(peer);
    if (listener >= 0) close(listener);
    if (bg.socket_path[0]) unlink(bg.socket_path);
    return rc;
}

static int bg_inline(uint32_t id, bg_rect r, int patch, const sr_canvas *frame)
{
    size_t total = (size_t)r.w * r.h * 4, position = 0;
    while (position < total) {
        unsigned char raw[3072]; char control[192];
        size_t n = total - position; if (n > sizeof(raw)) n = sizeof(raw);
        for (size_t i = 0; i < n; i += 4) {
            size_t pixel = (position + i) / 4;
            uint32_t c = frame->px[(size_t)(r.y + pixel / r.w) * frame->w + r.x + pixel % r.w];
            raw[i] = c >> 16; raw[i+1] = c >> 8; raw[i+2] = c; raw[i+3] = 255;
        }
        int more = position + n < total;
        if (!position && patch)
            snprintf(control, sizeof(control), "a=f,i=%u,r=1,X=1,q=2,f=32,x=%d,y=%d,s=%d,v=%d,m=%d",
                id, r.x, r.y, r.w, r.h, more);
        else if (!position)
            snprintf(control, sizeof(control), "a=t,t=d,i=%u,q=2,f=32,s=%d,v=%d,m=%d", id, r.w, r.h, more);
        else snprintf(control, sizeof(control), "%sq=2,m=%d", patch ? "a=f," : "", more);
        if (bg_packet(control, raw, n)) return -1;
        position += n;
    }
    return 0;
}

static void bg_scroll_pixels(sr_canvas *canvas, bg_rect r, int dx, int dy, uint32_t color)
{
    for (int iy = 0; iy < r.h; iy++) {
        int y = r.y + (dy > 0 ? r.h - 1 - iy : iy);
        for (int ix = 0; ix < r.w; ix++) {
            int x = r.x + (dx > 0 ? r.w - 1 - ix : ix);
            int sx = x - dx, sy = y - dy;
            canvas->px[(size_t)y * canvas->w + x] =
                sx >= r.x && sx < r.x + r.w && sy >= r.y && sy < r.y + r.h ?
                canvas->px[(size_t)sy * canvas->w + sx] : 0xff000000u | color;
        }
    }
}

static int bg_present(const bg_rect *explicit_rect)
{
    if (bg.tty < 0) { errno = ENOTTY; return -1; }
    uint32_t next = bg.image + !bg.image_slot;
    int rc = -1, full = !bg.displayed, slot = -1;
    const sr_canvas *frame = &bg.canvas;
    bg_rect r = {0, 0, bg.canvas.w, bg.canvas.h};
    bg.sync_active = 1;
    if (bg_emit(BG_ESC "[?2026h")) return -1;
    if (bg.transport == BG_DMABUF) {
        if (!bg_dmabuf(next)) { full = 1; goto placed; }
        if (bg_fallback()) goto done;
        full = 1;
    }
    if (bg_output()) goto done;
    if (bg.gpu_valid) frame = &bg.output;
    if (!full && !explicit_rect && bg.scroll_pending == 1 && getenv("KITTY_KILIX_RENDERING") &&
        !strcmp(getenv("KITTY_KILIX_RENDERING"), "1")) {
        bg_rect v = bg.scroll_rect;
        int dx = bg.scroll_x, dy = bg.scroll_y;
        if (abs(dx) < v.w && abs(dy) < v.h) {
            char command[256];
            /* Composition uses lowercase x/y for the destination and
               uppercase X/Y for the source, unlike an image crop. */
            snprintf(command, sizeof(command),
                BG_ESC "_Ga=c,i=%u,r=1,c=1,x=%d,y=%d,X=%d,Y=%d,w=%d,h=%d,C=1,N=2,q=2;" BG_ESC "\\",
                bg.image + bg.image_slot, v.x + (dx > 0 ? dx : 0), v.y + (dy > 0 ? dy : 0),
                v.x + (dx < 0 ? -dx : 0), v.y + (dy < 0 ? -dy : 0), v.w - abs(dx), v.h - abs(dy));
            if (bg_emit(command)) goto done;
            bg_scroll_pixels(&bg.previous, v, dx, dy, 0);
            /* Force every exposed edge into the subsequent exact damage pass. */
            for (int y = v.y; y < v.y + v.h; y++) for (int x = v.x; x < v.x + v.w; x++)
                if (x-dx < v.x || x-dx >= v.x+v.w || y-dy < v.y || y-dy >= v.y+v.h)
                    bg.previous.px[(size_t)y * bg.canvas.w + x] = frame->px[(size_t)y * bg.canvas.w + x] ^ 0xffffff;
            bg.composes++;
        }
    }
    if (!full) {
        if (explicit_rect) r = *explicit_rect;
        else {
            int left = bg.canvas.w, top = bg.canvas.h, right = -1, bottom = -1;
            for (int y = 0; y < bg.canvas.h; y++) for (int x = 0; x < bg.canvas.w; x++)
                if (frame->px[(size_t)y * bg.canvas.w + x] != bg.previous.px[(size_t)y * bg.canvas.w + x]) {
                    if (x < left) left = x;
                    if (x > right) right = x;
                    if (y < top) top = y;
                    if (y > bottom) bottom = y;
                }
            if (right < 0) { rc = 0; goto done; }
            r = (bg_rect){left, top, right-left+1, bottom-top+1};
        }
        if ((int64_t)r.w * r.h < (int64_t)bg.canvas.w * bg.canvas.h / 2) {
            if (bg_inline(bg.image + bg.image_slot, r, 1, frame)) goto done;
            for (int y = r.y; y < r.y+r.h; y++)
                memcpy(bg.previous.px + (size_t)y*bg.canvas.w+r.x,
                       frame->px + (size_t)y*bg.canvas.w+r.x, (size_t)r.w*4);
            bg.patches++; bg.frames++; rc = 0; goto done;
        }
        full = 1; r = (bg_rect){0, 0, bg.canvas.w, bg.canvas.h};
    }
    if (bg.transport == BG_SHM) {
        sr_pack_rgba(frame, bg.rgba, (size_t)r.w * r.h * 4);
        if (!bg_shm_create(bg.rgba, (size_t)r.w * r.h * 4, &slot)) {
            char control[160];
            snprintf(control, sizeof(control), "a=t,t=s,f=32,s=%d,v=%d,i=%u,q=2", r.w, r.h, next);
            if (bg_packet(control, (unsigned char *)bg.shm[slot], strlen(bg.shm[slot]))) goto done;
        } else {
            /* An unresponsive reader cannot grow the ring. A direct frame
               preserves the final image even if the reader never unlinks. */
            snprintf(bg.fallback, sizeof(bg.fallback), "shared memory: %s", strerror(errno));
            bg.fallbacks++;
            if (bg_inline(next, r, 0, frame)) goto done;
        }
    } else if (bg_inline(next, r, 0, frame)) goto done;
placed: {
        char command[160];
        snprintf(command, sizeof(command), BG_ESC "_Ga=p,i=%u,p=1,C=1,q=2,z=-1;" BG_ESC "\\", next);
        if (bg_emit(command)) goto done;
        bg_delete(bg.image + bg.image_slot);
        bg.image_slot = !bg.image_slot; bg.displayed = 1;
        if (bg.transport != BG_DMABUF)
            memcpy(bg.previous.px, frame->px, (size_t)bg.canvas.w * bg.canvas.h * 4);
        bg.frames++; rc = 0;
    }
done:
    bg.scroll_pending = 0;
    if (rc) bg.displayed = 0;
    if (bg_emit(BG_ESC "[?2026l")) rc = -1;
    else bg.sync_active = 0;
    return rc;
}

static void bg_env_label(const char *name, char label[64])
{
    const char *value = getenv(name);
    if (!value || !*value) value = "(unset)";
    bg_label(value, strlen(value), label, 64);
}

static void bg_probe_error(bg_transport transport, int error)
{
    int rejected = bg.probe_phase == BG_PROBE_REJECTED;
    if (!rejected && !(bg.probe_phase == BG_PROBE_WAIT && error == ETIMEDOUT)) {
        const char *stage = bg.probe_phase == BG_PROBE_SETUP ? "preparing Kitty graphics probe" :
            bg.probe_phase == BG_PROBE_SEND ? "sending Kitty graphics probe" : "reading Kitty graphics reply";
        builtin_error("start: %s (%s transport): %s", stage, bg_transports[transport], strerror(error));
        return;
    }
    char term[64], program[64];
    bg_env_label("TERM", term); bg_env_label("TERM_PROGRAM", program);
    builtin_error("start: Kitty graphics probe failed (%s, %s transport; TERM=%s, TERM_PROGRAM=%s)%s%s",
        rejected ? "terminal rejected the request" : "no reply from terminal",
        bg_transports[transport], term, program, rejected ? ": " : "", bg.probe_detail);
    if (transport == BG_SHM)
        builtin_error("start: try --transport auto or --transport inline in a terminal with Kitty graphics support");
    else if (bg_env_set("XTERM_VERSION"))
        builtin_error("start: XTERM_VERSION is set; if using XTerm, run directly in Kitty or Kilix instead, or use --headless to save images");
    else
        builtin_error("start: use a terminal with Kitty graphics support, such as Kitty or Kilix, or --headless to draw and save images");
    if (bg.tmux)
        builtin_error("start: TMUX is set; enable allow-passthrough in tmux and check the outer terminal supports Kitty graphics");
    if (bg.remote)
        builtin_error("start: SSH environment detected; the local terminal must support Kitty graphics");
}

static int bg_start(int argc, char **argv)
{
    int width, height, headless = 0, fullscreen = 0;
    const char *tty = "/dev/tty", *device = getenv("BASHOS_GPU_DEVICE");
    bg_transport transport = BG_AUTO;
    if (argc < 2 || bg_number(argv[0], 1, 10000, &width) || bg_number(argv[1], 1, 10000, &height) ||
        !bg_dimensions(width, height)) return EX_USAGE;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--headless")) headless = 1;
        else if (!strcmp(argv[i], "--fullscreen")) fullscreen = 1;
        else if (!strcmp(argv[i], "--tty") && i+1 < argc) tty = argv[++i];
        else if (!strcmp(argv[i], "--device") && i+1 < argc) device = argv[++i];
        else if (!strcmp(argv[i], "--transport") && i+1 < argc) {
            const char *value = argv[++i]; int found = 0;
            for (int j = 0; j < 4; j++) if (!strcmp(value, bg_transports[j])) { transport = j; found = 1; }
            if (!found) return EX_USAGE;
        } else return EX_USAGE;
    }
    if ((headless && fullscreen) || (device && strlen(device) >= sizeof(bg.device))) return EX_USAGE;
    if (bg.active) { builtin_error("session already open; call gpu stop first"); return EXECUTION_FAILURE; }
    bg.active = 1; bg.owner = getpid(); bg.transport = bg.requested = transport;
    bg.tmux = bg_env_set("TMUX");
    bg.remote = bg_env_set("SSH_CONNECTION") || bg_env_set("SSH_TTY");
    if (getrandom(&bg.nonce, sizeof(bg.nonce), 0) != sizeof(bg.nonce) || bg_resize(width, height)) goto fail;
    bg.image = ((uint32_t)bg.nonce & 0x7ffffffc) + 4;
    if (device) strcpy(bg.device, device);
    if (!bg_exit_registered) {
        if (atexit(bg_close)) goto fail;
        bg_exit_registered = 1;
    }
    if (headless) return EXECUTION_SUCCESS;
    /* Do not let cleanup write image-deletion commands to a rejected file. */
    int terminal = open(tty, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (terminal < 0) {
        builtin_error("start: cannot open terminal: %s", strerror(errno));
        bg_close(); return EXECUTION_FAILURE;
    }
    if (!isatty(terminal)) {
        int error = errno; close(terminal);
        builtin_error("start: cannot use terminal: %s", strerror(error));
        bg_close(); return EXECUTION_FAILURE;
    }
    bg.tty = terminal;
    ioctl(bg.tty, TIOCGWINSZ, &bg.size);
    if (transport == BG_AUTO && !bg.tmux && !bg.remote && !bg_probe(BG_SHM))
        bg.transport = BG_SHM;
    else {
        bg_transport probe_transport = transport == BG_SHM ? BG_SHM : BG_INLINE;
        if (bg_probe(probe_transport)) {
            bg_probe_error(probe_transport, errno); bg_close(); return EXECUTION_FAILURE;
        }
        if (transport == BG_AUTO) bg.transport = BG_INLINE;
    }
    if (fullscreen) {
        bg.fullscreen = 1;
        if (bg_emit(BG_ESC "[?1049h" BG_ESC "[H" BG_ESC "[?25l" BG_ESC "[?1000h" BG_ESC "[?1006h")) goto fail;
    }
    return EXECUTION_SUCCESS;
fail:
    builtin_error("start: %s", strerror(errno)); bg_close(); return EXECUTION_FAILURE;
}

/* Bounded P6 reader: dimensions are checked before allocation. */
static int bg_ppm_token(FILE *f, char *out, size_t size)
{
    int c;
    do {
        c = fgetc(f);
        if (c == '#') { do c = fgetc(f); while (c != '\n' && c != EOF); }
    } while (c == ' ' || c == '\t' || c == '\r' || c == '\n');
    size_t n = 0;
    while (c != EOF && c != ' ' && c != '\t' && c != '\r' && c != '\n') {
        if (n + 1 >= size) return -1;
        out[n++] = c; c = fgetc(f);
    }
    out[n] = 0;
    return n && c != EOF ? 0 : -1;
}

static int bg_load_ppm(sr_canvas *canvas, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    char token[64]; int width, height, rc = -1;
    if (bg_ppm_token(f, token, sizeof(token)) || strcmp(token, "P6") ||
        bg_ppm_token(f, token, sizeof(token)) || bg_number(token, 1, 10000, &width) ||
        bg_ppm_token(f, token, sizeof(token)) || bg_number(token, 1, 10000, &height) ||
        !bg_dimensions(width, height) || bg_ppm_token(f, token, sizeof(token)) || strcmp(token, "255")) {
        errno = EINVAL; goto done;
    }
    if (!sr_canvas_init(canvas, width, height)) { errno = ENOMEM; goto done; }
    for (size_t i = 0; i < (size_t)width * height; i++) {
        unsigned char p[3];
        if (fread(p, 1, 3, f) != 3) { errno = EINVAL; goto done; }
        canvas->px[i] = 0xff000000u | (p[0]<<16) | (p[1]<<8) | p[2];
    }
    rc = 0;
done:
    fclose(f);
    if (rc) sr_canvas_free(canvas);
    return rc;
}

static int bg_input(const char *variable, int timeout)
{
    if (!legal_identifier(variable)) return EX_USAGE;
    if (bg.tty < 0) { builtin_error("input requires a terminal session"); return EXECUTION_FAILURE; }
    char event[128] = "";
    struct winsize size = {0}; struct termios saved;
    int rc = 0;
    if (!ioctl(bg.tty, TIOCGWINSZ, &size) && memcmp(&size, &bg.size, sizeof(size))) {
        bg.size = size;
        snprintf(event, sizeof(event), "RESIZE:%u:%u:%u:%u", size.ws_col, size.ws_row, size.ws_xpixel, size.ws_ypixel);
        goto bind;
    }
    if (bg_raw(&saved, 1)) return EXECUTION_FAILURE;
    int64_t deadline = bg_now() + timeout;
    for (;;) {
        (void)bg_take_reply(0);
        if (bg.pending_len) break;
        if (bg_read_pending(deadline)) { rc = 1; goto restored; }
    }
    if ((unsigned char)bg.pending[0] == 27) {
        int64_t sequence_deadline = bg_now() + 35;
        while (bg.pending_len < 2 || (bg.pending_len >= 2 && bg.pending[1] == '[' &&
               (bg.pending_len < 3 || bg.pending[bg.pending_len-1] < '@' || bg.pending[bg.pending_len-1] > '~'))) {
            if (bg_read_pending(sequence_deadline)) break;
        }
        static const struct { const char *bytes, *name; } keys[] = {
            {"\033[A","UP"}, {"\033[B","DOWN"}, {"\033[C","RIGHT"}, {"\033[D","LEFT"},
            {"\033[H","HOME"}, {"\033[F","END"}, {"\033[2~","INSERT"}, {"\033[3~","DELETE"},
            {"\033[5~","PAGEUP"}, {"\033[6~","PAGEDOWN"}
        };
        size_t length = 1; strcpy(event, "ESC");
        for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
            size_t n = strlen(keys[i].bytes);
            if (bg.pending_len >= n && !memcmp(bg.pending, keys[i].bytes, n)) {
                strcpy(event, keys[i].name); length = n; break;
            }
        }
        if (bg.pending_len >= 6 && !memcmp(bg.pending, "\033[<", 3)) {
            char sequence[96];
            size_t n = bg.pending_len < sizeof(sequence)-1 ? bg.pending_len : sizeof(sequence)-1;
            memcpy(sequence, bg.pending, n); sequence[n] = 0;
            unsigned button, x, y; char end; int used = 0;
            if (sscanf(sequence, "\033[<%u;%u;%u%c%n", &button, &x, &y, &end, &used) == 4 &&
                (end == 'M' || end == 'm')) {
                snprintf(event, sizeof(event), "MOUSE:%s:%u:%u:%u", end == 'M' ? "down" : "up", button, x, y);
                length = used;
            }
        }
        bg_consume(0, length);
    } else {
        unsigned char c = bg.pending[0]; size_t length = 1;
        if (c >= 0xc2 && c <= 0xf4) {
            size_t expected = c < 0xe0 ? 2 : c < 0xf0 ? 3 : 4;
            while (bg.pending_len < expected && !bg_read_pending(bg_now()+35)) {}
            if (bg.pending_len >= expected) {
                length = expected;
                for (size_t i = 1; i < length; i++) if (((unsigned char)bg.pending[i] & 0xc0) != 0x80) { length = 1; break; }
            }
        }
        if (c == '\r' || c == '\n') strcpy(event, "ENTER");
        else if (c == '\t') strcpy(event, "TAB");
        else if (c == 127 || c == 8) strcpy(event, "BACKSPACE");
        else if (c < 32) snprintf(event, sizeof(event), "CTRL-%c", c + '@');
        else { memcpy(event, bg.pending, length); event[length] = 0; }
        bg_consume(0, length);
    }
restored:
    tcsetattr(bg.tty, TCSANOW, &saved);
bind:
    if (!builtin_bind_variable((char *)variable, event, 0)) return EXECUTION_FAILURE;
    return rc;
}

int gpu_builtin(WORD_LIST *list)
{
    char *argv[8192]; int argc = 0;
    for (; list; list = list->next) {
        if (argc == (int)(sizeof(argv)/sizeof(argv[0]))) { builtin_error("too many arguments"); return EX_USAGE; }
        argv[argc++] = list->word->word;
    }
    if (!argc || !strcmp(argv[0], "--help") || !strcmp(argv[0], "help")) {
        extern char *gpu_doc[];
        for (int i = 0; gpu_doc[i]; i++) puts(gpu_doc[i]);
        return sh_chkwrite(EXECUTION_SUCCESS);
    }
    const char *command = argv[0]; argc--; char **args = argv + 1;
    if (!strcmp(command, "info") && !argc) {
        printf("active=%d width=%d height=%d transport=%s frames=%llu bytes=%llu patches=%llu composes=%llu fallbacks=%llu readbacks=%llu uploads=%llu\n",
            bg.active, bg.canvas.w, bg.canvas.h, bg.tty < 0 ? "headless" : bg_transports[bg.transport],
            (unsigned long long)bg.frames, (unsigned long long)bg.bytes, (unsigned long long)bg.patches,
            (unsigned long long)bg.composes, (unsigned long long)bg.fallbacks, (unsigned long long)bg.readbacks,
            (unsigned long long)bg.uploads);
        if (bg.native.renderer[0]) printf("renderer=%s\n", bg.native.renderer);
        if (bg.fallback[0]) printf("fallback=%s\n", bg.fallback);
        return sh_chkwrite(EXECUTION_SUCCESS);
    }
    if (bg.active && bg.owner != getpid()) {
        builtin_error("session belongs to the parent shell; invoke gpu directly, outside pipelines and $(...)");
        return EXECUTION_FAILURE;
    }
    if (!strcmp(command, "start")) return bg_start(argc, args);
    if (!strcmp(command, "stop") && !argc) { bg_close(); return EXECUTION_SUCCESS; }
    if (!bg.active) { builtin_error("no session; call gpu start WIDTH HEIGHT"); return EXECUTION_FAILURE; }
    int n[8] = {0}; uint32_t color;
    if (!strcmp(command, "input")) {
        if (argc != 2 || bg_number(args[1], 0, 60000, n)) goto usage;
        return bg_input(args[0], n[0]);
    }
    if (!strcmp(command, "size") && !argc) {
        struct winsize size = {0};
        if (bg.tty < 0 || ioctl(bg.tty, TIOCGWINSZ, &size)) goto error;
        printf("%u %u %u %u\n", size.ws_col, size.ws_row, size.ws_xpixel, size.ws_ypixel);
        return sh_chkwrite(EXECUTION_SUCCESS);
    }
    if (!strcmp(command, "resize")) {
        if (argc != 2 || bg_number(args[0], 1, 10000, n) || bg_number(args[1], 1, 10000, n+1)) goto usage;
        if (bg_resize(n[0], n[1])) goto error;
    } else if (!strcmp(command, "present")) {
        if (argc && argc != 4) goto usage;
        bg_rect r;
        if (argc) {
            for (int i = 0; i < 4; i++) if (bg_number(args[i], i<2 ? 0 : 1, 10000, n+i)) goto usage;
            r = (bg_rect){n[0], n[1], n[2], n[3]};
            if (r.x+r.w > bg.canvas.w || r.y+r.h > bg.canvas.h) goto usage;
        }
        if (bg_present(argc ? &r : NULL)) goto error;
    } else if (!strcmp(command, "clear")) {
        if (argc != 1 || bg_color(args[0], &color)) goto usage;
        bg.gpu_valid = bg.output_valid = bg.native.input_valid = 0; sr_clear(&bg.canvas, color);
    } else if (!strcmp(command, "shader")) {
        if (argc != 1) goto usage;
        if (!strcmp(args[0], "off")) {
            if (bg_cpu()) goto error;
            if (bg.native.program) bg.native.glDeleteProgram(bg.native.program);
            bg.native.program = 0; free(bg.fragment); bg.fragment = NULL;
            return EXECUTION_SUCCESS;
        }
        FILE *f = fopen(args[0], "rb");
        if (!f) goto error;
        char *text = malloc(1024*1024+1);
        if (!text) { fclose(f); goto error; }
        size_t length = fread(text, 1, 1024*1024+1, f);
        int invalid = ferror(f) || length > 1024*1024 || memchr(text, 0, length);
        fclose(f);
        if (invalid) { free(text); errno = EINVAL; goto error; }
        text[length] = 0;
        if (bg_graphics()) { builtin_error("%s", bg.native.error); free(text); return EXECUTION_FAILURE; }
        unsigned program = bg_program(&bg.native, text);
        if (!program) { builtin_error("shader: %s", bg.native.error); free(text); return EXECUTION_FAILURE; }
        if (bg.native.program) bg.native.glDeleteProgram(bg.native.program);
        bg.native.program = program; free(bg.fragment); bg.fragment = text;
    } else if (!strcmp(command, "render")) {
        char *end; float time;
        if (argc != 1) goto usage;
        errno = 0; time = strtof(args[0], &end);
        if (!*args[0] || *end || errno || !isfinite(time)) goto usage;
        if (!bg.fragment) { builtin_error("load a fragment shader first"); return EXECUTION_FAILURE; }
        if (bg_graphics()) { builtin_error("%s", bg.native.error); return EXECUTION_FAILURE; }
        /* The CPU canvas remains the shader input across successive frames. */
        if (bg_draw(time, 1)) goto error;
        bg.gpu_valid = 1; bg.output_valid = bg.scroll_pending = 0;
    } else {
        if (!strcmp(command, "save")) {
            if (argc < 1 || argc > 2 || (argc == 2 && strcmp(args[1], "rgba") && strcmp(args[1], "ppm"))) goto usage;
            if (bg_output()) goto error;
            const sr_canvas *frame = bg.gpu_valid ? &bg.output : &bg.canvas;
            if (argc == 1 || !strcmp(args[1], "ppm")) {
                if (!sr_write_ppm(frame, args[0])) goto error;
            } else {
                FILE *f = fopen(args[0], "wb"); if (!f) goto error;
                size_t length = (size_t)bg.canvas.w * bg.canvas.h * 4;
                sr_pack_rgba(frame, bg.rgba, length);
                int bad = fwrite(bg.rgba, 1, length, f) != length;
                if (fclose(f)) bad = 1;
                if (bad) goto error;
            }
        } else if (!strcmp(command, "load-rgba")) {
            if (argc != 1) goto usage;
            /* Cache output first so committing a valid import cannot overwrite
               the raw bytes with a GPU readback in the same scratch buffer. */
            if (bg_output()) goto error;
            FILE *f = fopen(args[0], "rb"); if (!f) goto error;
            size_t length = (size_t)bg.canvas.w * bg.canvas.h * 4;
            int bad = fread(bg.rgba, 1, length, f) != length || fgetc(f) != EOF || ferror(f);
            fclose(f);
            if (bad) { errno = EINVAL; goto error; }
            if (bg_edit()) goto error;
            for (size_t i = 0; i < length/4; i++) {
                unsigned char *p = bg.rgba+i*4;
                bg.canvas.px[i] = 0xff000000u | (p[0]<<16) | (p[1]<<8) | p[2];
            }
        } else if (!strcmp(command, "load") || !strcmp(command, "blit")) {
            int blit = !strcmp(command, "blit");
            if (argc != (blit ? 3 : 1)) goto usage;
            if (blit && (bg_number(args[1], -100000, 100000, n) || bg_number(args[2], -100000, 100000, n+1))) goto usage;
            sr_canvas image = {0};
            if (bg_load_ppm(&image, args[0])) goto error;
            if (!blit && (image.w != bg.canvas.w || image.h != bg.canvas.h)) {
                sr_canvas_free(&image); builtin_error("image dimensions must match canvas; use resize or blit"); return EXECUTION_FAILURE;
            }
            if (bg_edit()) { sr_canvas_free(&image); goto error; }
            sr_blit(&bg.canvas, &image, n[0], n[1]); sr_canvas_free(&image);
        } else if (!strcmp(command, "pixel")) {
            if (argc != 3 || bg_number(args[0], -100000, 100000, n) || bg_number(args[1], -100000, 100000, n+1) || bg_color(args[2], &color)) goto usage;
            if (bg_edit()) goto error;
            sr_px(&bg.canvas, n[0], n[1], color);
        } else if (!strcmp(command, "rect") || !strcmp(command, "line")) {
            int line = !strcmp(command, "line");
            if (argc != 5 && argc != 6) goto usage;
            for (int i = 0; i < 4; i++) if (bg_number(args[i], -100000, 100000, n+i)) goto usage;
            if (bg_color(args[4], &color) || (argc == 6 && bg_number(args[5], 1, 10000, n+4))) goto usage;
            if (!line && (n[2] < 0 || n[3] < 0)) goto usage;
            if (bg_edit()) goto error;
            if (line) sr_line(&bg.canvas, n[0], n[1], n[2], n[3], argc == 6 ? n[4] : 1, color, 1, 0, 0);
            else if (argc == 6) sr_stroke_rect(&bg.canvas, n[0], n[1], n[2], n[3], n[4], color, 1);
            else sr_fill_rect(&bg.canvas, n[0], n[1], n[2], n[3], color, 1);
        } else if (!strcmp(command, "circle")) {
            if (argc != 4 && argc != 5) goto usage;
            for (int i = 0; i < 3; i++) if (bg_number(args[i], i == 2 ? 0 : -100000, 100000, n+i)) goto usage;
            if (bg_color(args[3], &color) || (argc == 5 && bg_number(args[4], 1, 10000, n+3))) goto usage;
            if (bg_edit()) goto error;
            if (argc == 5) sr_ring(&bg.canvas, n[0], n[1], n[2], n[3], color, 1);
            else sr_fill_circle(&bg.canvas, n[0], n[1], n[2], color, 1);
        } else if (!strcmp(command, "text")) {
            if (argc != 4 && argc != 5) goto usage;
            if (bg_number(args[0], -100000, 100000, n) || bg_number(args[1], -100000, 100000, n+1) ||
                bg_color(args[2], &color) || strlen(args[3]) > 65536 || (argc == 5 && bg_number(args[4], 1, 16, n+2))) goto usage;
            if (bg_edit()) goto error;
            sr_text(&bg.canvas, n[0], n[1], args[3], color, 1, argc == 5 ? n[2] : 1);
        } else if (!strcmp(command, "plot")) {
            /* gpu plot COLOR WIDTH X Y X Y ...: one native polyline per series. */
            if (argc < 6 || argc % 2 || bg_color(args[0], &color) || bg_number(args[1], 1, 10000, n)) goto usage;
            size_t count = (argc-2)/2;
            float *points = malloc(count*2*sizeof(float));
            if (!points) goto error;
            for (size_t i = 0; i < count*2; i++) {
                int value;
                if (bg_number(args[i+2], -100000, 100000, &value)) { free(points); goto usage; }
                points[i%2 ? count+i/2 : i/2] = value;
            }
            if (bg_edit()) { free(points); goto error; }
            sr_polyline(&bg.canvas, points, points+count, count, n[0], color, 1, 0, 0, 0, SR_CAP_ROUND);
            free(points);
        } else if (!strcmp(command, "scroll")) {
            if (argc != 3 && argc != 7) goto usage;
            if (bg_number(args[0], -10000, 10000, n) || bg_number(args[1], -10000, 10000, n+1) || bg_color(args[2], &color)) goto usage;
            bg_rect r = {0, 0, bg.canvas.w, bg.canvas.h};
            if (argc == 7) {
                for (int i = 0; i < 4; i++) if (bg_number(args[i+3], i < 2 ? 0 : 1, 10000, n+i+2)) goto usage;
                r = (bg_rect){n[2], n[3], n[4], n[5]};
                if (r.x+r.w > bg.canvas.w || r.y+r.h > bg.canvas.h) goto usage;
            }
            if (bg_edit()) goto error;
            bg_scroll_pixels(&bg.canvas, r, n[0], n[1], color);
            bg.scroll_pending = bg.scroll_pending ? -1 : 1;
            bg.scroll_rect = r; bg.scroll_x = n[0]; bg.scroll_y = n[1];
        } else goto usage;
    }
    return EXECUTION_SUCCESS;
usage:
    builtin_error("invalid arguments to %s; see help gpu", command); return EX_USAGE;
error:
    builtin_error("%s: %s", command, strerror(errno)); return EXECUTION_FAILURE;
}

char *gpu_doc[] = {
    "Persistent pixel canvas, Kitty presentation, and optional GLES2 shaders.",
    "gpu start WIDTH HEIGHT [--headless] [--fullscreen] [--tty PATH]",
    "          [--transport auto|shm|inline|dmabuf] [--device RENDER_NODE]",
    "gpu stop | info | size | resize WIDTH HEIGHT",
    "gpu clear RRGGBB | pixel X Y RRGGBB",
    "gpu rect X Y W H RRGGBB [LINE_WIDTH]",
    "gpu line X1 Y1 X2 Y2 RRGGBB [LINE_WIDTH]",
    "gpu circle X Y RADIUS RRGGBB [LINE_WIDTH]",
    "gpu text X Y RRGGBB STRING [SCALE]",
    "gpu plot RRGGBB LINE_WIDTH X Y X Y ...",
    "gpu scroll DX DY RRGGBB [X Y WIDTH HEIGHT]",
    "gpu load PPM_FILE | blit PPM_FILE X Y | load-rgba FILE",
    "gpu save FILE [ppm|rgba] | present [X Y WIDTH HEIGHT]",
    "gpu input VARIABLE TIMEOUT_MS     # 0: event; 1: timeout; 2: usage",
    "gpu shader FRAGMENT_FILE|off | render TIME_SECONDS",
    "",
    "Drawing clips to the canvas; colors are six hex digits, optionally # or 0x.",
    "Images are opaque. load-rgba accepts exact-size, top-to-bottom RGBA bytes.",
    "present detects changed pixels automatically; its optional rectangle is a hint.",
    "input binds keys, UTF-8 text, MOUSE:down|up:button:x:y, or RESIZE:cols:rows:w:h.",
    "Shader uniforms: resolution (vec2), time (float), canvas (sampler2D); uv",
    "is a varying vec2 with a top-left origin. See docs/gpu.md for examples.",
    "",
    "Call state-changing commands directly: pipelines and $(...) fork a child.",
    "Use trap 'gpu stop' EXIT for interactive scripts. Normal exit and unload",
    "also clean up. Input restores termios before returning; no threads are used.",
    "Shared memory is local; auto probes it, then falls back to inline graphics.",
    "DMA-BUF requires the Kilix fork's EGL import mode; it falls back on failure.",
    "A headless canvas needs no terminal or GPU. Graphics drivers load on demand.",
    (char *)NULL
};
struct builtin gpu_struct = {
    "gpu", gpu_builtin, BUILTIN_ENABLED, gpu_doc, "gpu COMMAND [ARGUMENT ...]", 0
};
