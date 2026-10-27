/* SPDX-License-Identifier: MIT */
/* Shared binary-safe base64 encoder. */
#define B64_BUFSZ 4096

static const char b64_std[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_url[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Decode lookup: index by ASCII char → 6-bit value, or 255 for invalid. */
static int
b64_lookup (unsigned char c, int url_safe)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (url_safe) {
        if (c == '-') return 62;
        if (c == '_') return 63;
    } else {
        if (c == '+') return 62;
        if (c == '/') return 63;
    }
    return -1;
}

/* write() the full buffer, retrying short writes / EINTR. */
static int
b64_write_all (int fd, const char *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write (fd, buf + off, n - off);
        if (w <= 0) {
            if (w == 0) errno = EIO;
            if (errno == EINTR) continue;
            builtin_error ("write: %s", strerror (errno));
            return -1;
        }
        off += (size_t) w;
    }
    return 0;
}

/* Emit N base64 chars, inserting '\n' every WRAP chars (GNU `base64 -w`).
   *col tracks the column across chunks. WRAP <= 0 disables wrapping. */
static int
b64_emit (int out_fd, const char *buf, size_t n, int wrap, int *col)
{
    if (wrap <= 0)
        return b64_write_all (out_fd, buf, n);
    size_t i = 0;
    while (i < n) {
        if (*col == wrap) {
            if (b64_write_all (out_fd, "\n", 1) < 0) return -1;
            *col = 0;
        }
        size_t span = (size_t) (wrap - *col);
        if (span > n - i) span = n - i;
        if (b64_write_all (out_fd, buf + i, span) < 0) return -1;
        *col += (int) span;
        i += span;
    }
    return 0;
}

/* Encode in_fd → out_fd. Returns 0 on success, 1 on I/O error.
   WRAP > 0 line-wraps every WRAP chars (GNU -w); 0 = single line (the
   bash-os shell-variable-round-trip default). */
static int
b64_encode (int in_fd, int out_fd, int url_safe, int wrap)
{
    const char *alpha = url_safe ? b64_url : b64_std;
    unsigned char inbuf[B64_BUFSZ * 3 + 2];  /* + carry from prior read */
    char outbuf[B64_BUFSZ * 4];
    ssize_t n;
    int col = 0;
    size_t carry = 0;
    for (;;) {
        n = read (in_fd, inbuf + carry, sizeof inbuf - carry);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        size_t total = carry + (size_t) n;
        size_t groups = (total / 3) * 3;
        size_t i = 0, o = 0;
        while (i < groups) {
            unsigned int v = ((unsigned int) inbuf[i] << 16)
                           | ((unsigned int) inbuf[i+1] << 8)
                           | (unsigned int) inbuf[i+2];
            outbuf[o++] = alpha[(v >> 18) & 0x3f];
            outbuf[o++] = alpha[(v >> 12) & 0x3f];
            outbuf[o++] = alpha[(v >>  6) & 0x3f];
            outbuf[o++] = alpha[v & 0x3f];
            i += 3;
        }
        if (b64_emit (out_fd, outbuf, (size_t) o, wrap, &col) < 0)
            return 1;
        carry = total - groups;
        if (carry)
            memmove (inbuf, inbuf + groups, carry);
    }
    if (n < 0) {
        builtin_error ("read: %s", strerror (errno));
        return 1;
    }
    if (carry) {
        size_t o = 0;
        unsigned int v = (unsigned int) inbuf[0] << 16;
        if (carry == 2) v |= (unsigned int) inbuf[1] << 8;
        outbuf[o++] = alpha[(v >> 18) & 0x3f];
        outbuf[o++] = alpha[(v >> 12) & 0x3f];
        outbuf[o++] = (carry == 2) ? alpha[(v >> 6) & 0x3f] : '=';
        outbuf[o++] = '=';
        if (b64_emit (out_fd, outbuf, o, wrap, &col) < 0)
            return 1;
    }
    /* GNU base64 emits a final newline only for wrapped output. `-w0` is
       exact byte output with no terminator. */
    if (wrap > 0 && col > 0 && b64_write_all (out_fd, "\n", 1) < 0) return 1;
    return 0;
}
