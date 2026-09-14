/* bashbase64.c — base64 encode/decode loadable, mirror of binhex.
 *
 * Bash variables are C strings; storing a NUL byte truncates. binhex
 * already provides a NUL-free hex round-trip; this builtin is the
 * symmetric base64 path — useful when interop with PEM-adjacent or
 * signify-style formats requires standard alphabet `+/=` decoding.
 *
 * Encode (default):
 *     bashbase64 < bin > base64-text
 *     b64=$(bashbase64 < bin)
 *
 * Decode (-d):
 *     bashbase64 -d < base64-text > bin
 *     printf '%s' "$b64" | bashbase64 -d > bin
 *
 * Standard alphabet (RFC 4648 §4): A-Z a-z 0-9 + /, padding '='.
 * Decode tolerates ASCII whitespace + a leading "0x" tag (matches
 * binhex's tolerance for hand-pasted input). URL-safe variant
 * (`-_` instead of `+/`, RFC 4648 §5) NOT auto-detected — pass
 * `-u` to use URL-safe alphabet on either side.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#include "loadables.h"

#define BUFSZ 4096

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
        if (w < 0) {
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
    unsigned char inbuf[BUFSZ * 3 + 2];  /* + carry from prior read */
    char outbuf[BUFSZ * 4];
    ssize_t n;
    int col = 0;
    size_t carry = 0;
    while ((n = read (in_fd, inbuf + carry, sizeof inbuf - carry)) > 0) {
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
    if (wrap > 0 && col > 0 && write (out_fd, "\n", 1) != 1) { /* best-effort */ }
    return 0;
}

/* Decode in_fd → out_fd. Tolerates whitespace + leading "0x". Stops
   at the first '=' in a group. */
static int
b64_decode (int in_fd, int out_fd, int url_safe, int ignore_garbage)
{
    /* Slurp into memory. Base64 input is small in our use cases
       (PEM blocks, signify keys); avoid the streaming-quadgroup
       complexity. */
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { builtin_error ("malloc"); return 1; }
    ssize_t r;
    while ((r = read (in_fd, buf + len, cap - len)) > 0) {
        len += (size_t) r;
        if (len == cap) {
            cap *= 2;
            unsigned char *nb = realloc (buf, cap);
            if (!nb) { free (buf); builtin_error ("realloc"); return 1; }
            buf = nb;
        }
    }
    if (r < 0) {
        free (buf);
        builtin_error ("read: %s", strerror (errno));
        return 1;
    }

    /* Walk the input. Skip whitespace + leading "0x". Accumulate
       quadgroups into 3-byte output. */
    unsigned char *out = malloc (len + 4);
    if (!out) { free (buf); builtin_error ("malloc"); return 1; }
    size_t olen = 0;
    int nibble[4];
    int n_in_group = 0;
    int post_padding_error = 0;
    unsigned char post_padding_char = 0;
    size_t post_padding_offset = 0;
    size_t i = 0;
    if (len >= 2 && buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) i = 2;
    for (; i < len; i++) {
        unsigned char c = buf[i];
        if (isspace (c)) continue;
        if (c == '=') {
            /* Pad — close out the partial group. */
            if (n_in_group < 2) goto decode_done;
            unsigned int v = ((unsigned int) nibble[0] << 18)
                           | ((unsigned int) nibble[1] << 12)
                           | (n_in_group >= 3 ? (unsigned int) nibble[2] << 6 : 0);
            out[olen++] = (unsigned char) ((v >> 16) & 0xff);
            if (n_in_group == 3) out[olen++] = (unsigned char) ((v >> 8) & 0xff);
            int expected_pad = n_in_group == 2 ? 2 : 1;
            n_in_group = 0;
            int pad_count = 1;
            while (i + 1 < len && buf[i+1] == '=') {
                i++;
                pad_count++;
            }
            /* GNU -i/--ignore-garbage tolerates a malformed pad count and
               any trailing junk after the padding; default mode is strict. */
            if (!ignore_garbage) {
                if (pad_count != expected_pad) {
                    post_padding_error = 1;
                    post_padding_char = '=';
                    post_padding_offset = i;
                    break;
                }
                for (size_t j = i + 1; j < len; j++)
                  {
                    if (buf[j] != '\n')
                      {
                        post_padding_error = 1;
                        post_padding_char = buf[j];
                        post_padding_offset = j;
                        break;
                      }
                  }
            }
            break;
        }
        int v = b64_lookup (c, url_safe);
        if (v < 0) {
            if (ignore_garbage)   /* GNU -i: silently drop non-alphabet bytes */
                continue;
            free (buf); free (out);
            builtin_error ("invalid base64 char: 0x%02x at offset %zu",
                           c, i);
            return 1;
        }
        nibble[n_in_group++] = v;
        if (n_in_group == 4) {
            unsigned int q = ((unsigned int) nibble[0] << 18)
                           | ((unsigned int) nibble[1] << 12)
                           | ((unsigned int) nibble[2] << 6)
                           | (unsigned int) nibble[3];
            out[olen++] = (unsigned char) ((q >> 16) & 0xff);
            out[olen++] = (unsigned char) ((q >> 8) & 0xff);
            out[olen++] = (unsigned char) (q & 0xff);
            n_in_group = 0;
        }
    }
decode_done:
    free (buf);
    /* Write all bytes (NUL-safe). */
    size_t off = 0;
    while (off < olen) {
        ssize_t w = write (out_fd, out + off, olen - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            free (out);
            builtin_error ("write: %s", strerror (errno));
            return 1;
        }
        off += (size_t) w;
    }
    free (out);
    if (post_padding_error) {
        builtin_error ("invalid base64 char after padding: 0x%02x at offset %zu",
                       post_padding_char, post_padding_offset);
        return 1;
    }
    return 0;
}

/* Parse a non-negative wrap width (-w / --wrap). Returns -1 on junk. */
static int
b64_parse_wrap (const char *s, int *out)
{
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol (s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 0) return -1;
    *out = (int) v;
    return 0;
}

int
bashbase64_builtin (WORD_LIST *list)
{
    int decode = 0, url_safe = 0, ignore_garbage = 0, wrap = 0;
    const char *file = NULL;
    int end_opts = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_opts && !strcmp (w, "--help")) {
            builtin_usage ();
            return EXECUTION_SUCCESS;
        }
        if (!end_opts && !strcmp (w, "--version")) {
            puts ("bashbase64 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        if (!end_opts && !strcmp (w, "--")) { end_opts = 1; continue; }
        if (!end_opts && (!strcmp (w, "-d") || !strcmp (w, "--decode")))  { decode = 1; continue; }
        if (!end_opts && !strcmp (w, "-u"))  { url_safe = 1; continue; }
        if (!end_opts && (!strcmp (w, "-i") || !strcmp (w, "--ignore-garbage"))) { ignore_garbage = 1; continue; }
        if (!end_opts && (!strcmp (w, "-w") || !strcmp (w, "--wrap"))) {
            if (!p->next) { builtin_error ("option '%s' requires an argument", w); builtin_usage (); return EX_USAGE; }
            p = p->next;
            if (b64_parse_wrap (p->word->word, &wrap) < 0)
                { builtin_error ("invalid wrap size: %s", p->word->word); return EX_USAGE; }
            continue;
        }
        if (!end_opts && !strncmp (w, "--wrap=", 7)) {
            if (b64_parse_wrap (w + 7, &wrap) < 0)
                { builtin_error ("invalid wrap size: %s", w + 7); return EX_USAGE; }
            continue;
        }
        if (!end_opts && !strncmp (w, "-w", 2) && w[2]) {
            if (b64_parse_wrap (w + 2, &wrap) < 0)
                { builtin_error ("invalid wrap size: %s", w + 2); return EX_USAGE; }
            continue;
        }
        if (!end_opts && w[0] == '-' && w[1] && strcmp (w, "-")) {
            builtin_error ("unknown flag: %s (try -d, -u, -i, -w N)", w);
            builtin_usage ();
            return EX_USAGE;
        }
        /* Positional FILE operand ("-" = stdin). GNU base64 takes one. */
        if (file) { builtin_error ("extra operand: %s", w); builtin_usage (); return EX_USAGE; }
        file = w;
    }

    int in_fd = STDIN_FILENO;
    int opened = 0;
    if (file && strcmp (file, "-") != 0) {
        in_fd = open (file, O_RDONLY | O_CLOEXEC);
        if (in_fd < 0) { builtin_error ("%s: %s", file, strerror (errno)); return EXECUTION_FAILURE; }
        opened = 1;
    }
    int rc = decode
        ? b64_decode (in_fd, STDOUT_FILENO, url_safe, ignore_garbage)
        : b64_encode (in_fd, STDOUT_FILENO, url_safe, wrap);
    if (opened) close (in_fd);
    return rc;
}

char *bashbase64_doc[] = {
    "Base64 encode/decode (RFC 4648).",
    "",
    "    bashbase64 [-u] [-w N] [FILE] > b64",
    "    bashbase64 -d [-u] [-i] [FILE] > bin",
    "    bashbase64 --help | --version",
    "",
    "    -d, --decode          decode (default: encode)",
    "    -u                    URL-safe alphabet (`-_` instead of `+/`)",
    "    -w, --wrap=N          wrap encoded lines at N chars (0 = no wrap)",
    "    -i, --ignore-garbage  when decoding, skip non-alphabet bytes",
    "    FILE                  read from FILE instead of stdin ('-' = stdin)",
    "",
    "Decode tolerates ASCII whitespace and a leading '0x' tag. NUL-safe",
    "via fd-only I/O — no shell variable in the byte path. Unlike GNU",
    "base64, encoding is NOT wrapped by default (single line, no trailing",
    "newline); pass -w 76 for GNU-style wrapping.",
    (char *) NULL
};

struct builtin bashbase64_struct = {
    "bashbase64",
    bashbase64_builtin,
    BUILTIN_ENABLED,
    bashbase64_doc,
    "bashbase64 [-d] [-u] [-i] [-w N] [FILE] > output",
    0
};
