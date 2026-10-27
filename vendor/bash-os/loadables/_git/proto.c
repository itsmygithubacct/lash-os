/* SPDX-License-Identifier: MIT */
/* _git/proto.c — pkt-line framing, and the shape of protocol v2. See
 * proto.h.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

#include "proto.h"

/* ---- reading ------------------------------------------------------------ */

void
bgit_pkt_from_fd (bgit_pkt_reader *reader, int fd)
{
    memset (reader, 0, sizeof *reader);
    reader->fd = fd;
}

void
bgit_pkt_from_memory (bgit_pkt_reader *reader, const unsigned char *data,
                      size_t len)
{
    memset (reader, 0, sizeof *reader);
    reader->fd = -1;
    reader->buf = (unsigned char *) data;
    reader->len = len;
}

void
bgit_pkt_release (bgit_pkt_reader *reader)
{
    if (reader->owns) free (reader->buf);
    memset (reader, 0, sizeof *reader);
    reader->fd = -1;
}

/* Make sure WANT bytes past the read point are in hand, reading more when
   they are not. Returns 0, or -1 when the stream ends first. */
static int
bgit_pkt_fill (bgit_pkt_reader *reader, size_t want)
{
    if (reader->len - reader->at >= want) return 0;
    if (reader->fd < 0) return -1;              /* memory holds all there is */

    /* Make room by dropping what has been used. */
    if (reader->at) {
        memmove (reader->buf, reader->buf + reader->at, reader->len - reader->at);
        reader->len -= reader->at;
        reader->at = 0;
    }
    while (reader->len < want) {
        if (reader->len + 8192 > reader->cap) {
            size_t next = reader->cap ? reader->cap * 2 : 16384;
            while (next < reader->len + 8192) next *= 2;
            unsigned char *grown = realloc (reader->buf, next);
            if (!grown) return -1;
            reader->buf = grown;
            reader->cap = next;
            reader->owns = 1;
        }
        ssize_t got = read (reader->fd, reader->buf + reader->len,
                            reader->cap - reader->len);
        if (got < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (!got) return -1;                    /* the far end stopped */
        reader->len += (size_t) got;
    }
    return 0;
}

static int
bgit_pkt_hex (const unsigned char *four)
{
    int value = 0;
    for (int i = 0; i < 4; i++) {
        int digit;
        unsigned char c = four[i];
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else return -1;
        value = value * 16 + digit;
    }
    return value;
}

int
bgit_pkt_read (bgit_pkt_reader *reader, const unsigned char **data)
{
    if (data) *data = NULL;
    if (bgit_pkt_fill (reader, 4) < 0)
        return reader->at == reader->len ? BGIT_PKT_EOF : BGIT_PKT_ERROR;
    int length = bgit_pkt_hex (reader->buf + reader->at);
    if (length < 0 || (length > 0 && length < 4)) {
        if (length == 1) { reader->at += 4; return BGIT_PKT_DELIM; }
        if (length == 2) { reader->at += 4; return BGIT_PKT_END; }
        return BGIT_PKT_ERROR;
    }
    if (!length) { reader->at += 4; return BGIT_PKT_FLUSH; }
    if (bgit_pkt_fill (reader, (size_t) length) < 0) return BGIT_PKT_ERROR;
    if (data) *data = reader->buf + reader->at + 4;
    reader->at += (size_t) length;
    return length - 4;
}

int
bgit_pkt_read_line (bgit_pkt_reader *reader, char **line)
{
    const unsigned char *data = NULL;
    *line = NULL;
    int length = bgit_pkt_read (reader, &data);
    if (length < 0) return length;
    while (length > 0 && (data[length - 1] == '\n' || data[length - 1] == '\r'))
        length--;
    char *copy = malloc ((size_t) length + 1);
    if (!copy) return BGIT_PKT_ERROR;
    memcpy (copy, data, (size_t) length);
    copy[length] = '\0';
    *line = copy;
    return length;
}

void
bgit_pkt_pending (const bgit_pkt_reader *reader, const unsigned char **data,
                  size_t *len)
{
    *data = reader->buf + reader->at;
    *len = reader->len - reader->at;
}

/* ---- writing ------------------------------------------------------------ */

static int
bgit_write_all (int fd, const void *data, size_t len)
{
    const char *at = data;
    while (len) {
        ssize_t put = write (fd, at, len);
        if (put < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        at += put;
        len -= (size_t) put;
    }
    return 0;
}

int
bgit_pkt_write (int fd, const void *data, size_t len)
{
    /* A packet carries its own four digits, and cannot hold more than
       65516 bytes of payload. */
    if (len + 4 > 65520) return -1;
    char header[5];
    snprintf (header, sizeof header, "%04x", (unsigned) (len + 4));
    if (bgit_write_all (fd, header, 4) < 0) return -1;
    return bgit_write_all (fd, data, len);
}

int
bgit_pkt_write_raw (int fd, const void *data, size_t len)
{
    return bgit_write_all (fd, data, len);
}

int
bgit_pkt_write_band (int fd, int channel, const void *data, size_t len)
{
    /* A packet holds 65516 bytes at most, one of which is the channel. */
    const unsigned char *at = data;
    unsigned char framed[65516];
    framed[0] = (unsigned char) channel;
    do {
        size_t take = len > sizeof framed - 1 ? sizeof framed - 1 : len;
        memcpy (framed + 1, at, take);
        if (bgit_pkt_write (fd, framed, take + 1) < 0) return -1;
        at += take;
        len -= take;
    } while (len);
    return 0;
}

int
bgit_pkt_writef (int fd, const char *format, ...)
{
    char buf[4096];
    va_list args;
    va_start (args, format);
    int len = vsnprintf (buf, sizeof buf, format, args);
    va_end (args);
    if (len < 0 || (size_t) len >= sizeof buf) return -1;
    return bgit_pkt_write (fd, buf, (size_t) len);
}

int
bgit_pkt_flush (int fd)
{
    return bgit_write_all (fd, "0000", 4);
}

int
bgit_pkt_delim (int fd)
{
    return bgit_write_all (fd, "0001", 4);
}

/* ---- where a request goes ----------------------------------------------- */

static int
bgit_proto_io_fd_write (bgit_proto_io *io, const void *data, size_t len)
{
    return bgit_write_all (io->fd, data, len);
}

static int
bgit_proto_io_fd_done (bgit_proto_io *io)
{
    (void) io;
    return 0;                      /* a pipe has already carried it */
}

void
bgit_proto_io_fd (bgit_proto_io *io, bgit_pkt_reader *reader, int fd)
{
    memset (io, 0, sizeof *io);
    io->reader = reader;
    io->fd = fd;
    io->write = bgit_proto_io_fd_write;
    io->done = bgit_proto_io_fd_done;
}

int
bgit_proto_write (bgit_proto_io *io, const void *data, size_t len)
{
    if (len + 4 > 65520) return -1;
    char header[5];
    snprintf (header, sizeof header, "%04x", (unsigned) (len + 4));
    if (io->write (io, header, 4) < 0) return -1;
    return io->write (io, data, len);
}

int
bgit_proto_writef (bgit_proto_io *io, const char *format, ...)
{
    char buf[4096];
    va_list args;
    va_start (args, format);
    int len = vsnprintf (buf, sizeof buf, format, args);
    va_end (args);
    if (len < 0 || (size_t) len >= sizeof buf) return -1;
    return bgit_proto_write (io, buf, (size_t) len);
}

int
bgit_proto_flush (bgit_proto_io *io)
{
    return io->write (io, "0000", 4);
}

int
bgit_proto_delim (bgit_proto_io *io)
{
    return io->write (io, "0001", 4);
}

int
bgit_proto_raw (bgit_proto_io *io, const void *data, size_t len)
{
    return io->write (io, data, len);
}

int
bgit_proto_done (bgit_proto_io *io)
{
    return io->done (io);
}

/* ---- protocol v2 -------------------------------------------------------- */

static int
bgit_caps_add (bgit_proto_caps *caps, char *line)
{
    char **grown = realloc (caps->lines, (caps->n + 1) * sizeof *grown);
    if (!grown) { free (line); return -1; }
    caps->lines = grown;
    caps->lines[caps->n++] = line;
    return 0;
}

void
bgit_proto_caps_release (bgit_proto_caps *caps)
{
    for (size_t i = 0; i < caps->n; i++) free (caps->lines[i]);
    free (caps->lines);
    caps->lines = NULL;
    caps->n = 0;
}

int
bgit_proto_read_caps (bgit_pkt_reader *reader, bgit_proto_caps *caps)
{
    memset (caps, 0, sizeof *caps);
    int named_service = 0;
    for (;;) {
        char *line = NULL;
        int length = bgit_pkt_read_line (reader, &line);
        if (length == BGIT_PKT_FLUSH) {
            /* Over HTTP the advertisement opens by naming the service,
               and the flush after that line is not the end of it: what
               the far end can do comes after. */
            if (named_service && !caps->n) {
                named_service = 0;
                continue;
            }
            break;
        }
        if (length < 0) {
            bgit_proto_caps_release (caps);
            return -1;
        }
        if (!caps->n && !strncmp (line, "# service=", 10)) {
            named_service = 1;
            continue;
        }
        if (bgit_caps_add (caps, line) < 0) {
            bgit_proto_caps_release (caps);
            return -1;
        }
    }
    /* The first line says which protocol this is. */
    if (!caps->n || strcmp (caps->lines[0], "version 2")) {
        bgit_proto_caps_release (caps);
        return -1;
    }
    return 0;
}

const char *
bgit_proto_cap (const bgit_proto_caps *caps, const char *name)
{
    size_t len = strlen (name);
    for (size_t i = 1; i < caps->n; i++) {
        const char *line = caps->lines[i];
        if (strncmp (line, name, len)) continue;
        if (!line[len]) return "";
        if (line[len] == '=') return line + len + 1;
    }
    return NULL;
}

void
bgit_proto_refs_release (bgit_proto_ref *refs, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free (refs[i].name);
        free (refs[i].symref);
    }
    free (refs);
}

/* Room for LEN more bytes in a growing buffer. */
static int
bgit_proto_room (unsigned char **buf, size_t len, size_t *cap, size_t more)
{
    if (len + more <= *cap) return 0;
    size_t next = *cap ? *cap : 65536;
    while (next < len + more) next *= 2;
    unsigned char *grown = realloc (*buf, next);
    if (!grown) return -1;
    *buf = grown;
    *cap = next;
    return 0;
}

void
bgit_proto_aside_say (bgit_proto_aside *aside, const unsigned char *data,
                      size_t len)
{
    fflush (stdout);
    for (size_t i = 0; i < len; i++) {
        char c = (char) data[i];
        if (c == '\n' || aside->len + 1 >= sizeof aside->held) {
            fprintf (stderr, "remote: %.*s\n", (int) aside->len, aside->held);
            aside->len = 0;
            if (c == '\n') continue;
        }
        aside->held[aside->len++] = c;
    }
}

void
bgit_proto_aside_flush (bgit_proto_aside *aside)
{
    if (!aside->len) return;
    fflush (stdout);
    fprintf (stderr, "remote: %.*s\n", (int) aside->len, aside->held);
    aside->len = 0;
}

int
bgit_proto_read_refs_v0 (bgit_pkt_reader *reader, bgit_proto_ref **out,
                         size_t *n_out, char **caps)
{
    bgit_proto_ref *refs = NULL;
    size_t n = 0, cap = 0;
    int named_service = 0;
    if (caps) *caps = NULL;
    for (;;) {
        const unsigned char *data = NULL;
        int got = bgit_pkt_read (reader, &data);
        /* Over HTTP the advertisement opens by naming the service, and
           the flush after that line is not the end of anything. */
        if (got == BGIT_PKT_FLUSH && named_service) {
            named_service = 0;
            continue;
        }
        if (got == BGIT_PKT_FLUSH || got == BGIT_PKT_EOF) break;
        if (got < 0) {
            bgit_proto_refs_release (refs, n);
            return -1;
        }
        if (got > 10 && !memcmp (data, "# service=", 10)) {
            named_service = 1;
            continue;
        }
        /* The first line carries the capabilities after a NUL. */
        size_t len = (size_t) got;
        const unsigned char *nul = memchr (data, '\0', len);
        if (nul) {
            if (caps && !*caps) {
                size_t caps_len = len - (size_t) (nul + 1 - data);
                while (caps_len && (nul[caps_len] == '\n' || nul[caps_len] == '\r'))
                    caps_len--;
                *caps = malloc (caps_len + 1);
                if (*caps) {
                    memcpy (*caps, nul + 1, caps_len);
                    (*caps)[caps_len] = '\0';
                }
            }
            len = (size_t) (nul - data);
        }
        while (len && (data[len - 1] == '\n' || data[len - 1] == '\r')) len--;
        if (len < 42 || data[40] != ' ') continue;
        const char *name = (const char *) data + 41;
        size_t name_len = len - 41;
        /* An empty repository names no ref, only what it can do. */
        if (name_len == 15 && !memcmp (name, "capabilities^{}", 15)) continue;
        if (n == cap) {
            size_t next = cap ? cap * 2 : 32;
            bgit_proto_ref *grown = realloc (refs, next * sizeof *grown);
            if (!grown) {
                bgit_proto_refs_release (refs, n);
                return -1;
            }
            refs = grown;
            cap = next;
        }
        memset (&refs[n], 0, sizeof refs[n]);
        memcpy (refs[n].id, data, 40);
        refs[n].id[40] = '\0';
        refs[n].name = malloc (name_len + 1);
        if (!refs[n].name) {
            bgit_proto_refs_release (refs, n);
            return -1;
        }
        memcpy (refs[n].name, name, name_len);
        refs[n].name[name_len] = '\0';
        n++;
    }
    *out = refs;
    *n_out = n;
    return 0;
}

int
bgit_proto_fetch (bgit_proto_io *io,
                  const char *const *wants, size_t n_wants,
                  const char *const *haves, size_t n_haves,
                  unsigned char **pack, size_t *pack_len)
{
    *pack = NULL;
    *pack_len = 0;
    if (bgit_proto_writef (io, "command=fetch\n") < 0 ||
        bgit_proto_writef (io, "object-format=sha1\n") < 0 ||
        bgit_proto_delim (io) < 0)
        return -1;
    /* No thin pack is asked for: this end completes nothing from its own
       objects yet. Offset deltas it can read. */
    if (bgit_proto_writef (io, "ofs-delta\n") < 0 ||
        bgit_proto_writef (io, "no-progress\n") < 0 ||
        bgit_proto_writef (io, "include-tag\n") < 0)
        return -1;
    for (size_t i = 0; i < n_wants; i++)
        if (bgit_proto_writef (io, "want %s\n", wants[i]) < 0) return -1;
    for (size_t i = 0; i < n_haves; i++)
        if (bgit_proto_writef (io, "have %s\n", haves[i]) < 0) return -1;
    /* Saying "done" ends the negotiation in one round: the far end works
       out what to send from the haves it has been given. */
    if (bgit_proto_writef (io, "done\n") < 0 || bgit_proto_flush (io) < 0 ||
        bgit_proto_done (io) < 0)
        return -1;
    bgit_pkt_reader *reader = io->reader;

    unsigned char *body = NULL;
    size_t len = 0, cap = 0;
    int in_pack = 0;
    bgit_proto_aside aside;
    memset (&aside, 0, sizeof aside);
    for (;;) {
        const unsigned char *data = NULL;
        int got = bgit_pkt_read (reader, &data);
        if (got == BGIT_PKT_FLUSH || got == BGIT_PKT_EOF) break;
        if (got == BGIT_PKT_DELIM) continue;
        if (got < 0) { free (body); return -1; }
        if (!in_pack) {
            /* Section headers, and the acknowledgments of a far end that
               answers one even though this one said it was done. */
            if (got >= 8 && !memcmp (data, "packfile", 8)) in_pack = 1;
            continue;
        }
        if (!got) continue;
        int channel = data[0];
        if (channel == 1) {
            if (bgit_proto_room (&body, len, &cap, (size_t) got - 1) < 0) {
                free (body);
                return -1;
            }
            memcpy (body + len, data + 1, (size_t) got - 1);
            len += (size_t) got - 1;
        } else if (channel == 2) {
            bgit_proto_aside_say (&aside, data + 1, (size_t) got - 1);
        } else {
            fflush (stdout);
            fprintf (stderr, "remote: %.*s", got - 1, (const char *) data + 1);
            free (body);
            return -1;
        }
    }
    bgit_proto_aside_flush (&aside);
    *pack = body;
    *pack_len = len;
    return 0;
}

int
bgit_proto_ls_refs (bgit_proto_io *io,
                    const char *const *prefixes, size_t n_prefixes,
                    int want_symrefs, int want_peeled,
                    bgit_proto_ref **refs_out, size_t *n_out)
{
    bgit_pkt_reader *reader = io->reader;
    if (bgit_proto_writef (io, "command=ls-refs\n") < 0 ||
        bgit_proto_writef (io, "object-format=sha1\n") < 0 ||
        bgit_proto_delim (io) < 0)
        return -1;
    if (want_peeled && bgit_proto_writef (io, "peel\n") < 0) return -1;
    if (want_symrefs && bgit_proto_writef (io, "symrefs\n") < 0) return -1;
    for (size_t i = 0; i < n_prefixes; i++)
        if (bgit_proto_writef (io, "ref-prefix %s\n", prefixes[i]) < 0)
            return -1;
    if (bgit_proto_flush (io) < 0 || bgit_proto_done (io) < 0) return -1;
    reader = io->reader;           /* a POST answers into a new one */

    bgit_proto_ref *refs = NULL;
    size_t n = 0, cap = 0;
    for (;;) {
        char *line = NULL;
        int length = bgit_pkt_read_line (reader, &line);
        if (length == BGIT_PKT_FLUSH) break;
        if (length < 0) {
            bgit_proto_refs_release (refs, n);
            return -1;
        }
        /* "<id> <name>[ symref-target:<ref>][ peeled:<id>]" */
        char *space = strchr (line, ' ');
        if (!space || space - line != 40) { free (line); continue; }
        if (n == cap) {
            size_t next = cap ? cap * 2 : 32;
            bgit_proto_ref *grown = realloc (refs, next * sizeof *grown);
            if (!grown) {
                free (line);
                bgit_proto_refs_release (refs, n);
                return -1;
            }
            refs = grown;
            cap = next;
        }
        bgit_proto_ref *ref = &refs[n];
        memset (ref, 0, sizeof *ref);
        memcpy (ref->id, line, 40);
        ref->id[40] = '\0';
        char *name = space + 1;
        char *attribute = strchr (name, ' ');
        if (attribute) *attribute++ = '\0';
        ref->name = strdup (name);
        if (!ref->name) {
            free (line);
            bgit_proto_refs_release (refs, n);
            return -1;
        }
        while (attribute && *attribute) {
            char *next = strchr (attribute, ' ');
            if (next) *next++ = '\0';
            if (!strncmp (attribute, "symref-target:", 14))
                ref->symref = strdup (attribute + 14);
            else if (!strncmp (attribute, "peeled:", 7) &&
                     strlen (attribute + 7) == 40)
                memcpy (ref->peeled, attribute + 7, 41);
            attribute = next;
        }
        n++;
        free (line);
    }
    *refs_out = refs;
    *n_out = n;
    return 0;
}
