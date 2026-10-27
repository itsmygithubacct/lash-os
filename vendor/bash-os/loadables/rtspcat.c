/* rtspcat.c — an RTSP/RTP H.264 client as a bash builtin: the demux for bashrtsp.
 *
 *   rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-t SECS] [-v]
 *
 * Connects to an RTSP camera (or any RTSP server), sets up its H.264 video
 * track over interleaved TCP, and writes each access unit as one framed
 * record — a 4-byte big-endian length, then the unit in Annex-B form — to FD
 * (default 1). `bashrtsp feed -l` takes exactly one such record from a pipe,
 * so the appliance's detection loop is
 *
 *     rtspcat rtsp://cam/stream | while bashrtsp feed "$s" -l; do ...; done
 *
 * Why write one rather than vendor libavformat: the appliance is a MIT,
 * bash-only image with no ffmpeg; the demux needs no decode, and what a
 * camera actually sends — RTSP over TCP, RTP with single-NAL, STAP-A and FU-A
 * packetisation — is a few hundred lines. Basic and Digest authentication are
 * both here because real cameras use Digest.
 *
 * What it does with the stream: reassembles fragmented NALs, splits aggregate
 * packets, groups NALs into access units on the RTP marker bit (and on a
 * timestamp change, for senders that never set it), and puts the SPS/PPS from
 * the session description in front of every IDR so a decoder that joins late
 * — or is reset — always has parameter sets. It writes exactly what the
 * decoder on this board wants and, deliberately, does not touch what it does
 * not understand.
 *
 * Runs until the server goes away or COUNT units have been written; returns
 * non-zero on any error so a supervisor restarts it. A keepalive
 * (GET_PARAMETER) goes every SECS seconds, default 25, because RTSP sessions
 * time out at 60.
 *
 * Standalone test build (host): cc -DRTSPCAT_STANDALONE rtspcat.c -o rtspcat
 *
 * MIT-licensed. No vendor code, no third-party code: the MD5 for Digest is
 * the RFC 1321 algorithm written out below.
 */
#ifndef RTSPCAT_STANDALONE
#  include <config.h>
#  include "loadables.h"
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* ---- MD5 (RFC 1321), for Digest authentication ------------------------- */
typedef struct { uint32_t a, b, c, d; uint64_t len; unsigned char buf[64]; size_t n; } md5_t;
static const uint32_t md5_k[64] = {
 0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
 0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
 0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
 0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
 0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
 0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
 0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
 0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
static const unsigned char md5_r[64] = {
 7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22, 5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
 4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23, 6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
static void md5_block(md5_t *s, const unsigned char *p) {
    uint32_t w[16], a = s->a, b = s->b, c = s->c, d = s->d;
    for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) | ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;          g = (3*i + 5) & 15; }
        else             { f = c ^ (b | ~d);       g = (7*i) & 15; }
        uint32_t t = d; d = c; c = b;
        uint32_t x = a + f + md5_k[i] + w[g];
        b = b + ((x << md5_r[i]) | (x >> (32 - md5_r[i])));
        a = t;
    }
    s->a += a; s->b += b; s->c += c; s->d += d;
}
static void md5_init(md5_t *s) { s->a = 0x67452301; s->b = 0xefcdab89; s->c = 0x98badcfe; s->d = 0x10325476; s->len = 0; s->n = 0; }
static void md5_update(md5_t *s, const void *data, size_t n) {
    const unsigned char *p = data; s->len += n;
    while (n) {
        size_t take = 64 - s->n; if (take > n) take = n;
        memcpy(s->buf + s->n, p, take); s->n += take; p += take; n -= take;
        if (s->n == 64) { md5_block(s, s->buf); s->n = 0; }
    }
}
static void md5_hex(md5_t *s, char out[33]) {
    uint64_t bits = s->len * 8; unsigned char pad = 0x80;
    md5_update(s, &pad, 1);
    while (s->n != 56) { unsigned char z = 0; md5_update(s, &z, 1); }
    unsigned char lenb[8]; for (int i = 0; i < 8; i++) lenb[i] = (unsigned char)(bits >> (8*i));
    md5_update(s, lenb, 8);
    uint32_t v[4] = { s->a, s->b, s->c, s->d };
    for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) sprintf(out + (i*4 + j)*2, "%02x", (v[i] >> (8*j)) & 0xff);
    out[32] = 0;
}
static void md5_str(const char *s, char out[33]) { md5_t m; md5_init(&m); md5_update(&m, s, strlen(s)); md5_hex(&m, out); }

/* ---- base64 ------------------------------------------------------------- */
static const char b64c[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static size_t b64_encode(const unsigned char *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (i+1 < n ? (uint32_t)in[i+1] << 8 : 0) | (i+2 < n ? in[i+2] : 0);
        out[o++] = b64c[v >> 18]; out[o++] = b64c[(v >> 12) & 63];
        out[o++] = i+1 < n ? b64c[(v >> 6) & 63] : '='; out[o++] = i+2 < n ? b64c[v & 63] : '=';
    }
    out[o] = 0; return o;
}
static int b64_val(char c) { const char *p = c ? strchr(b64c, c) : NULL; return p ? (int)(p - b64c) : -1; }
static size_t b64_decode(const char *in, size_t n, unsigned char *out) {
    uint32_t v = 0; int bits = 0; size_t o = 0;
    for (size_t i = 0; i < n && in[i] != '='; i++) {
        int d = b64_val(in[i]); if (d < 0) continue;
        v = (v << 6) | (uint32_t)d; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (unsigned char)(v >> bits); }
    }
    return o;
}

/* ---- the session ---------------------------------------------------------- */
/* Bounds apply independently to an access unit, a fragmented NAL and SDP. */
#define RC_MAX_UNIT (8u * 1024u * 1024u)
#define RC_MAX_BODY 65535u
struct rc {
    int fd, out;
    char host[256], path[512], user[128], pass[128]; int port;
    char url[1024];                 /* the URL as requested, for Digest's uri and DESCRIBE */
    char base[1024];                /* Content-Base or the URL, for relative control */
    char control[1024];             /* the video track's control URL */
    char session[128];
    char realm[128], nonce[256], opaque[256]; int auth, qop; unsigned int nc; /* 0 none, 1 basic, 2 digest */
    int cseq, verbose, keepalive_s, chan_rtp, timeout_ms, streaming;
    unsigned char input[16384]; size_t input_pos, input_len;
    unsigned long max_units;
    int64_t last_keepalive_ms;
    int pt;                         /* the H.264 payload type from the SDP */
    unsigned char *sps; size_t sps_len; unsigned char *pps; size_t pps_len;
    /* access-unit assembly */
    unsigned char *au; size_t au_len, au_cap; int au_has_ps, au_is_idr;
    unsigned char *fu; size_t fu_len, fu_cap; int fu_active;
    uint32_t ts; int have_ts, damaged, have_seq;
    uint16_t seq; unsigned char fu_header;
    unsigned long units, packets, dropped;
    char err[256];
};
static void rc_err(struct rc *c, const char *fmt, ...) { va_list ap; va_start(ap, fmt); vsnprintf(c->err, sizeof c->err, fmt, ap); va_end(ap); }
static void rc_log(struct rc *c, const char *fmt, ...) {
    if (!c->verbose) return;
    va_list ap; va_start(ap, fmt); fputs("rtspcat: ", stderr); vfprintf(stderr, fmt, ap); fputc('\n', stderr); va_end(ap);
}

static int parse_url(struct rc *c, const char *url) {
    const char *p = url;
    for (const unsigned char *q = (const unsigned char *)url; *q; q++)
        if (*q <= 32 || *q == 127 || *q == '"' || *q == '\\') { rc_err(c, "invalid character in URL"); return -1; }
    if (strlen(url) >= sizeof c->url) { rc_err(c, "URL too long"); return -1; }
    if (strncmp(p, "rtsp://", 7) != 0) { rc_err(c, "URL must start with rtsp://"); return -1; }
    p += 7;
    const char *slash = strchr(p, '/'); const char *at = NULL;
    for (const char *q = p; *q && q != slash; q++) if (*q == '@') at = q;
    if (at) {
        const char *colon = memchr(p, ':', (size_t)(at - p));
        size_t ul = colon ? (size_t)(colon - p) : (size_t)(at - p);
        if (ul >= sizeof c->user) { rc_err(c, "username too long"); return -1; }
        memcpy(c->user, p, ul); c->user[ul] = 0;
        if (colon) { size_t pl = (size_t)(at - colon - 1); if (pl >= sizeof c->pass) { rc_err(c, "password too long"); return -1; } memcpy(c->pass, colon + 1, pl); c->pass[pl] = 0; }
        p = at + 1;
    }
    const char *hostend = slash ? slash : p + strlen(p);
    const char *pc = memchr(p, ':', (size_t)(hostend - p));
    size_t hl = pc ? (size_t)(pc - p) : (size_t)(hostend - p);
    if (hl == 0 || hl >= sizeof c->host) { rc_err(c, "bad host in URL"); return -1; }
    memcpy(c->host, p, hl); c->host[hl] = 0;
    c->port = 554;
    if (pc) {
        char *end; errno = 0; long port = strtol(pc + 1, &end, 10);
        if (errno || end != hostend || end == pc + 1 || port < 1 || port > 65535) { rc_err(c, "bad port in URL"); return -1; }
        c->port = (int)port;
    }
    if (c->port <= 0 || c->port > 65535) { rc_err(c, "bad port in URL"); return -1; }
    if (slash && strlen(slash) >= sizeof c->path) { rc_err(c, "URL path too long"); return -1; }
    snprintf(c->path, sizeof c->path, "%s", slash ? slash : "/");
    /* the URL we present to the server carries no credentials */
    snprintf(c->url, sizeof c->url, "rtsp://%s:%d%s", c->host, c->port, c->path);
    return 0;
}

static int tcp_connect(struct rc *c) {
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char port[8]; snprintf(port, sizeof port, "%d", c->port);
    int rc = getaddrinfo(c->host, port, &hints, &res);
    if (rc != 0) { rc_err(c, "resolve %s: %s", c->host, gai_strerror(rc)); return -1; }
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { rc_err(c, "connect %s:%d: %s", c->host, c->port, strerror(errno)); return -1; }
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    c->fd = fd; return 0;
}

/* ---- RTSP transactions ------------------------------------------------------ */
static int write_all(int fd, const void *p, size_t n) {
    const unsigned char *b = p; size_t off = 0;
    while (off < n) { ssize_t w = write(fd, b + off, n - off); if (w < 0) { if (errno == EINTR) continue; return -1; } if (w == 0) { errno = EIO; return -1; } off += (size_t)w; }
    return 0;
}
static int keepalive(struct rc *c);
static int64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
/* A small read-ahead buffer removes a poll/read pair per RTSP header byte.
 * Deadlines do not restart on EINTR, short reads or a trickled partial record. */
static int read_exactly(struct rc *c, unsigned char *p, size_t n, int timeout_ms) {
    int64_t deadline = now_ms() + timeout_ms;
    while (n) {
        if (c->input_pos < c->input_len) {
            size_t take = c->input_len - c->input_pos; if (take > n) take = n;
            memcpy(p, c->input + c->input_pos, take); c->input_pos += take; p += take; n -= take;
            continue;
        }
        int64_t now = now_ms();
        if (c->streaming && c->keepalive_s > 0 && now - c->last_keepalive_ms >= (int64_t)c->keepalive_s * 1000) {
            if (keepalive(c) != 0) { rc_err(c, "keepalive: %s", strerror(errno)); return -1; }
            c->last_keepalive_ms = now;
        }
        int64_t left = deadline - now;
        if (left <= 0) { rc_err(c, "server read timeout (%d ms)", timeout_ms); return -1; }
        if (c->streaming && c->keepalive_s > 0) {
            int64_t until = c->last_keepalive_ms + (int64_t)c->keepalive_s * 1000 - now;
            if (until < left) left = until;
        }
        struct pollfd pf = { .fd = c->fd, .events = POLLIN };
        int r = poll(&pf, 1, (int)left);
        if (r < 0) { if (errno == EINTR) continue; rc_err(c, "poll: %s", strerror(errno)); return -1; }
        if (r == 0) continue;
        ssize_t got = read(c->fd, c->input, sizeof c->input);
        if (got < 0) { if (errno == EINTR) continue; rc_err(c, "read: %s", strerror(errno)); return -1; }
        if (got == 0) { rc_err(c, "server closed the connection"); return -1; }
        c->input_pos = 0; c->input_len = (size_t)got;
    }
    return 0;
}
/* Header fields are bounded to one line. Reject ambiguous/oversized bodies. */
static int content_length(struct rc *c, const char *hdrs, size_t *len) {
    *len = 0; int seen = 0;
    for (const char *p = hdrs; (p = strchr(p, '\n')) != NULL;) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15)) continue;
        p += 15; while (*p == ' ' || *p == '\t') p++;
        char *end; errno = 0; unsigned long n = strtoul(p, &end, 10);
        if (seen++ || *p < '0' || *p > '9' || errno || n > RC_MAX_BODY) goto bad;
        while (*end == ' ' || *end == '\t') end++;
        if (*end != '\r' || end[1] != '\n') goto bad;
        *len = (size_t)n;
    }
    return 0;
bad: rc_err(c, "invalid Content-Length"); return -1;
}
static int read_headers(struct rc *c, char *hdrs, size_t cap, int first) {
    size_t n = 0; int64_t deadline = now_ms() + c->timeout_ms;
    if (first >= 0) hdrs[n++] = (char)first;
    for (;;) {
        unsigned char b;
        if (n + 1 >= cap) { rc_err(c, "response headers too long"); return -1; }
        int64_t left = deadline - now_ms();
        if (left <= 0) { rc_err(c, "server header timeout"); return -1; }
        if (read_exactly(c, &b, 1, (int)left)) return -1;
        hdrs[n++] = (char)b; hdrs[n] = 0;
        if (n >= 4 && !memcmp(hdrs + n - 4, "\r\n\r\n", 4)) return 0;
    }
}

/* Parse a Digest parameter without searching past its quoted value. */
static int auth_param(const char *header, const char *name, char *out, size_t cap) {
    size_t name_len = strlen(name); out[0] = 0;
    const char *p = strchr(header, ' '); if (!p) return 0;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        const char *key = p; while (*p && *p != '=' && *p != ',') p++;
        if (*p != '=') break;
        const char *key_end = p; while (key_end > key && (key_end[-1] == ' ' || key_end[-1] == '\t')) key_end--;
        p++; while (*p == ' ' || *p == '\t') p++;
        int quoted = *p == '"'; if (quoted) p++;
        const char *value = p;
        while (*p && (quoted ? *p != '"' : *p != ',' && *p != ' ' && *p != '\t')) p++;
        size_t n = (size_t)(p - value);
        if (quoted && !*p) return -1;
        if ((size_t)(key_end - key) == name_len && !strncasecmp(key, name, name_len)) {
            if (n >= cap || memchr(value, '\\', n)) return -1;
            memcpy(out, value, n); out[n] = 0; return 1;
        }
        if (quoted) p++;
        while (*p && *p != ',') p++;
    }
    return 0;
}
static int supports_auth_qop(const char *value) {
    while (*value) {
        while (*value == ',' || *value == ' ' || *value == '\t') value++;
        size_t n = strcspn(value, ", \t");
        if (n == 4 && !strncasecmp(value, "auth", n)) return 1;
        value += n;
    }
    return 0;
}

static void auth_header(struct rc *c, const char *method, const char *uri, char *out, size_t n) {
    out[0] = 0;
    if (!c->user[0] || !c->auth) return;
    if (c->auth == 2) {
        char a1[33], a2[33], resp[33], tmp[2048], suffix[512] = "";
        snprintf(tmp, sizeof tmp, "%s:%s:%s", c->user, c->realm, c->pass); md5_str(tmp, a1);
        snprintf(tmp, sizeof tmp, "%s:%s", method, uri); md5_str(tmp, a2);
        if (c->qop) {
            char cnonce[33]; snprintf(tmp, sizeof tmp, "%s:%ld", c->nonce, (long)getpid()); md5_str(tmp, cnonce);
            unsigned int nc = ++c->nc;
            snprintf(tmp, sizeof tmp, "%s:%s:%08x:%s:auth:%s", a1, c->nonce, nc, cnonce, a2);
            snprintf(suffix, sizeof suffix, ", qop=auth, nc=%08x, cnonce=\"%s\"", nc, cnonce);
        } else snprintf(tmp, sizeof tmp, "%s:%s:%s", a1, c->nonce, a2);
        md5_str(tmp, resp);
        if (c->opaque[0]) { size_t used = strlen(suffix); snprintf(suffix + used, sizeof suffix - used, ", opaque=\"%s\"", c->opaque); }
        snprintf(out, n, "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"%s\r\n",
                 c->user, c->realm, c->nonce, uri, resp, suffix);
    } else {
        char up[300], b64[420]; snprintf(up, sizeof up, "%s:%s", c->user, c->pass);
        b64_encode((unsigned char *)up, strlen(up), b64);
        snprintf(out, n, "Authorization: Basic %s\r\n", b64);
    }
}

/* One request/response. Returns the status code, fills body (malloc'd, may be
 * NULL) and the raw headers. Handles the 401 challenge once by switching to
 * the scheme the server names and retrying. */
static int rtsp_do(struct rc *c, const char *method, const char *uri, const char *extra,
                   char *hdrs, size_t hdrs_n, char **body, size_t *body_n) {
    for (int attempt = 0; attempt < 2; attempt++) {
        *body = NULL; *body_n = 0;
        char auth[2048]; auth_header(c, method, uri, auth, sizeof auth);
        char req[8192];
        int len = snprintf(req, sizeof req, "%s %s RTSP/1.0\r\nCSeq: %d\r\nUser-Agent: rtspcat\r\n%s%s%s%s%s\r\n",
                           method, uri, ++c->cseq,
                           c->session[0] ? "Session: " : "", c->session[0] ? c->session : "", c->session[0] ? "\r\n" : "",
                           extra ? extra : "", auth);
        if (len <= 0 || (size_t)len >= sizeof req) { rc_err(c, "request too long"); return -1; }
        rc_log(c, "> %s %s (CSeq %d)", method, uri, c->cseq);
        if (write_all(c->fd, req, (size_t)len) != 0) { rc_err(c, "write: %s", strerror(errno)); return -1; }

        if (read_headers(c, hdrs, hdrs_n, -1)) return -1;
        int status = 0;
        if (sscanf(hdrs, "RTSP/1.0 %d", &status) != 1 || status < 100 || status > 599) { rc_err(c, "invalid RTSP response"); return -1; }
        size_t n;
        if (content_length(c, hdrs, &n)) return -1;
        if (n) {
            *body = malloc(n + 1);
            if (!*body) { rc_err(c, "oom"); return -1; }
            if (read_exactly(c, (unsigned char *)*body, n, c->timeout_ms)) { free(*body); *body = NULL; return -1; }
            (*body)[n] = 0; *body_n = n;
        }
        const char *sess = strcasestr(hdrs, "\nSession:");
        if (sess && !c->session[0]) { sess += 9; while (*sess == ' ') sess++; size_t i = 0; while (sess[i] && sess[i] != ';' && sess[i] != '\r' && i < sizeof c->session - 1) { c->session[i] = sess[i]; i++; } c->session[i] = 0; }
        rc_log(c, "< %d", status);
        if (status == 401 && attempt == 0 && c->user[0]) {
            const char *wa = strcasestr(hdrs, "\nWWW-Authenticate:");
            char challenge[2048] = "";
            if (wa) { wa += 18; size_t z = strcspn(wa, "\r\n"); if (z >= sizeof challenge) z = sizeof challenge - 1; memcpy(challenge, wa, z); }
            wa = challenge;
            while (*wa == ' ' || *wa == '\t') wa++;
            if (!strncasecmp(wa, "Digest ", 7)) {
                char qop[256], algorithm[64];
                int qr = auth_param(wa, "qop", qop, sizeof qop);
                int ar = auth_param(wa, "algorithm", algorithm, sizeof algorithm);
                if (auth_param(wa, "realm", c->realm, sizeof c->realm) != 1 ||
                    auth_param(wa, "nonce", c->nonce, sizeof c->nonce) != 1 ||
                    auth_param(wa, "opaque", c->opaque, sizeof c->opaque) < 0 ||
                    qr < 0 || ar < 0 || (qr && !supports_auth_qop(qop)) || (ar && strcasecmp(algorithm, "MD5"))) {
                    rc_err(c, "unsupported or malformed Digest challenge"); free(*body); *body = NULL; return -1;
                }
                c->qop = qr; c->nc = 0; c->auth = 2;
                free(*body); *body = NULL; continue;
            }
            if (wa && strcasestr(wa, "Basic")) { c->auth = 1; free(*body); *body = NULL; continue; }
        }
        return status;
    }
    return -1;
}

/* ---- SDP: find the H.264 video track ------------------------------------- */
static int parse_sdp(struct rc *c, const char *sdp) {
    /* Select a media section only after seeing its H264 rtpmap. Audio and
     * later sections cannot overwrite the selected track's parameters. */
    c->pt = -1;
    for (const char *m = sdp; m && *m;) {
        const char *end = strstr(m + 1, "\nm="); if (end) end++;
        size_t size = end ? (size_t)(end - m) : strlen(m);
        if (!strncmp(m, "m=video ", 8)) {
            char *section = malloc(size + 1); if (!section) { rc_err(c, "oom"); return -1; }
            memcpy(section, m, size); section[size] = 0;
            int pt = -1;
            for (char *line = section; line && *line;) {
                int v; char enc[64];
                if (sscanf(line, "a=rtpmap:%d %63s", &v, enc) == 2 && v >= 0 && v <= 127 && !strcasecmp(enc, "H264/90000")) { pt = v; break; }
                line = strchr(line, '\n'); if (line) line++;
            }
            if (pt >= 0) {
                c->pt = pt;
                for (char *line = section; line && *line;) {
                    char *nl = strchr(line, '\n'); if (nl) *nl = 0;
                    size_t ll = strlen(line); if (ll && line[ll-1] == '\r') line[--ll] = 0;
                    if (!strncmp(line, "a=control:", 10)) {
                        const char *v = line + 10; int written;
                        if (!strncmp(v, "rtsp://", 7)) written = snprintf(c->control, sizeof c->control, "%s", v);
                        else if (v[0] == '/') {
                            const char *authority = strstr(c->base, "://");
                            if (!authority) { free(section); rc_err(c, "invalid control base URL"); return -1; }
                            const char *path = strchr(authority + 3, '/');
                            size_t prefix = path ? (size_t)(path - c->base) : strlen(c->base);
                            written = snprintf(c->control, sizeof c->control, "%.*s%s", (int)prefix, c->base, v);
                        }
                        else { size_t bl = strlen(c->base); written = snprintf(c->control, sizeof c->control, "%s%s%s", c->base, bl && c->base[bl-1] != '/' && v[0] != '/' ? "/" : "", v); }
                        if (written < 0 || (size_t)written >= sizeof c->control) { free(section); rc_err(c, "control URL too long"); return -1; }
                    }
                    int fp; const char *sp = strstr(line, "sprop-parameter-sets=");
                    if (sscanf(line, "a=fmtp:%d", &fp) == 1 && fp == pt && sp) {
                        sp += 21; size_t len = strcspn(sp, ";"); const char *comma = memchr(sp, ',', len);
                        if (comma) {
                            size_t l1 = (size_t)(comma - sp), l2 = len - l1 - 1;
                            unsigned char *sps = malloc(l1 + 1), *pps = malloc(l2 + 1);
                            if (!sps || !pps) { free(sps); free(pps); free(section); rc_err(c, "oom"); return -1; }
                            free(c->sps); free(c->pps); c->sps = sps; c->pps = pps;
                            c->sps_len = b64_decode(sp, l1, sps); c->pps_len = b64_decode(comma + 1, l2, pps);
                        }
                    }
                    line = nl ? nl + 1 : NULL;
                }
                free(section);
                if (!c->control[0]) snprintf(c->control, sizeof c->control, "%s", c->url);
                return 0;
            }
            free(section);
        }
        m = end;
    }
    rc_err(c, "no H.264 video track in the session description"); return -1;
}

/* ---- access units out ---------------------------------------------------- */
static int au_append(struct rc *c, const unsigned char *nal, size_t n) {
    if (n > RC_MAX_UNIT - 4 || c->au_len > RC_MAX_UNIT - 4 - n) { rc_err(c, "access unit exceeds 8 MiB"); return -1; }
    size_t need = c->au_len + 4 + n;
    if (need > c->au_cap) {
        size_t cap = c->au_cap ? c->au_cap : (1 << 16); while (cap < need) cap *= 2;
        unsigned char *p = realloc(c->au, cap); if (!p) { rc_err(c, "oom"); return -1; }
        c->au = p; c->au_cap = cap;
    }
    static const unsigned char sc[4] = { 0, 0, 0, 1 };
    memcpy(c->au + c->au_len, sc, 4); memcpy(c->au + c->au_len + 4, nal, n); c->au_len += 4 + n;
    return 0;
}
static int au_add_nal(struct rc *c, const unsigned char *nal, size_t n) {
    if (n == 0) return 0;
    int type = nal[0] & 0x1F;
    if (type == 7) c->au_has_ps |= 1;
    if (type == 8) c->au_has_ps |= 2;
    if (type == 5 && c->au_has_ps != 3 && c->sps && c->pps) {
        /* a decoder that joins late, or was just reset, needs these */
        if (!(c->au_has_ps & 1) && au_append(c, c->sps, c->sps_len)) return -1;
        if (!(c->au_has_ps & 2) && au_append(c, c->pps, c->pps_len)) return -1;
        c->au_has_ps = 3;
    }
    if (type == 5) c->au_is_idr = 1;
    return au_append(c, nal, n);
}
static int au_flush(struct rc *c) {
    if (c->au_len == 0) return 0;
    unsigned char hdr[4] = { (unsigned char)(c->au_len >> 24), (unsigned char)(c->au_len >> 16), (unsigned char)(c->au_len >> 8), (unsigned char)c->au_len };
    if (write_all(c->out, hdr, 4) != 0 || write_all(c->out, c->au, c->au_len) != 0) { rc_err(c, "write to fd %d: %s", c->out, strerror(errno)); return -1; }
    c->units++; c->au_len = 0; c->au_has_ps = 0; c->au_is_idr = 0;
    return 0;
}

/* ---- RTP H.264 depacketising (RFC 6184) ---------------------------------- */
static void damage_unit(struct rc *c) {
    c->au_len = c->fu_len = 0; c->fu_active = c->au_has_ps = 0;
    c->damaged = 1; c->dropped++;
}
static int rtp_packet(struct rc *c, const unsigned char *p, size_t n) {
    if (n < 12 || (p[0] >> 6) != 2) { damage_unit(c); if (!c->have_ts) c->damaged = 0; return 0; }
    int cc = p[0] & 15, ext = p[0] & 16, pad = p[0] & 32, marker = p[1] & 128;
    if ((p[1] & 127) != c->pt) return 0;
    uint16_t seq = (uint16_t)((p[2] << 8) | p[3]);
    uint32_t ts = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
    c->packets++;
    unsigned delta = (uint16_t)(seq - c->seq);
    /* TCP preserves wire order: do not turn late/duplicate RTP into new NALs.
     * A forward gap invalidates the old timestamp; resume at the next one. */
    if (c->have_seq && (delta == 0 || delta >= 32768)) { c->dropped++; return 0; }
    if (c->have_seq && delta != 1) damage_unit(c);
    c->seq = seq; c->have_seq = 1;
    if (c->have_ts && ts != c->ts) {
        if (c->fu_active) damage_unit(c);
        if (!c->damaged && au_flush(c)) return -1;
        c->au_len = c->fu_len = 0; c->fu_active = c->au_has_ps = c->damaged = 0;
        if (c->max_units && c->units >= c->max_units) return 0;
    }
    c->ts = ts; c->have_ts = 1;
    size_t off = 12 + (size_t)cc * 4;
    if (off > n) goto malformed;
    if (ext) { if (off + 4 > n) goto malformed; size_t xl = (((size_t)p[off+2] << 8) | p[off+3]) * 4; off += 4 + xl; }
    if (pad) { size_t pl = p[n-1]; if (!pl || pl > n - 12) goto malformed; n -= pl; }
    if (off >= n) goto malformed;
    if (c->damaged) return 0;
    const unsigned char *pl = p + off; size_t pn = n - off;
    int type = pl[0] & 31;
    if (pl[0] & 128) goto malformed;
    if (type >= 1 && type <= 23) {
        if (c->fu_active) goto malformed;
        if (au_add_nal(c, pl, pn)) return -1;
    } else if (type == 24) {
        if (c->fu_active || pn < 4) goto malformed;
        /* Validate the entire aggregate before appending any part. */
        for (size_t i = 1; i < pn;) {
            if (i + 2 > pn) goto malformed;
            size_t sz = ((size_t)pl[i] << 8) | pl[i+1]; i += 2;
            if (!sz || sz > pn - i || (pl[i] & 128) || !(pl[i] & 31) || (pl[i] & 31) > 23) goto malformed;
            i += sz;
        }
        for (size_t i = 1; i < pn;) {
            size_t sz = ((size_t)pl[i] << 8) | pl[i+1]; i += 2;
            if (au_add_nal(c, pl + i, sz)) return -1;
            i += sz;
        }
    } else if (type == 28) {
        if (pn < 3 || (pl[1] & 32) || !(pl[1] & 31) || (pl[1] & 31) > 23) goto malformed;
        int start = pl[1] & 128, end = pl[1] & 64;
        unsigned char hdr = (unsigned char)((pl[0] & 0xe0) | (pl[1] & 31));
        if (start && end) goto malformed;
        if (start) {
            if (c->fu_active) goto malformed;
            c->fu_len = 1; c->fu_active = 1; c->fu_header = hdr;
        } else if (!c->fu_active || hdr != c->fu_header) goto malformed;
        size_t frag = pn - 2;
        if (frag > RC_MAX_UNIT - c->fu_len) { rc_err(c, "fragmented NAL exceeds 8 MiB"); return -1; }
        size_t need = c->fu_len + frag;
        if (need > c->fu_cap) {
            size_t cap = c->fu_cap ? c->fu_cap : 65536; while (cap < need) cap *= 2;
            unsigned char *np = realloc(c->fu, cap); if (!np) { rc_err(c, "oom"); return -1; }
            c->fu = np; c->fu_cap = cap;
        }
        if (start) c->fu[0] = hdr;
        memcpy(c->fu + c->fu_len, pl + 2, frag); c->fu_len += frag;
        if (end) { c->fu_active = 0; if (au_add_nal(c, c->fu, c->fu_len)) return -1; }
    } else goto malformed;
    if (marker) {
        if (c->fu_active) goto malformed;
        return au_flush(c);
    }
    return 0;
malformed: damage_unit(c); return 0;
}

/* ---- the packet loop -------------------------------------------------------- */
static int session_request(struct rc *c, const char *method) {
    char req[4096], auth[2048]; auth_header(c, method, c->url, auth, sizeof auth);
    int len = snprintf(req, sizeof req, "%s %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n%s\r\n", method, c->url, ++c->cseq, c->session, auth);
    if (len < 0 || (size_t)len >= sizeof req) { errno = EMSGSIZE; return -1; }
    return write_all(c->fd, req, (size_t)len);
}
static int keepalive(struct rc *c) { return session_request(c, "GET_PARAMETER"); }
static int stream_loop(struct rc *c, unsigned long max_units) {
    unsigned char *buf = malloc(65536); if (!buf) { rc_err(c, "oom"); return -1; }
    c->streaming = 1; c->last_keepalive_ms = now_ms(); c->max_units = max_units;
    int rc = 0;
    while (!max_units || c->units < max_units) {
        unsigned char b;
        if (read_exactly(c, &b, 1, c->timeout_ms)) { rc = -1; break; }
        if (b == '$') {
            unsigned char h[3]; if (read_exactly(c, h, 3, c->timeout_ms)) { rc = -1; break; }
            size_t len = ((size_t)h[1] << 8) | h[2];
            if (read_exactly(c, buf, len, c->timeout_ms)) { rc = -1; break; }
            if (h[0] == c->chan_rtp && rtp_packet(c, buf, len)) { rc = -1; break; }
        } else {
            char headers[8192]; size_t len;
            if (read_headers(c, headers, sizeof headers, b) || content_length(c, headers, &len)) { rc = -1; break; }
            int status;
            if (sscanf(headers, "RTSP/1.0 %d", &status) != 1 || status != 200) { rc_err(c, "keepalive response failed"); rc = -1; break; }
            if (len && read_exactly(c, buf, len, c->timeout_ms)) { rc = -1; break; }
        }
    }
    c->streaming = 0; free(buf); return rc;
}

static int rtspcat_run(struct rc *c, const char *url, unsigned long max_units) {
    if (parse_url(c, url) != 0) return -1;
    if (tcp_connect(c) != 0) return -1;
    char hdrs[8192]; char *body = NULL; size_t bn = 0;
    int st = rtsp_do(c, "OPTIONS", c->url, NULL, hdrs, sizeof hdrs, &body, &bn); free(body);
    if (st < 0) return -1;
    st = rtsp_do(c, "DESCRIBE", c->url, "Accept: application/sdp\r\n", hdrs, sizeof hdrs, &body, &bn);
    if (st != 200 || !body) { if (st >= 0) rc_err(c, "DESCRIBE: status %d%s", st, st == 401 ? " (authentication)" : ""); free(body); return -1; }
    const char *cb = strcasestr(hdrs, "\nContent-Base:");
    if (cb) { cb += 14; while (*cb == ' ') cb++; size_t i = 0; while (cb[i] && cb[i] != '\r' && i < sizeof c->base - 1) { c->base[i] = cb[i]; i++; } c->base[i] = 0; }
    else snprintf(c->base, sizeof c->base, "%s", c->url);
    int sdp_rc = parse_sdp(c, body); free(body);
    if (sdp_rc != 0) return -1;
    rc_log(c, "video track: payload type %d, control %s, sps %zu B pps %zu B", c->pt, c->control, c->sps_len, c->pps_len);
    char tr[128]; snprintf(tr, sizeof tr, "Transport: RTP/AVP/TCP;unicast;interleaved=%d-%d\r\n", c->chan_rtp, c->chan_rtp + 1);
    st = rtsp_do(c, "SETUP", c->control, tr, hdrs, sizeof hdrs, &body, &bn); free(body);
    if (st != 200) { rc_err(c, "SETUP: status %d", st); return -1; }
    if (!c->session[0]) { rc_err(c, "SETUP gave no session"); return -1; }
    const char *transport = strcasestr(hdrs, "\nTransport:");
    const char *channels = transport ? strcasestr(transport, "interleaved=") : NULL;
    if (channels) { int first, second; if (sscanf(channels + 12, "%d-%d", &first, &second) != 2 || first < 0 || first > 254 || second != first + 1) { rc_err(c, "invalid interleaved channels"); return -1; } c->chan_rtp = first; }
    st = rtsp_do(c, "PLAY", c->url, "Range: npt=0.000-\r\n", hdrs, sizeof hdrs, &body, &bn); free(body);
    if (st != 200) { rc_err(c, "PLAY: status %d", st); return -1; }
    rc_log(c, "playing, session %s", c->session);
    int rc = stream_loop(c, max_units);
    /* EOF/error cannot establish the end of a partial access unit. */
    session_request(c, "TEARDOWN");
    return rc;
}

static void rc_free(struct rc *c) { if (c->fd >= 0) close(c->fd); free(c->sps); free(c->pps); free(c->au); free(c->fu); }

static int number(const char *text, unsigned long limit, unsigned long *value) {
    char *end; errno = 0;
    if (!text || *text < '0' || *text > '9') return -1;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || *end || n > limit) return -1;
    *value = n; return 0;
}
static int option(struct rc *c, int opt, const char *arg, unsigned long *max_units) {
    unsigned long n;
    if (opt == 'v') { c->verbose = 1; return 0; }
    if (number(arg, opt == 'n' ? ULONG_MAX : opt == 't' ? INT_MAX / 1000 : INT_MAX, &n)) return -1;
    switch (opt) {
    case 'o': c->out = (int)n; break;
    case 'n': *max_units = n; break;
    case 'k': c->keepalive_s = (int)n; break;
    case 't': if (!n) return -1; c->timeout_ms = (int)n * 1000; break;
    default: return -1;
    }
    return 0;
}
/* A broken output pipe must fail this invocation without killing its shell.
 * Restore the shell's disposition on every path. */
static int run_guarded(struct rc *c, const char *url, unsigned long max_units) {
    struct sigaction old, ignore; memset(&ignore, 0, sizeof ignore);
    ignore.sa_handler = SIG_IGN; sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, &old)) { rc_err(c, "sigaction: %s", strerror(errno)); return -1; }
    int rc = rtspcat_run(c, url, max_units);
    sigaction(SIGPIPE, &old, NULL);
    return rc;
}
#ifdef RTSPCAT_STANDALONE
int main(int argc, char **argv) {
    struct rc c; memset(&c, 0, sizeof c); c.fd = -1; c.out = 1; c.keepalive_s = 25; c.timeout_ms = 15000;
    unsigned long max_units = 0;
    if (argc < 2) return 2;
    for (int i = 2; i < argc; i++) {
        if (strlen(argv[i]) != 2 || argv[i][0] != '-') return 2;
        int opt = argv[i][1]; const char *arg = NULL;
        if (opt != 'v') { if (++i == argc) return 2; arg = argv[i]; }
        if (option(&c, opt, arg, &max_units)) return 2;
    }
    int rc = run_guarded(&c, argv[1], max_units);
    if (rc) fprintf(stderr, "rtspcat: %s\n", c.err);
    if (c.verbose) fprintf(stderr, "rtspcat: %lu units, %lu packets, %lu dropped\n", c.units, c.packets, c.dropped);
    rc_free(&c); return rc == 0 ? 0 : 1;
}
#else
static int rtspcat_builtin(WORD_LIST *list) {
    struct rc c; memset(&c, 0, sizeof c); c.fd = -1; c.out = 1; c.keepalive_s = 25; c.timeout_ms = 15000;
    unsigned long max_units = 0;
    if (!list) { builtin_usage(); return EX_USAGE; }
    const char *url = list->word->word;
    reset_internal_getopt(); int opt;
    while ((opt = internal_getopt(list->next, "o:n:k:t:v")) != -1) {
        if (option(&c, opt, list_optarg, &max_units)) { builtin_usage(); return EX_USAGE; }
    }
    if (loptend) { builtin_usage(); return EX_USAGE; }
    int rc = run_guarded(&c, url, max_units);
    if (rc) builtin_error("%s (after %lu units, %lu packets, %lu dropped)", c.err, c.units, c.packets, c.dropped);
    else if (c.verbose) fprintf(stderr, "rtspcat: done, %lu units, %lu packets, %lu dropped\n", c.units, c.packets, c.dropped);
    rc_free(&c); return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *rtspcat_doc[] = {
    "RTSP/RTP H.264 client: access units out as framed records.",
    "",
    "    rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-t SECS] [-v]",
    "",
    "Connects to rtsp://[user:pass@]host[:port]/path (Basic or Digest), sets up",
    "the H.264 track over interleaved TCP, and writes each access unit to FD",
    "(default 1) as a 4-byte big-endian length followed by the unit in Annex-B",
    "form, with SPS/PPS in front of every IDR. `bashrtsp feed -l` reads one.",
    "Stops after COUNT units, or runs until the server goes away (non-zero, so",
    "a supervisor restarts it). Keepalive every SECS (default 25; 0 disables).",
    "-t sets the read timeout in seconds (default 15). -v logs statistics.",
    "Drops damaged access units on RTP loss/reordering; buffers at most 8 MiB",
    "each for an access unit and a fragmented NAL. Incomplete EOF units drop.",
    (char *)NULL
};

struct builtin rtspcat_struct = {
    "rtspcat", rtspcat_builtin, BUILTIN_ENABLED, rtspcat_doc,
    "rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-t SECS] [-v]", 0
};
#endif
