/* rtspcat.c — an RTSP/RTP H.264 client as a bash builtin: the demux for bashrtsp.
 *
 *   rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-v]
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
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
struct rc {
    int fd, out;
    char host[256], path[512], user[128], pass[128]; int port;
    char url[1024];                 /* the URL as requested, for Digest's uri and DESCRIBE */
    char base[1024];                /* Content-Base or the URL, for relative control */
    char control[1024];             /* the video track's control URL */
    char session[128];
    char realm[128], nonce[256]; int auth; /* 0 none, 1 basic, 2 digest */
    int cseq, verbose, keepalive_s, chan_rtp;
    int pt;                         /* the H.264 payload type from the SDP */
    unsigned char *sps; size_t sps_len; unsigned char *pps; size_t pps_len;
    /* access-unit assembly */
    unsigned char *au; size_t au_len, au_cap; int au_has_ps, au_is_idr;
    unsigned char *fu; size_t fu_len, fu_cap; int fu_active;
    uint32_t ts; int have_ts;
    unsigned long units, packets, dropped;
    time_t last_keepalive;
    char err[256];
};
static void rc_err(struct rc *c, const char *fmt, ...) { va_list ap; va_start(ap, fmt); vsnprintf(c->err, sizeof c->err, fmt, ap); va_end(ap); }
static void rc_log(struct rc *c, const char *fmt, ...) {
    if (!c->verbose) return;
    va_list ap; va_start(ap, fmt); fputs("rtspcat: ", stderr); vfprintf(stderr, fmt, ap); fputc('\n', stderr); va_end(ap);
}

static int parse_url(struct rc *c, const char *url) {
    const char *p = url;
    if (strncmp(p, "rtsp://", 7) != 0) { rc_err(c, "URL must start with rtsp://"); return -1; }
    p += 7;
    const char *slash = strchr(p, '/'); const char *at = NULL;
    for (const char *q = p; *q && q != slash; q++) if (*q == '@') at = q;
    if (at) {
        const char *colon = memchr(p, ':', (size_t)(at - p));
        size_t ul = colon ? (size_t)(colon - p) : (size_t)(at - p);
        if (ul >= sizeof c->user) return -1;
        memcpy(c->user, p, ul); c->user[ul] = 0;
        if (colon) { size_t pl = (size_t)(at - colon - 1); if (pl >= sizeof c->pass) return -1; memcpy(c->pass, colon + 1, pl); c->pass[pl] = 0; }
        p = at + 1;
    }
    const char *hostend = slash ? slash : p + strlen(p);
    const char *pc = memchr(p, ':', (size_t)(hostend - p));
    size_t hl = pc ? (size_t)(pc - p) : (size_t)(hostend - p);
    if (hl == 0 || hl >= sizeof c->host) { rc_err(c, "bad host in URL"); return -1; }
    memcpy(c->host, p, hl); c->host[hl] = 0;
    c->port = pc ? atoi(pc + 1) : 554;
    if (c->port <= 0 || c->port > 65535) { rc_err(c, "bad port in URL"); return -1; }
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
    while (off < n) { ssize_t w = write(fd, b + off, n - off); if (w < 0) { if (errno == EINTR) continue; return -1; } off += (size_t)w; }
    return 0;
}
/* Read from the socket with a deadline, retrying on signals. */
static ssize_t read_wait(struct rc *c, unsigned char *p, size_t n, int timeout_ms) {
    for (;;) {
        struct pollfd pf = { .fd = c->fd, .events = POLLIN };
        int r = poll(&pf, 1, timeout_ms);
        if (r < 0) { if (errno == EINTR) continue; rc_err(c, "poll: %s", strerror(errno)); return -1; }
        if (r == 0) { rc_err(c, "no data from the server for %d ms", timeout_ms); return -1; }
        ssize_t got = read(c->fd, p, n);
        if (got < 0) { if (errno == EINTR) continue; rc_err(c, "read: %s", strerror(errno)); return -1; }
        if (got == 0) { rc_err(c, "server closed the connection"); return -1; }
        return got;
    }
}
static int read_exactly(struct rc *c, unsigned char *p, size_t n, int timeout_ms) {
    size_t have = 0;
    while (have < n) { ssize_t g = read_wait(c, p + have, n - have, timeout_ms); if (g < 0) return -1; have += (size_t)g; }
    return 0;
}

static void auth_header(struct rc *c, const char *method, const char *uri, char *out, size_t n) {
    out[0] = 0;
    if (!c->user[0]) return;
    if (c->auth == 2) {
        char a1[33], a2[33], resp[33], tmp[1024];
        snprintf(tmp, sizeof tmp, "%s:%s:%s", c->user, c->realm, c->pass); md5_str(tmp, a1);
        snprintf(tmp, sizeof tmp, "%s:%s", method, uri); md5_str(tmp, a2);
        snprintf(tmp, sizeof tmp, "%s:%s:%s", a1, c->nonce, a2); md5_str(tmp, resp);
        snprintf(out, n, "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n",
                 c->user, c->realm, c->nonce, uri, resp);
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
        char auth[1200]; auth_header(c, method, uri, auth, sizeof auth);
        char req[2048];
        int len = snprintf(req, sizeof req, "%s %s RTSP/1.0\r\nCSeq: %d\r\nUser-Agent: rtspcat\r\n%s%s%s%s\r\n",
                           method, uri, ++c->cseq,
                           c->session[0] ? "Session: " : "", c->session[0] ? c->session : "", c->session[0] ? "\r\n" : "",
                           extra ? extra : "");
        if (len <= 0 || (size_t)len >= sizeof req) { rc_err(c, "request too long"); return -1; }
        if (auth[0]) { /* insert before the blank line */
            char req2[3300]; snprintf(req2, sizeof req2, "%.*s%s\r\n", len - 2, req, auth); strcpy(req, req2); len = (int)strlen(req);
        }
        rc_log(c, "> %s %s (CSeq %d)", method, uri, c->cseq);
        if (write_all(c->fd, req, (size_t)len) != 0) { rc_err(c, "write: %s", strerror(errno)); return -1; }

        /* headers: read until \r\n\r\n; interleaved '$' data must not appear
         * here — before PLAY nothing is interleaved, and keepalives are sent
         * from the packet loop which handles both. */
        size_t hl = 0;
        for (;;) {
            unsigned char ch;
            if (read_exactly(c, &ch, 1, 10000) != 0) return -1;
            if (hl + 1 >= hdrs_n) { rc_err(c, "response headers too long"); return -1; }
            hdrs[hl++] = (char)ch; hdrs[hl] = 0;
            if (hl >= 4 && memcmp(hdrs + hl - 4, "\r\n\r\n", 4) == 0) break;
        }
        int status = 0; sscanf(hdrs, "RTSP/1.0 %d", &status);
        *body = NULL; *body_n = 0;
        const char *cl = strcasestr(hdrs, "\nContent-Length:");
        if (cl) {
            long n = atol(cl + 16);
            if (n > 0 && n < 65536) {
                *body = malloc((size_t)n + 1);
                if (!*body || read_exactly(c, (unsigned char *)*body, (size_t)n, 10000) != 0) { free(*body); *body = NULL; return -1; }
                (*body)[n] = 0; *body_n = (size_t)n;
            }
        }
        const char *sess = strcasestr(hdrs, "\nSession:");
        if (sess && !c->session[0]) { sess += 9; while (*sess == ' ') sess++; size_t i = 0; while (sess[i] && sess[i] != ';' && sess[i] != '\r' && i < sizeof c->session - 1) { c->session[i] = sess[i]; i++; } c->session[i] = 0; }
        rc_log(c, "< %d", status);
        if (status == 401 && attempt == 0 && c->user[0]) {
            const char *wa = strcasestr(hdrs, "\nWWW-Authenticate:");
            if (wa && strcasestr(wa, "Digest")) {
                const char *r = strcasestr(wa, "realm=\""); const char *nn = strcasestr(wa, "nonce=\"");
                if (r && nn) {
                    r += 7; nn += 7; size_t i;
                    for (i = 0; r[i] && r[i] != '"' && i < sizeof c->realm - 1; i++) c->realm[i] = r[i];
                    c->realm[i] = 0;
                    for (i = 0; nn[i] && nn[i] != '"' && i < sizeof c->nonce - 1; i++) c->nonce[i] = nn[i];
                    c->nonce[i] = 0;
                    c->auth = 2; free(*body); *body = NULL; continue;
                }
            }
            if (wa && strcasestr(wa, "Basic")) { c->auth = 1; free(*body); *body = NULL; continue; }
        }
        return status;
    }
    return -1;
}

/* ---- SDP: find the H.264 video track ------------------------------------- */
static int parse_sdp(struct rc *c, const char *sdp) {
    const char *line = sdp; int in_video = 0; int found = 0;
    c->pt = -1;
    while (line && *line) {
        const char *eol = strchr(line, '\n'); size_t ll = eol ? (size_t)(eol - line) : strlen(line);
        while (ll && (line[ll-1] == '\r')) ll--;
        if (ll >= 2 && line[0] == 'm' && line[1] == '=') {
            in_video = (ll > 8 && memcmp(line, "m=video ", 8) == 0) && !found;
            if (in_video) { int port, pt; char proto[32]; if (sscanf(line, "m=video %d %31s %d", &port, proto, &pt) == 3) c->pt = pt; }
        } else if (in_video && ll > 10 && memcmp(line, "a=control:", 10) == 0) {
            char v[1024]; size_t n = ll - 10; if (n >= sizeof v) n = sizeof v - 1; memcpy(v, line + 10, n); v[n] = 0;
            if (strncmp(v, "rtsp://", 7) == 0) snprintf(c->control, sizeof c->control, "%s", v);
            else { size_t bl = strlen(c->base); snprintf(c->control, sizeof c->control, "%s%s%s", c->base, (bl && c->base[bl-1] != '/' && v[0] != '/') ? "/" : "", v); }
            found = 1;
        } else if (in_video && ll > 9 && memcmp(line, "a=rtpmap:", 9) == 0) {
            int pt; char enc[64]; if (sscanf(line + 9, "%d %63s", &pt, enc) == 2 && strncasecmp(enc, "H264/", 5) == 0) c->pt = pt;
        } else if (in_video && ll > 7 && memcmp(line, "a=fmtp:", 7) == 0) {
            const char *sp = strstr(line, "sprop-parameter-sets=");
            if (sp && sp < line + ll) {
                sp += 21; const char *end = sp; while (end < line + ll && *end != ';') end++;
                const char *comma = memchr(sp, ',', (size_t)(end - sp));
                size_t l1 = comma ? (size_t)(comma - sp) : (size_t)(end - sp);
                c->sps = malloc(l1 + 4); c->sps_len = b64_decode(sp, l1, c->sps);
                if (comma) { size_t l2 = (size_t)(end - comma - 1); c->pps = malloc(l2 + 4); c->pps_len = b64_decode(comma + 1, l2, c->pps); }
            }
        }
        line = eol ? eol + 1 : NULL;
    }
    if (c->pt < 0) { rc_err(c, "no H.264 video track in the session description"); return -1; }
    if (!c->control[0]) snprintf(c->control, sizeof c->control, "%s", c->url);
    return 0;
}

/* ---- access units out ---------------------------------------------------- */
static int au_append(struct rc *c, const unsigned char *nal, size_t n) {
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
    if (type == 7 || type == 8) c->au_has_ps = 1;
    if (type == 5 && !c->au_has_ps && c->sps && c->pps) {
        /* a decoder that joins late, or was just reset, needs these */
        if (au_append(c, c->sps, c->sps_len) != 0 || au_append(c, c->pps, c->pps_len) != 0) return -1;
        c->au_has_ps = 1;
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
static int rtp_packet(struct rc *c, const unsigned char *p, size_t n) {
    if (n < 12 || (p[0] >> 6) != 2) return 0;               /* not RTP v2: ignore */
    int cc = p[0] & 0x0F, ext = p[0] & 0x10, pad = p[0] & 0x20, marker = p[1] & 0x80, pt = p[1] & 0x7F;
    uint32_t ts = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
    size_t off = 12 + (size_t)cc * 4;
    if (ext) { if (off + 4 > n) return 0; size_t xl = (((size_t)p[off+2] << 8) | p[off+3]) * 4; off += 4 + xl; }
    if (pad && n > 0) { size_t pl = p[n-1]; if (pl < n) n -= pl; }
    if (off >= n) return 0;
    if (pt != c->pt) return 0;                               /* another track on the same channel */
    c->packets++;
    /* a new timestamp is a new picture even if the sender never sets the marker */
    if (c->have_ts && ts != c->ts && c->au_len) { if (au_flush(c) != 0) return -1; }
    c->ts = ts; c->have_ts = 1;

    const unsigned char *pl = p + off; size_t pn = n - off;
    int type = pl[0] & 0x1F;
    if (type >= 1 && type <= 23) {                           /* single NAL unit */
        if (au_add_nal(c, pl, pn) != 0) return -1;
    } else if (type == 24) {                                 /* STAP-A: 16-bit size + NAL, repeated */
        size_t i = 1;
        while (i + 2 <= pn) {
            size_t sz = ((size_t)pl[i] << 8) | pl[i+1]; i += 2;
            if (sz == 0 || i + sz > pn) break;
            if (au_add_nal(c, pl + i, sz) != 0) return -1;
            i += sz;
        }
    } else if (type == 28 && pn >= 2) {                      /* FU-A: fragments of one NAL */
        int s = pl[1] & 0x80, e = pl[1] & 0x40, ntype = pl[1] & 0x1F;
        if (s) {
            c->fu_len = 0; c->fu_active = 1;
            unsigned char hdr = (unsigned char)((pl[0] & 0xE0) | ntype);
            if (c->fu_cap < 1) { c->fu_cap = 1 << 16; c->fu = malloc(c->fu_cap); if (!c->fu) { rc_err(c, "oom"); return -1; } }
            c->fu[c->fu_len++] = hdr;
        }
        if (!c->fu_active) { c->dropped++; return 0; }       /* a middle piece with no start: lost packet */
        size_t frag = pn - 2;
        if (c->fu_len + frag > c->fu_cap) {
            size_t cap = c->fu_cap; while (cap < c->fu_len + frag) cap *= 2;
            unsigned char *np = realloc(c->fu, cap); if (!np) { rc_err(c, "oom"); return -1; }
            c->fu = np; c->fu_cap = cap;
        }
        memcpy(c->fu + c->fu_len, pl + 2, frag); c->fu_len += frag;
        if (e) { c->fu_active = 0; if (au_add_nal(c, c->fu, c->fu_len) != 0) return -1; }
    } else {
        c->dropped++;                                        /* STAP-B, MTAP, FU-B: not from cameras we care about */
    }
    if (marker && c->au_len) return au_flush(c);
    return 0;
}

/* ---- the packet loop -------------------------------------------------------- */
static int keepalive(struct rc *c) {
    char req[512];
    int len = snprintf(req, sizeof req, "GET_PARAMETER %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n\r\n", c->url, ++c->cseq, c->session);
    return write_all(c->fd, req, (size_t)len);
}
static int stream_loop(struct rc *c, unsigned long max_units) {
    unsigned char *buf = malloc(65536 + 4); if (!buf) { rc_err(c, "oom"); return -1; }
    c->last_keepalive = time(NULL);
    int rc = 0;
    for (;;) {
        if (max_units && c->units >= max_units) break;
        if (c->keepalive_s > 0 && time(NULL) - c->last_keepalive >= c->keepalive_s) { if (keepalive(c) != 0) { rc_err(c, "keepalive: %s", strerror(errno)); rc = -1; break; } c->last_keepalive = time(NULL); }
        unsigned char b;
        if (read_exactly(c, &b, 1, 15000) != 0) { rc = -1; break; }
        if (b == '$') {
            unsigned char h[3]; if (read_exactly(c, h, 3, 15000) != 0) { rc = -1; break; }
            size_t len = ((size_t)h[1] << 8) | h[2];
            if (read_exactly(c, buf, len, 15000) != 0) { rc = -1; break; }
            if (h[0] == c->chan_rtp) { if (rtp_packet(c, buf, len) != 0) { rc = -1; break; } }
            /* the RTCP channel is ignored: interleaved TCP is reliable and the camera does not need reports */
        } else {
            /* an RTSP message on the control connection: a keepalive reply,
             * or an announcement. Skip to the blank line and its body. */
            char line[2048]; size_t l = 0; line[l++] = (char)b;
            long clen = 0;
            for (;;) {
                if (read_exactly(c, &b, 1, 15000) != 0) { rc = -1; goto out; }
                if (l < sizeof line - 1) line[l++] = (char)b; line[l] = 0;
                if (l >= 4 && memcmp(line + l - 4, "\r\n\r\n", 4) == 0) break;
                if (l >= sizeof line - 1) l = 0;   /* absurdly long: keep scanning */
            }
            const char *cl = strcasestr(line, "Content-Length:"); if (cl) clen = atol(cl + 15);
            while (clen-- > 0) { if (read_exactly(c, &b, 1, 15000) != 0) { rc = -1; goto out; } }
        }
    }
out:
    free(buf);
    return rc;
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
    st = rtsp_do(c, "PLAY", c->url, "Range: npt=0.000-\r\n", hdrs, sizeof hdrs, &body, &bn); free(body);
    if (st != 200) { rc_err(c, "PLAY: status %d", st); return -1; }
    rc_log(c, "playing, session %s", c->session);
    int rc = stream_loop(c, max_units);
    if (c->au_len) au_flush(c);
    /* best-effort: tell the server we are going */
    char req[512]; int len = snprintf(req, sizeof req, "TEARDOWN %s RTSP/1.0\r\nCSeq: %d\r\nSession: %s\r\n\r\n", c->url, ++c->cseq, c->session);
    write_all(c->fd, req, (size_t)len);
    return rc;
}

static void rc_free(struct rc *c) { if (c->fd >= 0) close(c->fd); free(c->sps); free(c->pps); free(c->au); free(c->fu); }

#ifdef RTSPCAT_STANDALONE
int main(int argc, char **argv) {
    struct rc c; memset(&c, 0, sizeof c); c.fd = -1; c.out = 1; c.keepalive_s = 25; c.chan_rtp = 0;
    unsigned long max_units = 0; const char *url = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) c.verbose = 1;
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) max_units = strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) c.out = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-k") && i + 1 < argc) c.keepalive_s = atoi(argv[++i]);
        else url = argv[i];
    }
    if (!url) { fprintf(stderr, "usage: rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-v]\n"); return 2; }
    int rc = rtspcat_run(&c, url, max_units);
    if (rc != 0) fprintf(stderr, "rtspcat: %s\n", c.err);
    fprintf(stderr, "rtspcat: %lu units, %lu packets, %lu dropped\n", c.units, c.packets, c.dropped);
    rc_free(&c);
    return rc == 0 ? 0 : 1;
}
#else
static int rtspcat_builtin(WORD_LIST *list) {
    struct rc c; memset(&c, 0, sizeof c); c.fd = -1; c.out = 1; c.keepalive_s = 25; c.chan_rtp = 0;
    unsigned long max_units = 0;
    if (!list) { builtin_usage(); return EX_USAGE; }
    const char *url = list->word->word;
    reset_internal_getopt();
    int opt;
    while ((opt = internal_getopt(list->next, "o:n:k:v")) != -1) {
        switch (opt) {
        case 'o': c.out = atoi(list_optarg); break;
        case 'n': max_units = strtoul(list_optarg, NULL, 10); break;
        case 'k': c.keepalive_s = atoi(list_optarg); break;
        case 'v': c.verbose = 1; break;
        default: builtin_usage(); return EX_USAGE;
        }
    }
    int rc = rtspcat_run(&c, url, max_units);
    if (rc != 0) builtin_error("%s (after %lu units, %lu packets, %lu dropped)", c.err, c.units, c.packets, c.dropped);
    else if (c.verbose) fprintf(stderr, "rtspcat: done, %lu units, %lu packets, %lu dropped\n", c.units, c.packets, c.dropped);
    rc_free(&c);
    return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

char *rtspcat_doc[] = {
    "RTSP/RTP H.264 client: access units out as framed records.",
    "",
    "    rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-v]",
    "",
    "Connects to rtsp://[user:pass@]host[:port]/path (Basic or Digest), sets up",
    "the H.264 track over interleaved TCP, and writes each access unit to FD",
    "(default 1) as a 4-byte big-endian length followed by the unit in Annex-B",
    "form, with SPS/PPS in front of every IDR. `bashrtsp feed -l` reads one.",
    "Stops after COUNT units, or runs until the server goes away (non-zero, so",
    "a supervisor restarts it). Keepalive every SECS (default 25). -v logs.",
    (char *)NULL
};

struct builtin rtspcat_struct = {
    "rtspcat", rtspcat_builtin, BUILTIN_ENABLED, rtspcat_doc,
    "rtspcat URL [-o FD] [-n COUNT] [-k SECS] [-v]", 0
};
#endif
