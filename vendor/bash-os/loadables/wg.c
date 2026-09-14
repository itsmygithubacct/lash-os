/* SPDX-License-Identifier: MIT */
/* wg.c — WireGuard control plane via generic netlink.
 *
 * Server-gap slice A from SERVER-GAP-WIREGUARD-ACME-PLAN.md.
 *
 * v1 verbs (do not extend without bumping the doc fence):
 *   wg genkey
 *   wg pubkey
 *   wg show [IFACE]
 *   wg set IFACE [private-key FILE] [listen-port PORT]
 *                    [peer PUBKEY [endpoint HOST:PORT] [allowed-ips IPs,...]
 *                    [persistent-keepalive SEC] [preshared-key FILE]
 *                    [remove]]...
 *   wg setconf IFACE CONF.conf
 *
 * Scope (matches the plan's slice A non-goals):
 *   - Control plane only.  Data plane is the in-kernel WireGuard
 *     driver (CONFIG_WIREGUARD=y or =m) on any kernel >= 5.6.
 *   - No userspace Noise IK, no blake2s MAC1/MAC2, no NAT traversal,
 *     no multi-peer mesh tooling.
 *   - The IFNAME create/up/addr/route part lives in
 *     rootfs/bash-os/wg-quick.sh, which wraps `ip link add type
 *     wireguard` + `ip addr add` + `wg setconf`.
 *
 * Dry-run: set BASHWG_DRY=1 to hex-dump the assembled set/get netlink
 * message bytes to stdout instead of sending them.  Used by the host-
 * side TAP suite to pin the wire format without root or a tun-capable
 * kernel.
 *
 * Cap requirements: CAP_NET_ADMIN for set verbs.  show is read-only.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "loadables.h"
#include "_mbedtls_base64.h"
#include "_mbedtls_x25519.h"

/* ------------------------------------------------------------------- *
 * WireGuard genetlink protocol (uapi/linux/wireguard.h, kernel >= 5.6) *
 * Mirror the kernel header verbatim so we are not coupled to whether   *
 * the build host's headers include it.                                 *
 * ------------------------------------------------------------------- */
#define BW_GENL_NAME    "wireguard"
#define BW_GENL_VERSION 1
#define BW_KEY_LEN      32

enum bw_cmd {
    BW_CMD_GET_DEVICE = 0,
    BW_CMD_SET_DEVICE = 1,
};

enum bw_device_attr {
    BW_DEV_A_UNSPEC = 0,
    BW_DEV_A_IFINDEX,
    BW_DEV_A_IFNAME,
    BW_DEV_A_PRIVATE_KEY,
    BW_DEV_A_PUBLIC_KEY,
    BW_DEV_A_FLAGS,
    BW_DEV_A_LISTEN_PORT,
    BW_DEV_A_FWMARK,
    BW_DEV_A_PEERS,
};

enum bw_peer_attr {
    BW_PEER_A_UNSPEC = 0,
    BW_PEER_A_PUBLIC_KEY,
    BW_PEER_A_PRESHARED_KEY,
    BW_PEER_A_FLAGS,
    BW_PEER_A_ENDPOINT,
    BW_PEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
    BW_PEER_A_LAST_HANDSHAKE_TIME,
    BW_PEER_A_RX_BYTES,
    BW_PEER_A_TX_BYTES,
    BW_PEER_A_ALLOWEDIPS,
    BW_PEER_A_PROTOCOL_VERSION,
};

enum bw_allowedip_attr {
    BW_AIP_A_UNSPEC = 0,
    BW_AIP_A_FAMILY,
    BW_AIP_A_IPADDR,
    BW_AIP_A_CIDR_MASK,
};

#define BW_DEVICE_F_REPLACE_PEERS       (1U << 0)
#define BW_PEER_F_REMOVE_ME              (1U << 0)
#define BW_PEER_F_REPLACE_ALLOWEDIPS     (1U << 1)
#define BW_PEER_F_UPDATE_ONLY            (1U << 2)

#define BW_BUFSZ 8192
#define BW_SEQ_BASE 0xb947e500U

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO     4
#endif
#define BW_NLA_ALIGN(x) (((x) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define BW_NLA_HDRLEN   BW_NLA_ALIGN(sizeof(struct nlattr))

/* Conservative cap on how many peers we accept in a single set call.
   Larger configurations need to fragment; out of slice-A scope.        */
#define BW_MAX_PEERS    64
#define BW_MAX_AIPS     128
#define BW_NETLINK_RECV_TIMEOUT_SEC 2

/* ------------------------------------------------------------------- *
 * helpers: I/O, base64 (standard alphabet), x25519                     *
 * ------------------------------------------------------------------- */

static int
bw_write_all (const unsigned char *buf, size_t n)
{
    size_t left = n;
    const unsigned char *p = buf;
    while (left > 0) {
        ssize_t w = write (STDOUT_FILENO, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            builtin_error ("write: %s", strerror (errno));
            return -1;
        }
        p += w; left -= (size_t) w;
    }
    return 0;
}

static int
bw_slurp_fd (int fd, unsigned char **out_buf, size_t *out_len)
{
    size_t cap = 1024, len = 0;
    unsigned char *buf = malloc (cap);
    if (!buf) { builtin_error ("malloc"); return -1; }
    for (;;) {
        if (len == cap) {
            cap *= 2;
            unsigned char *n = realloc (buf, cap);
            if (!n) { free (buf); builtin_error ("realloc"); return -1; }
            buf = n;
        }
        ssize_t r = read (fd, buf + len, cap - len);
        if (r < 0) { if (errno == EINTR) continue;
                     free (buf); builtin_error ("read: %s", strerror (errno));
                     return -1; }
        if (r == 0) break;
        len += (size_t) r;
    }
    *out_buf = buf; *out_len = len;
    return 0;
}

static int
bw_random_bytes (unsigned char *buf, size_t n)
{
    int fd = open ("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { builtin_error ("/dev/urandom: %s", strerror (errno)); return -1; }
    size_t left = n;
    unsigned char *p = buf;
    while (left > 0) {
        ssize_t r = read (fd, p, left);
        if (r < 0) { if (errno == EINTR) continue;
                     close (fd); builtin_error ("read: %s", strerror (errno));
                     return -1; }
        if (r == 0) { close (fd); builtin_error ("/dev/urandom: short"); return -1; }
        p += r; left -= (size_t) r;
    }
    close (fd);
    return 0;
}

/* Trim ASCII whitespace from a buffer in place; returns new length. */
static size_t
bw_trim_ws (unsigned char *buf, size_t len)
{
    size_t w = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        buf[w++] = c;
    }
    return w;
}

/* Encode 32-byte raw key into a 45-char NUL-terminated std-base64
   string (44 chars + trailing `=`).  Caller owns the buffer. */
static int
bw_key_to_base64 (const unsigned char key[BW_KEY_LEN], char out[45])
{
    size_t b64_len = 0;
    int rc = mbedtls_base64_encode ((unsigned char *) out, 45, &b64_len,
                                    key, BW_KEY_LEN);
    if (rc != 0 || b64_len != 44) return -1;
    out[44] = 0;
    return 0;
}

/* Decode a base64 string into a 32-byte raw key.  Accepts 44 base64
   chars + optional `=` padding, ignores embedded whitespace. */
static int
bw_base64_to_key (const char *s, unsigned char out[BW_KEY_LEN])
{
    unsigned char tmp[64];
    size_t tlen = 0;
    for (const char *p = s; *p && tlen < sizeof tmp; p++) {
        unsigned char c = (unsigned char) *p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        tmp[tlen++] = c;
    }
    while (tlen < 44) {
        if (tlen >= sizeof tmp) return -1;
        tmp[tlen++] = '=';
    }
    size_t dec_len = 0;
    int rc = mbedtls_base64_decode (out, BW_KEY_LEN, &dec_len, tmp, tlen);
    if (rc != 0 || dec_len != BW_KEY_LEN) return -1;
    return 0;
}

/* ------------------------------------------------------------------- *
 * netlink attribute building                                            *
 * ------------------------------------------------------------------- */

static int
bw_nla_put (unsigned char *buf, size_t *off, size_t cap,
            int type, const void *data, int alen)
{
    size_t need = BW_NLA_HDRLEN + BW_NLA_ALIGN ((size_t) alen);
    if (*off + need > cap) return -1;
    struct nlattr *nla = (struct nlattr *) (buf + *off);
    nla->nla_len = (unsigned short) (BW_NLA_HDRLEN + (size_t) alen);
    nla->nla_type = (unsigned short) type;
    if (alen > 0 && data) memcpy (buf + *off + BW_NLA_HDRLEN, data, (size_t) alen);
    /* zero-pad tail to NLA alignment */
    size_t pad = BW_NLA_ALIGN ((size_t) alen) - (size_t) alen;
    if (pad)
        memset (buf + *off + BW_NLA_HDRLEN + alen, 0, pad);
    *off += need;
    return 0;
}

static int
bw_nla_put_u16 (unsigned char *buf, size_t *off, size_t cap, int type, uint16_t v)
{
    return bw_nla_put (buf, off, cap, type, &v, sizeof v);
}

static int
bw_nla_put_u32 (unsigned char *buf, size_t *off, size_t cap, int type, uint32_t v)
{
    return bw_nla_put (buf, off, cap, type, &v, sizeof v);
}

static int
bw_nla_put_u8 (unsigned char *buf, size_t *off, size_t cap, int type, uint8_t v)
{
    return bw_nla_put (buf, off, cap, type, &v, sizeof v);
}

static int
bw_nla_put_str (unsigned char *buf, size_t *off, size_t cap, int type, const char *s)
{
    return bw_nla_put (buf, off, cap, type, s, (int) strlen (s) + 1);
}

/* Start a nested attribute.  Returns the offset of the outer nlattr
   header; caller must fill nla_len later via bw_nla_nest_end.  */
static ssize_t
bw_nla_nest_start (unsigned char *buf, size_t *off, size_t cap, int type)
{
    if (*off + BW_NLA_HDRLEN > cap) return -1;
    size_t at = *off;
    struct nlattr *nla = (struct nlattr *) (buf + at);
    nla->nla_len = 0;
    nla->nla_type = (unsigned short) (type | NLA_F_NESTED);
    *off += BW_NLA_HDRLEN;
    return (ssize_t) at;
}

static void
bw_nla_nest_end (unsigned char *buf, size_t at, size_t end_off)
{
    struct nlattr *nla = (struct nlattr *) (buf + at);
    nla->nla_len = (unsigned short) (end_off - at);
}

/* ------------------------------------------------------------------- *
 * netlink transport                                                     *
 * ------------------------------------------------------------------- */

static int
bw_open (void)
{
    int fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) {
        builtin_error ("netlink socket: %s", strerror (errno));
        return -1;
    }
    struct sockaddr_nl sa;
    memset (&sa, 0, sizeof sa);
    sa.nl_family = AF_NETLINK;
    if (bind (fd, (struct sockaddr *) &sa, sizeof sa) < 0) {
        builtin_error ("netlink bind: %s", strerror (errno));
        close (fd);
        return -1;
    }
    return fd;
}

static unsigned
bw_seq (void)
{
    static unsigned s = 0;
    if (s == 0) s = BW_SEQ_BASE ^ (unsigned) time (NULL) ^ ((unsigned) getpid () << 8);
    return ++s;
}

/* Hex-dump raw bytes to stdout for BASHWG_DRY=1 mode. */
static void
bw_hexdump (const unsigned char *buf, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        putchar (d[(buf[i] >> 4) & 0xf]);
        putchar (d[buf[i] & 0xf]);
        if ((i & 15) == 15) putchar ('\n');
        else if ((i & 1) == 1) putchar (' ');
    }
    if (n & 15) putchar ('\n');
}

static int
bw_dry_run_enabled (void)
{
    const char *e = getenv ("BASHWG_DRY");
    return e && *e && strcmp (e, "0") != 0;
}

/* Send @buf bytes of nlmsg; collect reply messages into @rbuf (caller
   provides BW_BUFSZ-sized).  On dump (NLM_F_DUMP), invoke @cb on each
   reply message until NLMSG_DONE.  On a single ACK, invoke @cb on the
   single payload message (excluding the ACK).  */
typedef int (*bw_cb_t) (struct nlmsghdr *, void *);

static int
bw_talk (int fd, unsigned char *buf, size_t buf_len, bw_cb_t cb, void *ctx)
{
    struct sockaddr_nl kaddr;
    memset (&kaddr, 0, sizeof kaddr);
    kaddr.nl_family = AF_NETLINK;
    struct iovec iov = { buf, buf_len };
    struct msghdr msg;
    memset (&msg, 0, sizeof msg);
    msg.msg_name = &kaddr;
    msg.msg_namelen = sizeof kaddr;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    if (sendmsg (fd, &msg, 0) < 0) {
        builtin_error ("netlink send: %s", strerror (errno));
        return -1;
    }

    unsigned wanted_seq = ((struct nlmsghdr *) buf)->nlmsg_seq;
    unsigned char *rbuf = malloc (BW_BUFSZ);
    if (!rbuf) { builtin_error ("malloc"); return -1; }

    int rc = 0, done = 0;
    while (!done) {
        fd_set rfds;
        FD_ZERO (&rfds);
        FD_SET (fd, &rfds);
        struct timeval tv;
        tv.tv_sec = BW_NETLINK_RECV_TIMEOUT_SEC;
        tv.tv_usec = 0;
        int ready = select (fd + 1, &rfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) continue;
            builtin_error ("netlink recv wait: %s", strerror (errno));
            rc = -1; break;
        }
        if (ready == 0) {
            builtin_error ("netlink recv timeout waiting for WireGuard generic netlink family (kernel WireGuard module unavailable?)");
            rc = -1; break;
        }
        iov.iov_base = rbuf; iov.iov_len = BW_BUFSZ;
        ssize_t s = recvmsg (fd, &msg, 0);
        if (s < 0) {
            if (errno == EINTR) continue;
            builtin_error ("netlink recv: %s", strerror (errno));
            rc = -1; break;
        }
        if (s == 0) { builtin_error ("netlink: EOF on socket"); rc = -1; break; }
        struct nlmsghdr *h = (struct nlmsghdr *) rbuf;
        while (NLMSG_OK (h, (size_t) s)) {
            if (h->nlmsg_seq != wanted_seq) { h = NLMSG_NEXT (h, s); continue; }
            if (h->nlmsg_type == NLMSG_DONE) { done = 1; break; }
            if (h->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA (h);
                if (err->error == 0) { done = 1; break; } /* ACK */
                errno = -err->error;
                builtin_error ("genetlink: %s", strerror (errno));
                if (errno == EPERM)
                    builtin_error ("(this verb needs CAP_NET_ADMIN; try as uid 0)");
                if (errno == ENODEV)
                    builtin_error ("(no such WireGuard interface; create it first via `ip link add IFACE type wireguard`)");
                if (errno == ENOENT || errno == ENOPROTOOPT)
                    builtin_error ("(kernel WireGuard module not loaded; modprobe wireguard or boot a kernel with CONFIG_WIREGUARD=y)");
                rc = -1; done = 1; break;
            }
            if (cb && cb (h, ctx) != 0) { done = 1; break; }
            h = NLMSG_NEXT (h, s);
        }
    }
    free (rbuf);
    return rc;
}

/* ------------------------------------------------------------------- *
 * genetlink family resolution                                           *
 * ------------------------------------------------------------------- */

struct bw_family_lookup { int found; uint16_t fid; };

static int
bw_family_cb (struct nlmsghdr *h, void *ctx)
{
    struct bw_family_lookup *r = (struct bw_family_lookup *) ctx;
    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (h);
    size_t rem = h->nlmsg_len - NLMSG_LENGTH (sizeof *gh);
    struct nlattr *a = (struct nlattr *) ((unsigned char *) gh + sizeof *gh);
    while (rem >= BW_NLA_HDRLEN) {
        if (a->nla_len < BW_NLA_HDRLEN || a->nla_len > rem) break;
        if ((a->nla_type & ~NLA_F_NESTED) == CTRL_ATTR_FAMILY_ID
            && a->nla_len >= BW_NLA_HDRLEN + 2) {
            memcpy (&r->fid, (unsigned char *) a + BW_NLA_HDRLEN, 2);
            r->found = 1;
        }
        size_t step = BW_NLA_ALIGN ((size_t) a->nla_len);
        if (step == 0 || step > rem) break;
        rem -= step;
        a = (struct nlattr *) ((unsigned char *) a + step);
    }
    return 0;
}

static int
bw_resolve_family (int fd, uint16_t *out_fid)
{
    unsigned char buf[256];
    memset (buf, 0, sizeof buf);
    struct nlmsghdr *nh = (struct nlmsghdr *) buf;
    nh->nlmsg_type  = GENL_ID_CTRL;
    nh->nlmsg_flags = NLM_F_REQUEST;
    nh->nlmsg_seq   = bw_seq ();
    nh->nlmsg_pid   = 0;
    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (nh);
    gh->cmd = CTRL_CMD_GETFAMILY;
    gh->version = 1;
    size_t off = NLMSG_LENGTH (sizeof *gh);
    if (bw_nla_put_str (buf, &off, sizeof buf, CTRL_ATTR_FAMILY_NAME, BW_GENL_NAME) < 0) {
        builtin_error ("genetlink: build CTRL_CMD_GETFAMILY failed"); return -1;
    }
    nh->nlmsg_len = off;
    struct bw_family_lookup r = { 0, 0 };
    if (bw_talk (fd, buf, off, bw_family_cb, &r) < 0) return -1;
    if (!r.found) {
        builtin_error ("wg: kernel WireGuard module not available "
                       "(CTRL_CMD_GETFAMILY returned no family ID for \"%s\")", BW_GENL_NAME);
        return -1;
    }
    *out_fid = r.fid;
    return 0;
}

/* ------------------------------------------------------------------- *
 * verb: genkey                                                          *
 * ------------------------------------------------------------------- */

static int
bw_genkey_cmd (WORD_LIST *args)
{
    (void) args;
    unsigned char key[BW_KEY_LEN];
    if (bw_random_bytes (key, sizeof key) < 0) return EXECUTION_FAILURE;
    /* Emit the canonical Curve25519 scalar form used by wg genkey. */
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
    char out[45];
    if (bw_key_to_base64 (key, out) < 0) {
        builtin_error ("genkey: base64 encode failed"); return EXECUTION_FAILURE;
    }
    printf ("%s\n", out);
    return EXECUTION_SUCCESS;
}

/* ------------------------------------------------------------------- *
 * verb: pubkey                                                          *
 * ------------------------------------------------------------------- */

static int
bw_pubkey_cmd (WORD_LIST *args)
{
    (void) args;
    unsigned char *in; size_t inlen;
    if (bw_slurp_fd (STDIN_FILENO, &in, &inlen) < 0) return EXECUTION_FAILURE;
    inlen = bw_trim_ws (in, inlen);
    in[inlen] = 0;
    unsigned char sk[BW_KEY_LEN], pk[BW_KEY_LEN];
    if (bw_base64_to_key ((const char *) in, sk) < 0) {
        free (in);
        builtin_error ("pubkey: input must be a 44-char std-base64 32-byte key");
        return EX_USAGE;
    }
    free (in);
    if (mbedtls_x25519_base (pk, sk) != 0) {
        builtin_error ("pubkey: x25519 scalarmult failed"); return EXECUTION_FAILURE;
    }
    char out[45];
    if (bw_key_to_base64 (pk, out) < 0) {
        builtin_error ("pubkey: base64 encode failed"); return EXECUTION_FAILURE;
    }
    printf ("%s\n", out);
    return EXECUTION_SUCCESS;
}

/* ------------------------------------------------------------------- *
 * verb: show                                                            *
 * ------------------------------------------------------------------- */

struct bw_show_ctx { int saw_any; int verbose; };

/* Walk an NLA stream into a flat index by type — only kept attrs whose
   type is <= max.  Each slot points at the nlattr header.  */
static void
bw_index_attrs (const unsigned char *buf, size_t len,
                struct nlattr **slots, int max)
{
    memset (slots, 0, sizeof (struct nlattr *) * (size_t) (max + 1));
    const unsigned char *p = buf;
    size_t rem = len;
    while (rem >= BW_NLA_HDRLEN) {
        struct nlattr *a = (struct nlattr *) p;
        if (a->nla_len < BW_NLA_HDRLEN || a->nla_len > rem) break;
        int t = a->nla_type & ~NLA_F_NESTED;
        if (t >= 0 && t <= max) slots[t] = a;
        size_t step = BW_NLA_ALIGN ((size_t) a->nla_len);
        if (step == 0 || step > rem) break;
        rem -= step; p += step;
    }
}

static void
bw_print_key (const struct nlattr *a)
{
    if (!a || a->nla_len < BW_NLA_HDRLEN + BW_KEY_LEN) { printf ("(none)\n"); return; }
    char out[45];
    if (bw_key_to_base64 ((const unsigned char *) a + BW_NLA_HDRLEN, out) < 0)
        printf ("(invalid)\n");
    else
        printf ("%s\n", out);
}

static void
bw_print_endpoint (const struct nlattr *a)
{
    if (!a) { printf ("(none)\n"); return; }
    const unsigned char *p = (const unsigned char *) a + BW_NLA_HDRLEN;
    size_t dlen = a->nla_len - BW_NLA_HDRLEN;
    if (dlen < sizeof (struct sockaddr_in)) { printf ("(short)\n"); return; }
    unsigned short fam;
    memcpy (&fam, p, 2);
    char host[INET6_ADDRSTRLEN] = "?";
    int port = 0;
    if (fam == AF_INET && dlen >= sizeof (struct sockaddr_in)) {
        struct sockaddr_in sa; memcpy (&sa, p, sizeof sa);
        inet_ntop (AF_INET, &sa.sin_addr, host, sizeof host);
        port = ntohs (sa.sin_port);
        printf ("%s:%d\n", host, port);
    } else if (fam == AF_INET6 && dlen >= sizeof (struct sockaddr_in6)) {
        struct sockaddr_in6 sa6; memcpy (&sa6, p, sizeof sa6);
        inet_ntop (AF_INET6, &sa6.sin6_addr, host, sizeof host);
        port = ntohs (sa6.sin6_port);
        printf ("[%s]:%d\n", host, port);
    } else {
        printf ("(?)\n");
    }
}

static void
bw_print_allowedips (const struct nlattr *outer)
{
    if (!outer) { printf ("(none)\n"); return; }
    const unsigned char *base = (const unsigned char *) outer + BW_NLA_HDRLEN;
    size_t left = outer->nla_len - BW_NLA_HDRLEN;
    int first = 1;
    while (left >= BW_NLA_HDRLEN) {
        struct nlattr *a = (struct nlattr *) base;
        if (a->nla_len < BW_NLA_HDRLEN || a->nla_len > left) break;
        struct nlattr *slots[BW_AIP_A_CIDR_MASK + 1];
        bw_index_attrs (base + BW_NLA_HDRLEN, a->nla_len - BW_NLA_HDRLEN,
                        slots, BW_AIP_A_CIDR_MASK);
        unsigned short fam = 0;
        unsigned char mask = 0;
        if (slots[BW_AIP_A_FAMILY])
            memcpy (&fam, (unsigned char *) slots[BW_AIP_A_FAMILY] + BW_NLA_HDRLEN, 2);
        if (slots[BW_AIP_A_CIDR_MASK])
            mask = *((unsigned char *) slots[BW_AIP_A_CIDR_MASK] + BW_NLA_HDRLEN);
        if (slots[BW_AIP_A_IPADDR]) {
            const unsigned char *ipd = (unsigned char *) slots[BW_AIP_A_IPADDR] + BW_NLA_HDRLEN;
            char host[INET6_ADDRSTRLEN] = "?";
            if (fam == AF_INET) inet_ntop (AF_INET, ipd, host, sizeof host);
            else if (fam == AF_INET6) inet_ntop (AF_INET6, ipd, host, sizeof host);
            printf ("%s%s/%u", first ? "" : ", ", host, mask);
            first = 0;
        }
        size_t step = BW_NLA_ALIGN ((size_t) a->nla_len);
        if (step == 0 || step > left) break;
        left -= step; base += step;
    }
    if (first) printf ("(none)");
    putchar ('\n');
}

static int
bw_show_cb (struct nlmsghdr *h, void *ctx)
{
    struct bw_show_ctx *c = (struct bw_show_ctx *) ctx;
    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (h);
    size_t plen = h->nlmsg_len - NLMSG_LENGTH (sizeof *gh);
    unsigned char *pbuf = (unsigned char *) gh + sizeof *gh;

    struct nlattr *dev[BW_DEV_A_PEERS + 1];
    bw_index_attrs (pbuf, plen, dev, BW_DEV_A_PEERS);
    if (!dev[BW_DEV_A_IFNAME]) return 0;
    const char *ifn = (const char *) ((unsigned char *) dev[BW_DEV_A_IFNAME] + BW_NLA_HDRLEN);
    c->saw_any = 1;
    printf ("interface: %s\n", ifn);
    printf ("  public key: "); bw_print_key (dev[BW_DEV_A_PUBLIC_KEY]);
    /* Per wg(8): private key is shown as "(hidden)" unless verbose. */
    printf ("  private key: %s\n", dev[BW_DEV_A_PRIVATE_KEY] ? "(hidden)" : "(none)");
    if (dev[BW_DEV_A_LISTEN_PORT]) {
        unsigned short port;
        memcpy (&port, (unsigned char *) dev[BW_DEV_A_LISTEN_PORT] + BW_NLA_HDRLEN, 2);
        printf ("  listening port: %u\n", port);
    }
    if (dev[BW_DEV_A_FWMARK]) {
        unsigned int fw;
        memcpy (&fw, (unsigned char *) dev[BW_DEV_A_FWMARK] + BW_NLA_HDRLEN, 4);
        if (fw) printf ("  fwmark: 0x%x\n", fw);
    }
    if (dev[BW_DEV_A_PEERS]) {
        const unsigned char *base = (unsigned char *) dev[BW_DEV_A_PEERS] + BW_NLA_HDRLEN;
        size_t left = dev[BW_DEV_A_PEERS]->nla_len - BW_NLA_HDRLEN;
        while (left >= BW_NLA_HDRLEN) {
            struct nlattr *p = (struct nlattr *) base;
            if (p->nla_len < BW_NLA_HDRLEN || p->nla_len > left) break;
            struct nlattr *pa[BW_PEER_A_PROTOCOL_VERSION + 1];
            bw_index_attrs (base + BW_NLA_HDRLEN, p->nla_len - BW_NLA_HDRLEN,
                            pa, BW_PEER_A_PROTOCOL_VERSION);
            printf ("\npeer: "); bw_print_key (pa[BW_PEER_A_PUBLIC_KEY]);
            if (pa[BW_PEER_A_ENDPOINT]) {
                printf ("  endpoint: "); bw_print_endpoint (pa[BW_PEER_A_ENDPOINT]);
            }
            if (pa[BW_PEER_A_ALLOWEDIPS]) {
                printf ("  allowed ips: ");
                bw_print_allowedips (pa[BW_PEER_A_ALLOWEDIPS]);
            }
            if (pa[BW_PEER_A_PERSISTENT_KEEPALIVE_INTERVAL]) {
                unsigned short ka;
                memcpy (&ka, (unsigned char *) pa[BW_PEER_A_PERSISTENT_KEEPALIVE_INTERVAL] + BW_NLA_HDRLEN, 2);
                if (ka) printf ("  persistent keepalive: %u seconds\n", ka);
            }
            if (pa[BW_PEER_A_LAST_HANDSHAKE_TIME]) {
                struct { long long sec, nsec; } ts = { 0, 0 };
                size_t avail = pa[BW_PEER_A_LAST_HANDSHAKE_TIME]->nla_len - BW_NLA_HDRLEN;
                if (avail >= sizeof ts) memcpy (&ts, (unsigned char *) pa[BW_PEER_A_LAST_HANDSHAKE_TIME] + BW_NLA_HDRLEN, sizeof ts);
                if (ts.sec)
                    printf ("  latest handshake: %lld seconds ago\n", (long long) time (NULL) - ts.sec);
            }
            if (pa[BW_PEER_A_RX_BYTES] || pa[BW_PEER_A_TX_BYTES]) {
                unsigned long long rx = 0, tx = 0;
                if (pa[BW_PEER_A_RX_BYTES])
                    memcpy (&rx, (unsigned char *) pa[BW_PEER_A_RX_BYTES] + BW_NLA_HDRLEN, 8);
                if (pa[BW_PEER_A_TX_BYTES])
                    memcpy (&tx, (unsigned char *) pa[BW_PEER_A_TX_BYTES] + BW_NLA_HDRLEN, 8);
                printf ("  transfer: %llu B received, %llu B sent\n", rx, tx);
            }
            size_t step = BW_NLA_ALIGN ((size_t) p->nla_len);
            if (step == 0 || step > left) break;
            left -= step; base += step;
        }
    }
    return 0;
}

static int
bw_show_cmd (WORD_LIST *args)
{
    const char *iface = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        if (iface) { builtin_error ("show: too many args"); return EX_USAGE; }
        iface = p->word->word;
    }
    if (!iface) {
        /* Slice-A scope: caller must specify an interface.  `wg show
           all` enumeration is deferred. */
        builtin_error ("show: pass an interface name (slice-A scope; wg show all is deferred)");
        return EX_USAGE;
    }

    /* Dry-run: build the GET_DEVICE message without socket I/O. */
    if (bw_dry_run_enabled ()) {
        unsigned char buf[BW_BUFSZ];
        memset (buf, 0, sizeof buf);
        struct nlmsghdr *nh = (struct nlmsghdr *) buf;
        nh->nlmsg_type = 0;       /* placeholder family id */
        nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        nh->nlmsg_seq = bw_seq ();
        struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (nh);
        gh->cmd = BW_CMD_GET_DEVICE;
        gh->version = BW_GENL_VERSION;
        size_t off = NLMSG_LENGTH (sizeof *gh);
        if (bw_nla_put_str (buf, &off, sizeof buf, BW_DEV_A_IFNAME, iface) < 0)
          { builtin_error ("show: nlattr put failed"); return EXECUTION_FAILURE; }
        nh->nlmsg_len = off;
        printf ("BASHWG_DRY: WG_CMD_GET_DEVICE ifname=%s\n", iface);
        bw_hexdump (buf, off);
        return EXECUTION_SUCCESS;
    }

    int fd = bw_open ();
    if (fd < 0) return EXECUTION_FAILURE;
    uint16_t fid;
    if (bw_resolve_family (fd, &fid) < 0) { close (fd); return EXECUTION_FAILURE; }

    unsigned char buf[BW_BUFSZ];
    memset (buf, 0, sizeof buf);
    struct nlmsghdr *nh = (struct nlmsghdr *) buf;
    nh->nlmsg_type = fid;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nh->nlmsg_seq = bw_seq ();
    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (nh);
    gh->cmd = BW_CMD_GET_DEVICE;
    gh->version = BW_GENL_VERSION;
    size_t off = NLMSG_LENGTH (sizeof *gh);
    if (bw_nla_put_str (buf, &off, sizeof buf, BW_DEV_A_IFNAME, iface) < 0) {
        builtin_error ("show: nlattr put failed"); close (fd); return EXECUTION_FAILURE;
    }
    nh->nlmsg_len = off;

    struct bw_show_ctx ctx = { 0, 0 };
    int rc = bw_talk (fd, buf, off, bw_show_cb, &ctx);
    close (fd);
    if (rc < 0) return EXECUTION_FAILURE;
    if (!ctx.saw_any) {
        builtin_error ("show: no such WireGuard interface: %s", iface);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* ------------------------------------------------------------------- *
 * verb: set / setconf (shared message-builder)                          *
 * ------------------------------------------------------------------- */

struct bw_aip {
    int family;        /* AF_INET / AF_INET6 */
    unsigned char ip[16];
    unsigned char mask;
};

struct bw_peer_spec {
    int has_pubkey;       unsigned char pubkey[BW_KEY_LEN];
    int has_psk;          unsigned char psk[BW_KEY_LEN];
    int has_endpoint;     struct sockaddr_storage ep; socklen_t ep_len;
    int has_keepalive;    unsigned short keepalive;
    int replace_aips;
    int remove_me;
    struct bw_aip aips[BW_MAX_AIPS]; int n_aips;
};

struct bw_dev_spec {
    const char *iface;
    int has_priv;        unsigned char priv[BW_KEY_LEN];
    int has_port;        unsigned short port;
    int has_fwmark;      unsigned int fwmark;
    int replace_peers;
    struct bw_peer_spec peers[BW_MAX_PEERS]; int n_peers;
};

/* Parse "host:port" or "[ipv6]:port" into a sockaddr.  Returns 0 ok. */
static int
bw_parse_endpoint (const char *s, struct sockaddr_storage *out, socklen_t *outlen)
{
    char host[1025];   /* same as NI_MAXHOST; avoid pulling <netdb.h> just for the macro */
    const char *colon;
    int v6 = 0;
    if (s[0] == '[') {
        const char *rbr = strchr (s, ']');
        if (!rbr || rbr[1] != ':') return -1;
        size_t n = (size_t) (rbr - s - 1);
        if (n >= sizeof host) return -1;
        memcpy (host, s + 1, n); host[n] = 0;
        colon = rbr + 1;
        v6 = 1;
    } else {
        colon = strrchr (s, ':');
        if (!colon) return -1;
        size_t n = (size_t) (colon - s);
        if (n >= sizeof host) return -1;
        memcpy (host, s, n); host[n] = 0;
    }
    int port = atoi (colon + 1);
    if (port <= 0 || port > 65535) return -1;
    if (!v6) {
        struct in_addr a4;
        if (inet_pton (AF_INET, host, &a4) == 1) {
            struct sockaddr_in *sa = (struct sockaddr_in *) out;
            memset (sa, 0, sizeof *sa);
            sa->sin_family = AF_INET; sa->sin_port = htons ((unsigned short) port);
            sa->sin_addr = a4;
            *outlen = sizeof *sa;
            return 0;
        }
        /* fall back to v6 parse if v4 fails (operator may have given
           a bare IPv6 without bracket form, which is technically
           ambiguous with port — wg accepts only the bracketed form). */
    }
    struct in6_addr a6;
    if (inet_pton (AF_INET6, host, &a6) == 1) {
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) out;
        memset (sa, 0, sizeof *sa);
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons ((unsigned short) port);
        sa->sin6_addr = a6;
        *outlen = sizeof *sa;
        return 0;
    }
    return -1;
}

/* Parse "10.0.0.0/24" or "fd00::/8" or bare host into one bw_aip. */
static int
bw_parse_aip (const char *s, struct bw_aip *out)
{
    char tmp[80];
    if (strlen (s) >= sizeof tmp) return -1;
    strcpy (tmp, s);
    char *slash = strchr (tmp, '/');
    int p = -1;
    if (slash) { *slash = 0; p = atoi (slash + 1); if (p < 0 || p > 128) return -1; }
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton (AF_INET, tmp, &a4) == 1) {
        memcpy (out->ip, &a4, 4);
        out->family = AF_INET;
        out->mask = (unsigned char) (slash ? p : 32);
        if (out->mask > 32) out->mask = 32;
        return 0;
    }
    if (inet_pton (AF_INET6, tmp, &a6) == 1) {
        memcpy (out->ip, &a6, 16);
        out->family = AF_INET6;
        out->mask = (unsigned char) (slash ? p : 128);
        if (out->mask > 128) out->mask = 128;
        return 0;
    }
    return -1;
}

/* Read a private-key file: "PRIVATE_KEY = <base64>" or just a bare
   base64 line. */
static int
bw_read_key_file (const char *path, unsigned char out[BW_KEY_LEN])
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { builtin_error ("open %s: %s", path, strerror (errno)); return -1; }
    unsigned char buf[256]; size_t len = 0;
    for (;;) {
        if (len >= sizeof buf - 1) break;
        ssize_t r = read (fd, buf + len, sizeof buf - 1 - len);
        if (r < 0) { if (errno == EINTR) continue;
                     close (fd); builtin_error ("read %s: %s", path, strerror (errno)); return -1; }
        if (r == 0) break;
        len += (size_t) r;
    }
    close (fd);
    buf[len] = 0;
    /* Skip leading "PrivateKey =" / "PSK =" if present. */
    char *eq = strchr ((char *) buf, '=');
    char *src = (char *) buf;
    if (eq && (eq - (char *) buf) < 32) src = eq + 1;
    return bw_base64_to_key (src, out);
}

/* Build a complete WG_CMD_SET_DEVICE message into @buf.  Returns
   bytes-written, or -1 on overflow.  */
static ssize_t
bw_build_set (unsigned char *buf, size_t cap, uint16_t fid, const struct bw_dev_spec *d)
{
    memset (buf, 0, cap);
    struct nlmsghdr *nh = (struct nlmsghdr *) buf;
    nh->nlmsg_type = fid;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nh->nlmsg_seq = bw_seq ();
    nh->nlmsg_pid = 0;
    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA (nh);
    gh->cmd = BW_CMD_SET_DEVICE;
    gh->version = BW_GENL_VERSION;
    size_t off = NLMSG_LENGTH (sizeof *gh);

    if (bw_nla_put_str (buf, &off, cap, BW_DEV_A_IFNAME, d->iface) < 0) return -1;
    if (d->replace_peers)
        if (bw_nla_put_u32 (buf, &off, cap, BW_DEV_A_FLAGS, BW_DEVICE_F_REPLACE_PEERS) < 0) return -1;
    if (d->has_priv)
        if (bw_nla_put (buf, &off, cap, BW_DEV_A_PRIVATE_KEY, d->priv, BW_KEY_LEN) < 0) return -1;
    if (d->has_port)
        if (bw_nla_put_u16 (buf, &off, cap, BW_DEV_A_LISTEN_PORT, d->port) < 0) return -1;
    if (d->has_fwmark)
        if (bw_nla_put_u32 (buf, &off, cap, BW_DEV_A_FWMARK, d->fwmark) < 0) return -1;

    if (d->n_peers > 0) {
        ssize_t peers_at = bw_nla_nest_start (buf, &off, cap, BW_DEV_A_PEERS);
        if (peers_at < 0) return -1;
        for (int i = 0; i < d->n_peers; i++) {
            const struct bw_peer_spec *p = &d->peers[i];
            ssize_t peer_at = bw_nla_nest_start (buf, &off, cap, 0);
            if (peer_at < 0) return -1;
            if (p->has_pubkey) {
                if (bw_nla_put (buf, &off, cap, BW_PEER_A_PUBLIC_KEY, p->pubkey, BW_KEY_LEN) < 0) return -1;
            }
            uint32_t pf = 0;
            if (p->remove_me)     pf |= BW_PEER_F_REMOVE_ME;
            if (p->replace_aips)  pf |= BW_PEER_F_REPLACE_ALLOWEDIPS;
            if (pf) if (bw_nla_put_u32 (buf, &off, cap, BW_PEER_A_FLAGS, pf) < 0) return -1;
            if (p->has_psk)
                if (bw_nla_put (buf, &off, cap, BW_PEER_A_PRESHARED_KEY, p->psk, BW_KEY_LEN) < 0) return -1;
            if (p->has_endpoint)
                if (bw_nla_put (buf, &off, cap, BW_PEER_A_ENDPOINT, &p->ep, (int) p->ep_len) < 0) return -1;
            if (p->has_keepalive)
                if (bw_nla_put_u16 (buf, &off, cap, BW_PEER_A_PERSISTENT_KEEPALIVE_INTERVAL, p->keepalive) < 0) return -1;
            if (p->n_aips > 0) {
                ssize_t aips_at = bw_nla_nest_start (buf, &off, cap, BW_PEER_A_ALLOWEDIPS);
                if (aips_at < 0) return -1;
                for (int j = 0; j < p->n_aips; j++) {
                    ssize_t aip_at = bw_nla_nest_start (buf, &off, cap, 0);
                    if (aip_at < 0) return -1;
                    uint16_t fam = (uint16_t) p->aips[j].family;
                    if (bw_nla_put_u16 (buf, &off, cap, BW_AIP_A_FAMILY, fam) < 0) return -1;
                    int iplen = (p->aips[j].family == AF_INET) ? 4 : 16;
                    if (bw_nla_put (buf, &off, cap, BW_AIP_A_IPADDR, p->aips[j].ip, iplen) < 0) return -1;
                    if (bw_nla_put_u8 (buf, &off, cap, BW_AIP_A_CIDR_MASK, p->aips[j].mask) < 0) return -1;
                    bw_nla_nest_end (buf, (size_t) aip_at, off);
                }
                bw_nla_nest_end (buf, (size_t) aips_at, off);
            }
            bw_nla_nest_end (buf, (size_t) peer_at, off);
        }
        bw_nla_nest_end (buf, (size_t) peers_at, off);
    }
    nh->nlmsg_len = off;
    return (ssize_t) off;
}

/* set IFACE [private-key FILE] [listen-port N] [fwmark N]
            [peer PUBKEY [endpoint H:P] [allowed-ips IP/M,...]
                         [persistent-keepalive N] [preshared-key FILE]
                         [remove]]... */
static int
bw_set_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("set: IFACE required"); return EX_USAGE; }
    struct bw_dev_spec d;
    memset (&d, 0, sizeof d);
    d.iface = args->word->word;
    WORD_LIST *p = args->next;
    struct bw_peer_spec *cur = NULL;

    while (p) {
        const char *w = p->word->word;
        if (cur && (!strcmp (w, "peer"))) cur = NULL; /* fall through; new peer */
        if (!cur && strcmp (w, "peer") == 0) {
            if (!p->next) { builtin_error ("set: peer needs PUBKEY"); return EX_USAGE; }
            if (d.n_peers >= BW_MAX_PEERS)
              { builtin_error ("set: too many peers (max %d)", BW_MAX_PEERS); return EX_USAGE; }
            cur = &d.peers[d.n_peers++];
            memset (cur, 0, sizeof *cur);
            p = p->next;
            if (bw_base64_to_key (p->word->word, cur->pubkey) < 0)
              { builtin_error ("set: peer key not a 32-byte base64"); return EX_USAGE; }
            cur->has_pubkey = 1;
            p = p->next; continue;
        }
        if (!cur) {
            /* device-level options */
            if (!strcmp (w, "private-key")) {
                if (!p->next) { builtin_error ("set: private-key needs FILE"); return EX_USAGE; }
                p = p->next;
                if (bw_read_key_file (p->word->word, d.priv) < 0) return EXECUTION_FAILURE;
                d.has_priv = 1;
            } else if (!strcmp (w, "listen-port")) {
                if (!p->next) { builtin_error ("set: listen-port needs N"); return EX_USAGE; }
                p = p->next;
                d.port = (unsigned short) atoi (p->word->word); d.has_port = 1;
            } else if (!strcmp (w, "fwmark")) {
                if (!p->next) { builtin_error ("set: fwmark needs N"); return EX_USAGE; }
                p = p->next;
                d.fwmark = (unsigned int) strtoul (p->word->word, NULL, 0); d.has_fwmark = 1;
            } else if (!strcmp (w, "replace-peers")) {
                d.replace_peers = 1;
            } else {
                builtin_error ("set: unexpected device opt: %s", w); return EX_USAGE;
            }
        } else {
            /* peer-level options */
            if (!strcmp (w, "endpoint")) {
                if (!p->next) { builtin_error ("set: endpoint needs HOST:PORT"); return EX_USAGE; }
                p = p->next;
                if (bw_parse_endpoint (p->word->word, &cur->ep, &cur->ep_len) < 0)
                    { builtin_error ("set: bad endpoint: %s", p->word->word); return EX_USAGE; }
                cur->has_endpoint = 1;
            } else if (!strcmp (w, "allowed-ips")) {
                if (!p->next) { builtin_error ("set: allowed-ips needs LIST"); return EX_USAGE; }
                p = p->next;
                cur->replace_aips = 1;
                char tmp[1024];
                if (strlen (p->word->word) >= sizeof tmp) { builtin_error ("set: allowed-ips too long"); return EX_USAGE; }
                strcpy (tmp, p->word->word);
                char *sp = tmp;
                while (*sp) {
                    while (*sp == ' ' || *sp == '\t' || *sp == ',') sp++;
                    if (!*sp) break;
                    char *end = sp;
                    while (*end && *end != ',') end++;
                    char save = *end; *end = 0;
                    if (cur->n_aips >= BW_MAX_AIPS) { builtin_error ("set: too many allowed-ips"); return EX_USAGE; }
                    if (bw_parse_aip (sp, &cur->aips[cur->n_aips]) < 0)
                        { builtin_error ("set: bad CIDR: %s", sp); return EX_USAGE; }
                    cur->n_aips++;
                    if (save == 0) break;
                    sp = end + 1;
                }
            } else if (!strcmp (w, "persistent-keepalive")) {
                if (!p->next) { builtin_error ("set: persistent-keepalive needs N"); return EX_USAGE; }
                p = p->next;
                cur->keepalive = (unsigned short) atoi (p->word->word); cur->has_keepalive = 1;
            } else if (!strcmp (w, "preshared-key")) {
                if (!p->next) { builtin_error ("set: preshared-key needs FILE"); return EX_USAGE; }
                p = p->next;
                if (bw_read_key_file (p->word->word, cur->psk) < 0) return EXECUTION_FAILURE;
                cur->has_psk = 1;
            } else if (!strcmp (w, "remove")) {
                cur->remove_me = 1;
            } else if (!strcmp (w, "peer")) {
                /* start new peer */
                continue;  /* defer; next loop iter resets cur */
            } else {
                builtin_error ("set: unexpected peer opt: %s", w); return EX_USAGE;
            }
        }
        p = p->next;
    }

    /* Dry-run: assemble against a placeholder family id and dump the
       bytes without ever talking to the kernel.  Used by host TAP. */
    if (bw_dry_run_enabled ()) {
        unsigned char buf[BW_BUFSZ];
        ssize_t mlen = bw_build_set (buf, sizeof buf, 0, &d);
        if (mlen < 0) { builtin_error ("set: message too large"); return EXECUTION_FAILURE; }
        printf ("BASHWG_DRY: WG_CMD_SET_DEVICE ifname=%s n_peers=%d msg-len=%zd\n",
                d.iface, d.n_peers, mlen);
        bw_hexdump (buf, (size_t) mlen);
        return EXECUTION_SUCCESS;
    }

    int fd = bw_open ();
    if (fd < 0) return EXECUTION_FAILURE;
    uint16_t fid;
    if (bw_resolve_family (fd, &fid) < 0) { close (fd); return EXECUTION_FAILURE; }

    unsigned char buf[BW_BUFSZ];
    ssize_t mlen = bw_build_set (buf, sizeof buf, fid, &d);
    if (mlen < 0) { builtin_error ("set: message too large"); close (fd); return EXECUTION_FAILURE; }

    int rc = bw_talk (fd, buf, (size_t) mlen, NULL, NULL);
    close (fd);
    return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ------------------------------------------------------------------- *
 * verb: setconf — read wg-quick-shape INI, build a single set call     *
 *                  (replacing all peers).                                *
 *
 * Recognised keys (per-section):
 *   [Interface]   PrivateKey, ListenPort, FwMark
 *   [Peer]        PublicKey, PresharedKey, Endpoint, AllowedIPs,
 *                 PersistentKeepalive
 * ------------------------------------------------------------------- */

static char *
bw_lstrip (char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static void
bw_rstrip (char *s)
{
    size_t n = strlen (s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = 0;
}

static int
bw_setconf_cmd (WORD_LIST *args)
{
    if (!args || !args->next) {
        builtin_error ("setconf: IFACE CONF required"); return EX_USAGE;
    }
    const char *iface = args->word->word;
    const char *path = args->next->word->word;

    FILE *fp = fopen (path, "r");
    if (!fp) { builtin_error ("setconf: open %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }

    struct bw_dev_spec d;
    memset (&d, 0, sizeof d);
    d.iface = iface;
    d.replace_peers = 1;
    enum { SEC_NONE, SEC_INTERFACE, SEC_PEER } section = SEC_NONE;
    struct bw_peer_spec *cur = NULL;

    char line[1024];
    int lineno = 0;
    while (fgets (line, sizeof line, fp)) {
        lineno++;
        char *s = bw_lstrip (line);
        bw_rstrip (s);
        if (*s == 0 || *s == '#' || *s == ';') continue;
        if (*s == '[') {
            char *rb = strchr (s, ']');
            if (!rb) continue;
            *rb = 0;
            char *name = s + 1;
            if (!strcasecmp (name, "Interface")) { section = SEC_INTERFACE; cur = NULL; }
            else if (!strcasecmp (name, "Peer")) {
                if (d.n_peers >= BW_MAX_PEERS) {
                    fclose (fp);
                    builtin_error ("setconf: %s:%d too many peers", path, lineno);
                    return EXECUTION_FAILURE;
                }
                section = SEC_PEER;
                cur = &d.peers[d.n_peers++];
                memset (cur, 0, sizeof *cur);
                cur->replace_aips = 1;
            } else {
                section = SEC_NONE; cur = NULL;
            }
            continue;
        }
        char *eq = strchr (s, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = s; bw_rstrip (k);
        char *v = bw_lstrip (eq + 1); bw_rstrip (v);

        if (section == SEC_INTERFACE) {
            if (!strcasecmp (k, "PrivateKey")) {
                if (bw_base64_to_key (v, d.priv) < 0) {
                    fclose (fp);
                    builtin_error ("setconf: %s:%d: PrivateKey must be a 32-byte base64",
                                   path, lineno);
                    return EXECUTION_FAILURE;
                }
                d.has_priv = 1;
            } else if (!strcasecmp (k, "ListenPort")) {
                d.port = (unsigned short) atoi (v); d.has_port = 1;
            } else if (!strcasecmp (k, "FwMark")) {
                d.fwmark = (unsigned int) strtoul (v, NULL, 0); d.has_fwmark = 1;
            } else if (!strcasecmp (k, "Address") || !strcasecmp (k, "DNS")
                       || !strcasecmp (k, "MTU") || !strcasecmp (k, "Table")
                       || !strcasecmp (k, "PreUp") || !strcasecmp (k, "PostUp")
                       || !strcasecmp (k, "PreDown") || !strcasecmp (k, "PostDown")
                       || !strcasecmp (k, "SaveConfig")) {
                /* wg-quick-only keys — wg ignores; wg-quick.sh
                   applies them via ip + sv hooks. */
            } else {
                fclose (fp);
                builtin_error ("setconf: %s:%d unknown [Interface] key: %s", path, lineno, k);
                return EXECUTION_FAILURE;
            }
        } else if (section == SEC_PEER && cur) {
            if (!strcasecmp (k, "PublicKey")) {
                if (bw_base64_to_key (v, cur->pubkey) < 0) {
                    fclose (fp);
                    builtin_error ("setconf: %s:%d: PublicKey must be a 32-byte base64",
                                   path, lineno);
                    return EXECUTION_FAILURE;
                }
                cur->has_pubkey = 1;
            } else if (!strcasecmp (k, "PresharedKey")) {
                if (bw_base64_to_key (v, cur->psk) < 0) {
                    fclose (fp);
                    builtin_error ("setconf: %s:%d: bad PresharedKey", path, lineno);
                    return EXECUTION_FAILURE;
                }
                cur->has_psk = 1;
            } else if (!strcasecmp (k, "Endpoint")) {
                if (bw_parse_endpoint (v, &cur->ep, &cur->ep_len) < 0) {
                    fclose (fp);
                    builtin_error ("setconf: %s:%d: bad Endpoint: %s", path, lineno, v);
                    return EXECUTION_FAILURE;
                }
                cur->has_endpoint = 1;
            } else if (!strcasecmp (k, "AllowedIPs")) {
                /* comma-separated list */
                char *sp = v;
                while (*sp) {
                    while (*sp == ' ' || *sp == '\t' || *sp == ',') sp++;
                    if (!*sp) break;
                    char *end = sp;
                    while (*end && *end != ',') end++;
                    char save = *end; *end = 0;
                    char *t = sp; bw_rstrip (t);
                    if (cur->n_aips >= BW_MAX_AIPS) {
                        fclose (fp);
                        builtin_error ("setconf: %s:%d too many AllowedIPs", path, lineno);
                        return EXECUTION_FAILURE;
                    }
                    if (bw_parse_aip (t, &cur->aips[cur->n_aips]) < 0) {
                        fclose (fp);
                        builtin_error ("setconf: %s:%d bad AllowedIP: %s", path, lineno, t);
                        return EXECUTION_FAILURE;
                    }
                    cur->n_aips++;
                    if (save == 0) break;
                    sp = end + 1;
                }
            } else if (!strcasecmp (k, "PersistentKeepalive")) {
                cur->keepalive = (unsigned short) atoi (v); cur->has_keepalive = 1;
            } else {
                fclose (fp);
                builtin_error ("setconf: %s:%d unknown [Peer] key: %s", path, lineno, k);
                return EXECUTION_FAILURE;
            }
        }
    }
    fclose (fp);

    /* Dry-run: assemble against a placeholder family id and dump
       without talking to the kernel.  Used by host TAP. */
    if (bw_dry_run_enabled ()) {
        unsigned char buf[BW_BUFSZ];
        ssize_t mlen = bw_build_set (buf, sizeof buf, 0, &d);
        if (mlen < 0) { builtin_error ("setconf: message too large"); return EXECUTION_FAILURE; }
        printf ("BASHWG_DRY: WG_CMD_SET_DEVICE (setconf) iface=%s peers=%d msg-len=%zd\n",
                d.iface, d.n_peers, mlen);
        bw_hexdump (buf, (size_t) mlen);
        return EXECUTION_SUCCESS;
    }

    int fd = bw_open ();
    if (fd < 0) return EXECUTION_FAILURE;
    uint16_t fid;
    if (bw_resolve_family (fd, &fid) < 0) { close (fd); return EXECUTION_FAILURE; }

    unsigned char buf[BW_BUFSZ];
    ssize_t mlen = bw_build_set (buf, sizeof buf, fid, &d);
    if (mlen < 0) { builtin_error ("setconf: message too large"); close (fd); return EXECUTION_FAILURE; }

    int rc = bw_talk (fd, buf, (size_t) mlen, NULL, NULL);
    close (fd);
    return rc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* ------------------------------------------------------------------- *
 * builtin entry                                                          *
 * ------------------------------------------------------------------- */

int
wg_builtin (WORD_LIST *list)
{
    if (list == 0) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;

    if (strcmp (cmd, "genkey")  == 0) return bw_genkey_cmd  (args);
    if (strcmp (cmd, "pubkey")  == 0) return bw_pubkey_cmd  (args);
    if (strcmp (cmd, "show")    == 0) return bw_show_cmd    (args);
    if (strcmp (cmd, "set")     == 0) return bw_set_cmd     (args);
    if (strcmp (cmd, "setconf") == 0) return bw_setconf_cmd (args);

    builtin_error ("unknown subcommand: %s", cmd);
    builtin_usage ();
    return EX_USAGE;
}

char *wg_doc[] = {
    "WireGuard control plane via generic netlink.",
    "",
    "Subcommands:",
    "    wg genkey                       random 32-byte private key (base64)",
    "    wg pubkey  < SK_B64             derive public key from private",
    "    wg show IFACE                   dump device + peer state",
    "    wg set IFACE [private-key FILE] [listen-port N] [fwmark N]",
    "               [replace-peers]",
    "               [peer PUBKEY [endpoint HOST:PORT] [allowed-ips IP/M,...]",
    "                            [persistent-keepalive N] [preshared-key FILE]",
    "                            [remove] ]...",
    "    wg setconf IFACE CONF.conf      apply wg-quick-shape conf, replace peers",
    "",
    "Notes:",
    "  - Control plane only.  Data plane is the in-kernel WireGuard driver",
    "    (CONFIG_WIREGUARD=y or =m).",
    "  - IFNAME create/up/addr/route belong to wg-quick.sh, which wraps",
    "    ip + wg setconf.",
    "  - BASHWG_DRY=1 hex-dumps the assembled netlink message bytes",
    "    instead of sending them (used by the host-side TAP suite).",
    (char *) NULL
};

struct builtin wg_struct = {
    "wg",
    wg_builtin,
    BUILTIN_ENABLED,
    wg_doc,
    "wg SUBCOMMAND [FLAGS...]",
    0
};
