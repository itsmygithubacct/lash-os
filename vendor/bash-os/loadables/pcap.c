/* SPDX-License-Identifier: MIT */
/* pcap.c - Packet capture writer (libpcap classic file format).
 *
 * MISSING_LOADABLES T4 (ML-T4-02). Single builtin, four verbs:
 *
 *   pcap [-i IFACE] -w FILE [-c COUNT] [-s SNAPLEN] [-W TIMEOUT]
 *                     capture COUNT frames from IFACE (default: any),
 *                     write to FILE in classic pcap format. Decode
 *                     host-side with `tcpdump -r FILE`.
 *
 *   pcap info FILE
 *                     print pcap-file header (magic, version, snaplen,
 *                     linktype) + record count.
 *
 *   pcap selftest
 *                     TAP unit tests for the header writer / reader /
 *                     record framing. No raw socket required.
 *
 *   pcap -h | --help
 *
 * File format reference: <https://wiki.wireshark.org/Development/LibpcapFileFormat>.
 *
 *   24-byte global header   : magic + ver maj/min + thiszone + sigfigs
 *                             + snaplen + linktype
 *   per-record              : 16-byte rec hdr (ts_sec/ts_usec/incl/orig)
 *                             + incl_len bytes of frame data
 *
 * We always emit microsecond resolution (magic 0xa1b2c3d4) and
 * LINKTYPE_ETHERNET (1). AF_PACKET delivers full Ethernet frames for
 * both `lo` and `ethN`, so consumers see a uniform link type. Full
 * tcpdump decodes the result without ceremony.
 *
 * Requires CAP_NET_RAW for capture mode (info/selftest do not). uid 0
 * has it; non-root needs `setcap cap_net_raw=ep $(which bash)`. The
 * raw socket is AF_PACKET, not AF_INET SOCK_RAW, so the kernel never
 * fabricates an IP header for us — we receive bytes as the NIC sees
 * them.
 *
 * Why not the full tcpdump surface:
 *   tcpdump itself is ~30k LoC + libpcap (~40k) + BPF compiler + 50+
 *   protocol decoders. The bash-os v1 deal is: pcap captures into
 *   the same file format real tcpdump produces, and you decode with
 *   real tcpdump on the host (or `pcap info` for header sanity).
 *
 * Source counterparts: ping.c (raw-socket idioms + selftest shape),
 * libpcap's savefile.c (file format constants).
 *
 * --- LICENSE ---
 * MIT License
 *
 * Copyright (c) 2026 bash_linux contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software. See the
 * full MIT text for the standard disclaimer.
 *
 * Note: when statically linked into GNU Bash, the combined binary is a
 * derivative work of bash and is GPL-3+. MIT for this source is
 * GPL-3+-compatible, so the resulting binary's license is unchanged.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <poll.h>
#include <linux/capability.h>
#include <sys/prctl.h>

#ifndef BASHPCAP_STANDALONE
#  include <config.h>
#  include "loadables.h"
#else
#  define EXECUTION_SUCCESS 0
#  define EXECUTION_FAILURE 1
#  define EX_USAGE          2
typedef struct word_desc { char *word; } WORD_DESC;
typedef struct word_list { struct word_list *next; WORD_DESC *word; } WORD_LIST;
#  define builtin_error(...) do { fprintf (stderr, "pcap: "); \
                                  fprintf (stderr, __VA_ARGS__);  \
                                  fputc ('\n', stderr); } while (0)
#  define builtin_usage()    fprintf (stderr, "pcap: usage\n")
#  define BUILTIN_ENABLED    0
struct builtin;
#endif

/* AF_PACKET headers (Linux-only; bash-os is Linux-only by design). */
#ifndef BASHPCAP_NO_AF_PACKET
#  include <net/if.h>
#  include <netinet/in.h>
#  include <linux/if_packet.h>
#  include <linux/if_ether.h>
#endif

/* ---- file-format constants ---------------------------------------- */

#define PCAP_MAGIC_USEC    0xa1b2c3d4u   /* microsecond resolution */
#define PCAP_MAGIC_NSEC    0xa1b23c4du   /* nanosecond resolution */
#define PCAP_MAGIC_SWAPPED 0xd4c3b2a1u   /* opposite-endian usec */
#define PCAP_VERSION_MAJ   2
#define PCAP_VERSION_MIN   4

/* Subset of tcpdump's link-layer header types. */
#define LINKTYPE_NULL      0
#define LINKTYPE_ETHERNET  1
#define LINKTYPE_RAW       101
#define LINKTYPE_LINUX_SLL 113

#define BPC_DEFAULT_SNAPLEN 65535
#define BPC_DEFAULT_COUNT   5

/* Private-but-exported frame callback surface for sibling bash-os loadables
   such as netids. Kept in this TU to avoid adding a public ABI. */
struct bashpcap_frame {
    const unsigned char *data;
    uint32_t caplen;
    uint32_t origlen;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t linktype;
};

struct bashpcap_capture_opts {
    const char *iface;
    int count;
    int snaplen;
    double timeout_s;
    int keep_caps;
};

typedef int (*bashpcap_frame_cb) (const struct bashpcap_frame *, void *);

/* ---- on-disk layouts ---------------------------------------------- */

struct bpc_global_hdr {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} __attribute__((packed));

struct bpc_record_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed));

/* Sanity: catch any accidental compiler padding. */
typedef char bpc_static_global_assert
    [(sizeof (struct bpc_global_hdr) == 24) ? 1 : -1];
typedef char bpc_static_record_assert
    [(sizeof (struct bpc_record_hdr) == 16) ? 1 : -1];

/* ---- helpers ------------------------------------------------------ */

static int
bpc_write_all (int fd, const void *buf, size_t n)
{
    const char *p = buf;
    size_t left = n;
    while (left) {
        ssize_t w = write (fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        p += w;
        left -= (size_t) w;
    }
    return 0;
}

static int
bpc_read_all (int fd, void *buf, size_t n)
{
    char *p = buf;
    size_t left = n;
    while (left) {
        ssize_t r = read (fd, p, left);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return left == n ? -2 : -1;   /* -2 = clean EOF */
        p += r;
        left -= (size_t) r;
    }
    return 0;
}

static int
bpc_write_global (int fd, uint32_t snaplen, uint32_t linktype)
{
    struct bpc_global_hdr h;
    memset (&h, 0, sizeof h);
    h.magic_number  = PCAP_MAGIC_USEC;
    h.version_major = PCAP_VERSION_MAJ;
    h.version_minor = PCAP_VERSION_MIN;
    h.thiszone      = 0;
    h.sigfigs       = 0;
    h.snaplen       = snaplen;
    h.network       = linktype;
    return bpc_write_all (fd, &h, sizeof h);
}

static int
bpc_write_record (int fd, const void *data, uint32_t incl_len, uint32_t orig_len,
                  uint32_t ts_sec, uint32_t ts_usec)
{
    struct bpc_record_hdr r;
    memset (&r, 0, sizeof r);
    r.ts_sec   = ts_sec;
    r.ts_usec  = ts_usec;
    r.incl_len = incl_len;
    r.orig_len = orig_len;
    if (bpc_write_all (fd, &r, sizeof r) < 0) return -1;
    if (incl_len && bpc_write_all (fd, data, incl_len) < 0) return -1;
    return 0;
}

/* ---- info verb ---------------------------------------------------- */

static const char *
bpc_linktype_name (uint32_t lt)
{
    switch (lt) {
    case LINKTYPE_NULL:       return "NULL";
    case LINKTYPE_ETHERNET:   return "EN10MB";
    case LINKTYPE_RAW:        return "RAW";
    case LINKTYPE_LINUX_SLL:  return "LINUX_SLL";
    default:                  return "UNKNOWN";
    }
}

static int
bpc_info_file (const char *path)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) {
        builtin_error ("info: open(%s): %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    struct bpc_global_hdr h;
    if (bpc_read_all (fd, &h, sizeof h) < 0) {
        builtin_error ("info: %s: truncated global header", path);
        close (fd);
        return EXECUTION_FAILURE;
    }
    int swapped = 0;
    if (h.magic_number != PCAP_MAGIC_USEC &&
        h.magic_number != PCAP_MAGIC_NSEC) {
        if (h.magic_number == PCAP_MAGIC_SWAPPED) {
            swapped = 1;
        } else {
            builtin_error ("info: %s: bad magic 0x%08x", path,
                           (unsigned) h.magic_number);
            close (fd);
            return EXECUTION_FAILURE;
        }
    }
    uint32_t snaplen  = h.snaplen;
    uint32_t linktype = h.network;
    uint16_t vmaj     = h.version_major;
    uint16_t vmin     = h.version_minor;
    if (swapped) {
        /* Byte-swap the fields we report on (cheap, no host-endian
           dependency at runtime). */
        snaplen  = ((snaplen  & 0x000000ffu) << 24)
                 | ((snaplen  & 0x0000ff00u) <<  8)
                 | ((snaplen  & 0x00ff0000u) >>  8)
                 | ((snaplen  & 0xff000000u) >> 24);
        linktype = ((linktype & 0x000000ffu) << 24)
                 | ((linktype & 0x0000ff00u) <<  8)
                 | ((linktype & 0x00ff0000u) >>  8)
                 | ((linktype & 0xff000000u) >> 24);
        vmaj     = (uint16_t) ((vmaj << 8) | (vmaj >> 8));
        vmin     = (uint16_t) ((vmin << 8) | (vmin >> 8));
    }

    printf ("file:     %s\n", path);
    printf ("magic:    0x%08x%s\n", (unsigned) h.magic_number,
            swapped ? " (swapped endian)" : "");
    printf ("version:  %u.%u\n", (unsigned) vmaj, (unsigned) vmin);
    printf ("snaplen:  %u\n", (unsigned) snaplen);
    printf ("linktype: %u (%s)\n", (unsigned) linktype,
            bpc_linktype_name (linktype));

    /* Walk records to count them; skip-by-incl_len is cheap. */
    size_t records = 0;
    size_t total_bytes = 0;
    while (1) {
        struct bpc_record_hdr r;
        int rc = bpc_read_all (fd, &r, sizeof r);
        if (rc == -2) break;          /* clean EOF */
        if (rc < 0) {
            builtin_error ("info: %s: truncated record %zu",
                           path, records);
            close (fd);
            return EXECUTION_FAILURE;
        }
        uint32_t incl = r.incl_len;
        if (swapped) {
            incl = ((incl & 0x000000ffu) << 24)
                 | ((incl & 0x0000ff00u) <<  8)
                 | ((incl & 0x00ff0000u) >>  8)
                 | ((incl & 0xff000000u) >> 24);
        }
        if (incl > snaplen + 64) {
            builtin_error ("info: %s: record %zu len=%u exceeds snaplen+64",
                           path, records, (unsigned) incl);
            close (fd);
            return EXECUTION_FAILURE;
        }
        if (incl > 0 && lseek (fd, (off_t) incl, SEEK_CUR) == (off_t) -1) {
            builtin_error ("info: %s: seek past record %zu: %s",
                           path, records, strerror (errno));
            close (fd);
            return EXECUTION_FAILURE;
        }
        records++;
        total_bytes += incl;
    }
    printf ("records:  %zu\n", records);
    printf ("payload:  %zu bytes\n", total_bytes);
    close (fd);
    return EXECUTION_SUCCESS;
}

/* ---- capture verb ------------------------------------------------- */

#ifndef BASHPCAP_STANDALONE
/* Drop CAP_NET_RAW from the current process's effective+permitted+
   inheritable sets via the legacy capset(2) ABI (no libcap dep) AND
   from the bounding + ambient sets via prctl. The three layers close
   different regain paths:

     - legacy capset:      revokes the cap on the current thread.
     - PR_CAPBSET_DROP:    even a subsequent execve of a file with
                           CAP_NET_RAW in its file-cap permitted set
                           cannot re-grant it (the bounding set is
                           the per-thread upper bound). One-way.
     - PR_CAP_AMBIENT_LOWER: an exec'd child cannot inherit
                           CAP_NET_RAW via the ambient mechanism.

   Best-effort throughout: on EINVAL or unsupported kernels we leave
   the bit alone. Called after socket(AF_PACKET) returns so the
   post-open process can no longer open another raw socket.

   Precedent for PR_CAPBSET_DROP / PR_CAP_AMBIENT_LOWER calls and
   their best-effort posture: scripts/loadables/caps.c:266,277,
   323,330. */
static void
bpc_drop_net_raw (void)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];
    memset (&data, 0, sizeof data);
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall (SYS_capget, &hdr, data) < 0) return;
    /* CAP_NET_RAW = 13 (bit 13 in word 0). */
    uint32_t mask = ~((uint32_t) 1 << 13);
    data[0].effective   &= mask;
    data[0].permitted   &= mask;
    data[0].inheritable &= mask;
    (void) syscall (SYS_capset, &hdr, data);
    /* Bounding set drop: prevents re-acquisition via execve of a
       binary with CAP_NET_RAW in its file-cap permitted set. */
    (void) prctl (PR_CAPBSET_DROP, (unsigned long) CAP_NET_RAW, 0, 0, 0);
    /* Ambient drop: prevents an exec'd child from inheriting
       CAP_NET_RAW via the ambient mechanism (Linux 4.3+). */
    (void) prctl (PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER,
                  (unsigned long) CAP_NET_RAW, 0, 0);
}

int
bashpcap_capture_frames (const struct bashpcap_capture_opts *opts,
                         bashpcap_frame_cb cb, void *userdata)
{
#ifdef ETH_P_ALL
    const char *iface = opts ? opts->iface : NULL;
    int count = opts ? opts->count : BPC_DEFAULT_COUNT;
    int snaplen = opts ? opts->snaplen : BPC_DEFAULT_SNAPLEN;
    double timeout_s = opts ? opts->timeout_s : 1.0;
    int keep_caps = opts ? opts->keep_caps : 0;

    if (!cb) {
        builtin_error ("capture: frame callback required");
        return -1;
    }
    if (count <= 0)         count = 1;
    if (count > 1000000)    count = 1000000;
    if (snaplen <= 0)       snaplen = 64;
    if (snaplen > 65535)    snaplen = 65535;
    if (timeout_s < 0.1)    timeout_s = 0.1;
    if (timeout_s > 3600.0) timeout_s = 3600.0;

    int sock = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if (sock < 0) {
        if (errno == EPERM || errno == EACCES)
            builtin_error ("capture: CAP_NET_RAW required (try: sudo setcap cap_net_raw=ep $(which bash))");
        else
            builtin_error ("capture: socket(AF_PACKET): %s",
                           strerror (errno));
        return -1;
    }

    /* Drop CAP_NET_RAW post-open (defense in depth) unless caller passed
       -k / --keep-caps. Best-effort; older kernels may refuse silently. */
    if (!keep_caps) bpc_drop_net_raw ();

    if (iface && *iface) {
        unsigned int ifindex = if_nametoindex (iface);
        if (ifindex == 0) {
            builtin_error ("capture: no such interface: %s", iface);
            close (sock);
            return -1;
        }
        struct sockaddr_ll sll;
        memset (&sll, 0, sizeof sll);
        sll.sll_family   = AF_PACKET;
        sll.sll_protocol = htons (ETH_P_ALL);
        sll.sll_ifindex  = (int) ifindex;
        if (bind (sock, (struct sockaddr *) &sll, sizeof sll) < 0) {
            builtin_error ("capture: bind(%s): %s",
                           iface, strerror (errno));
            close (sock);
            return -1;
        }
    }

    /* Capacity: snaplen + a margin for headers we never see at this
       layer (raw frame already comes in). */
    size_t bufcap = (size_t) snaplen;
    if (bufcap < 64)    bufcap = 64;
    if (bufcap > 65535) bufcap = 65535;
    unsigned char *buf = malloc (bufcap);
    if (!buf) {
        builtin_error ("capture: malloc(%zu): %s",
                       bufcap, strerror (errno));
        close (sock);
        return -1;
    }

    int got = 0;
    /* Per-frame deadline; if we receive nothing in timeout_s seconds
       we declare the capture done early (this is the user's signal
       that traffic isn't flowing). */
    int timeout_ms = (int) (timeout_s * 1000.0);
    if (timeout_ms < 100) timeout_ms = 100;
    while (got < count) {
        struct pollfd pfd = { sock, POLLIN, 0 };
        int pr = poll (&pfd, 1, timeout_ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            builtin_error ("capture: poll: %s", strerror (errno));
            free (buf);
            close (sock);
            return -1;
        }
        if (pr == 0) {
            /* No traffic; surface partial result rather than block
               forever. */
            fprintf (stderr,
                     "pcap: capture timeout after %d/%d frames\n",
                     got, count);
            break;
        }
        ssize_t r = recv (sock, buf, bufcap, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            builtin_error ("capture: recv: %s", strerror (errno));
            free (buf);
            close (sock);
            return -1;
        }
        struct timespec ts;
        clock_gettime (CLOCK_REALTIME, &ts);
        uint32_t incl = (uint32_t) r;
        uint32_t orig = incl;            /* AF_PACKET gives us full frame */
        if (incl > (uint32_t) snaplen) incl = (uint32_t) snaplen;
        struct bashpcap_frame frame;
        memset (&frame, 0, sizeof frame);
        frame.data = buf;
        frame.caplen = incl;
        frame.origlen = orig;
        frame.ts_sec = (uint32_t) ts.tv_sec;
        frame.ts_usec = (uint32_t) (ts.tv_nsec / 1000);
        frame.linktype = LINKTYPE_ETHERNET;
        if (cb (&frame, userdata) < 0) {
            builtin_error ("capture: frame callback failed");
            free (buf);
            close (sock);
            return -1;
        }
        got++;
    }

    free (buf);
    close (sock);
    return got;
#else
    (void) opts; (void) cb; (void) userdata;
    builtin_error ("capture: AF_PACKET / ETH_P_ALL not available on this build");
    return -1;
#endif
}

struct bpc_file_writer {
    int fd;
};

static int
bpc_capture_write_frame (const struct bashpcap_frame *frame, void *userdata)
{
    struct bpc_file_writer *w = userdata;
    if (!w || w->fd < 0 || !frame) return -1;
    if (bpc_write_record (w->fd, frame->data, frame->caplen, frame->origlen,
                          frame->ts_sec, frame->ts_usec) < 0) {
        builtin_error ("capture: write record: %s", strerror (errno));
        return -1;
    }
    return 0;
}

static int
bpc_capture (const char *iface, const char *out_path,
             int count, int snaplen, double timeout_s, int keep_caps)
{
    int fd = open (out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        builtin_error ("capture: open(%s): %s",
                       out_path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (bpc_write_global (fd, (uint32_t) snaplen, LINKTYPE_ETHERNET) < 0) {
        builtin_error ("capture: write global header: %s",
                       strerror (errno));
        close (fd);
        return EXECUTION_FAILURE;
    }

    struct bashpcap_capture_opts opts;
    memset (&opts, 0, sizeof opts);
    opts.iface = iface;
    opts.count = count;
    opts.snaplen = snaplen;
    opts.timeout_s = timeout_s;
    opts.keep_caps = keep_caps;
    struct bpc_file_writer writer;
    writer.fd = fd;
    int got = bashpcap_capture_frames (&opts, bpc_capture_write_frame, &writer);

    if (got < 0) {
        close (fd);
        return EXECUTION_FAILURE;
    }
    if (fsync (fd) < 0) {
        /* Non-fatal: data is in the page cache and the kernel will
           flush it. We complain to stderr but still return success
           if we captured anything. */
        fprintf (stderr, "pcap: fsync(%s): %s\n",
                 out_path, strerror (errno));
    }
    close (fd);
    fprintf (stderr, "pcap: wrote %d frame%s to %s\n",
             got, got == 1 ? "" : "s", out_path);
    return got > 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}
#endif /* !BASHPCAP_STANDALONE */

/* ---- selftest ----------------------------------------------------- */

/* Emit one TAP line, return 0/1 to mirror the assertion status. */
static int
bpc_tap (int idx, int ok, const char *name, const char *diag)
{
    if (ok) {
        printf ("ok %d - %s\n", idx, name);
        return 0;
    }
    printf ("not ok %d - %s", idx, name);
    if (diag && *diag) printf (" # %s", diag);
    printf ("\n");
    return 1;
}

static int
bpc_selftest (void)
{
    enum { N = 8 };
    printf ("1..%d\n", N);
    int fails = 0;
    int idx = 0;

    /* Case 1: global header is exactly 24 bytes. */
    fails += bpc_tap (++idx,
                      sizeof (struct bpc_global_hdr) == 24,
                      "global header is 24 bytes",
                      NULL);

    /* Case 2: record header is exactly 16 bytes. */
    fails += bpc_tap (++idx,
                      sizeof (struct bpc_record_hdr) == 16,
                      "record header is 16 bytes",
                      NULL);

    /* Case 3: write a header to a temp file, verify magic+version+
       snaplen+linktype byte fields. */
    char tmpl[] = "/tmp/pcap.selftest.XXXXXX";
    int fd = mkstemp (tmpl);
    if (fd < 0) {
        fails += bpc_tap (++idx, 0, "header writes valid magic",
                          "mkstemp failed");
        fails += bpc_tap (++idx, 0, "header writes correct linktype",
                          "mkstemp failed");
        fails += bpc_tap (++idx, 0, "record header writes incl/orig len",
                          "mkstemp failed");
        fails += bpc_tap (++idx, 0, "record payload byte-roundtrips",
                          "mkstemp failed");
        fails += bpc_tap (++idx, 0, "info reader accepts our own output",
                          "mkstemp failed");
        fails += bpc_tap (++idx, 0, "snaplen is honored on truncation",
                          "mkstemp failed");
        return fails == 0 ? 0 : 1;
    }
    /* Always clean up the temp path even on failure. */
    unlink (tmpl);

    if (bpc_write_global (fd, BPC_DEFAULT_SNAPLEN, LINKTYPE_ETHERNET) < 0) {
        fails += bpc_tap (++idx, 0, "header writes valid magic",
                          "write_global failed");
    } else {
        lseek (fd, 0, SEEK_SET);
        struct bpc_global_hdr h;
        ssize_t got = read (fd, &h, sizeof h);
        int magic_ok = (got == (ssize_t) sizeof h)
            && (h.magic_number == PCAP_MAGIC_USEC)
            && (h.version_major == PCAP_VERSION_MAJ)
            && (h.version_minor == PCAP_VERSION_MIN);
        fails += bpc_tap (++idx, magic_ok,
                          "header writes valid magic",
                          magic_ok ? NULL : "magic/version mismatch");
    }

    /* Case 4: linktype field is LINKTYPE_ETHERNET. */
    lseek (fd, 0, SEEK_SET);
    {
        struct bpc_global_hdr h;
        read (fd, &h, sizeof h);
        int lt_ok = (h.network == LINKTYPE_ETHERNET)
            && (h.snaplen == BPC_DEFAULT_SNAPLEN);
        fails += bpc_tap (++idx, lt_ok,
                          "header writes correct linktype and snaplen",
                          lt_ok ? NULL : "linktype/snaplen mismatch");
    }

    /* Case 5: write a 12-byte payload as a record, read back the rec
       header and confirm incl_len/orig_len match. */
    {
        const unsigned char payload[12] = {
            'B','A','S','H','P','C','A','P','-','0','0','1'
        };
        lseek (fd, 0, SEEK_END);
        off_t after_global = lseek (fd, 0, SEEK_CUR);
        int wr_ok = (bpc_write_record (fd, payload,
                                       (uint32_t) sizeof payload,
                                       (uint32_t) sizeof payload,
                                       1234567, 7654) == 0);
        if (wr_ok) {
            lseek (fd, after_global, SEEK_SET);
            struct bpc_record_hdr r;
            read (fd, &r, sizeof r);
            int len_ok = (r.incl_len == sizeof payload)
                && (r.orig_len == sizeof payload)
                && (r.ts_sec == 1234567)
                && (r.ts_usec == 7654);
            fails += bpc_tap (++idx, len_ok,
                              "record header writes incl/orig len + timestamps",
                              len_ok ? NULL : "field mismatch");

            /* Case 6: payload byte-equal. */
            unsigned char rb[12];
            read (fd, rb, sizeof rb);
            int eq = memcmp (rb, payload, sizeof payload) == 0;
            fails += bpc_tap (++idx, eq,
                              "record payload byte-roundtrips",
                              eq ? NULL : "payload bytes diverge");
        } else {
            fails += bpc_tap (++idx, 0,
                              "record header writes incl/orig len + timestamps",
                              "write_record failed");
            fails += bpc_tap (++idx, 0,
                              "record payload byte-roundtrips",
                              "write_record failed");
        }
    }

    /* Case 7: re-read via info verb (its parser is the consumer-side
       half of the format). */
    {
        char path2[] = "/tmp/pcap.selftest.info.XXXXXX";
        int fd2 = mkstemp (path2);
        if (fd2 >= 0) {
            bpc_write_global (fd2, BPC_DEFAULT_SNAPLEN, LINKTYPE_ETHERNET);
            unsigned char p[4] = { 0xde, 0xad, 0xbe, 0xef };
            bpc_write_record (fd2, p, 4, 4, 100, 200);
            close (fd2);
            /* bpc_info_file prints to stdout; that's already part of
               TAP output. We redirect away by dup'ing /dev/null over
               stdout during the info pass to keep TAP clean. */
            fflush (stdout);
            int saved_stdout = dup (1);
            int devnull = open ("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2 (devnull, 1);
                close (devnull);
            }
            int rc = bpc_info_file (path2);
            fflush (stdout);
            if (saved_stdout >= 0) {
                dup2 (saved_stdout, 1);
                close (saved_stdout);
            }
            unlink (path2);
            fails += bpc_tap (++idx, rc == EXECUTION_SUCCESS,
                              "info reader accepts our own output",
                              rc == EXECUTION_SUCCESS ? NULL : "info parse failed");
        } else {
            fails += bpc_tap (++idx, 0,
                              "info reader accepts our own output",
                              "mkstemp failed");
        }
    }

    /* Case 8: snaplen truncation in the write path. We write a record
       with incl_len=4 and orig_len=8 — that's the contract the capture
       loop uses when the wire frame exceeds snaplen. The reader should
       not complain (incl_len <= snaplen+64 is the info-verb guard). */
    {
        char path3[] = "/tmp/pcap.selftest.snap.XXXXXX";
        int fd3 = mkstemp (path3);
        int ok = 0;
        if (fd3 >= 0) {
            bpc_write_global (fd3, 64, LINKTYPE_ETHERNET);
            unsigned char p[4] = { 1,2,3,4 };
            if (bpc_write_record (fd3, p, 4, 8, 0, 0) == 0)
                ok = 1;
            close (fd3);
            unlink (path3);
        }
        fails += bpc_tap (++idx, ok,
                          "snaplen truncation: incl<orig honored",
                          ok ? NULL : "write_record refused incl<orig");
    }

    close (fd);
    return fails == 0 ? 0 : 1;
}

/* ---- argv parsing ------------------------------------------------- */

static void
bpc_usage (void)
{
    fprintf (stderr,
"pcap — pcap-format packet capture writer.\n"
"  pcap [-i IFACE] -w FILE [-c COUNT] [-s SNAPLEN] [-W TIMEOUT]\n"
"  pcap info FILE\n"
"  pcap selftest\n"
"\n"
"  -i IFACE     capture interface (default: any)\n"
"  -w FILE      output pcap file (required for capture mode)\n"
"  -c COUNT     stop after COUNT frames (default %d)\n"
"  -s SNAPLEN   per-frame byte cap (default %d)\n"
"  -W TIMEOUT   per-frame poll timeout in seconds (default 1)\n"
"  -k, --keep-caps  keep CAP_NET_RAW after socket open (hardening tests)\n"
"\n"
"Requires CAP_NET_RAW for capture mode; it is dropped after socket open unless -k is set. info / selftest are unprivileged.\n",
             BPC_DEFAULT_COUNT, BPC_DEFAULT_SNAPLEN);
}

static int
bpc_dispatch (int argc, char **argv)
{
    if (argc < 1) { bpc_usage (); return EX_USAGE; }

    /* Verb forms: info / selftest / -h / --help. */
    if (strcmp (argv[0], "info") == 0) {
        if (argc < 2) {
            builtin_error ("info: FILE required");
            return EX_USAGE;
        }
        return bpc_info_file (argv[1]);
    }
    if (strcmp (argv[0], "selftest") == 0) {
        return bpc_selftest () == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
    if (strcmp (argv[0], "-h") == 0 || strcmp (argv[0], "--help") == 0) {
        bpc_usage ();
        return EXECUTION_SUCCESS;
    }

    /* Otherwise it's the capture form, parsed positionally. */
    const char *iface = NULL;
    const char *out   = NULL;
    int count   = BPC_DEFAULT_COUNT;
    int snaplen = BPC_DEFAULT_SNAPLEN;
    double tmo  = 1.0;
    int keep_caps = 0;

    int i = 0;
    while (i < argc) {
        const char *a = argv[i];
        if (strcmp (a, "-i") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp (a, "-w") == 0 && i + 1 < argc) {
            out = argv[++i];
        } else if (strcmp (a, "-c") == 0 && i + 1 < argc) {
            count = atoi (argv[++i]);
        } else if (strcmp (a, "-s") == 0 && i + 1 < argc) {
            snaplen = atoi (argv[++i]);
        } else if (strcmp (a, "-W") == 0 && i + 1 < argc) {
            tmo = atof (argv[++i]);
        } else if (strcmp (a, "-k") == 0 || strcmp (a, "--keep-caps") == 0) {
            keep_caps = 1;
        } else if (strcmp (a, "-h") == 0 || strcmp (a, "--help") == 0) {
            bpc_usage ();
            return EXECUTION_SUCCESS;
        } else {
            builtin_error ("unexpected argument: %s", a);
            return EX_USAGE;
        }
        i++;
    }

    if (!out) {
        builtin_error ("-w FILE is required for capture mode");
        return EX_USAGE;
    }
    if (count <= 0)         count = 1;
    if (count > 1000000)    count = 1000000;
    if (snaplen <= 0)       snaplen = 64;
    if (snaplen > 65535)    snaplen = 65535;
    if (tmo < 0.1)          tmo = 0.1;
    if (tmo > 3600.0)       tmo = 3600.0;

#ifndef BASHPCAP_STANDALONE
    return bpc_capture (iface, out, count, snaplen, tmo, keep_caps);
#else
    (void) iface;
    (void) keep_caps;
    builtin_error ("capture mode requires the bash builtin (not standalone)");
    return EXECUTION_FAILURE;
#endif
}

/* ---- bash glue ---------------------------------------------------- */

#ifndef BASHPCAP_STANDALONE
int
pcap_builtin (WORD_LIST *list)
{
    int argc = 0;
    for (WORD_LIST *p = list; p; p = p->next) argc++;
    char **argv = calloc ((size_t) (argc + 1), sizeof (char *));
    if (!argv) {
        builtin_error ("out of memory");
        return EXECUTION_FAILURE;
    }
    int i = 0;
    for (WORD_LIST *p = list; p; p = p->next) argv[i++] = p->word->word;
    int rc = bpc_dispatch (argc, argv);
    free (argv);
    return rc;
}

char *pcap_doc[] = {
    "Packet capture writer (libpcap classic file format).",
    "",
    "  pcap [-i IFACE] -w FILE [-c N] [-s SNAPLEN] [-W TIMEOUT]",
    "                              capture N frames to FILE",
    "  pcap info FILE          print pcap header + record count",
    "  pcap selftest           TAP unit tests (header/record/info)",
    "  pcap -h | --help        this usage",
    "",
    "Capture mode requires CAP_NET_RAW. uid 0 has it; non-root needs",
    "    sudo setcap cap_net_raw=ep $(which bash)",
    "",
    "Output is LINKTYPE_ETHERNET (1) microsecond-resolution pcap. Decode",
    "with host-side tcpdump -r FILE; sanity-check with `pcap info`.",
    (char *) NULL
};

struct builtin pcap_struct = {
    "pcap",
    pcap_builtin,
    BUILTIN_ENABLED,
    pcap_doc,
    "pcap [-i IFACE] -w FILE [-c N] [-s SNAP] [-W T] | info FILE | selftest",
    0
};
#endif /* !BASHPCAP_STANDALONE */

#ifdef BASHPCAP_STANDALONE
int
main (int argc, char **argv)
{
    return bpc_dispatch (argc - 1, argv + 1);
}
#endif
