/* bashdd.c — POSIX dd(1) subset as a bash builtin.
 *
 * Phase A.5 of bash-os shell-ergonomics. Closes the long-standing
 * "no dd in bash-os" gap that forces binhex-slurp workarounds in
 * bl-decrypt.sh and others.
 *
 *   bashdd [if=FILE] [of=FILE] [bs=N|ibs=N obs=N] [count=N]
 *          [skip=N] [seek=N]
 *          [cbs=N]
 *          [conv=notrunc,sync,noerror,swab,fsync,fdatasync,excl,nocreat,ucase,lcase,block,unblock]
 *          [iflag=fullblock,count_bytes,skip_bytes]
 *          [oflag=append,seek_bytes]
 *          [status=none|noxfer|progress]
 *
 * v2 surface is a sbase/toybox-equivalent subset. The mainframe conv=
 * ascii/ebcdic variants are dropped, but cbs= + conv=block/unblock
 * (record reblocking, GNU dd byte-exact) and ucase/lcase ARE supported.
 *
 * Block sizes accept POSIX suffixes:
 *   c=1, w=2, b=512, k=1024, K=1000, M=1024^2, G=1024^3
 *   xN multiplier:  bs=2x1024 → 2048
 *
 * Differences from POSIX:
 *   conv=ascii|ebcdic                            — pipe through tr
 *   (conv=ucase/lcase/block/unblock ARE supported; cbs=N supported.)
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
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "loadables.h"

/* conv=  */
#define DDC_NOTRUNC   (1<<0)
#define DDC_SYNC      (1<<1)
#define DDC_NOERROR   (1<<2)
#define DDC_SWAB      (1<<3)
#define DDC_FSYNC     (1<<4)
#define DDC_FDATASYNC (1<<5)
#define DDC_EXCL      (1<<6)
#define DDC_NOCREAT   (1<<7)
#define DDC_UCASE     (1<<8)
#define DDC_LCASE     (1<<9)
#define DDC_BLOCK     (1<<10)
#define DDC_UNBLOCK   (1<<11)
/* iflag= */
#define DDI_FULLBLOCK (1<<0)
#define DDI_COUNT_BYTES (1<<1)
#define DDI_SKIP_BYTES  (1<<2)
/* oflag= */
#define DDO_APPEND    (1<<0)
#define DDO_SEEK_BYTES (1<<1)
/* status= */
#define DDS_NONE      (1<<0)
#define DDS_NOXFER    (1<<1)
#define DDS_PROGRESS  (1<<2)

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

static volatile sig_atomic_t dd_sigusr1_progress;

static void
dd_sigusr1_handler (int sig)
{
    (void) sig;
    dd_sigusr1_progress = 1;
}

/* parsesize — POSIX 'c/w/b/k/K/M/G' + 'xN' multiplier expressions.
   Mirrors vendor/sbase/dd.c:19-39 but returns -1 on parse error
   instead of calling eprintf. */
static long long
dd_parsesize (const char *expr)
{
    const char *s = expr;
    long long n = 1;
    char *end;
    for (;;) {
        long long v;
        long long factor = 1;
        if (*s == '-') return -1;
        errno = 0;
        v = strtoll (s, &end, 10);
        if (errno || end == s || v < 0) return -1;
        if (n != 0 && v > LLONG_MAX / n) return -1;
        n *= v;
        s = end;
        switch (*s) {
            case 'c': factor = 1;          s++; break;
            case 'w': factor = 2;          s++; break;
            case 'b': factor = 512;        s++; break;
            case 'k': factor = 1024;       s++; break;
            case 'K': factor = 1000;       s++; break;
            case 'M': factor = 1048576;    s++; break;
            case 'G': factor = 1073741824; s++; break;
            default: break;
        }
        if (factor != 1) {
            if (n != 0 && factor > LLONG_MAX / n) return -1;
            n *= factor;
        }
        if (*s != 'x' || !s[1]) break;
        s++;
    }
    if (*s || n < 0) return -1;
    return n;
}

static int
dd_parse_nonnegative (const char *val, long long *out)
{
    long long n = dd_parsesize (val);
    if (n < 0) return -1;
    *out = n;
    return 0;
}

static int
dd_parse_positive (const char *val, long long *out)
{
    long long n = dd_parsesize (val);
    if (n <= 0) return -1;
    *out = n;
    return 0;
}

/* Stateful conv=swab matching GNU dd: swapping is global across the whole
   output stream, not per-block. An unpaired trailing byte in one block is
   carried and swapped with the first byte of the next block. This matters
   for odd block sizes (and conv=swab,sync, where sync pads the final block
   *before* swabbing). Returns the number of bytes now ready in `out`
   (which the caller owns and must size to at least `len + 1`). The carry
   state lives in *carry / *have_carry across calls; flush with len==0 to
   emit any final held byte. */
static size_t
dd_swab_stream (const unsigned char *in, size_t len,
                unsigned char *out,
                unsigned char *carry, int *have_carry)
{
    size_t oi = 0;
    size_t i = 0;
    if (len == 0) {
        /* Flush: emit a held byte unpaired (GNU leaves it as-is). */
        if (*have_carry) {
            out[oi++] = *carry;
            *have_carry = 0;
        }
        return oi;
    }
    if (*have_carry) {
        /* Pair the held byte with the first new byte: GNU swaps them so
           the new byte is emitted first, then the held byte. */
        out[oi++] = in[0];
        out[oi++] = *carry;
        *have_carry = 0;
        i = 1;
    }
    for (; i + 1 < len; i += 2) {
        out[oi++] = in[i + 1];
        out[oi++] = in[i];
    }
    if (i < len) {
        /* Odd leftover — hold it for the next block. */
        *carry = in[i];
        *have_carry = 1;
    }
    return oi;
}

/* conv=ucase / conv=lcase byte-at-a-time case fold. */
static void
dd_case (unsigned char *buf, size_t len, int up)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = up ? (unsigned char) toupper (buf[i])
                    : (unsigned char) tolower (buf[i]);
}

/* conv=block / conv=unblock record-reblocking state, carried across read
   blocks (records may span the boundary between two input reads). GNU dd
   treats the input as a record stream independent of ibs/obs, so the
   conversion is stateful and the produced output is concatenated. */
typedef struct {
    long long cbs;          /* conversion-block size (record width)      */
    long long col;          /* bytes seen in the current record so far   */
    int started;            /* a record byte has been seen since the last
                               newline (block) / since last flush         */
    int trunc_marked;       /* block: this record already counted truncated */
    long long truncated;    /* block: total truncated-record count        */
    long long pending_sp;   /* unblock: trailing spaces held back, emitted
                               only if a non-space follows (else dropped)  */
} dd_block_state;

/* conv=block: input is newline-delimited records. Each record is emitted as
   exactly cbs bytes — short records space-padded, long records truncated to
   cbs (the overflow discarded, counted once). The newline itself is removed.
   Returns the number of bytes written to *out (caller sizes out >= len*?).
   Worst-case expansion: a stream of empty records ("\n\n...") yields cbs
   bytes per input newline, so the caller must size out to len*cbs. With
   len==0 this flushes a final unterminated record (padded to cbs). */
static size_t
dd_block_stream (const unsigned char *in, size_t len,
                 unsigned char *out, dd_block_state *st)
{
    size_t oi = 0;
    if (len == 0) {
        /* EOF flush: a record in progress (no terminating newline) is still
           padded out to cbs. A record that ended exactly on a newline left
           started=0, so nothing is emitted here. */
        if (st->started) {
            while (st->col < st->cbs) { out[oi++] = ' '; st->col++; }
            st->started = 0;
            st->col = 0;
            st->trunc_marked = 0;
        }
        return oi;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = in[i];
        if (c == '\n') {
            while (st->col < st->cbs) { out[oi++] = ' '; st->col++; }
            st->col = 0;
            st->started = 0;
            st->trunc_marked = 0;
        } else {
            st->started = 1;
            if (st->col < st->cbs) {
                out[oi++] = c;
                st->col++;
            } else if (!st->trunc_marked) {
                st->trunc_marked = 1;
                st->truncated++;
            }
        }
    }
    return oi;
}

/* conv=unblock: input is fixed cbs-byte records. For each, trailing spaces
   are stripped and a newline appended. We process byte-at-a-time across the
   record stream: spaces are held in pending_sp; a non-space first flushes
   the held spaces, then itself; at record boundary (col == cbs) any held
   trailing spaces are dropped and a newline is emitted. With len==0 this
   flushes a final short record (held spaces dropped, newline appended) —
   but only if the record had any bytes at all. Worst case the output adds
   at most one newline per cbs bytes plus held spaces, so out sized to
   len + 1 (per call, with the EOF flush emitting <= cbs+1) is sufficient
   when the caller buffers held spaces in state; here held spaces are not
   yet emitted, so out >= len + 1 suffices for the streaming calls and the
   final flush needs >= 1. Caller sizes out to len + 1. */
static size_t
dd_unblock_stream (const unsigned char *in, size_t len,
                   unsigned char *out, dd_block_state *st)
{
    size_t oi = 0;
    if (len == 0) {
        /* EOF flush: a short final record (col>0) gets its newline; held
           trailing spaces are dropped. A record that ended exactly on a
           boundary (col==0) emitted its newline already. */
        if (st->col > 0) {
            out[oi++] = '\n';
            st->col = 0;
            st->pending_sp = 0;
        }
        return oi;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = in[i];
        if (c == ' ') {
            st->pending_sp++;
        } else {
            while (st->pending_sp > 0) { out[oi++] = ' '; st->pending_sp--; }
            out[oi++] = c;
        }
        st->col++;
        if (st->col == st->cbs) {
            /* End of a full record: drop held trailing spaces, terminate. */
            st->pending_sp = 0;
            out[oi++] = '\n';
            st->col = 0;
        }
    }
    return oi;
}

/* Lookup-table entry shared by conv/iflag/oflag/status flag parsers. */
typedef struct { const char *name; int bit; } dd_flag_entry;

extern char *dd_doc[];

/* Parse a comma-separated flag list and OR matching bits into *out. */
static int
dd_parse_flags (const char *spec, const dd_flag_entry *table, int *out)
{
    char buf[256];
    if (strlen (spec) >= sizeof buf) return -1;
    strcpy (buf, spec);
    char *save = NULL;
    for (char *tok = strtok_r (buf, ",", &save); tok;
         tok = strtok_r (NULL, ",", &save)) {
        int hit = 0;
        for (int i = 0; table[i].name; i++) {
            if (!strcmp (tok, table[i].name)) {
                *out |= table[i].bit;
                hit = 1;
                break;
            }
        }
        if (!hit) {
            builtin_error ("unknown flag value: %s", tok);
            builtin_usage ();
            return -1;
        }
    }
    return 0;
}

/* Repeatedly read until `want` bytes are filled or EOF/error. Used
   when iflag=fullblock — POSIX dd's default short-read on pipes is
   the canonical bashdd-fixes-everything use case. */
static ssize_t
dd_read_full (int fd, void *buf, size_t want)
{
    size_t got = 0;
    while (got < want) {
        ssize_t r = read (fd, (char *) buf + got, want - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;        /* EOF */
        got += (size_t) r;
    }
    return (ssize_t) got;
}

/* Skip bytes on input. Try lseek first; if input is a pipe /
   non-seekable, fall back to read-and-discard (POSIX skip semantic). */
static int
dd_skip_bytes (int fd, long long nbytes)
{
    if (nbytes <= 0) return 0;
    off_t total = (off_t) nbytes;
    if (lseek (fd, total, SEEK_CUR) >= 0) return 0;
    if (errno != ESPIPE) {
        builtin_error ("skip lseek: %s", strerror (errno));
        return -1;
    }
    /* Pipe: read+discard. */
    char buf[8192];
    while (total > 0) {
        size_t want = total > (off_t) sizeof buf ? sizeof buf : (size_t) total;
        ssize_t r = read (fd, buf, want);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) break;
        total -= r;
    }
    return 0;
}

static double
dd_now_seconds (void)
{
    struct timeval tv;
    if (gettimeofday (&tv, NULL) < 0) return 0.0;
    return (double) tv.tv_sec + (double) tv.tv_usec / 1000000.0;
}

static void
dd_human (long long bytes, int iec, char *out, size_t outsz)
{
    const char *si_units[] = { "B", "kB", "MB", "GB", "TB", "PB", "EB" };
    const char *iec_units[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
    const char **units = iec ? iec_units : si_units;
    double v = (double) bytes;
    double base = iec ? 1024.0 : 1000.0;
    size_t u = 0;

    while (v >= base && u < 6) {
        v /= base;
        u++;
    }
    if (u == 0)
        snprintf (out, outsz, "%lld %s", bytes, units[u]);
    else if (v >= 100.0)
        snprintf (out, outsz, "%.0f %s", v, units[u]);
    else if (v >= 10.0)
        snprintf (out, outsz, "%.1f %s", v, units[u]);
    else
        snprintf (out, outsz, "%.2f %s", v, units[u]);
}

static void
dd_print_xfer (long long bytes, double elapsed, int progress)
{
    char si[32], iec[32], rate[32];
    double secs = elapsed > 0.000001 ? elapsed : 0.000001;
    dd_human (bytes, 0, si, sizeof si);
    dd_human (bytes, 1, iec, sizeof iec);
    dd_human ((long long) ((double) bytes / secs), 0, rate, sizeof rate);
    fprintf (stderr, "%lld bytes (%s, %s) copied, %.3f s, %s/s%s\n",
             bytes, si, iec, secs, rate, progress ? " [progress]" : "");
}

int
dd_builtin (WORD_LIST *list)
{
    long long bs    = 0;
    long long ibs   = 512, obs = 512;
    long long cbs   = 0;
    long long count = -1;
    long long skip  = 0,   seek = 0;
    int conv = 0, iflag = 0, oflag = 0, status = 0;
    const char *iname = "-", *oname = "-";

    static const dd_flag_entry conv_tbl[] = {
        { "notrunc", DDC_NOTRUNC },
        { "sync",    DDC_SYNC    },
        { "noerror", DDC_NOERROR },
        { "swab",    DDC_SWAB    },
        { "fsync",   DDC_FSYNC   },
        { "fdatasync", DDC_FDATASYNC },
        { "excl",    DDC_EXCL    },
        { "nocreat", DDC_NOCREAT },
        { "ucase",   DDC_UCASE   },
        { "lcase",   DDC_LCASE   },
        { "block",   DDC_BLOCK   },
        { "unblock", DDC_UNBLOCK },
        { NULL, 0 }
    };
    static const dd_flag_entry iflag_tbl[] = {
        { "fullblock", DDI_FULLBLOCK },
        { "count_bytes", DDI_COUNT_BYTES },
        { "skip_bytes",  DDI_SKIP_BYTES  },
        { NULL, 0 }
    };
    static const dd_flag_entry oflag_tbl[] = {
        { "append", DDO_APPEND },
        { "seek_bytes", DDO_SEEK_BYTES },
        { NULL, 0 }
    };
    static const dd_flag_entry status_tbl[] = {
        { "none",   DDS_NONE   },
        { "noxfer", DDS_NOXFER },
        { "progress", DDS_PROGRESS },
        { NULL, 0 }
    };

    /* Parse key=value operands. */
    for (WORD_LIST *l = list; l; l = l->next) {
        const char *arg = l->word->word;
        if (!strcmp (arg, "--help")) {
            for (char **dp = dd_doc; *dp; dp++) puts (*dp);
            return EXECUTION_SUCCESS;
        }
        if (!strcmp (arg, "--version")) {
            puts ("bashdd 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        const char *eq = strchr (arg, '=');
        if (!eq) {
            builtin_error ("bad operand (no =): %s", arg);
            builtin_usage ();
            return EX_USAGE;
        }
        size_t klen = (size_t) (eq - arg);
        const char *val = eq + 1;
#define K(s) (klen == strlen (s) && !memcmp (arg, s, klen))
        if      (K ("if"))     iname = val;
        else if (K ("of"))     oname = val;
        else if (K ("bs"))     { if (dd_parse_positive (val, &bs)    < 0) goto bad_size; }
        else if (K ("ibs"))    { if (dd_parse_positive (val, &ibs)   < 0) goto bad_size; }
        else if (K ("obs"))    { if (dd_parse_positive (val, &obs)   < 0) goto bad_size; }
        else if (K ("cbs"))    { if (dd_parse_positive (val, &cbs)   < 0) goto bad_size; }
        else if (K ("count"))  { if (dd_parse_nonnegative (val, &count) < 0) goto bad_size; }
        else if (K ("skip"))   { if (dd_parse_nonnegative (val, &skip)  < 0) goto bad_size; }
        else if (K ("seek"))   { if (dd_parse_nonnegative (val, &seek)  < 0) goto bad_size; }
        else if (K ("conv"))   { if (dd_parse_flags (val, conv_tbl,   &conv)   < 0) return EX_USAGE; }
        else if (K ("iflag"))  { if (dd_parse_flags (val, iflag_tbl,  &iflag)  < 0) return EX_USAGE; }
        else if (K ("oflag"))  { if (dd_parse_flags (val, oflag_tbl,  &oflag)  < 0) return EX_USAGE; }
        else if (K ("status")) { if (dd_parse_flags (val, status_tbl, &status) < 0) return EX_USAGE; }
        else {
            builtin_error ("unknown operand: %.*s", (int) klen, arg);
            builtin_usage ();
            return EX_USAGE;
        }
#undef K
        continue;
    bad_size:
        builtin_error ("bad size: %s", val);
        builtin_usage ();
        return EX_USAGE;
    }
    if (bs > 0) { ibs = bs; obs = bs; }

    /* GNU dd rejects combining the two reblocking modes. */
    if ((conv & DDC_BLOCK) && (conv & DDC_UNBLOCK)) {
        builtin_error ("cannot combine block and unblock");
        builtin_usage ();
        return EX_USAGE;
    }
    /* conv=block/unblock with cbs unset (0) is an identity passthrough in
       GNU dd, so only treat the reblocking as active when cbs > 0. */
    int reblock = (conv & (DDC_BLOCK | DDC_UNBLOCK)) && cbs > 0;

    /* Open input. "-" means stdin. */
    int ifd;
    if (!strcmp (iname, "-")) {
        ifd = STDIN_FILENO;
    } else {
        ifd = open (iname, O_RDONLY | O_CLOEXEC);
        if (ifd < 0) {
            builtin_error ("if=%s: %s", iname, strerror (errno));
            return EXECUTION_FAILURE;
        }
    }

    /* Open output. "-" means stdout. conv=notrunc inhibits O_TRUNC so
       in-place writes keep data outside the written range. */
    int ofd;
    if (!strcmp (oname, "-")) {
        ofd = STDOUT_FILENO;
    } else {
        int flags = O_WRONLY | O_CREAT;
        if (conv & DDC_NOCREAT) flags &= ~O_CREAT;
        if (conv & DDC_EXCL) flags |= O_EXCL;
        if (!(conv & DDC_NOTRUNC)) flags |= O_TRUNC;
        if (oflag & DDO_APPEND) flags |= O_APPEND;
        ofd = open (oname, flags | O_CLOEXEC, 0644);
        if (ofd < 0) {
            builtin_error ("of=%s: %s", oname, strerror (errno));
            if (ifd != STDIN_FILENO) close (ifd);
            return EXECUTION_FAILURE;
        }
    }

    /* Apply skip / seek. */
    long long skip_bytes = skip;
    if (!(iflag & DDI_SKIP_BYTES)) {
        if (skip != 0 && ibs > LLONG_MAX / skip) {
            builtin_error ("skip offset overflow");
            if (ifd != STDIN_FILENO)  close (ifd);
            if (ofd != STDOUT_FILENO) close (ofd);
            return EXECUTION_FAILURE;
        }
        skip_bytes = ibs * skip;
    }
    if (skip > 0 && dd_skip_bytes (ifd, skip_bytes) < 0) {
        if (ifd != STDIN_FILENO)  close (ifd);
        if (ofd != STDOUT_FILENO) close (ofd);
        return EXECUTION_FAILURE;
    }
    if (seek > 0) {
        long long seek_bytes = seek;
        if (!(oflag & DDO_SEEK_BYTES)) {
            if (obs > LLONG_MAX / seek) {
                builtin_error ("seek offset overflow");
                if (ifd != STDIN_FILENO)  close (ifd);
                if (ofd != STDOUT_FILENO) close (ofd);
                return EXECUTION_FAILURE;
            }
            seek_bytes = obs * seek;
        }
        if (lseek (ofd, (off_t) seek_bytes, SEEK_CUR) < 0) {
            builtin_error ("seek lseek: %s", strerror (errno));
            if (ifd != STDIN_FILENO)  close (ifd);
            if (ofd != STDOUT_FILENO) close (ofd);
            return EXECUTION_FAILURE;
        }
    }

    /* Main copy loop. */
    long long ifull = 0, ipart = 0, ofull = 0, opart = 0;
    long long bytes_total = 0;
    double start_time = dd_now_seconds ();
    double next_progress = start_time + 1.0;
    struct sigaction old_usr1;
    int have_usr1 = 0;

    if (status & DDS_PROGRESS) {
        struct sigaction sa;
        memset (&sa, 0, sizeof sa);
        sa.sa_handler = dd_sigusr1_handler;
        sigemptyset (&sa.sa_mask);
        if (sigaction (SIGUSR1, &sa, &old_usr1) == 0) {
            have_usr1 = 1;
            dd_sigusr1_progress = 0;
        }
    }

    unsigned char *ibuf = malloc ((size_t) ibs);
    /* Swab is global across blocks (GNU semantics): a held carry byte may
       prepend the next block's output, so the swab buffer needs room for
       ibs + 1 bytes. */
    unsigned char *swbuf = NULL;
    unsigned char swab_carry = 0;
    int swab_have_carry = 0;
    if ((conv & DDC_SWAB) && ibs > 0)
        swbuf = malloc ((size_t) ibs + 1);

    /* conv=block/unblock reblocking buffer + carried record state. block
       can expand (empty records emit cbs spaces each), so size to
       ibs*cbs+1; unblock can only add one newline per cbs bytes, so ibs+1
       is plenty. The conversion is stateful across read blocks. */
    unsigned char *rebuf = NULL;
    dd_block_state rbstate;
    memset (&rbstate, 0, sizeof rbstate);
    rbstate.cbs = cbs;
    if (reblock) {
        size_t rbsz;
        if (conv & DDC_BLOCK) {
            /* ibs*cbs may overflow for absurd sizes; guard it. Both ibs and
               cbs are positive here, so compare in size_t arithmetic. */
            if (ibs != 0 && (size_t) cbs > (SIZE_MAX - 1) / (size_t) ibs) {
                builtin_error ("cbs reblock buffer overflow");
                free (ibuf); free (swbuf);
                if (have_usr1) sigaction (SIGUSR1, &old_usr1, NULL);
                if (ifd != STDIN_FILENO)  close (ifd);
                if (ofd != STDOUT_FILENO) close (ofd);
                return EXECUTION_FAILURE;
            }
            rbsz = (size_t) (ibs * cbs) + 1;
        } else {
            rbsz = (size_t) ibs + 1;
        }
        rebuf = malloc (rbsz);
    }

    if (!ibuf || ((conv & DDC_SWAB) && !swbuf) || (reblock && !rebuf)) {
        builtin_error ("malloc: %s", strerror (errno));
        free (ibuf);
        free (swbuf);
        free (rebuf);
        if (have_usr1) sigaction (SIGUSR1, &old_usr1, NULL);
        if (ifd != STDIN_FILENO)  close (ifd);
        if (ofd != STDOUT_FILENO) close (ofd);
        return EXECUTION_FAILURE;
    }

    int rc = EXECUTION_SUCCESS;
    while ((iflag & DDI_COUNT_BYTES)
           ? (count < 0 || bytes_total < count)
           : (count < 0 || (ifull + ipart) < count)) {
        ssize_t r;
        size_t want = (size_t) ibs;
        if ((iflag & DDI_COUNT_BYTES) && count >= 0) {
            long long remain = count - bytes_total;
            if (remain <= 0) break;
            if (remain < ibs) want = (size_t) remain;
        }
        if (iflag & DDI_FULLBLOCK) {
            r = dd_read_full (ifd, ibuf, want);
        } else {
            do { r = read (ifd, ibuf, want); }
            while (r < 0 && errno == EINTR);
        }
        if (r < 0) {
            if (conv & DDC_NOERROR) continue;
            builtin_error ("read: %s", strerror (errno));
            rc = EXECUTION_FAILURE;
            break;
        }
        if (r == 0) break;
        if (r == ibs) ifull++;
        else          ipart++;

        /* conv ordering matches GNU dd: case-fold first, then sync-pad the
           short block, then swab the (possibly padded) block. With
           conv=block/unblock (reblock active) the case-folded bytes feed the
           record reblocker, which owns the output framing — sync/swab byte
           framing doesn't compose with record reblocking, so they're skipped
           on that path (matching GNU's translate-then-reblock pipeline). */
        if (conv & (DDC_UCASE | DDC_LCASE))
            dd_case (ibuf, (size_t) r, (conv & DDC_UCASE) ? 1 : 0);

        unsigned char *wbuf = ibuf;
        size_t wlen = (size_t) r;

        if (reblock) {
            if (conv & DDC_BLOCK)
                wlen = dd_block_stream (ibuf, (size_t) r, rebuf, &rbstate);
            else
                wlen = dd_unblock_stream (ibuf, (size_t) r, rebuf, &rbstate);
            wbuf = rebuf;
        } else {
            /* conv=sync: pad partial input blocks with NUL up to ibs. */
            if ((conv & DDC_SYNC) && r < ibs) {
                memset (ibuf + r, 0, (size_t) (ibs - r));
                r = (ssize_t) ibs;
                wlen = (size_t) r;
            }
            /* Select the write source. conv=swab streams through the global
               carry buffer; the produced length can differ from r by one
               byte (a held carry consumed from a previous block). */
            if (conv & DDC_SWAB) {
                wbuf = swbuf;
                wlen = dd_swab_stream (ibuf, (size_t) r, swbuf,
                                       &swab_carry, &swab_have_carry);
            }
        }

        /* Write loop — handle EINTR + short writes. */
        size_t off = 0;
        while (off < wlen) {
            ssize_t w = write (ofd, wbuf + off, wlen - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                builtin_error ("write: %s", strerror (errno));
                rc = EXECUTION_FAILURE;
                goto done;
            }
            off += (size_t) w;
        }
        if (r == obs) ofull++;
        else          opart++;
        bytes_total += r;

        if (status & DDS_PROGRESS) {
            double now = dd_now_seconds ();
            if (dd_sigusr1_progress || now >= next_progress) {
                dd_sigusr1_progress = 0;
                dd_print_xfer (bytes_total, now - start_time, 1);
                next_progress = now + 1.0;
            }
        }
    }

    /* Flush a final unterminated record for conv=block/unblock. block pads
       a short trailing record to cbs with spaces; unblock terminates a
       short trailing record with a newline. */
    if (rc == EXECUTION_SUCCESS && reblock) {
        size_t flen;
        if (conv & DDC_BLOCK)
            flen = dd_block_stream (NULL, 0, rebuf, &rbstate);
        else
            flen = dd_unblock_stream (NULL, 0, rebuf, &rbstate);
        size_t off = 0;
        while (off < flen) {
            ssize_t w = write (ofd, rebuf + off, flen - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                builtin_error ("write: %s", strerror (errno));
                rc = EXECUTION_FAILURE;
                break;
            }
            off += (size_t) w;
        }
        if (rc == EXECUTION_SUCCESS) bytes_total += (long long) flen;
    }

    /* Flush any held swab carry byte (odd-length stream). GNU emits the
       trailing unpaired byte verbatim. */
    if (rc == EXECUTION_SUCCESS && (conv & DDC_SWAB) && swab_have_carry) {
        unsigned char tail = swab_carry;
        swab_have_carry = 0;
        size_t off = 0;
        while (off < 1) {
            ssize_t w = write (ofd, &tail + off, 1 - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                builtin_error ("write: %s", strerror (errno));
                rc = EXECUTION_FAILURE;
                break;
            }
            off += (size_t) w;
        }
        if (rc == EXECUTION_SUCCESS) bytes_total += 1;
    }

done:
    free (rebuf);
    free (swbuf);
    free (ibuf);
    if (rc == EXECUTION_SUCCESS && ofd != STDOUT_FILENO) {
        if ((conv & DDC_FSYNC) && fsync (ofd) < 0) {
            builtin_error ("fsync: %s", strerror (errno));
            rc = EXECUTION_FAILURE;
        }
#if defined (_POSIX_SYNCHRONIZED_IO) && _POSIX_SYNCHRONIZED_IO > 0
        if (rc == EXECUTION_SUCCESS && (conv & DDC_FDATASYNC) && fdatasync (ofd) < 0) {
            builtin_error ("fdatasync: %s", strerror (errno));
            rc = EXECUTION_FAILURE;
        }
#else
        if (rc == EXECUTION_SUCCESS && (conv & DDC_FDATASYNC) && fsync (ofd) < 0) {
            builtin_error ("fdatasync: %s", strerror (errno));
            rc = EXECUTION_FAILURE;
        }
#endif
    }
    if (have_usr1) sigaction (SIGUSR1, &old_usr1, NULL);
    if (ifd != STDIN_FILENO)  close (ifd);
    if (ofd != STDOUT_FILENO) close (ofd);

    /* Summary unless status=none. */
    if (!(status & DDS_NONE)) {
        fprintf (stderr, "%lld+%lld records in\n",  ifull, ipart);
        fprintf (stderr, "%lld+%lld records out\n", ofull, opart);
        if (!(status & DDS_NOXFER))
            dd_print_xfer (bytes_total, dd_now_seconds () - start_time, 0);
    }
    return rc;
}

char *dd_doc[] = {
    "Convert and copy a file (POSIX dd subset).",
    "",
    "    bashdd [if=FILE] [of=FILE] [bs=N|ibs=N obs=N] [cbs=N] [count=N]",
    "           [skip=N] [seek=N]",
    "           [conv=notrunc,sync,noerror,swab,fsync,fdatasync,excl,nocreat,",
    "                 ucase,lcase,block,unblock]",
    "           [iflag=fullblock,count_bytes,skip_bytes]",
    "           [oflag=append,seek_bytes]",
    "           [status=none|noxfer|progress]",
    "    bashdd --help | --version",
    "",
    "Block sizes accept POSIX suffixes (c=1, w=2, b=512, k=1024,",
    "K=1000, M=1024^2, G=1024^3) and 'xN' multipliers (e.g. 2x1024).",
    "",
    "conv=block reblocks newline-delimited records to fixed cbs-byte",
    "records (space-padded / truncated); conv=unblock reverses it",
    "(strip trailing spaces, append newline). Both require cbs=N.",
    "",
    "Differences from POSIX dd:",
    "  - conv=ascii|ebcdic dropped (use tr).",
    "  - conv=ucase/lcase/block/unblock and cbs=N supported.",
    (char *) NULL
};

struct builtin bashdd_struct = {
    "bashdd",
    dd_builtin,
    BUILTIN_ENABLED,
    dd_doc,
    "bashdd [if=FILE] [of=FILE] [bs=N] [count=N] [skip=N] [seek=N] [conv=...] [iflag=...] [oflag=...] [status=...]",
    0
};

/* Also register under the bare `dd` name so `type -t dd == builtin`
   holds. Same function pointer. The /bin/dd shim still routes
   external fork-execs through _bash_shim → builtin dispatch. */
struct builtin dd_struct = {
    "dd",
    dd_builtin,
    BUILTIN_ENABLED,
    dd_doc,
    "dd [if=FILE] [of=FILE] [bs=N] [count=N] [skip=N] [seek=N] [conv=...] [iflag=...] [oflag=...] [status=...]",
    0
};
