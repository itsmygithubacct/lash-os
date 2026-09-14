/* bashls.c — GNU coreutils 9.7-parity ls(1) as a bash builtin.
 *
 * v3 of the bash-os ls loadable.  v1/v2 were a POSIX-shape ls; this
 * version targets byte-identical output with Debian 13's
 * `ls (GNU coreutils) 9.7` in the C locale, per spec
 * 98-deb_parity-ls-gnu-coreutils.md.  The behavioral oracle is
 * coreutils-9.7 src/ls.c plus its gnulib helpers (quotearg, human,
 * filevercmp, xstrtol, argmatch); the algorithms below are clean-room
 * re-implementations shaped to match that observable behavior.
 *
 * Surface: the full GNU 9.7 option set —
 *   short: -a -A -b -B -c -C -d -D -f -F -g -G -h -H -i -I -k -l -L -m
 *          -n -N -o -p -q -Q -r -R -s -S -t -T -u -U -v -w -x -X -Z -1
 *   long:  every GNU long option incl. --sort/--time/--time-style/
 *          --quoting-style/--indicator-style/--format/--block-size/
 *          --width/--tabsize/--ignore/--hide/--color/--classify/
 *          --hyperlink/--zero/--dired/--context/--group-directories-first/
 *          --author/--full-time/--si/--help/--version
 * Parsing uses libc getopt_long(3) with argument permutation (disabled
 * when POSIXLY_CORRECT is set), abbreviation, and optional_argument
 * semantics; the libc getopt globals are saved/restored around the call
 * so bash and sibling loadables are never corrupted.
 *
 * Known divergences from GNU ls (documented; out of scope per spec):
 *   - locale support: C/POSIX locale only (no LC_COLLATE tables, no
 *     multibyte width handling, no translated time formats);
 *   - human_group_digits (--block-size="'1k") parses but never groups,
 *     matching the C locale where the thousands separator is empty;
 *   - SELinux/SMACK contexts come from the security.selinux xattr only
 *     ("?" when absent, like GNU on a no-SELinux kernel);
 *   - +FORMAT time styles support the strftime(3) of the host libc
 *     plus %N (nanoseconds); exotic gnulib-only conversions differ.
 *
 * No static mutable state apart from the qsort context pointer (bash is
 * single-threaded); repeated invocation in one session cannot leak.
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
#include <dirent.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <stdarg.h>
#include <fnmatch.h>

#include "loadables.h"

/* The system <getopt.h> is shadowed by bash's builtins/getopt.h on the
   loadable include path, so declare the libc getopt_long(3) interface
   directly (identical ABI on glibc and musl).  <unistd.h> already
   declares optarg/optind/opterr/optopt and plain getopt.  */
struct option
{
    const char *name;
    int has_arg;
    int *flag;
    int val;
};
#define no_argument        0
#define required_argument  1
#define optional_argument  2
extern int getopt_long (int, char *const *, const char *,
                        const struct option *, int *);

/* ---------------- C-locale character classes ---------------- */

#define BL_ISPRINT(c)  (0x20 <= (c) && (c) < 0x7f)
#define BL_ISDIGIT(c)  ('0' <= (c) && (c) <= '9')
#define BL_ISALPHA(c)  (('a' <= (c) && (c) <= 'z') || ('A' <= (c) && (c) <= 'Z'))
#define BL_ISALNUM(c)  (BL_ISDIGIT (c) || BL_ISALPHA (c))

/* Nongraphic byte in the C locale (used by -q and the quoting engine). */
static int
bl_qmark_byte (unsigned char c)
{
    return (c < 0x20 || c == 0x7f || c > 0x7f);
}

/* ---------------- enums (mirroring coreutils ls.c) ---------------- */

enum bl_filetype
  {
    BL_T_UNKNOWN, BL_T_FIFO, BL_T_CHARDEV, BL_T_DIRECTORY, BL_T_BLOCKDEV,
    BL_T_NORMAL, BL_T_SYMLINK, BL_T_SOCK, BL_T_WHITEOUT, BL_T_ARG_DIRECTORY
  };
static const char bl_filetype_letter[] = "?pcdb-lswd";

enum bl_format
  {
    BL_FMT_LONG,            /* -l and other long options */
    BL_FMT_ONE_PER_LINE,    /* -1 */
    BL_FMT_MANY_PER_LINE,   /* -C */
    BL_FMT_HORIZONTAL,      /* -x */
    BL_FMT_COMMAS           /* -m */
  };

enum bl_sort
  {
    BL_SORT_NAME, BL_SORT_EXTENSION, BL_SORT_WIDTH, BL_SORT_SIZE,
    BL_SORT_VERSION, BL_SORT_TIME, BL_SORT_NONE
  };

enum bl_time
  {
    BL_TIME_MTIME, BL_TIME_CTIME, BL_TIME_ATIME, BL_TIME_BTIME
  };

enum bl_indicator
  {
    BL_IND_NONE, BL_IND_SLASH, BL_IND_FILE_TYPE, BL_IND_CLASSIFY
  };

enum bl_quoting
  {
    BL_Q_LITERAL, BL_Q_SHELL, BL_Q_SHELL_ALWAYS, BL_Q_SHELL_ESCAPE,
    BL_Q_SHELL_ESCAPE_ALWAYS, BL_Q_C, BL_Q_C_MAYBE, BL_Q_ESCAPE,
    BL_Q_LOCALE, BL_Q_CLOCALE
  };

enum bl_deref
  {
    BL_DEREF_UNDEFINED, BL_DEREF_NEVER, BL_DEREF_COMMAND_LINE_ARGUMENTS,
    BL_DEREF_COMMAND_LINE_SYMLINK_TO_DIR, BL_DEREF_ALWAYS
  };

enum bl_acl_type
  {
    BL_ACL_NONE, BL_ACL_LSM_CONTEXT_ONLY, BL_ACL_YES, BL_ACL_UNKNOWN
  };

/* Color indicator slots (order matches coreutils indicator_name[]).  */
enum bl_indicator_no
  {
    BLC_LEFT, BLC_RIGHT, BLC_END, BLC_RESET, BLC_NORM, BLC_FILE, BLC_DIR,
    BLC_LINK, BLC_FIFO, BLC_SOCK, BLC_BLK, BLC_CHR, BLC_MISSING, BLC_ORPHAN,
    BLC_EXEC, BLC_DOOR, BLC_SETUID, BLC_SETGID, BLC_STICKY,
    BLC_OTHER_WRITABLE, BLC_STICKY_OTHER_WRITABLE, BLC_CAP, BLC_MULTIHARDLINK,
    BLC_CLR_TO_EOL,
    BLC_N_INDICATORS
  };

/* human-readable formatting option bits (gnulib human.h subset).  */
enum
  {
    BL_HUMAN_CEILING = 0,
    BL_HUMAN_ROUND_TO_NEAREST = 1,
    BL_HUMAN_FLOOR = 2,
    BL_HUMAN_GROUP_DIGITS = 4,
    BL_HUMAN_SUPPRESS_POINT_ZERO = 8,
    BL_HUMAN_AUTOSCALE = 16,
    BL_HUMAN_BASE_1024 = 32,
    BL_HUMAN_SPACE_BEFORE_UNIT = 64,
    BL_HUMAN_SI = 128,
    BL_HUMAN_B = 256
  };
#define BL_HUMAN_INEXACT_MASK \
  (BL_HUMAN_ROUND_TO_NEAREST | BL_HUMAN_FLOOR | BL_HUMAN_CEILING)
#define BL_HUMAN_BUFLEN 200

/* ---------------- small data structures ---------------- */

typedef struct { size_t len; const char *string; } bl_bin_str;

typedef struct bl_color_ext
{
    struct bl_color_ext *next;
    bl_bin_str ext;
    bl_bin_str seq;
    int exact_match;
} bl_color_ext;

typedef struct bl_pattern
{
    struct bl_pattern *next;
    const char *pattern;
} bl_pattern;

/* Device/inode set for -R loop detection.  Mirrors GNU's active_dir_set:
   it holds the chain of directories currently being descended into; a
   marker entry on the pending queue pops a directory off when its whole
   subtree is done.  */
typedef struct ls_seen_dir
{
    dev_t dev;
    ino_t ino;
    struct ls_seen_dir *next;
} ls_seen_dir;

/* Pending-directory queue (a stack, like GNU's).  name == NULL marks a
   "subtree finished" entry whose realname names the finished dir.  */
typedef struct bl_pending
{
    char *name;
    char *realname;
    int command_line_arg;
    struct bl_pending *next;
} bl_pending;

/* One collected file.  */
typedef struct
{
    char         *name;
    char         *linkname;   /* symlink target, when read */
    char         *absolute_name; /* canonical path for --hyperlink */
    char         *scontext;   /* malloc'd security context or NULL ("?") */
    struct stat   st;
    int           stat_ok;
    int           ftype;      /* enum bl_filetype */
    mode_t        mode;       /* st.st_mode of whichever stat ran (0 if none) */
    mode_t        linkmode;   /* target mode when followed for -F/-l */
    int           linkok;
    int           acl_type;   /* enum bl_acl_type */
    int           quoted;     /* tri-state: -1 unknown, 0 no, 1 yes */
    size_t        width;      /* cached display width (0 = not cached) */
    off_t         size;       /* st.st_size copy for the comparator */
    struct timespec mtime;    /* the SELECTED timestamp (-c/-u/--time) */
    struct timespec btime;    /* birth time, (-1,-1) if unavailable */
} ls_entry;

/* Tiny per-call uid/gid name cache (kept from v2). 16 slots is plenty. */
#define BL_NAME_CACHE 16
typedef struct
{
    int   used;
    uid_t key[BL_NAME_CACHE];
    char  name[BL_NAME_CACHE][40];
} ls_idcache;

/* Growable byte buffer for the quoting engine.  */
typedef struct { char *p; size_t len, cap; } bl_buf;

/* Growable off_t array for --dired position pairs.  */
typedef struct { off_t *v; size_t len, cap; } bl_posbuf;

/* ---------------- the per-call context ---------------- */

/* Per-call options AND run state.  Lives on the builtin's stack; no
   global mutable state apart from the qsort context pointer.  */
typedef struct ls_opts ls_opts;
struct ls_opts
{
    /* option state (parse results) */
    int aflag;        /* -a: ignore minimal (show everything) */
    int Aflag;        /* -A: hide only . and .. */
    int dflag;        /* -d: list dirs themselves */
    int fflag;        /* sort_type == none (set by -f/-U/--sort=none) */
    int qflag;        /* -q tri-state: -1 default, 0 show, 1 hide ctl */
    int Sflag;        /* sort_type == size (comparator gate) */
    int cflag;        /* time_type == ctime */
    int uflag;        /* time_type == atime */
    int rflag;        /* -r: reverse sort */
    int Rflag;        /* -R: recursive */
    int Lflag;        /* dereference == ALWAYS */
    int numeric_ids;          /* -n */
    int print_owner;          /* !-g */
    int print_group;          /* !-G/-o */
    int print_author;         /* --author */
    int print_scontext;       /* -Z */
    int print_inode;          /* -i */
    int print_block_size;     /* -s */
    int print_with_color;
    int print_hyperlink;
    int dired;                /* -D */
    int group_directories_first;
    int immediate_dirs;       /* alias of dflag, kept in dflag */
    int recursive;            /* alias of Rflag, kept in Rflag */
    int format;               /* enum bl_format */
    int sort_type;            /* enum bl_sort */
    int time_type;            /* enum bl_time */
    int indicator_style;      /* enum bl_indicator */
    int quoting_style;        /* enum bl_quoting */
    int deref;                /* enum bl_deref */
    int qmark_funny_chars;
    char eolbyte;
    size_t line_length;       /* 0 = no limit */
    size_t tabsize;
    size_t max_idx;           /* max possible display columns */
    bl_pattern *ignore_patterns;
    bl_pattern *hide_patterns;
    int human_output_opts;            /* for blocks / totals */
    uintmax_t output_block_size;
    int file_human_output_opts;       /* for -l file sizes */
    uintmax_t file_output_block_size;
    const char *long_time_fmt[2];     /* [0] old, [1] recent */
    char *time_fmt_heap;              /* malloc'd backing for +FORMAT */
    int align_variable_outer_quotes;
    unsigned char filename_quote_map[32];   /* set_char_quoting bitmap */
    unsigned char dirname_quote_map[32];
    int check_symlink_mode;
    int format_needs_stat;
    int format_needs_type;
    int explicit_time;

    /* color state */
    bl_bin_str color_indicator[BLC_N_INDICATORS];
    bl_color_ext *color_ext_list;
    char *color_buf;          /* backing storage for parsed LS_COLORS */
    int color_symlink_as_referent;
    int used_color;

    /* hyperlink state */
    char *hostname;

    /* dired state */
    off_t dired_pos;
    bl_posbuf dired_obstack;
    bl_posbuf subdired_obstack;

    /* per-directory listing state */
    ls_entry *ents;
    size_t n_used, n_alloc;
    int cwd_some_quoted;
    int any_has_acl;
    int inode_number_width;
    int block_size_width;
    int nlink_width;
    int owner_width;
    int group_width;
    int author_width;
    int scontext_width;
    int major_device_number_width;
    int minor_device_number_width;
    int file_size_width;

    /* run state */
    int exit_status;
    bl_pending *pending_dirs;
    ls_seen_dir *active_dir_set;      /* -R loop detection */
    int print_dir_name;
    int first_dir;                    /* first print_dir? (blank-line glue) */
    struct timespec current_time;
    int current_time_ok;
    ls_idcache ucache, gcache;
    bl_buf qbuf;                      /* scratch for quoting */
    bl_buf qbuf2;                     /* scratch for symlink targets etc */

    /* printing context (so helpers can keep historical signatures) */
    size_t name_start_col;            /* column where the name begins */
    const ls_entry *cur_file;         /* entry being printed (long fmt) */
};

/* qsort(3) has no userdata pointer; bash is single-threaded so a file
   global is acceptable for the comparator context.  */
static ls_opts *bl_sort_opts;

/* ---------------- tiny helpers ---------------- */

static void *
bl_xmalloc (size_t n)
{
    void *p = malloc (n ? n : 1);
    return p;
}

static char *
bl_xstrdup (const char *s)
{
    return s ? strdup (s) : NULL;
}

static int
bl_buf_reserve (bl_buf *b, size_t need)
{
    if (b->len + need + 1 <= b->cap)
        return 0;
    size_t ncap = b->cap ? b->cap : 128;
    while (ncap < b->len + need + 1)
        ncap *= 2;
    char *np = realloc (b->p, ncap);
    if (np == NULL)
        return -1;
    b->p = np;
    b->cap = ncap;
    return 0;
}

static void
bl_buf_ch (bl_buf *b, char c)
{
    if (bl_buf_reserve (b, 1) == 0)
    {
        b->p[b->len++] = c;
        b->p[b->len] = '\0';
    }
}

static void
bl_buf_mem (bl_buf *b, const char *s, size_t n)
{
    if (bl_buf_reserve (b, n) == 0)
    {
        memcpy (b->p + b->len, s, n);
        b->len += n;
        b->p[b->len] = '\0';
    }
}

static void
bl_buf_str (bl_buf *b, const char *s)
{
    bl_buf_mem (b, s, strlen (s));
}

static void
bl_posbuf_push (bl_posbuf *pb, off_t v)
{
    if (pb->len == pb->cap)
    {
        size_t ncap = pb->cap ? pb->cap * 2 : 64;
        off_t *nv = realloc (pb->v, ncap * sizeof *nv);
        if (nv == NULL)
            return;
        pb->v = nv;
        pb->cap = ncap;
    }
    pb->v[pb->len++] = v;
}

/* All run output flows through these so --dired byte offsets stay
   accurate.  Color escape sequences intentionally bypass them, exactly
   like GNU ls (put_indicator does not advance dired_pos).  */
static void
bl_outbyte (ls_opts *o, char c)
{
    o->dired_pos++;
    putchar (c);
}

static void
bl_outbuf (ls_opts *o, const char *s, size_t n)
{
    o->dired_pos += n;
    fwrite (s, 1, n, stdout);
}

static void
bl_outstr (ls_opts *o, const char *s)
{
    bl_outbuf (o, s, strlen (s));
}

static void
bl_dired_indent (ls_opts *o)
{
    if (o->dired)
        bl_outstr (o, "  ");
}

static void
bl_push_dired_pos (ls_opts *o, bl_posbuf *pb)
{
    if (o->dired && pb)
        bl_posbuf_push (pb, o->dired_pos);
}

/* GNU error()-shaped diagnostics for option/usage problems: these keep
   the literal "ls: " prefix for byte parity.  Runtime file errors go
   through builtin_error() instead (so `bashls` reports as a builtin). */
static void
bl_try_help (void)
{
    fprintf (stderr, "Try 'ls --help' for more information.\n");
}

/* ---------------- uid/gid name cache (from v2) ---------------- */

static const char *
bl_lookup_uid (ls_idcache *c, uid_t u)
{
    for (int i = 0; i < c->used; i++)
        if (c->key[i] == u) return c->name[i];
    struct passwd *pw = getpwuid (u);
    if (c->used < BL_NAME_CACHE)
    {
        c->key[c->used] = u;
        if (pw)
            snprintf (c->name[c->used], sizeof c->name[0], "%s", pw->pw_name);
        else
            snprintf (c->name[c->used], sizeof c->name[0], "%ju", (uintmax_t) u);
        return c->name[c->used++];
    }
    static char scratch[40];
    if (pw) snprintf (scratch, sizeof scratch, "%s", pw->pw_name);
    else    snprintf (scratch, sizeof scratch, "%ju", (uintmax_t) u);
    return scratch;
}

static const char *
bl_lookup_gid (ls_idcache *c, gid_t g)
{
    for (int i = 0; i < c->used; i++)
        if (c->key[i] == g) return c->name[i];
    struct group *gr = getgrgid (g);
    if (c->used < BL_NAME_CACHE)
    {
        c->key[c->used] = g;
        if (gr)
            snprintf (c->name[c->used], sizeof c->name[0], "%s", gr->gr_name);
        else
            snprintf (c->name[c->used], sizeof c->name[0], "%ju", (uintmax_t) g);
        return c->name[c->used++];
    }
    static char scratch[40];
    if (gr) snprintf (scratch, sizeof scratch, "%s", gr->gr_name);
    else    snprintf (scratch, sizeof scratch, "%ju", (uintmax_t) g);
    return scratch;
}

/* ---------------- statx for birth time ---------------- */

struct bl_statx_timestamp { int64_t tv_sec; uint32_t tv_nsec; int32_t pad; };
struct bl_statx
{
    uint32_t stx_mask; uint32_t stx_blksize; uint64_t stx_attributes;
    uint32_t stx_nlink; uint32_t stx_uid; uint32_t stx_gid; uint16_t stx_mode;
    uint16_t pad1; uint64_t stx_ino; uint64_t stx_size; uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct bl_statx_timestamp stx_atime, stx_btime, stx_ctime, stx_mtime;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    uint64_t stx_mnt_id;
    uint64_t spare[13];
};
#define BL_STATX_BTIME 0x00000800U

static struct timespec
bl_get_btime (const char *path, int follow)
{
    struct timespec ts = { -1, -1 };
#ifdef SYS_statx
    struct bl_statx stx;
    memset (&stx, 0, sizeof stx);
    int flags = follow ? 0 : AT_SYMLINK_NOFOLLOW;
    if (syscall (SYS_statx, AT_FDCWD, path, flags, BL_STATX_BTIME, &stx) == 0
        && (stx.stx_mask & BL_STATX_BTIME))
    {
        ts.tv_sec = (time_t) stx.stx_btime.tv_sec;
        ts.tv_nsec = (long) stx.stx_btime.tv_nsec;
    }
#else
    (void) path; (void) follow;
#endif
    return ts;
}

static int
bl_timespec_cmp (struct timespec a, struct timespec b)
{
    if (a.tv_sec != b.tv_sec)
        return a.tv_sec < b.tv_sec ? -1 : 1;
    if (a.tv_nsec != b.tv_nsec)
        return a.tv_nsec < b.tv_nsec ? -1 : 1;
    return 0;
}

/* ================= quoting engine =================
 * Clean-room port of gnulib quotearg_buffer_restyled for the unibyte C
 * locale, covering the styles ls exposes.  Behavior matched against
 * coreutils 9.7 (see the differential fuzz in the parity TAP).  */

#define BL_QMAP_GET(map, c)  (((map)[(unsigned char)(c) >> 3] >> ((c) & 7)) & 1)
#define BL_QMAP_SET(map, c)  ((map)[(unsigned char)(c) >> 3] |= 1 << ((c) & 7))

/* Append the quoted form of ARG to B.  STYLE is a BL_Q_* style;
   QMAP is the set_char_quoting bitmap (may be NULL).  */
static void
bl_quotearg_append (bl_buf *b, const char *arg, int style,
                    const unsigned char *qmap)
{
    int elide_outer_quotes;
    int backslash_escapes;
    const char *quote_string;
    size_t quote_string_len;
    const char *left_quote = NULL;
    int pending_shell_escape_end;
    int encountered_single_quote;
    int all_c_and_shell_quote_compat;
    size_t i;
    size_t start;

restyle:
    elide_outer_quotes = 0;
    backslash_escapes = 0;
    quote_string = NULL;
    quote_string_len = 0;
    pending_shell_escape_end = 0;
    encountered_single_quote = 0;
    all_c_and_shell_quote_compat = 1;
    start = b->len;

    switch (style)
    {
        case BL_Q_C_MAYBE:
            style = BL_Q_C;
            elide_outer_quotes = 1;
            goto c_style;
        case BL_Q_C:
        c_style:
            if (!elide_outer_quotes)
                bl_buf_ch (b, '"');
            backslash_escapes = 1;
            quote_string = "\"";
            quote_string_len = 1;
            break;
        case BL_Q_ESCAPE:
            backslash_escapes = 1;
            break;
        case BL_Q_LOCALE:
        case BL_Q_CLOCALE:
            /* C-locale gettext fallback: locale quotes 'like this',
               clocale quotes "like this".  */
            left_quote = (style == BL_Q_CLOCALE) ? "\"" : "'";
            if (!elide_outer_quotes)
                bl_buf_str (b, left_quote);
            backslash_escapes = 1;
            quote_string = left_quote;
            quote_string_len = 1;
            break;
        case BL_Q_SHELL_ESCAPE:
            backslash_escapes = 1;
            elide_outer_quotes = 1;
            goto shell_style;
        case BL_Q_SHELL:
            elide_outer_quotes = 1;
            goto shell_style;
        case BL_Q_SHELL_ESCAPE_ALWAYS:
            backslash_escapes = 1;
            goto shell_style;
        case BL_Q_SHELL_ALWAYS:
        shell_style:
            style = BL_Q_SHELL_ALWAYS;
            if (!elide_outer_quotes)
                bl_buf_ch (b, '\'');
            quote_string = "'";
            quote_string_len = 1;
            break;
        case BL_Q_LITERAL:
        default:
            break;
    }

/* Open a backslash escape; in the shell styles also open a $'...'
   segment.  Bails out to outer quoting when eliding.  */
#define BL_START_ESC()                                          \
    do {                                                        \
        if (elide_outer_quotes)                                 \
            goto force_outer_quoting_style;                     \
        escaping = 1;                                           \
        if (style == BL_Q_SHELL_ALWAYS && !pending_shell_escape_end) \
        {                                                       \
            bl_buf_str (b, "'$'");                              \
            pending_shell_escape_end = 1;                       \
        }                                                       \
        bl_buf_ch (b, '\\');                                    \
    } while (0)

#define BL_END_ESC()                                            \
    do {                                                        \
        if (pending_shell_escape_end && !escaping)              \
        {                                                       \
            bl_buf_str (b, "''");                               \
            pending_shell_escape_end = 0;                       \
        }                                                       \
    } while (0)

    for (i = 0; arg[i] != '\0'; i++)
    {
        unsigned char c;
        unsigned char esc;
        int is_right_quote = 0;
        int escaping = 0;
        int c_and_shell_quote_compat = 0;

        if (backslash_escapes
            && style != BL_Q_SHELL_ALWAYS
            && quote_string_len
            && memcmp (arg + i, quote_string, quote_string_len) == 0)
        {
            if (elide_outer_quotes)
                goto force_outer_quoting_style;
            is_right_quote = 1;
        }

        c = (unsigned char) arg[i];
        switch (c)
        {
            case '?':
                if (style == BL_Q_SHELL_ALWAYS && elide_outer_quotes)
                    goto force_outer_quoting_style;
                break;

            case '\a': esc = 'a'; goto c_escape;
            case '\b': esc = 'b'; goto c_escape;
            case '\f': esc = 'f'; goto c_escape;
            case '\n': esc = 'n'; goto c_and_shell_escape;
            case '\r': esc = 'r'; goto c_and_shell_escape;
            case '\t': esc = 't'; goto c_and_shell_escape;
            case '\v': esc = 'v'; goto c_escape;
            case '\\': esc = c;
                /* Never need to escape '\' in shell case.  */
                if (style == BL_Q_SHELL_ALWAYS)
                {
                    if (elide_outer_quotes)
                        goto force_outer_quoting_style;
                    goto store_c;
                }
                /* No need to escape the escape if we are trying to elide
                   outer quotes and nothing else is problematic.  */
                if (backslash_escapes && elide_outer_quotes && quote_string_len)
                    goto store_c;
                /* fall through */
            c_and_shell_escape:
                if (style == BL_Q_SHELL_ALWAYS && elide_outer_quotes)
                    goto force_outer_quoting_style;
                /* fall through */
            c_escape:
                if (backslash_escapes)
                {
                    c = esc;
                    goto store_escape;
                }
                break;

            case '{': case '}': /* sometimes special if isolated */
                if (arg[1] != '\0')
                    break;
                /* fall through */
            case '#': case '~':
                if (i != 0)
                    break;
                /* fall through */
            case ' ':
                c_and_shell_quote_compat = 1;
                /* fall through */
            case '!': /* special in bash */
            case '"': case '$': case '&':
            case '(': case ')': case '*': case ';':
            case '<':
            case '=': /* sometimes special in 0th or (with "set -k") later args */
            case '>': case '[':
            case '^': /* special in old /bin/sh, e.g., Solaris 10 */
            case '`': case '|':
                /* A shell special character.  */
                if (style == BL_Q_SHELL_ALWAYS && elide_outer_quotes)
                    goto force_outer_quoting_style;
                break;

            case '\'':
                encountered_single_quote = 1;
                c_and_shell_quote_compat = 1;
                if (style == BL_Q_SHELL_ALWAYS)
                {
                    if (elide_outer_quotes)
                        goto force_outer_quoting_style;
                    bl_buf_str (b, "'\\'");
                    pending_shell_escape_end = 0;
                }
                break;

            case '%': case '+': case ',': case '-': case '.': case '/':
            case '0': case '1': case '2': case '3': case '4': case '5':
            case '6': case '7': case '8': case '9': case ':':
            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            case 'G': case 'H': case 'I': case 'J': case 'K': case 'L':
            case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R':
            case 'S': case 'T': case 'U': case 'V': case 'W': case 'X':
            case 'Y': case 'Z': case ']': case '_': case 'a': case 'b':
            case 'c': case 'd': case 'e': case 'f': case 'g': case 'h':
            case 'i': case 'j': case 'k': case 'l': case 'm': case 'n':
            case 'o': case 'p': case 'q': case 'r': case 's': case 't':
            case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
                /* These characters never cause problems.  */
                c_and_shell_quote_compat = 1;
                break;

            default:
            {
                /* Unibyte C locale: a single byte; printable iff graphic
                   ASCII (bl_qmark_byte is the complement).  */
                int printable = !bl_qmark_byte (c);
                c_and_shell_quote_compat = printable;
                if (backslash_escapes && !printable)
                {
                    BL_START_ESC ();
                    bl_buf_ch (b, (char) ('0' + (c >> 6)));
                    bl_buf_ch (b, (char) ('0' + ((c >> 3) & 7)));
                    c = (unsigned char) ('0' + (c & 7));
                    goto store_c;
                }
                break;
            }
        }

        if (!(((backslash_escapes && style != BL_Q_SHELL_ALWAYS)
               || elide_outer_quotes)
              && qmap && BL_QMAP_GET (qmap, c))
            && !is_right_quote)
            goto store_c;

    store_escape:
        BL_START_ESC ();

    store_c:
        BL_END_ESC ();
        bl_buf_ch (b, (char) c);

        if (!c_and_shell_quote_compat)
            all_c_and_shell_quote_compat = 0;
    }

    if (b->len == start && style == BL_Q_SHELL_ALWAYS && elide_outer_quotes)
        goto force_outer_quoting_style;

    /* Single quotes are commonly used as apostrophes; prefer the more
       concise C-quoted form when everything else is compatible.  */
    if (style == BL_Q_SHELL_ALWAYS && !elide_outer_quotes
        && encountered_single_quote && all_c_and_shell_quote_compat)
    {
        b->len = start;
        if (b->p) b->p[b->len] = '\0';
        style = BL_Q_C;
        qmap = NULL;
        goto restyle;
    }

    if (quote_string && !elide_outer_quotes)
        bl_buf_str (b, quote_string);
    return;

force_outer_quoting_style:
    b->len = start;
    if (b->p) b->p[b->len] = '\0';
    /* Don't reuse qmap: outer quotes quote those chars sufficiently.  */
    if (style == BL_Q_SHELL_ALWAYS && backslash_escapes)
        style = BL_Q_SHELL_ESCAPE_ALWAYS;
    qmap = NULL;
    goto restyle;

#undef BL_START_ESC
#undef BL_END_ESC
}

/* ================ quote_name layer (ls.c shape) ================ */

/* Quote NAME into B per the filename quoting options.  Returns the
   byte length, sets *QUOTEDP, and (when WIDTHP) the display width.
   Mirrors coreutils quote_name_buf for the unibyte case.  */
static size_t
bl_quote_name_buf (ls_opts *o, bl_buf *b, const char *name,
                   const unsigned char *qmap, int needs_general_quoting,
                   size_t *widthp, int *padp)
{
    int qs = o->quoting_style;
    int needs_further_quoting =
        o->qmark_funny_chars
        && (qs == BL_Q_SHELL || qs == BL_Q_SHELL_ALWAYS || qs == BL_Q_LITERAL);
    int quoted = 0;
    size_t len;

    b->len = 0;
    if (b->p) b->p[0] = '\0';

    if (needs_general_quoting != 0)
    {
        bl_quotearg_append (b, name, qs, qmap);
        len = b->len;
        quoted = (b->p == NULL || name[0] != b->p[0]
                  || strlen (name) != len);
    }
    else
    {
        bl_buf_str (b, name);
        len = b->len;
    }

    if (needs_further_quoting && b->p)
    {
        for (size_t i = 0; i < len; i++)
            if (bl_qmark_byte ((unsigned char) b->p[i]))
                b->p[i] = '?';
    }

    if (widthp)
    {
        size_t w = 0;
        if (needs_further_quoting)
            w = len;
        else if (b->p)
            for (size_t i = 0; i < len; i++)
                if (BL_ISPRINT ((unsigned char) b->p[i]))
                    w++;
        *widthp = w;
    }

    if (padp)
        *padp = (o->align_variable_outer_quotes && o->cwd_some_quoted
                 && !quoted);
    return len;
}

/* Would NAME be altered by the current filename quoting options?  */
static int
bl_needs_quoting (ls_opts *o, const char *name)
{
    int pad;
    size_t len = bl_quote_name_buf (o, &o->qbuf, name,
                                    o->filename_quote_map, -1, NULL, &pad);
    return o->qbuf.p == NULL || name[0] != o->qbuf.p[0]
           || strlen (name) != len;
}

/* Display width of NAME under the current quoting (including the
   alignment pad column when applicable).  */
static size_t
bl_name_width (const char *name, ls_opts *o)
{
    size_t w = 0;
    int pad = 0;
    bl_quote_name_buf (o, &o->qbuf, name, o->filename_quote_map, -1, &w, &pad);
    return w + (pad ? 1 : 0);
}

/* %XX-escape STR per RFC3986 for --hyperlink; if PATH, keep '/'.  */
static char *
bl_file_escape (const char *str, int path)
{
    bl_buf b = {0};
    for (const unsigned char *p = (const unsigned char *) str; *p; p++)
    {
        unsigned char c = *p;
        if ((path && c == '/')
            || BL_ISALNUM (c) || c == '-' || c == '.' || c == '_' || c == '~')
            bl_buf_ch (&b, (char) c);
        else
        {
            char hex[4];
            snprintf (hex, sizeof hex, "%%%02x", c);
            bl_buf_str (&b, hex);
        }
    }
    if (b.p == NULL)
        bl_buf_str (&b, "");
    return b.p;
}

/* forward decls used by the printers */
static int bl_is_colored (ls_opts *o, int type);
static void bl_put_indicator (ls_opts *o, const bl_bin_str *ind);
static void bl_prep_non_filename_text (ls_opts *o);
static const bl_bin_str *bl_get_color_indicator (ls_opts *o,
                                                 const ls_entry *f,
                                                 int symlink_target);

/* Emit NAME (already chosen: file or link target) with quoting, pad,
   color, hyperlink, and dired position tracking.  Mirrors quote_name +
   print_name_with_quoting.  Returns the printed byte length + pad.  */
static size_t
bl_quote_name_out (ls_opts *o, const char *name, int needs_general_quoting,
                   const bl_bin_str *color, int allow_pad,
                   bl_posbuf *stack, const char *absolute_name,
                   const unsigned char *qmap)
{
    int pad = 0;
    size_t len = bl_quote_name_buf (o, &o->qbuf, name, qmap,
                                    needs_general_quoting, NULL, &pad);
    const char *buf = o->qbuf.p ? o->qbuf.p : "";

    if (pad && allow_pad)
        bl_outbyte (o, ' ');

    if (color)
    {
        if (bl_is_colored (o, BLC_NORM))
        {
            /* restore_default_color(): LEFT+RIGHT — "\033[m" resets */
            bl_put_indicator (o, &o->color_indicator[BLC_LEFT]);
            bl_put_indicator (o, &o->color_indicator[BLC_RIGHT]);
        }
        bl_put_indicator (o, &o->color_indicator[BLC_LEFT]);
        bl_put_indicator (o, color);
        bl_put_indicator (o, &o->color_indicator[BLC_RIGHT]);
    }

    int skip_quotes = 0;
    if (absolute_name)
    {
        if (o->align_variable_outer_quotes && o->cwd_some_quoted && !pad)
        {
            skip_quotes = 1;
            putchar (buf[0]);
        }
        char *h = bl_file_escape (o->hostname ? o->hostname : "", 0);
        char *n2 = bl_file_escape (absolute_name, 1);
        printf ("\033]8;;file://%s%s%s\a", h, *n2 == '/' ? "" : "/", n2);
        free (h);
        free (n2);
    }

    bl_push_dired_pos (o, stack);
    fwrite (buf + skip_quotes, 1, len - (skip_quotes ? 2 : 0), stdout);
    o->dired_pos += len;
    bl_push_dired_pos (o, stack);

    if (absolute_name)
    {
        fputs ("\033]8;;\a", stdout);
        if (skip_quotes)
            putchar (buf[len - 1]);
    }

    return len + (pad ? 1 : 0);
}

/* print_name_with_quoting equivalent.  SYMLINK_TARGET selects
   f->linkname.  Uses o->name_start_col for the color EOL heuristic.  */
static size_t
bl_print_name_q (ls_opts *o, const ls_entry *f, int symlink_target,
                 bl_posbuf *stack)
{
    const char *name = symlink_target ? f->linkname : f->name;
    const bl_bin_str *color =
        o->print_with_color ? bl_get_color_indicator (o, f, symlink_target)
                            : NULL;
    int used_color_this_time =
        o->print_with_color && (color || bl_is_colored (o, BLC_NORM));

    size_t len = bl_quote_name_out (o, name, f->quoted, color,
                                    !symlink_target, stack,
                                    f->absolute_name,
                                    o->filename_quote_map);

    if (used_color_this_time)
    {
        bl_prep_non_filename_text (o);
        size_t start_col = o->name_start_col;
        if (o->line_length
            && (start_col / o->line_length
                != (start_col + len - 1) / o->line_length))
            bl_put_indicator (o, &o->color_indicator[BLC_CLR_TO_EOL]);
    }
    return len;
}

/* Print a free-standing name with the current quoting (used for
   symlink targets via the historical shape `bl_print_name (tgt, o)`:
   color and indicator handling for targets stays in the caller).  */
static void
bl_print_name (const char *tgt, ls_opts *o)
{
    (void) bl_print_name_q (o, o->cur_file, tgt == o->cur_file->linkname,
                            NULL);
}

/* ================= human-readable sizes ================= */

static const char bl_power_letter[] = "0KMGTPEZYRQ";

static long double
bl_adjust_value (int inexact_style, long double value)
{
    if (inexact_style != BL_HUMAN_ROUND_TO_NEAREST && value < UINTMAX_MAX)
    {
        uintmax_t u = (uintmax_t) value;
        value = u + (inexact_style == BL_HUMAN_CEILING && u != value);
    }
    return value;
}

/* Port of gnulib human_readable (C locale: '.' decimal point, no
   grouping).  BUF must hold BL_HUMAN_BUFLEN bytes.  */
static char *
bl_human_readable (uintmax_t n, char *buf, int opts,
                   uintmax_t from_block_size, uintmax_t to_block_size)
{
    int inexact_style = opts & BL_HUMAN_INEXACT_MASK;
    unsigned int base = (opts & BL_HUMAN_BASE_1024) ? 1024 : 1000;
    uintmax_t amt;
    int tenths;
    int exponent = -1;
    int exponent_max = (int) sizeof bl_power_letter - 2;
    char *p;
    char *psuffix;
    int rounding;

    psuffix = buf + BL_HUMAN_BUFLEN - 1 - 4;
    p = psuffix;

    if (to_block_size <= from_block_size)
    {
        if (to_block_size != 0 && from_block_size % to_block_size == 0)
        {
            uintmax_t multiplier = from_block_size / to_block_size;
            amt = n * multiplier;
            if (multiplier == 0 || amt / multiplier == n)
            {
                tenths = 0;
                rounding = 0;
                goto use_integer_arithmetic;
            }
        }
    }
    else if (from_block_size != 0 && to_block_size % from_block_size == 0)
    {
        uintmax_t divisor = to_block_size / from_block_size;
        uintmax_t r10 = (n % divisor) * 10;
        uintmax_t r2 = (r10 % divisor) * 2;
        amt = n / divisor;
        tenths = (int) (r10 / divisor);
        rounding = r2 < divisor ? 0 < r2 : 2 + (divisor < r2);
        goto use_integer_arithmetic;
    }

    {
        /* Fall back on long double (mirrors gnulib).  */
        long double dto_block_size = (long double) to_block_size;
        long double damt = n * (from_block_size / dto_block_size);
        size_t buflen;
        size_t nonintegerlen;

        if (!(opts & BL_HUMAN_AUTOSCALE))
        {
            snprintf (buf, BL_HUMAN_BUFLEN, "%.0Lf",
                      bl_adjust_value (inexact_style, damt));
            buflen = strlen (buf);
            nonintegerlen = 0;
        }
        else
        {
            long double e = 1;
            exponent = 0;
            do
            {
                e *= base;
                exponent++;
            }
            while (e * base <= damt && exponent < exponent_max);
            damt /= e;
            snprintf (buf, BL_HUMAN_BUFLEN, "%.1Lf",
                      bl_adjust_value (inexact_style, damt));
            buflen = strlen (buf);
            nonintegerlen = 2;
            if (1 + nonintegerlen + !(opts & BL_HUMAN_BASE_1024) < buflen
                || ((opts & BL_HUMAN_SUPPRESS_POINT_ZERO)
                    && buf[buflen - 1] == '0'))
            {
                snprintf (buf, BL_HUMAN_BUFLEN, "%.0Lf",
                          bl_adjust_value (inexact_style, damt * 10) / 10);
                buflen = strlen (buf);
                nonintegerlen = 0;
            }
        }
        p = psuffix - buflen;
        memmove (p, buf, buflen);
    }
    goto do_suffix;

use_integer_arithmetic:
    {
        if (opts & BL_HUMAN_AUTOSCALE)
        {
            exponent = 0;
            if (base <= amt)
            {
                do
                {
                    unsigned int r10 =
                        (unsigned int) ((amt % base) * 10 + tenths);
                    unsigned int r2 = (r10 % base) * 2 + (rounding >> 1);
                    amt /= base;
                    tenths = (int) (r10 / base);
                    rounding = (r2 < base
                                ? (r2 + rounding) != 0
                                : 2 + (base < r2 + rounding));
                    exponent++;
                }
                while (base <= amt && exponent < exponent_max);

                if (amt < 10)
                {
                    if (inexact_style == BL_HUMAN_ROUND_TO_NEAREST
                        ? 2 < rounding + (tenths & 1)
                        : inexact_style == BL_HUMAN_CEILING && 0 < rounding)
                    {
                        tenths++;
                        rounding = 0;
                        if (tenths == 10)
                        {
                            amt++;
                            tenths = 0;
                        }
                    }
                    if (amt < 10
                        && (tenths || !(opts & BL_HUMAN_SUPPRESS_POINT_ZERO)))
                    {
                        *--p = (char) ('0' + tenths);
                        *--p = '.';
                        tenths = rounding = 0;
                    }
                }
            }
        }

        if (inexact_style == BL_HUMAN_ROUND_TO_NEAREST
            ? 5 < tenths + (0 < rounding + (int) (amt & 1))
            : inexact_style == BL_HUMAN_CEILING && 0 < tenths + rounding)
        {
            amt++;
            if ((opts & BL_HUMAN_AUTOSCALE)
                && amt == base && exponent < exponent_max)
            {
                exponent++;
                if (!(opts & BL_HUMAN_SUPPRESS_POINT_ZERO))
                {
                    *--p = '0';
                    *--p = '.';
                }
                amt = 1;
            }
        }

        do
        {
            *--p = (char) ('0' + (int) (amt % 10));
        }
        while ((amt /= 10) != 0);
    }

do_suffix:
    if (opts & BL_HUMAN_SI)
    {
        if (exponent < 0)
        {
            uintmax_t power;
            exponent = 0;
            for (power = 1; power < to_block_size; power *= base)
                if (++exponent == exponent_max)
                    break;
        }
        if (exponent)
            *psuffix++ = (!(opts & BL_HUMAN_BASE_1024) && exponent == 1
                          ? 'k' : bl_power_letter[exponent]);
        if (opts & BL_HUMAN_B)
        {
            if ((opts & BL_HUMAN_BASE_1024) && exponent)
                *psuffix++ = 'i';
            *psuffix++ = 'B';
        }
    }
    *psuffix = '\0';
    return p;
}

/* ================= SIZE argument parsing (xstrtoumax+humblock) ===== */

enum { BL_LONGINT_OK = 0, BL_LONGINT_OVERFLOW = 1, BL_LONGINT_INVALID_SUFFIX = 2,
       BL_LONGINT_INVALID = 4 };

static int
bl_bkm_scale (uintmax_t *x, uintmax_t scale_factor)
{
    if (*x > UINTMAX_MAX / scale_factor)
    {
        *x = UINTMAX_MAX;
        return BL_LONGINT_OVERFLOW;
    }
    *x *= scale_factor;
    return BL_LONGINT_OK;
}

static int
bl_bkm_scale_by_power (uintmax_t *x, int base, int power)
{
    int err = BL_LONGINT_OK;
    while (power--)
        err |= bl_bkm_scale (x, (uintmax_t) base);
    return err;
}

/* xstrtoumax with the gnulib suffix machinery.  VALID_SUFFIXES as in
   gnulib ("" means none; '0' enables the B/iB second suffix).  */
static int
bl_xstrtoumax (const char *nptr, char **endptr, int strtol_base,
               uintmax_t *val, const char *valid_suffixes)
{
    char *t_ptr;
    char **p = endptr ? endptr : &t_ptr;
    const char *q = nptr;
    while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\v'
           || *q == '\f' || *q == '\r')
        q++;
    if (*q == '-')
    {
        *p = (char *) nptr;
        return BL_LONGINT_INVALID;
    }

    errno = 0;
    uintmax_t tmp = strtoumax (nptr, p, strtol_base);
    int err = BL_LONGINT_OK;

    if (*p == nptr)
    {
        if (!(valid_suffixes && *nptr && strchr (valid_suffixes, *nptr)))
            return BL_LONGINT_INVALID;
        tmp = 1;
    }
    else if (errno != 0)
    {
        if (errno != ERANGE)
            return BL_LONGINT_INVALID;
        err = BL_LONGINT_OVERFLOW;
    }

    if (valid_suffixes == NULL)
    {
        *val = tmp;
        return err;
    }

    if (**p != '\0')
    {
        int xbase = 1024;
        int suffixes = 1;
        int overflow;

        if (!strchr (valid_suffixes, **p))
        {
            *val = tmp;
            return err | BL_LONGINT_INVALID_SUFFIX;
        }
        switch (**p)
        {
            case 'E': case 'G': case 'g': case 'k': case 'K':
            case 'M': case 'm': case 'P': case 'Q': case 'R':
            case 'T': case 't': case 'Y': case 'Z':
                if (strchr (valid_suffixes, '0'))
                    switch (p[0][1])
                    {
                        case 'i':
                            if (p[0][2] == 'B')
                                suffixes += 2;
                            break;
                        case 'B':
                        case 'D':
                            xbase = 1000;
                            suffixes++;
                            break;
                    }
        }
        switch (**p)
        {
            case 'b': overflow = bl_bkm_scale (&tmp, 512); break;
            case 'B': overflow = bl_bkm_scale (&tmp, 1024); break;
            case 'c': overflow = BL_LONGINT_OK; break;
            case 'E': overflow = bl_bkm_scale_by_power (&tmp, xbase, 6); break;
            case 'G': case 'g':
                overflow = bl_bkm_scale_by_power (&tmp, xbase, 3); break;
            case 'k': case 'K':
                overflow = bl_bkm_scale_by_power (&tmp, xbase, 1); break;
            case 'M': case 'm':
                overflow = bl_bkm_scale_by_power (&tmp, xbase, 2); break;
            case 'P': overflow = bl_bkm_scale_by_power (&tmp, xbase, 5); break;
            case 'Q': overflow = bl_bkm_scale_by_power (&tmp, xbase, 10); break;
            case 'R': overflow = bl_bkm_scale_by_power (&tmp, xbase, 9); break;
            case 'T': case 't':
                overflow = bl_bkm_scale_by_power (&tmp, xbase, 4); break;
            case 'w': overflow = bl_bkm_scale (&tmp, 2); break;
            case 'Y': overflow = bl_bkm_scale_by_power (&tmp, xbase, 8); break;
            case 'Z': overflow = bl_bkm_scale_by_power (&tmp, xbase, 7); break;
            default:
                *val = tmp;
                return err | BL_LONGINT_INVALID_SUFFIX;
        }
        err |= overflow;
        *p += suffixes;
        if (**p)
            err |= BL_LONGINT_INVALID_SUFFIX;
    }
    *val = tmp;
    return err;
}

/* humblock: parse a block-size spec (or the BLOCK_SIZE/BLOCKSIZE env). */
static int
bl_humblock (const char *spec, uintmax_t *block_size, int *options)
{
    int opts = 0;

    if (!spec
        && !(spec = getenv ("BLOCK_SIZE"))
        && !(spec = getenv ("BLOCKSIZE")))
        *block_size = getenv ("POSIXLY_CORRECT") ? 512 : 1024;
    else
    {
        if (*spec == '\'')
        {
            opts |= BL_HUMAN_GROUP_DIGITS;
            spec++;
        }
        /* "human-readable" / "si" (unique abbreviations accepted) */
        size_t sl = strlen (spec);
        if (sl && strncmp (spec, "human-readable", sl) == 0)
        {
            opts |= BL_HUMAN_AUTOSCALE | BL_HUMAN_SI | BL_HUMAN_BASE_1024;
            *block_size = 1;
        }
        else if (sl && strncmp (spec, "si", sl) == 0)
        {
            opts |= BL_HUMAN_AUTOSCALE | BL_HUMAN_SI;
            *block_size = 1;
        }
        else
        {
            char *ptr;
            int e = bl_xstrtoumax (spec, &ptr, 0, block_size,
                                   "eEgGkKmMpPtTyYzZ0");
            if (e != BL_LONGINT_OK)
            {
                *options = 0;
                return e;
            }
            for (; !('0' <= *spec && *spec <= '9'); spec++)
                if (spec == ptr)
                {
                    opts |= BL_HUMAN_SI;
                    if (ptr[-1] == 'B')
                        opts |= BL_HUMAN_B;
                    if (ptr[-1] != 'B' || ptr[-2] == 'i')
                        opts |= BL_HUMAN_BASE_1024;
                    break;
                }
        }
    }
    *options = opts;
    return BL_LONGINT_OK;
}

static int
bl_human_options (const char *spec, int *opts, uintmax_t *block_size)
{
    int e = bl_humblock (spec, block_size, opts);
    if (*block_size == 0)
    {
        *block_size = getenv ("POSIXLY_CORRECT") ? 512 : 1024;
        e = BL_LONGINT_INVALID;
    }
    return e;
}

/* ================= time formatting ================= */

/* strftime with %N (nanoseconds) pre-substitution, GNU nstrftime-style. */
static size_t
bl_strftime_ns (char *out, size_t outsz, const char *fmt,
                const struct tm *tm, long nsec)
{
    bl_buf f = {0};
    for (const char *p = fmt; *p; p++)
    {
        if (p[0] == '%' && p[1] == 'N')
        {
            char ns[16];
            snprintf (ns, sizeof ns, "%09ld", nsec);
            bl_buf_str (&f, ns);
            p++;
        }
        else if (p[0] == '%' && p[1] != '\0')
        {
            bl_buf_ch (&f, p[0]);
            bl_buf_ch (&f, p[1]);
            p++;
        }
        else
            bl_buf_ch (&f, *p);
    }
    /* strftime returning 0 is ambiguous; use a leading marker so empty
       formats still round-trip (GNU nstrftime does similarly).  */
    size_t r = 0;
    if (f.p != NULL)
    {
        bl_buf pre = {0};
        bl_buf_ch (&pre, '\1');
        bl_buf_str (&pre, f.p);
        char tmp[1024];
        size_t got = strftime (tmp, sizeof tmp, pre.p ? pre.p : "\1", tm);
        if (got > 0 && tmp[0] == '\1')
        {
            r = got - 1;
            if (r >= outsz)
                r = outsz - 1;
            memcpy (out, tmp + 1, r);
            out[r] = '\0';
        }
        else
            out[0] = '\0';
        free (pre.p);
    }
    else
        out[0] = '\0';
    free (f.p);
    return r;
}

/* Expected number of columns in a long-format timestamp (epoch 0,
   non-recent format), for the "?" fallback alignment.  */
static int
bl_long_time_expected_width (ls_opts *o)
{
    time_t epoch = 0;
    struct tm tm;
    char buf[1024];
    if (localtime_r (&epoch, &tm) == NULL)
        return 0;
    size_t len = bl_strftime_ns (buf, sizeof buf, o->long_time_fmt[0], &tm, 0);
    int w = 0;
    for (size_t i = 0; i < len; i++)
        if (BL_ISPRINT ((unsigned char) buf[i]))
            w++;
    return w;
}

/* ================= filevercmp (gnulib port) ================= */

static size_t
bl_file_prefixlen (const char *s, size_t len)
{
    size_t prefixlen = 0;
    for (size_t i = 0; ;)
    {
        if (i == len)
            return prefixlen;
        i++;
        prefixlen = i;
        while (i + 1 < len && s[i] == '.'
               && (BL_ISALPHA ((unsigned char) s[i + 1]) || s[i + 1] == '~'))
            for (i += 2;
                 i < len && (BL_ISALNUM ((unsigned char) s[i]) || s[i] == '~');
                 i++)
                continue;
    }
}

static int
bl_ver_order (const char *s, size_t pos, size_t len)
{
    if (pos == len)
        return -1;
    unsigned char c = (unsigned char) s[pos];
    if (BL_ISDIGIT (c))
        return 0;
    else if (BL_ISALPHA (c))
        return c;
    else if (c == '~')
        return -2;
    else
        return (int) c + UCHAR_MAX + 1;
}

static int
bl_verrevcmp (const char *s1, size_t s1_len, const char *s2, size_t s2_len)
{
    size_t s1_pos = 0, s2_pos = 0;
    while (s1_pos < s1_len || s2_pos < s2_len)
    {
        int first_diff = 0;
        while ((s1_pos < s1_len && !BL_ISDIGIT ((unsigned char) s1[s1_pos]))
               || (s2_pos < s2_len && !BL_ISDIGIT ((unsigned char) s2[s2_pos])))
        {
            int s1_c = bl_ver_order (s1, s1_pos, s1_len);
            int s2_c = bl_ver_order (s2, s2_pos, s2_len);
            if (s1_c != s2_c)
                return s1_c - s2_c;
            s1_pos++;
            s2_pos++;
        }
        while (s1_pos < s1_len && s1[s1_pos] == '0')
            s1_pos++;
        while (s2_pos < s2_len && s2[s2_pos] == '0')
            s2_pos++;
        while (s1_pos < s1_len && s2_pos < s2_len
               && BL_ISDIGIT ((unsigned char) s1[s1_pos])
               && BL_ISDIGIT ((unsigned char) s2[s2_pos]))
        {
            if (!first_diff)
                first_diff = s1[s1_pos] - s2[s2_pos];
            s1_pos++;
            s2_pos++;
        }
        if (s1_pos < s1_len && BL_ISDIGIT ((unsigned char) s1[s1_pos]))
            return 1;
        if (s2_pos < s2_len && BL_ISDIGIT ((unsigned char) s2[s2_pos]))
            return -1;
        if (first_diff)
            return first_diff;
    }
    return 0;
}

static int
bl_filevercmp (const char *a, const char *b)
{
    if (!a[0])
        return -!!b[0];
    if (!b[0])
        return 1;

    if (a[0] == '.')
    {
        if (b[0] != '.')
            return -1;
        int adot = !a[1];
        int bdot = !b[1];
        if (adot)
            return -!bdot;
        if (bdot)
            return 1;
        int adotdot = a[1] == '.' && !a[2];
        int bdotdot = b[1] == '.' && !b[2];
        if (adotdot)
            return -!bdotdot;
        if (bdotdot)
            return 1;
    }
    else if (b[0] == '.')
        return 1;

    size_t alen = strlen (a), blen = strlen (b);
    size_t aprefixlen = bl_file_prefixlen (a, alen);
    size_t bprefixlen = bl_file_prefixlen (b, blen);
    int one_pass_only = aprefixlen == alen && bprefixlen == blen;
    int result = bl_verrevcmp (a, aprefixlen, b, bprefixlen);
    return (result || one_pass_only) ? result
                                     : bl_verrevcmp (a, alen, b, blen);
}

/* ================= the sort comparator ================= */

static int
bl_is_linked_directory (const ls_entry *f)
{
    return f->ftype == BL_T_DIRECTORY || f->ftype == BL_T_ARG_DIRECTORY
           || S_ISDIR (f->linkmode);
}

static int
bl_entcmp (const void *va, const void *vb)
{
    const ls_entry *a = va, *b = vb;
    ls_opts *o = bl_sort_opts;
    int cmp;

    if (o->group_directories_first)
    {
        int d = bl_is_linked_directory (b) - bl_is_linked_directory (a);
        if (d)
            return d;
    }

    if (bl_sort_opts->Sflag)
    {
        /* sort by size (descending → bigger first) */
        if (a->size != b->size)
            cmp = (a->size > b->size) ? -1 : 1;
        else
            cmp = strcmp (a->name, b->name);
    }
    else if (o->sort_type == BL_SORT_TIME)
    {
        cmp = bl_timespec_cmp (b->mtime, a->mtime);
        if (cmp == 0)
            cmp = strcmp (a->name, b->name);
    }
    else if (o->sort_type == BL_SORT_VERSION)
    {
        cmp = bl_filevercmp (a->name, b->name);
        if (cmp == 0)
            cmp = strcmp (a->name, b->name);
    }
    else if (o->sort_type == BL_SORT_EXTENSION)
    {
        const char *e1 = strrchr (a->name, '.');
        const char *e2 = strrchr (b->name, '.');
        cmp = strcmp (e1 ? e1 : "", e2 ? e2 : "");
        if (cmp == 0)
            cmp = strcmp (a->name, b->name);
    }
    else if (o->sort_type == BL_SORT_WIDTH)
    {
        cmp = (int) ((long) a->width - (long) b->width);
        if (cmp == 0)
            cmp = strcmp (a->name, b->name);
    }
    else
    {
        cmp = strcmp (a->name, b->name);
    }
    if (o->rflag)
        cmp = -cmp;
    return cmp;
}

/* ================= mode string / indicators ================= */

/* Mode string: 10 chars + NUL, like sbase's pattern (kept from v2). */
static void
bl_mode_string (mode_t m, char out[12])
{
    memcpy (out, "----------", 10);
    out[10] = '\0';
    if      (S_ISREG (m))  out[0] = '-';
    else if (S_ISBLK (m))  out[0] = 'b';
    else if (S_ISCHR (m))  out[0] = 'c';
    else if (S_ISDIR (m))  out[0] = 'd';
    else if (S_ISFIFO (m)) out[0] = 'p';
    else if (S_ISLNK (m))  out[0] = 'l';
    else if (S_ISSOCK (m)) out[0] = 's';
    else                   out[0] = '?';
    if (m & S_IRUSR) out[1] = 'r';
    if (m & S_IWUSR) out[2] = 'w';
    if (m & S_IXUSR) out[3] = 'x';
    if (m & S_IRGRP) out[4] = 'r';
    if (m & S_IWGRP) out[5] = 'w';
    if (m & S_IXGRP) out[6] = 'x';
    if (m & S_IROTH) out[7] = 'r';
    if (m & S_IWOTH) out[8] = 'w';
    if (m & S_IXOTH) out[9] = 'x';
    if (m & S_ISUID) out[3] = (out[3] == 'x') ? 's' : 'S';
    if (m & S_ISGID) out[6] = (out[6] == 'x') ? 's' : 'S';
    if (m & S_ISVTX) out[9] = (out[9] == 'x') ? 't' : 'T';
}

/* Single-byte type indicator, or 0 (GNU get_type_indicator).  */
static char
bl_get_type_indicator (ls_opts *o, int stat_ok, mode_t mode, int type)
{
    char c;
    if (stat_ok ? S_ISREG (mode) : type == BL_T_NORMAL)
    {
        if (stat_ok && o->indicator_style == BL_IND_CLASSIFY
            && (mode & (S_IXUSR | S_IXGRP | S_IXOTH)))
            c = '*';
        else
            c = 0;
    }
    else
    {
        if (stat_ok ? S_ISDIR (mode)
                    : type == BL_T_DIRECTORY || type == BL_T_ARG_DIRECTORY)
            c = '/';
        else if (o->indicator_style == BL_IND_SLASH)
            c = 0;
        else if (stat_ok ? S_ISLNK (mode) : type == BL_T_SYMLINK)
            c = '@';
        else if (stat_ok ? S_ISFIFO (mode) : type == BL_T_FIFO)
            c = '|';
        else if (stat_ok ? S_ISSOCK (mode) : type == BL_T_SOCK)
            c = '=';
        else
            c = 0;
    }
    return c;
}

static int
bl_print_type_indicator (ls_opts *o, int stat_ok, mode_t mode, int type)
{
    char c = bl_get_type_indicator (o, stat_ok, mode, type);
    if (c)
        bl_outbyte (o, c);
    return c != 0;
}

/* ================= color engine ================= */

static int
bl_c_strncasecmp (const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        unsigned char ca = (unsigned char) a[i], cb = (unsigned char) b[i];
        if ('A' <= ca && ca <= 'Z') ca += 'a' - 'A';
        if ('A' <= cb && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb)
            return ca < cb ? -1 : 1;
        if (ca == 0)
            return 0;
    }
    return 0;
}

/* coreutils 9.7 built-in default palette.  */
static void
bl_init_color_defaults (ls_opts *o)
{
    static const struct { size_t len; const char *s; } defs[BLC_N_INDICATORS] =
    {
        { 2, "\033[" },   /* lc */
        { 1, "m" },       /* rc */
        { 0, NULL },      /* ec */
        { 1, "0" },       /* rs */
        { 0, NULL },      /* no */
        { 0, NULL },      /* fi */
        { 5, "01;34" },   /* di */
        { 5, "01;36" },   /* ln */
        { 2, "33" },      /* pi */
        { 5, "01;35" },   /* so */
        { 5, "01;33" },   /* bd */
        { 5, "01;33" },   /* cd */
        { 0, NULL },      /* mi */
        { 0, NULL },      /* or */
        { 5, "01;32" },   /* ex */
        { 5, "01;35" },   /* do */
        { 5, "37;41" },   /* su */
        { 5, "30;43" },   /* sg */
        { 5, "37;44" },   /* st */
        { 5, "34;42" },   /* ow */
        { 5, "30;42" },   /* tw */
        { 0, NULL },      /* ca */
        { 0, NULL },      /* mh */
        { 3, "\033[K" },  /* cl */
    };
    for (int i = 0; i < BLC_N_INDICATORS; i++)
    {
        o->color_indicator[i].len = defs[i].len;
        o->color_indicator[i].string = defs[i].s;
    }
}

static const char bl_indicator_name[][3] =
{
    "lc", "rc", "ec", "rs", "no", "fi", "di", "ln", "pi", "so",
    "bd", "cd", "mi", "or", "ex", "do", "su", "sg", "st",
    "ow", "tw", "ca", "mh", "cl"
};

static int
bl_is_colored (ls_opts *o, int type)
{
    size_t len = o->color_indicator[type].len;
    const char *s = o->color_indicator[type].string;
    return !(len == 0
             || (len == 1 && s[0] == '0')
             || (len == 2 && s[0] == '0' && s[1] == '0'));
}

static void
bl_prep_non_filename_text (ls_opts *o)
{
    if (o->color_indicator[BLC_END].string != NULL)
        bl_put_indicator (o, &o->color_indicator[BLC_END]);
    else
    {
        bl_put_indicator (o, &o->color_indicator[BLC_LEFT]);
        bl_put_indicator (o, &o->color_indicator[BLC_RESET]);
        bl_put_indicator (o, &o->color_indicator[BLC_RIGHT]);
    }
}

/* Color escape output: NOT counted in dired_pos, exactly like GNU.  */
static void
bl_put_indicator (ls_opts *o, const bl_bin_str *ind)
{
    if (!o->used_color)
    {
        o->used_color = 1;
        bl_prep_non_filename_text (o);
    }
    if (ind->len)
        fwrite (ind->string, ind->len, 1, stdout);
}

static void
bl_set_normal_color (ls_opts *o)
{
    if (o->print_with_color && bl_is_colored (o, BLC_NORM))
    {
        bl_put_indicator (o, &o->color_indicator[BLC_LEFT]);
        bl_put_indicator (o, &o->color_indicator[BLC_NORM]);
        bl_put_indicator (o, &o->color_indicator[BLC_RIGHT]);
    }
}

/* LS_COLORS value lexer (port of coreutils get_funky_string).  */
static int
bl_get_funky_string (char **dest, const char **src, int equals_end,
                     size_t *output_count)
{
    char num = 0;
    size_t count = 0;
    enum { ST_GND, ST_BACKSLASH, ST_OCTAL, ST_HEX, ST_CARET, ST_END, ST_ERROR }
        state = ST_GND;
    const char *p = *src;
    char *q = *dest;

    while (state < ST_END)
    {
        switch (state)
        {
            case ST_GND:
                switch (*p)
                {
                    case ':':
                    case '\0':
                        state = ST_END;
                        break;
                    case '\\':
                        state = ST_BACKSLASH;
                        ++p;
                        break;
                    case '^':
                        state = ST_CARET;
                        ++p;
                        break;
                    case '=':
                        if (equals_end)
                        {
                            state = ST_END;
                            break;
                        }
                        /* fall through */
                    default:
                        *(q++) = *(p++);
                        ++count;
                        break;
                }
                break;

            case ST_BACKSLASH:
                switch (*p)
                {
                    case '0': case '1': case '2': case '3':
                    case '4': case '5': case '6': case '7':
                        state = ST_OCTAL;
                        num = *p - '0';
                        break;
                    case 'x': case 'X':
                        state = ST_HEX;
                        num = 0;
                        break;
                    case 'a': num = '\a'; break;
                    case 'b': num = '\b'; break;
                    case 'e': num = 27; break;
                    case 'f': num = '\f'; break;
                    case 'n': num = '\n'; break;
                    case 'r': num = '\r'; break;
                    case 't': num = '\t'; break;
                    case 'v': num = '\v'; break;
                    case '?': num = 127; break;
                    case '_': num = ' '; break;
                    case '\0': state = ST_ERROR; break;
                    default: num = *p; break;
                }
                if (state == ST_BACKSLASH)
                {
                    *(q++) = num;
                    ++count;
                    state = ST_GND;
                }
                ++p;
                break;

            case ST_OCTAL:
                if (*p < '0' || *p > '7')
                {
                    *(q++) = num;
                    ++count;
                    state = ST_GND;
                }
                else
                    num = (char) ((num << 3) + (*(p++) - '0'));
                break;

            case ST_HEX:
                switch (*p)
                {
                    case '0': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        num = (char) ((num << 4) + (*(p++) - '0'));
                        break;
                    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
                        num = (char) ((num << 4) + (*(p++) - 'a') + 10);
                        break;
                    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
                        num = (char) ((num << 4) + (*(p++) - 'A') + 10);
                        break;
                    default:
                        *(q++) = num;
                        ++count;
                        state = ST_GND;
                        break;
                }
                break;

            case ST_CARET:
                state = ST_GND;
                if (*p >= '@' && *p <= '~')
                {
                    *(q++) = *(p++) & 037;
                    ++count;
                }
                else if (*p == '?')
                {
                    *(q++) = 127;
                    ++count;
                    ++p;
                }
                else
                    state = ST_ERROR;
                break;

            default:
                state = ST_ERROR;
                break;
        }
    }

    *dest = q;
    *src = p;
    *output_count = count;
    return state != ST_ERROR;
}

static int
bl_known_term_type (void)
{
    const char *term = getenv ("TERM");
    if (!term || !*term)
        return 0;
    static const char *const pats[] =
    {
        "Eterm", "ansi", "*color*", "con[0-9]*x[0-9]*", "cons25", "console",
        "cygwin", "*direct*", "dtterm", "gnome", "hurd", "jfbterm", "konsole",
        "kterm", "linux", "linux-c", "mlterm", "putty", "rxvt*", "screen*",
        "st", "terminator", "tmux*", "vt100", "vt220", "xterm*", NULL
    };
    for (int i = 0; pats[i]; i++)
        if (fnmatch (pats[i], term, 0) == 0)
            return 1;
    return 0;
}

static void
bl_parse_ls_color (ls_opts *o)
{
    const char *p;
    char *buf;
    char label0, label1;
    bl_color_ext *ext = NULL;

    if ((p = getenv ("LS_COLORS")) == NULL || *p == '\0')
    {
        const char *colorterm = getenv ("COLORTERM");
        if (!(colorterm && *colorterm) && !bl_known_term_type ())
            o->print_with_color = 0;
        return;
    }

    buf = o->color_buf = bl_xstrdup (p);
    if (buf == NULL)
        return;

    enum { PS_START = 1, PS_2, PS_3, PS_4, PS_DONE, PS_FAIL } state = PS_START;
    label0 = label1 = 0;
    while (1)
    {
        switch (state)
        {
            case PS_START:
                switch (*p)
                {
                    case ':':
                        ++p;
                        break;
                    case '*':
                        ext = bl_xmalloc (sizeof *ext);
                        if (ext == NULL) { state = PS_FAIL; break; }
                        ext->next = o->color_ext_list;
                        o->color_ext_list = ext;
                        ext->exact_match = 0;
                        ext->seq.len = 0;
                        ext->seq.string = NULL;
                        ++p;
                        ext->ext.string = buf;
                        state = (bl_get_funky_string (&buf, &p, 1, &ext->ext.len)
                                 ? PS_4 : PS_FAIL);
                        break;
                    case '\0':
                        state = PS_DONE;
                        goto done;
                    default:
                        label0 = *p++;
                        state = PS_2;
                        break;
                }
                break;

            case PS_2:
                if (*p)
                {
                    label1 = *p++;
                    state = PS_3;
                }
                else
                    state = PS_FAIL;
                break;

            case PS_3:
                state = PS_FAIL;
                if (*(p++) == '=')
                {
                    for (int i = 0; i < BLC_N_INDICATORS; i++)
                    {
                        if (label0 == bl_indicator_name[i][0]
                            && label1 == bl_indicator_name[i][1])
                        {
                            o->color_indicator[i].string = buf;
                            state = (bl_get_funky_string (&buf, &p, 0,
                                                          &o->color_indicator[i].len)
                                     ? PS_START : PS_FAIL);
                            break;
                        }
                    }
                    if (state == PS_FAIL)
                        fprintf (stderr,
                                 "ls: unrecognized prefix: '%c%c'\n",
                                 label0, label1);
                }
                break;

            case PS_4:
                if (*(p++) == '=')
                {
                    ext->seq.string = buf;
                    state = (bl_get_funky_string (&buf, &p, 0, &ext->seq.len)
                             ? PS_START : PS_FAIL);
                }
                else
                    state = PS_FAIL;
                break;

            case PS_FAIL:
                goto done;

            default:
                goto done;
        }
    }
done:

    if (state == PS_FAIL)
    {
        fprintf (stderr,
                 "ls: unparsable value for LS_COLORS environment variable\n");
        free (o->color_buf);
        o->color_buf = NULL;
        for (bl_color_ext *e = o->color_ext_list; e != NULL;)
        {
            bl_color_ext *e2 = e;
            e = e->next;
            free (e2);
        }
        o->color_ext_list = NULL;
        bl_init_color_defaults (o);
        o->print_with_color = 0;
    }
    else
    {
        /* Mark case-clashing extensions for exact matching; disable
           shadowed duplicates.  */
        for (bl_color_ext *e1 = o->color_ext_list; e1 != NULL; e1 = e1->next)
        {
            int case_ignored = 0;
            for (bl_color_ext *e2 = e1->next; e2 != NULL; e2 = e2->next)
            {
                if (e2->ext.len < (size_t) -1 && e1->ext.len == e2->ext.len)
                {
                    if (memcmp (e1->ext.string, e2->ext.string,
                                e1->ext.len) == 0)
                        e2->ext.len = (size_t) -1;
                    else if (bl_c_strncasecmp (e1->ext.string, e2->ext.string,
                                               e1->ext.len) == 0)
                    {
                        if (case_ignored)
                            e2->ext.len = (size_t) -1;
                        else if (e1->seq.len == e2->seq.len
                                 && memcmp (e1->seq.string, e2->seq.string,
                                            e1->seq.len) == 0)
                        {
                            e2->ext.len = (size_t) -1;
                            case_ignored = 1;
                        }
                        else
                        {
                            e1->exact_match = 1;
                            e2->exact_match = 1;
                        }
                    }
                }
            }
        }
    }

    if (o->color_indicator[BLC_LINK].len == 6
        && strncmp (o->color_indicator[BLC_LINK].string, "target", 6) == 0)
        o->color_symlink_as_referent = 1;
}

static mode_t
bl_file_or_link_mode (ls_opts *o, const ls_entry *f)
{
    return (o->color_symlink_as_referent && f->linkok)
           ? f->linkmode : f->st.st_mode;
}

static const bl_bin_str *
bl_get_color_indicator (ls_opts *o, const ls_entry *f, int symlink_target)
{
    int type;
    bl_color_ext *ext = NULL;
    const char *name;
    mode_t mode;
    int linkok;

    if (symlink_target)
    {
        name = f->linkname;
        mode = f->linkmode;
        linkok = f->linkok ? 0 : -1;
    }
    else
    {
        name = f->name;
        mode = bl_file_or_link_mode (o, f);
        linkok = f->linkok;
    }

    if (linkok == -1 && bl_is_colored (o, BLC_MISSING))
        type = BLC_MISSING;
    else if (!f->stat_ok)
    {
        static const int filetype_indicator[] =
        {
            BLC_ORPHAN, BLC_FIFO, BLC_CHR, BLC_DIR, BLC_BLK, BLC_FILE,
            BLC_LINK, BLC_SOCK, BLC_FILE, BLC_DIR
        };
        type = filetype_indicator[f->ftype];
    }
    else
    {
        if (S_ISREG (mode))
        {
            type = BLC_FILE;
            if ((mode & S_ISUID) != 0 && bl_is_colored (o, BLC_SETUID))
                type = BLC_SETUID;
            else if ((mode & S_ISGID) != 0 && bl_is_colored (o, BLC_SETGID))
                type = BLC_SETGID;
            else if ((mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0
                     && bl_is_colored (o, BLC_EXEC))
                type = BLC_EXEC;
            else if (1 < f->st.st_nlink && bl_is_colored (o, BLC_MULTIHARDLINK))
                type = BLC_MULTIHARDLINK;
        }
        else if (S_ISDIR (mode))
        {
            type = BLC_DIR;
            if ((mode & S_ISVTX) && (mode & S_IWOTH)
                && bl_is_colored (o, BLC_STICKY_OTHER_WRITABLE))
                type = BLC_STICKY_OTHER_WRITABLE;
            else if ((mode & S_IWOTH) != 0 && bl_is_colored (o, BLC_OTHER_WRITABLE))
                type = BLC_OTHER_WRITABLE;
            else if ((mode & S_ISVTX) != 0 && bl_is_colored (o, BLC_STICKY))
                type = BLC_STICKY;
        }
        else if (S_ISLNK (mode))
            type = BLC_LINK;
        else if (S_ISFIFO (mode))
            type = BLC_FIFO;
        else if (S_ISSOCK (mode))
            type = BLC_SOCK;
        else if (S_ISBLK (mode))
            type = BLC_BLK;
        else if (S_ISCHR (mode))
            type = BLC_CHR;
        else
            type = BLC_ORPHAN;
    }

    if (type == BLC_FILE)
    {
        size_t len = strlen (name);
        const char *nend = name + len;
        for (ext = o->color_ext_list; ext != NULL; ext = ext->next)
        {
            if (ext->ext.len <= len && ext->ext.len < (size_t) -1)
            {
                if (ext->exact_match)
                {
                    if (memcmp (nend - ext->ext.len, ext->ext.string,
                                ext->ext.len) == 0)
                        break;
                }
                else
                {
                    if (bl_c_strncasecmp (nend - ext->ext.len, ext->ext.string,
                                          ext->ext.len) == 0)
                        break;
                }
            }
        }
    }

    if (type == BLC_LINK && !linkok)
    {
        if (o->color_symlink_as_referent || bl_is_colored (o, BLC_ORPHAN))
            type = BLC_ORPHAN;
    }

    const bl_bin_str *s = ext ? &ext->seq : &o->color_indicator[type];
    return s->string ? s : NULL;
}

/* ================= ACL / security context ================= */

/* Check the file's xattrs for a POSIX ACL and the SELinux context.
   Returns a BL_ACL_* classification; *SCONTEXT_OUT gets a malloc'd
   context string or NULL (rendered as "?").  Matches what GNU's
   file_has_aclinfo reports on a Linux host without SELinux.  */
static int
bl_file_aclinfo (const char *path, int deref, int get_scontext,
                 char **scontext_out)
{
    char sbuf[2048];
    char *list = sbuf;
    char *heap = NULL;
    ssize_t n;

    *scontext_out = NULL;

    errno = 0;
    n = deref ? listxattr (path, list, sizeof sbuf)
              : llistxattr (path, list, sizeof sbuf);
    if (n < 0 && errno == ERANGE)
    {
        ssize_t need = deref ? listxattr (path, NULL, 0)
                             : llistxattr (path, NULL, 0);
        if (need > 0 && (heap = bl_xmalloc ((size_t) need)) != NULL)
        {
            list = heap;
            n = deref ? listxattr (path, list, (size_t) need)
                      : llistxattr (path, list, (size_t) need);
        }
    }
    if (n < 0)
    {
        int e = errno;
        free (heap);
        if (e == EACCES || e == ENOENT)
            return BL_ACL_UNKNOWN;
        return BL_ACL_NONE;
    }

    int have_acl = 0, have_selinux = 0;
    for (ssize_t i = 0; i < n; i += (ssize_t) strlen (list + i) + 1)
    {
        const char *nm = list + i;
        if (strcmp (nm, "system.posix_acl_access") == 0
            || strcmp (nm, "system.posix_acl_default") == 0
            || strcmp (nm, "system.nfs4_acl") == 0)
            have_acl = 1;
        else if (strcmp (nm, "security.selinux") == 0)
            have_selinux = 1;
    }
    free (heap);

    if (have_selinux && get_scontext)
    {
        char vbuf[1024];
        ssize_t vn = deref
            ? getxattr (path, "security.selinux", vbuf, sizeof vbuf - 1)
            : lgetxattr (path, "security.selinux", vbuf, sizeof vbuf - 1);
        if (vn > 0)
        {
            while (vn > 0 && vbuf[vn - 1] == '\0')
                vn--;
            vbuf[vn] = '\0';
            *scontext_out = bl_xstrdup (vbuf);
        }
        else
            have_selinux = 0;
    }

    if (!have_acl && !have_selinux)
        return BL_ACL_NONE;
    if (have_selinux && !have_acl)
        return BL_ACL_LSM_CONTEXT_ONLY;
    return BL_ACL_YES;
}

/* ================= seen-dir set (-R loop detection) ================= */

/* Push DEV/INO onto the active set.  Returns 1 if already present
   (cycle), 0 if added, -1 on allocation failure.  */
static int
bl_seen_dir_add (ls_seen_dir **seen, dev_t dev, ino_t ino)
{
    for (ls_seen_dir *p = *seen; p; p = p->next)
        if (p->dev == dev && p->ino == ino)
            return 1;
    ls_seen_dir *n = malloc (sizeof *n);
    if (!n)
        return -1;
    n->dev = dev;
    n->ino = ino;
    n->next = *seen;
    *seen = n;
    return 0;
}

/* Pop the most recently pushed entry (subtree finished).  */
static void
bl_seen_dir_pop (ls_seen_dir **seen)
{
    if (*seen)
    {
        ls_seen_dir *head = *seen;
        *seen = head->next;
        free (head);
    }
}

static void
bl_seen_dir_free (ls_seen_dir *seen)
{
    while (seen)
    {
        ls_seen_dir *next = seen->next;
        free (seen);
        seen = next;
    }
}

/* ================= path + misc helpers ================= */

/* Build path = dir + "/" + name when dir is non-NULL/".".  Result is
   malloc'd; caller frees.  GNU attach() semantics: a bare "." prefix
   is dropped.  */
static char *
bl_join_path (const char *dir, const char *name)
{
    if (!dir || !*dir || (dir[0] == '.' && dir[1] == '\0'))
        return strdup (name);
    size_t dl = strlen (dir), nl = strlen (name);
    int need_slash = (dir[dl - 1] != '/');
    char *p = malloc (dl + (need_slash ? 1 : 0) + nl + 1);
    if (!p) return NULL;
    memcpy (p, dir, dl);
    if (need_slash) p[dl++] = '/';
    memcpy (p + dl, name, nl + 1);
    return p;
}

/* file_name_concat semantics: always join (keeps a "." prefix; the -R
   headers use this, so `ls -R .` prints "./dir1:" like GNU).  */
static char *
bl_concat_path (const char *dir, const char *name)
{
    if (!dir || !*dir)
        return strdup (name);
    size_t dl = strlen (dir), nl = strlen (name);
    int need_slash = (dir[dl - 1] != '/');
    char *p = malloc (dl + (need_slash ? 1 : 0) + nl + 1);
    if (!p) return NULL;
    memcpy (p, dir, dl);
    if (need_slash) p[dl++] = '/';
    memcpy (p + dl, name, nl + 1);
    return p;
}

static char *bl_areadlink (const char *path, off_t size_hint);

/* realpath with a CAN_MISSING fallback (missing final components are
   allowed and symlink chains are followed), for --hyperlink.  */
static char *
bl_canonicalize (const char *name)
{
    char *cur = bl_xstrdup (name);

    for (int depth = 0; cur && depth < 40; depth++)
    {
        char *r = realpath (cur, NULL);
        if (r)
        {
            free (cur);
            return r;
        }

        /* canonicalize the parent and re-append the last component */
        char *base = strrchr (cur, '/');
        char *rd;
        const char *last;
        if (base)
        {
            size_t dlen = (size_t) (base - cur);
            char dirbuf_root[2] = "/";
            char *dir = dlen ? bl_xmalloc (dlen + 1) : NULL;
            if (dlen && dir)
            {
                memcpy (dir, cur, dlen);
                dir[dlen] = '\0';
            }
            rd = realpath (dlen ? (dir ? dir : ".") : dirbuf_root, NULL);
            free (dir);
            last = base + 1;
        }
        else
        {
            rd = getcwd (NULL, 0);
            last = cur;
        }
        if (!rd)
            return cur;   /* best effort */

        char *path = bl_concat_path (rd, last);
        if (!path)
        {
            free (rd);
            return cur;
        }

        /* If the final component is a symlink, chase it (CAN_MISSING
           resolves through dangling links).  */
        struct stat st;
        if (lstat (path, &st) == 0 && S_ISLNK (st.st_mode))
        {
            char *tgt = bl_areadlink (path, st.st_size);
            if (tgt)
            {
                char *next = (tgt[0] == '/') ? bl_xstrdup (tgt)
                                             : bl_concat_path (rd, tgt);
                free (tgt);
                free (path);
                free (rd);
                free (cur);
                cur = next;
                continue;
            }
        }
        free (rd);
        free (cur);
        return path;
    }
    return cur;
}

/* Shell-escape-always quoting of NAME for diagnostics (GNU quoteaf).  */
static const char *
bl_quoteaf (ls_opts *o, const char *name)
{
    o->qbuf2.len = 0;
    if (o->qbuf2.p) o->qbuf2.p[0] = '\0';
    bl_quotearg_append (&o->qbuf2, name, BL_Q_SHELL_ESCAPE_ALWAYS, NULL);
    return o->qbuf2.p ? o->qbuf2.p : name;
}

static void
bl_set_exit_status (ls_opts *o, int serious)
{
    if (serious)
        o->exit_status = 2;
    else if (o->exit_status == 0)
        o->exit_status = 1;
}

/* GNU file_failure: report a file access failure (errno applies).  */
static void
bl_file_failure (ls_opts *o, int serious, const char *message,
                 const char *file)
{
    builtin_error ("%s %s: %s", message, bl_quoteaf (o, file),
                   strerror (errno));
    bl_set_exit_status (o, serious);
}

/* ================= file table management ================= */

static void
bl_free_entry (ls_entry *e)
{
    free (e->name);
    free (e->linkname);
    free (e->absolute_name);
    free (e->scontext);
}

static void
bl_clear_files (ls_opts *o)
{
    for (size_t i = 0; i < o->n_used; i++)
        bl_free_entry (&o->ents[i]);
    o->n_used = 0;
    o->cwd_some_quoted = 0;
    o->any_has_acl = 0;
    o->inode_number_width = 0;
    o->block_size_width = 0;
    o->nlink_width = 0;
    o->owner_width = 0;
    o->group_width = 0;
    o->author_width = 0;
    o->scontext_width = 0;
    o->major_device_number_width = 0;
    o->minor_device_number_width = 0;
    o->file_size_width = 0;
}

/* POSIX wants file sizes printed without a sign even when negative
   (treat as wrapped-around positive values).  */
static uintmax_t
bl_unsigned_file_size (off_t size)
{
    return (uintmax_t) size;
}

static int
bl_dtype_to_filetype (unsigned char d)
{
    switch (d)
    {
        case DT_BLK: return BL_T_BLOCKDEV;
        case DT_CHR: return BL_T_CHARDEV;
        case DT_DIR: return BL_T_DIRECTORY;
        case DT_FIFO: return BL_T_FIFO;
        case DT_LNK: return BL_T_SYMLINK;
        case DT_REG: return BL_T_NORMAL;
        case DT_SOCK: return BL_T_SOCK;
        default: return BL_T_UNKNOWN;
    }
}

static int
bl_mode_to_filetype (mode_t m)
{
    if (S_ISREG (m)) return BL_T_NORMAL;
    if (S_ISDIR (m)) return BL_T_DIRECTORY;
    if (S_ISLNK (m)) return BL_T_SYMLINK;
    if (S_ISFIFO (m)) return BL_T_FIFO;
    if (S_ISSOCK (m)) return BL_T_SOCK;
    if (S_ISBLK (m)) return BL_T_BLOCKDEV;
    if (S_ISCHR (m)) return BL_T_CHARDEV;
    return BL_T_UNKNOWN;
}

/* Read the symlink target (areadlink-with-size shape).  */
static char *
bl_areadlink (const char *path, off_t size_hint)
{
    size_t bufsz = (size_hint > 0 ? (size_t) size_hint : 256) + 1;
    for (;;)
    {
        char *buf = bl_xmalloc (bufsz);
        if (!buf)
            return NULL;
        ssize_t got = readlink (path, buf, bufsz);
        if (got < 0)
        {
            free (buf);
            return NULL;
        }
        if ((size_t) got < bufsz)
        {
            buf[got] = '\0';
            return buf;
        }
        free (buf);
        bufsz *= 2;
    }
}

/* Add one file to the table: stat as needed, fetch link/ACL/context
   info, and accumulate the long-format column widths.  Returns the
   file's block count (for the "total" line).  Port of gobble_file.  */
static uintmax_t
bl_gobble_file (ls_opts *o, const char *name, int type,
                int command_line_arg, const char *dirname)
{
    uintmax_t blocks = 0;

    if (o->n_used == o->n_alloc)
    {
        size_t ncap = o->n_alloc ? o->n_alloc * 2 : 64;
        ls_entry *bigger = realloc (o->ents, ncap * sizeof *bigger);
        if (!bigger)
            return 0;
        o->ents = bigger;
        o->n_alloc = ncap;
    }

    ls_entry *e = &o->ents[o->n_used];
    memset (e, 0, sizeof *e);
    e->ftype = type;
    e->quoted = -1;
    e->btime.tv_sec = -1;
    e->btime.tv_nsec = -1;

    if (!o->cwd_some_quoted && o->align_variable_outer_quotes)
    {
        e->quoted = bl_needs_quoting (o, name);
        if (e->quoted)
            o->cwd_some_quoted = 1;
    }

    int check_stat =
        (command_line_arg
         || o->print_hyperlink
         || o->format_needs_stat
         || (o->format_needs_type && type == BL_T_UNKNOWN)
         || ((type == BL_T_DIRECTORY || type == BL_T_UNKNOWN)
             && o->print_with_color
             && (bl_is_colored (o, BLC_OTHER_WRITABLE)
                 || bl_is_colored (o, BLC_STICKY)
                 || bl_is_colored (o, BLC_STICKY_OTHER_WRITABLE)))
         || ((o->print_inode || o->format_needs_type)
             && (type == BL_T_SYMLINK || type == BL_T_UNKNOWN)
             && (o->deref == BL_DEREF_ALWAYS
                 || o->color_symlink_as_referent || o->check_symlink_mode))
         || (o->print_inode)
         || ((type == BL_T_NORMAL || type == BL_T_UNKNOWN)
             && (o->indicator_style == BL_IND_CLASSIFY
                 || (o->print_with_color
                     && (bl_is_colored (o, BLC_EXEC)
                         || bl_is_colored (o, BLC_SETUID)
                         || bl_is_colored (o, BLC_SETGID))))));

    char *joined = NULL;
    const char *full_name = name;
    if (name[0] != '/' && dirname)
    {
        joined = bl_join_path (dirname, name);
        if (joined)
            full_name = joined;
    }

    int do_deref;

    if (!check_stat)
        do_deref = (o->deref == BL_DEREF_ALWAYS);
    else
    {
        int err;
        struct stat st;

        if (o->print_hyperlink)
            e->absolute_name = bl_canonicalize (full_name);

        switch (o->deref)
        {
            case BL_DEREF_ALWAYS:
                err = stat (full_name, &st);
                do_deref = 1;
                break;

            case BL_DEREF_COMMAND_LINE_ARGUMENTS:
            case BL_DEREF_COMMAND_LINE_SYMLINK_TO_DIR:
                if (command_line_arg)
                {
                    int need_lstat;
                    err = stat (full_name, &st);
                    do_deref = 1;
                    if (o->deref == BL_DEREF_COMMAND_LINE_ARGUMENTS)
                        break;
                    need_lstat = (err < 0
                                  ? (errno == ENOENT || errno == ELOOP)
                                  : !S_ISDIR (st.st_mode));
                    if (!need_lstat)
                        break;
                    /* fall through to lstat */
                }
                /* fall through */
            case BL_DEREF_NEVER:
            default:
                err = lstat (full_name, &st);
                do_deref = 0;
                break;
        }

        if (err != 0)
        {
            /* Failure to stat a command line argument leads to exit
               status 2; for other files it is a minor problem.  */
            bl_file_failure (o, command_line_arg, "cannot access", full_name);
            if (command_line_arg)
            {
                free (joined);
                return 0;
            }
            e->name = bl_xstrdup (name);
            o->n_used++;
            free (joined);
            return 0;
        }

        e->stat_ok = 1;
        e->st = st;
        e->mode = st.st_mode;
        e->ftype = type = bl_mode_to_filetype (st.st_mode);
        e->size = st.st_size;
        if (o->time_type == BL_TIME_BTIME)
            e->btime = bl_get_btime (full_name, do_deref);
        /* -c uses ctime, -u atime, --time=birth btime; default mtime. */
        if (o->cflag)      e->mtime = st.st_ctim;
        else if (o->uflag) e->mtime = st.st_atim;
        else if (o->time_type == BL_TIME_BTIME) e->mtime = e->btime;
        else               e->mtime = st.st_mtim;
    }

    if (type == BL_T_DIRECTORY && command_line_arg && !o->dflag)
        e->ftype = type = BL_T_ARG_DIRECTORY;

    int get_scontext = (o->format == BL_FMT_LONG) | o->print_scontext;
    if (get_scontext && e->stat_ok)
    {
        e->acl_type = bl_file_aclinfo (full_name, do_deref,
                                       o->print_scontext || 1, &e->scontext);
        if (e->acl_type != BL_ACL_NONE)
            o->any_has_acl = 1;
    }

    if (type == BL_T_SYMLINK
        && (o->format == BL_FMT_LONG || o->check_symlink_mode))
    {
        struct stat linkstats;
        e->linkname = bl_areadlink (full_name, e->stat_ok ? e->st.st_size : 0);
        if (e->linkname == NULL)
            bl_file_failure (o, command_line_arg,
                             "cannot read symbolic link", full_name);
        if (e->linkname && e->quoted == 0 && bl_needs_quoting (o, e->linkname))
            e->quoted = -1;
        if (e->linkname
            && (o->indicator_style >= BL_IND_FILE_TYPE || o->check_symlink_mode)
            && stat (full_name, &linkstats) == 0)
        {
            e->linkok = 1;
            e->linkmode = linkstats.st_mode;
        }
    }

    if (e->stat_ok)
        blocks = (uintmax_t) e->st.st_blocks;

    if (o->format == BL_FMT_LONG || o->print_block_size)
    {
        char hbuf[BL_HUMAN_BUFLEN];
        int len = (int) strlen (e->stat_ok
                                ? bl_human_readable (blocks, hbuf,
                                                     o->human_output_opts, 512,
                                                     o->output_block_size)
                                : "?");
        if (o->block_size_width < len)
            o->block_size_width = len;
    }

    if (o->format == BL_FMT_LONG && e->stat_ok)
    {
        if (o->print_owner)
        {
            int len;
            if (o->numeric_ids)
            {
                char nb[24];
                len = snprintf (nb, sizeof nb, "%ju",
                                (uintmax_t) e->st.st_uid);
            }
            else
                len = (int) strlen (bl_lookup_uid (&o->ucache, e->st.st_uid));
            if (o->owner_width < len)
                o->owner_width = len;
        }
        if (o->print_group)
        {
            int len;
            if (o->numeric_ids)
            {
                char nb[24];
                len = snprintf (nb, sizeof nb, "%ju",
                                (uintmax_t) e->st.st_gid);
            }
            else
                len = (int) strlen (bl_lookup_gid (&o->gcache, e->st.st_gid));
            if (o->group_width < len)
                o->group_width = len;
        }
        if (o->print_author)
        {
            int len;
            if (o->numeric_ids)
            {
                char nb[24];
                len = snprintf (nb, sizeof nb, "%ju",
                                (uintmax_t) e->st.st_uid);
            }
            else
                len = (int) strlen (bl_lookup_uid (&o->ucache, e->st.st_uid));
            if (o->author_width < len)
                o->author_width = len;
        }
    }

    if (o->print_scontext)
    {
        int len = (int) strlen (e->scontext ? e->scontext : "?");
        if (o->scontext_width < len)
            o->scontext_width = len;
    }

    if (o->format == BL_FMT_LONG)
    {
        char nb[32];
        int b_len = snprintf (nb, sizeof nb, "%ju",
                              e->stat_ok ? (uintmax_t) e->st.st_nlink : 1);
        if (!e->stat_ok)
            b_len = 1; /* "?" */
        if (o->nlink_width < b_len)
            o->nlink_width = b_len;

        if (e->stat_ok
            && (S_ISCHR (e->st.st_mode) || S_ISBLK (e->st.st_mode)))
        {
            int len = snprintf (nb, sizeof nb, "%ju",
                                (uintmax_t) major (e->st.st_rdev));
            if (o->major_device_number_width < len)
                o->major_device_number_width = len;
            len = snprintf (nb, sizeof nb, "%ju",
                            (uintmax_t) minor (e->st.st_rdev));
            if (o->minor_device_number_width < len)
                o->minor_device_number_width = len;
            len = o->major_device_number_width + 2
                  + o->minor_device_number_width;
            if (o->file_size_width < len)
                o->file_size_width = len;
        }
        else
        {
            char hbuf[BL_HUMAN_BUFLEN];
            int len = (int) strlen (e->stat_ok
                                    ? bl_human_readable (
                                          bl_unsigned_file_size (e->st.st_size),
                                          hbuf, o->file_human_output_opts, 1,
                                          o->file_output_block_size)
                                    : "?");
            if (o->file_size_width < len)
                o->file_size_width = len;
        }
    }

    if (o->print_inode)
    {
        char nb[32];
        int len = snprintf (nb, sizeof nb, "%ju",
                            e->stat_ok ? (uintmax_t) e->st.st_ino : 0);
        if (!e->stat_ok)
            len = 1; /* "?" */
        if (o->inode_number_width < len)
            o->inode_number_width = len;
    }

    e->name = bl_xstrdup (name);
    o->n_used++;
    free (joined);
    return blocks;
}

/* ================= pending-directory queue ================= */

static void
bl_queue_directory (ls_opts *o, const char *name, const char *realname,
                    int command_line_arg)
{
    bl_pending *n = bl_xmalloc (sizeof *n);
    if (!n)
        return;
    n->realname = bl_xstrdup (realname);
    n->name = bl_xstrdup (name);
    n->command_line_arg = command_line_arg;
    n->next = o->pending_dirs;
    o->pending_dirs = n;
}

static int
bl_is_directory_entry (const ls_entry *f)
{
    return f->ftype == BL_T_DIRECTORY || f->ftype == BL_T_ARG_DIRECTORY;
}

/* Remove directories from the table and queue them for listing.
   Port of extract_dirs_from_files.  */
static void
bl_extract_dirs_from_files (ls_opts *o, const char *dirname,
                            int command_line_arg)
{
    size_t i, j;
    ls_entry *ents = o->ents;

    if (dirname && o->Rflag)
    {
        /* Marker so the loop-detection set pops DIRNAME after its
           whole subtree is processed.  */
        bl_queue_directory (o, NULL, dirname, 0);
    }

    /* Queue in reverse so the pending stack preserves sort order.  */
    for (i = o->n_used; 0 < i;)
    {
        i--;
        const char *nm = ents[i].name;
        if (dirname)
        {
            if (!strcmp (nm, ".") || !strcmp (nm, "..")) continue;
        }
        if (S_ISLNK (ents[i].mode) && !o->Lflag) continue;
        if (!bl_is_directory_entry (&ents[i]))
            continue;
        if (!dirname || nm[0] == '/')
            bl_queue_directory (o, nm, ents[i].linkname, command_line_arg);
        else
        {
            char *full = bl_concat_path (dirname, nm);
            if (full)
            {
                bl_queue_directory (o, full, ents[i].linkname,
                                    command_line_arg);
                free (full);
            }
        }
        if (ents[i].ftype == BL_T_ARG_DIRECTORY)
            bl_free_entry (&ents[i]);
    }

    /* Compact: drop the queued command-line directories.  */
    for (i = 0, j = 0; i < o->n_used; i++)
    {
        if (ents[i].ftype != BL_T_ARG_DIRECTORY)
        {
            if (j != i)
                ents[j] = ents[i];
            j++;
        }
    }
    o->n_used = j;
}

/* ================= sorting ================= */

static void
bl_sort_entries (ls_opts *o)
{
    ls_entry *ents = o->ents;

    /* Cache display widths when the layout or sort needs them.  */
    if (o->sort_type == BL_SORT_WIDTH
        || (o->line_length
            && (o->format == BL_FMT_MANY_PER_LINE
                || o->format == BL_FMT_HORIZONTAL)))
    {
        for (size_t i = 0; i < o->n_used; i++)
            ents[i].width = bl_name_width (ents[i].name, o);
    }

    bl_sort_opts = o;
    if (!o->fflag)
        qsort (ents, o->n_used, sizeof *ents, bl_entcmp);
}

/* ================= printers ================= */

static const char *
bl_format_inode (ls_opts *o, char buf[32], const ls_entry *f)
{
    (void) o;
    if (f->stat_ok)
    {
        snprintf (buf, 32, "%ju", (uintmax_t) f->st.st_ino);
        return buf;
    }
    return "?";
}

/* Display width of one entry including inode/blocks/context prefixes
   and the type indicator (length_of_file_name_and_frills).  */
static size_t
bl_frills_width (ls_opts *o, const ls_entry *f)
{
    size_t len = 0;
    char buf[BL_HUMAN_BUFLEN];

    if (o->print_inode)
        len += 1 + (o->format == BL_FMT_COMMAS
                    ? strlen (bl_format_inode (o, buf, f))
                    : (size_t) o->inode_number_width);
    if (o->print_block_size)
        len += 1 + (o->format == BL_FMT_COMMAS
                    ? strlen (!f->stat_ok ? "?"
                              : bl_human_readable ((uintmax_t) f->st.st_blocks,
                                                   buf, o->human_output_opts,
                                                   512, o->output_block_size))
                    : (size_t) o->block_size_width);
    if (o->print_scontext)
        len += 1 + (o->format == BL_FMT_COMMAS
                    ? strlen (f->scontext ? f->scontext : "?")
                    : (size_t) o->scontext_width);

    len += f->width ? f->width : bl_name_width (f->name, o);

    if (o->indicator_style != BL_IND_NONE)
    {
        char c = bl_get_type_indicator (o, f->stat_ok, f->st.st_mode,
                                        f->ftype);
        len += (c != 0);
    }
    return len;
}

static void
bl_outf (ls_opts *o, const char *fmt, ...)
{
    char tmp[1024];
    va_list ap;
    va_start (ap, fmt);
    int n = vsnprintf (tmp, sizeof tmp, fmt, ap);
    va_end (ap);
    if (n > 0)
        bl_outbuf (o, tmp, ((size_t) n < sizeof tmp) ? (size_t) n
                                                     : sizeof tmp - 1);
}

/* Print one entry's frills + name (+indicator); the non-long formats
   all route through here (print_file_name_and_frills).  The caller
   sets o->name_start_col.  Returns the printed display width.  */
static size_t
bl_print_colored_name (const ls_entry *f, ls_opts *o)
{
    char buf[BL_HUMAN_BUFLEN];

    bl_set_normal_color (o);

    if (o->print_inode)
        bl_outf (o, "%*s ",
                 o->format == BL_FMT_COMMAS ? 0 : o->inode_number_width,
                 bl_format_inode (o, buf, f));

    if (o->print_block_size)
    {
        const char *blocks =
            (!f->stat_ok
             ? "?"
             : bl_human_readable ((uintmax_t) f->st.st_blocks, buf,
                                  o->human_output_opts, 512,
                                  o->output_block_size));
        int blocks_width = (int) strlen (blocks);
        int pad = 0;
        if (o->block_size_width && o->format != BL_FMT_COMMAS)
            pad = o->block_size_width - blocks_width;
        if (pad < 0)
            pad = 0;
        bl_outf (o, "%*s%s ", pad, "", blocks);
    }

    if (o->print_scontext)
        bl_outf (o, "%*s ",
                 o->format == BL_FMT_COMMAS ? 0 : o->scontext_width,
                 f->scontext ? f->scontext : "?");

    o->cur_file = f;
    size_t width = bl_print_name_q (o, f, 0, NULL);

    if (o->indicator_style != BL_IND_NONE)
        width += (size_t) bl_print_type_indicator (o, f->stat_ok,
                                                   f->st.st_mode, f->ftype);
    return width;
}

/* user/group/context column in long format (format_user_or_group).  */
static void
bl_format_user_or_group (ls_opts *o, const char *name, uintmax_t id,
                         int width)
{
    if (name)
    {
        int name_width = (int) strlen (name);
        int pad = width - name_width;
        if (pad < 0)
            pad = 0;
        bl_outstr (o, name);
        do
            bl_outbyte (o, ' ');
        while (pad--);
    }
    else
        bl_outf (o, "%*ju ", width, id);
}

static void
bl_format_user (ls_opts *o, uid_t u, int width, int stat_ok)
{
    bl_format_user_or_group (o,
                             !stat_ok ? "?"
                             : (o->numeric_ids ? NULL
                                : bl_lookup_uid (&o->ucache, u)),
                             (uintmax_t) u, width);
}

static void
bl_format_group (ls_opts *o, gid_t g, int width, int stat_ok)
{
    bl_format_user_or_group (o,
                             !stat_ok ? "?"
                             : (o->numeric_ids ? NULL
                                : bl_lookup_gid (&o->gcache, g)),
                             (uintmax_t) g, width);
}

/* Print one entry in long format (print_long_format).  */
static void
bl_print_long_format (ls_opts *o, const ls_entry *f)
{
    char modebuf[12];
    char buf[2048];
    char *p;
    struct timespec when_timespec;
    struct tm when_local;
    int btime_ok = 1;

    if (f->stat_ok)
    {
        bl_mode_string (f->st.st_mode, modebuf);
        modebuf[10] = ' ';
        modebuf[11] = '\0';
    }
    else
    {
        modebuf[0] = bl_filetype_letter[f->ftype];
        memset (modebuf + 1, '?', 10);
        modebuf[11] = '\0';
    }
    if (!o->any_has_acl)
        modebuf[10] = '\0';
    else if (f->acl_type == BL_ACL_LSM_CONTEXT_ONLY)
        modebuf[10] = '.';
    else if (f->acl_type == BL_ACL_YES)
        modebuf[10] = '+';
    else if (f->acl_type == BL_ACL_UNKNOWN)
        modebuf[10] = '?';

    when_timespec = f->mtime;
    if (o->time_type == BL_TIME_BTIME
        && f->btime.tv_sec == -1 && f->btime.tv_nsec == -1)
        btime_ok = 0;

    p = buf;

    if (o->print_inode)
    {
        char ib[32];
        p += sprintf (p, "%*s ", o->inode_number_width,
                      bl_format_inode (o, ib, f));
    }

    if (o->print_block_size)
    {
        char hbuf[BL_HUMAN_BUFLEN];
        const char *blocks =
            (!f->stat_ok
             ? "?"
             : bl_human_readable ((uintmax_t) f->st.st_blocks, hbuf,
                                  o->human_output_opts, 512,
                                  o->output_block_size));
        int blocks_width = (int) strlen (blocks);
        for (int pad = o->block_size_width - blocks_width; 0 < pad; pad--)
            *p++ = ' ';
        while ((*p++ = *blocks++))
            continue;
        p[-1] = ' ';
    }

    {
        char nb[32];
        if (f->stat_ok)
            snprintf (nb, sizeof nb, "%ju", (uintmax_t) f->st.st_nlink);
        p += sprintf (p, "%s %*s ", modebuf, o->nlink_width,
                      !f->stat_ok ? "?" : nb);
    }

    bl_dired_indent (o);

    if (o->print_owner || o->print_group || o->print_author
        || o->print_scontext)
    {
        bl_outbuf (o, buf, (size_t) (p - buf));
        if (o->print_owner)
            bl_format_user (o, f->st.st_uid, o->owner_width, f->stat_ok);
        if (o->print_group)
            bl_format_group (o, f->st.st_gid, o->group_width, f->stat_ok);
        if (o->print_author)
            bl_format_user (o, f->st.st_uid, o->author_width, f->stat_ok);
        if (o->print_scontext)
            bl_format_user_or_group (o, f->scontext ? f->scontext : "?", 0,
                                     o->scontext_width);
        p = buf;
    }

    if (f->stat_ok && (S_ISCHR (f->st.st_mode) || S_ISBLK (f->st.st_mode)))
    {
        int blanks_width = (o->file_size_width
                            - (o->major_device_number_width + 2
                               + o->minor_device_number_width));
        if (blanks_width < 0)
            blanks_width = 0;
        p += sprintf (p, "%*ju, %*ju ",
                      o->major_device_number_width + blanks_width,
                      (uintmax_t) major (f->st.st_rdev),
                      o->minor_device_number_width,
                      (uintmax_t) minor (f->st.st_rdev));
    }
    else
    {
        char hbuf[BL_HUMAN_BUFLEN];
        const char *size =
            (!f->stat_ok
             ? "?"
             : bl_human_readable (bl_unsigned_file_size (f->st.st_size), hbuf,
                                  o->file_human_output_opts, 1,
                                  o->file_output_block_size));
        int size_width = (int) strlen (size);
        for (int pad = o->file_size_width - size_width; 0 < pad; pad--)
            *p++ = ' ';
        while ((*p++ = *size++))
            continue;
        p[-1] = ' ';
    }

    {
        ssize_t s = -1;

        if (f->stat_ok && btime_ok
            && localtime_r (&when_timespec.tv_sec, &when_local))
        {
            struct timespec six_months_ago;
            int recent;

            if (!o->current_time_ok
                || bl_timespec_cmp (o->current_time, when_timespec) < 0)
            {
                clock_gettime (CLOCK_REALTIME, &o->current_time);
                o->current_time_ok = 1;
            }

            /* Half a Gregorian year: 31556952/2 seconds.  */
            six_months_ago.tv_sec = o->current_time.tv_sec - 31556952 / 2;
            six_months_ago.tv_nsec = o->current_time.tv_nsec;

            recent = (bl_timespec_cmp (six_months_ago, when_timespec) < 0
                      && bl_timespec_cmp (when_timespec, o->current_time) < 0);

            s = (ssize_t) bl_strftime_ns (p, 1024,
                                          o->long_time_fmt[recent],
                                          &when_local,
                                          when_timespec.tv_nsec);
            if (s == 0 && o->long_time_fmt[recent][0] != '\0')
                s = -1;
        }

        if (0 <= s)
        {
            p += s;
            *p++ = ' ';
        }
        else
        {
            char tb[32];
            if (f->stat_ok && btime_ok)
                snprintf (tb, sizeof tb, "%jd",
                          (intmax_t) when_timespec.tv_sec);
            p += sprintf (p, "%*s ", bl_long_time_expected_width (o),
                          (!f->stat_ok || !btime_ok) ? "?" : tb);
        }
    }

    bl_outbuf (o, buf, (size_t) (p - buf));
    o->name_start_col = (size_t) (p - buf);
    o->cur_file = f;
    size_t w = bl_print_name_q (o, f, 0, &o->dired_obstack);

    if (f->ftype == BL_T_SYMLINK)
    {
        if (f->linkname)
        {
            const char *tgt = f->linkname;
            bl_outstr (o, " -> ");
            o->name_start_col = (size_t) (p - buf) + w + 4;
            bl_print_name (tgt, o);
            if (o->indicator_style != BL_IND_NONE)
                bl_print_type_indicator (o, 1, f->linkmode, BL_T_UNKNOWN);
        }
    }
    else if (o->indicator_style != BL_IND_NONE)
        bl_print_type_indicator (o, f->stat_ok, f->st.st_mode, f->ftype);
}

/* ================= column layout ================= */

/* Assuming cursor is at position FROM, indent up to position TO, using
   tabs where possible.  */
static void
bl_indent (ls_opts *o, size_t from, size_t to)
{
    while (from < to)
    {
        if (o->tabsize != 0 && to / o->tabsize > (from + 1) / o->tabsize)
        {
            bl_outbyte (o, '\t');
            from += o->tabsize - from % o->tabsize;
        }
        else
        {
            bl_outbyte (o, ' ');
            from++;
        }
    }
}

#define BL_MIN_COLUMN_WIDTH 3

/* Compute the column layout (calculate_columns).  On success returns
   the column count and stores a malloc'd width array in *COL_ARR_OUT
   (caller frees).  */
static size_t
bl_calculate_columns (ls_opts *o, int by_columns, size_t **col_arr_out)
{
    size_t n = o->n_used;
    size_t max_cols = (0 < o->max_idx && o->max_idx < n) ? o->max_idx : n;
    ls_entry *ents = o->ents;

    struct { int valid_len; size_t line_len; size_t *col_arr; } *ci;
    ci = bl_xmalloc (max_cols * sizeof *ci);
    size_t *backing = bl_xmalloc (max_cols * (max_cols + 1) / 2
                                  * sizeof (size_t));
    if (!ci || !backing)
    {
        free (ci);
        free (backing);
        *col_arr_out = NULL;
        return 1;
    }
    {
        size_t *bp = backing;
        for (size_t i = 0; i < max_cols; i++)
        {
            ci[i].col_arr = bp;
            bp += i + 1;
            ci[i].valid_len = 1;
            ci[i].line_len = i * BL_MIN_COLUMN_WIDTH + 1;
            for (size_t j = 0; j < i; j++)
                ci[i].col_arr[j] = BL_MIN_COLUMN_WIDTH;
            ci[i].col_arr[i] = 1;
        }
    }

    for (size_t filesno = 0; filesno < n; filesno++)
    {
        size_t name_length = bl_frills_width (o, &ents[filesno]);
        for (size_t i = 0; i < max_cols; i++)
        {
            if (ci[i].valid_len)
            {
                size_t idx = (by_columns
                              ? filesno / ((n + i) / (i + 1))
                              : filesno % (i + 1));
                size_t real_length = name_length + (idx == i ? 0 : 2);
                if (ci[i].col_arr[idx] < real_length)
                {
                    ci[i].line_len += real_length - ci[i].col_arr[idx];
                    ci[i].col_arr[idx] = real_length;
                    ci[i].valid_len = ci[i].line_len <= o->line_length;
                }
            }
        }
    }

    size_t cols;
    for (cols = max_cols; 1 < cols; --cols)
        if (ci[cols - 1].valid_len)
            break;

    size_t *out = bl_xmalloc (cols * sizeof *out);
    if (out)
        memcpy (out, ci[cols - 1].col_arr, cols * sizeof *out);
    free (ci);
    free (backing);
    *col_arr_out = out;
    return cols;
}

/* Many-per-line (-C) grid.  Down-then-across: the layout is computed
   column-major and emitted row-major, matching GNU `ls -C`.  */
static void
bl_print_grid (ls_opts *o)
{
    ls_entry *ents = o->ents;
    size_t *col_arr = NULL;
    size_t cols = bl_calculate_columns (o, 1, &col_arr);
    if (!col_arr)
        return;
    size_t rows = o->n_used / cols + (o->n_used % cols != 0);

    for (size_t row = 0; row < rows; row++)
    {
        size_t col = 0;
        size_t idx = row;
        size_t pos = 0;

        while (1)
        {
            const ls_entry *f = &ents[idx];
            size_t name_length = bl_frills_width (o, f);
            size_t max_name_length = col_arr[col++];
            o->name_start_col = pos;
            bl_print_colored_name (&ents[idx], o);
            if (o->n_used - rows <= idx)
                break;
            idx += rows;
            bl_indent (o, pos + name_length, pos + max_name_length);
            pos += max_name_length;
        }
        bl_outbyte (o, o->eolbyte);
    }
    free (col_arr);
}

/* Across (-x) layout.  */
static void
bl_print_horizontal (ls_opts *o)
{
    ls_entry *ents = o->ents;
    size_t *col_arr = NULL;
    size_t cols = bl_calculate_columns (o, 0, &col_arr);
    if (!col_arr)
        return;
    size_t pos = 0;
    size_t name_length = bl_frills_width (o, &ents[0]);
    size_t max_name_length = col_arr[0];

    o->name_start_col = 0;
    {
        size_t idx = 0;
        bl_print_colored_name (&ents[idx], o);
    }

    for (size_t filesno = 1; filesno < o->n_used; filesno++)
    {
        size_t col = filesno % cols;
        if (col == 0)
        {
            bl_outbyte (o, o->eolbyte);
            pos = 0;
        }
        else
        {
            bl_indent (o, pos + name_length, pos + max_name_length);
            pos += max_name_length;
        }
        o->name_start_col = pos;
        bl_print_colored_name (&ents[filesno], o);
        name_length = bl_frills_width (o, &ents[filesno]);
        max_name_length = col_arr[col];
    }
    bl_outbyte (o, o->eolbyte);
    free (col_arr);
}

/* -m / unlimited-width layouts: name + SEP + ' '.  */
static void
bl_print_with_separator (ls_opts *o, char sep)
{
    ls_entry *ents = o->ents;
    size_t pos = 0;

    for (size_t filesno = 0; filesno < o->n_used; filesno++)
    {
        size_t len = o->line_length ? bl_frills_width (o, &ents[filesno]) : 0;

        if (filesno != 0)
        {
            char separator;
            size_t next_pos =
                2 + (sep == ',' && filesno < o->n_used - 1) + pos + len;

            if (!o->line_length || next_pos <= o->line_length)
            {
                pos += 2;
                separator = ' ';
            }
            else
            {
                pos = 0;
                separator = o->eolbyte;
            }
            bl_outbyte (o, sep);
            bl_outbyte (o, separator);
        }
        o->name_start_col = pos;
        bl_print_colored_name (&ents[filesno], o);
        pos += len;
    }
    bl_outbyte (o, o->eolbyte);
}

static void
bl_print_current_files (ls_opts *o)
{
    ls_entry *ents = o->ents;

    switch (o->format)
    {
        case BL_FMT_ONE_PER_LINE:
            for (size_t i = 0; i < o->n_used; i++)
            {
                o->name_start_col = 0;
                bl_print_colored_name (&ents[i], o);
                bl_outbyte (o, o->eolbyte);
            }
            break;

        case BL_FMT_MANY_PER_LINE:
            if (!o->line_length)
                bl_print_with_separator (o, ' ');
            else
                bl_print_grid (o);
            break;

        case BL_FMT_HORIZONTAL:
            if (!o->line_length)
                bl_print_with_separator (o, ' ');
            else
                bl_print_horizontal (o);
            break;

        case BL_FMT_COMMAS:
            bl_print_with_separator (o, ',');
            break;

        case BL_FMT_LONG:
            for (size_t i = 0; i < o->n_used; i++)
            {
                bl_set_normal_color (o);
                bl_print_long_format (o, &ents[i]);
                bl_outbyte (o, o->eolbyte);
            }
            break;
    }
}

/* ================= directory listing ================= */

static void
bl_print_dir (ls_opts *o, const char *name, const char *realname,
              int command_line_arg)
{
    DIR *d;
    struct dirent *de;
    uintmax_t total_blocks = 0;

    errno = 0;
    d = opendir (name);
    if (!d)
    {
        bl_file_failure (o, command_line_arg, "cannot open directory", name);
        return;
    }

    if (o->Rflag)
    {
        struct stat st;
        int fd = dirfd (d);
        if ((0 <= fd ? fstat (fd, &st) : stat (name, &st)) < 0)
        {
            bl_file_failure (o, command_line_arg,
                             "cannot determine device and inode of", name);
            closedir (d);
            return;
        }
        int seen_rc = bl_seen_dir_add (&o->active_dir_set,
                                       st.st_dev, st.st_ino);
        if (seen_rc > 0)
        {
            builtin_error ("%s: not listing already-listed directory", name);
            closedir (d);
            bl_set_exit_status (o, 1);
            return;
        }
        if (seen_rc < 0)
        {
            closedir (d);
            return;
        }
    }

    bl_clear_files (o);

    if (o->Rflag || o->print_dir_name)
    {
        if (!o->first_dir)
            bl_outbyte (o, '\n');
        o->first_dir = 0;
        bl_dired_indent (o);

        char *absolute_name = NULL;
        if (o->print_hyperlink)
            absolute_name = bl_canonicalize (name);
        bl_quote_name_out (o, realname ? realname : name, -1, NULL, 1,
                           &o->subdired_obstack, absolute_name,
                           o->dirname_quote_map);
        free (absolute_name);
        bl_outstr (o, ":\n");
    }

    while (1)
    {
        errno = 0;
        de = readdir (d);
        if (de)
        {
            const char *name2 = de->d_name;
            {
                const char *name3 = name2;
                /* file_ignored(): default ignore mode hides dotfiles;
                   -A hides only . and ..; then --hide (unless -a/-A)
                   and -I/-B patterns.  */
                const char *name = name3;
                if (!o->aflag && !o->Aflag && name[0] == '.') continue;
                if (o->Aflag && (!strcmp (name, ".") || !strcmp (name, ".."))) continue;
                if (!o->aflag && !o->Aflag)
                {
                    int hidden = 0;
                    for (bl_pattern *pp = o->hide_patterns; pp; pp = pp->next)
                        if (fnmatch (pp->pattern, name, FNM_PERIOD) == 0)
                        {
                            hidden = 1;
                            break;
                        }
                    if (hidden) continue;
                }
                {
                    int ignored = 0;
                    for (bl_pattern *pp = o->ignore_patterns; pp; pp = pp->next)
                        if (fnmatch (pp->pattern, name, FNM_PERIOD) == 0)
                        {
                            ignored = 1;
                            break;
                        }
                    if (ignored) continue;
                }
            }
            total_blocks += bl_gobble_file (o, name2,
                                            bl_dtype_to_filetype (de->d_type),
                                            0, name);
        }
        else
        {
            int err = errno;
            if (err == 0)
                break;
            bl_file_failure (o, command_line_arg, "reading directory", name);
            if (err != EOVERFLOW)
                break;
        }
    }

    if (closedir (d) != 0)
        bl_file_failure (o, command_line_arg, "closing directory", name);

    bl_sort_entries (o);

    if (o->Rflag)
        bl_extract_dirs_from_files (o, name, 0);

    if (o->format == BL_FMT_LONG || o->print_block_size)
    {
        char buf[BL_HUMAN_BUFLEN + 3];
        char *p = bl_human_readable (total_blocks, buf + 1,
                                     o->human_output_opts, 512,
                                     o->output_block_size);
        char *pend = p + strlen (p);
        *--p = ' ';
        *pend++ = o->eolbyte;
        bl_dired_indent (o);
        bl_outstr (o, "total");
        bl_outbuf (o, p, (size_t) (pend - p));
    }

    if (o->n_used)
        bl_print_current_files (o);
}

/* //DIRED// trailer dump.  */
static void
bl_dired_dump (const char *prefix, const bl_posbuf *pb)
{
    if (pb->len > 0)
    {
        fputs (prefix, stdout);
        for (size_t i = 0; i < pb->len; i++)
            printf (" %jd", (intmax_t) pb->v[i]);
        putchar ('\n');
    }
}

/* ================= option tables ================= */

enum
{
    BL_OPT_AUTHOR = 1000, BL_OPT_BLOCK_SIZE, BL_OPT_COLOR,
    BL_OPT_DEREF_CL_SYMLINK_TO_DIR, BL_OPT_FILE_TYPE, BL_OPT_FORMAT,
    BL_OPT_FULL_TIME, BL_OPT_GROUP_DIRS, BL_OPT_HIDE, BL_OPT_HYPERLINK,
    BL_OPT_INDICATOR_STYLE, BL_OPT_QUOTING_STYLE, BL_OPT_SHOW_CONTROL_CHARS,
    BL_OPT_SI, BL_OPT_SORT, BL_OPT_TIME, BL_OPT_TIME_STYLE, BL_OPT_ZERO,
    BL_OPT_HELP, BL_OPT_VERSION
};

/* Same order as coreutils' table (the ambiguity diagnostics list
   candidates in table order).  */
static const struct option bl_long_options[] =
{
    {"all", no_argument, NULL, 'a'},
    {"escape", no_argument, NULL, 'b'},
    {"directory", no_argument, NULL, 'd'},
    {"dired", no_argument, NULL, 'D'},
    {"full-time", no_argument, NULL, BL_OPT_FULL_TIME},
    {"group-directories-first", no_argument, NULL, BL_OPT_GROUP_DIRS},
    {"human-readable", no_argument, NULL, 'h'},
    {"inode", no_argument, NULL, 'i'},
    {"kibibytes", no_argument, NULL, 'k'},
    {"numeric-uid-gid", no_argument, NULL, 'n'},
    {"no-group", no_argument, NULL, 'G'},
    {"hide-control-chars", no_argument, NULL, 'q'},
    {"reverse", no_argument, NULL, 'r'},
    {"size", no_argument, NULL, 's'},
    {"width", required_argument, NULL, 'w'},
    {"almost-all", no_argument, NULL, 'A'},
    {"ignore-backups", no_argument, NULL, 'B'},
    {"classify", optional_argument, NULL, 'F'},
    {"file-type", no_argument, NULL, BL_OPT_FILE_TYPE},
    {"si", no_argument, NULL, BL_OPT_SI},
    {"dereference-command-line", no_argument, NULL, 'H'},
    {"dereference-command-line-symlink-to-dir", no_argument, NULL,
     BL_OPT_DEREF_CL_SYMLINK_TO_DIR},
    {"hide", required_argument, NULL, BL_OPT_HIDE},
    {"ignore", required_argument, NULL, 'I'},
    {"indicator-style", required_argument, NULL, BL_OPT_INDICATOR_STYLE},
    {"dereference", no_argument, NULL, 'L'},
    {"literal", no_argument, NULL, 'N'},
    {"quote-name", no_argument, NULL, 'Q'},
    {"quoting-style", required_argument, NULL, BL_OPT_QUOTING_STYLE},
    {"recursive", no_argument, NULL, 'R'},
    {"format", required_argument, NULL, BL_OPT_FORMAT},
    {"show-control-chars", no_argument, NULL, BL_OPT_SHOW_CONTROL_CHARS},
    {"sort", required_argument, NULL, BL_OPT_SORT},
    {"tabsize", required_argument, NULL, 'T'},
    {"time", required_argument, NULL, BL_OPT_TIME},
    {"time-style", required_argument, NULL, BL_OPT_TIME_STYLE},
    {"zero", no_argument, NULL, BL_OPT_ZERO},
    {"color", optional_argument, NULL, BL_OPT_COLOR},
    {"hyperlink", optional_argument, NULL, BL_OPT_HYPERLINK},
    {"block-size", required_argument, NULL, BL_OPT_BLOCK_SIZE},
    {"context", no_argument, NULL, 'Z'},
    {"author", no_argument, NULL, BL_OPT_AUTHOR},
    {"help", no_argument, NULL, BL_OPT_HELP},
    {"version", no_argument, NULL, BL_OPT_VERSION},
    {NULL, 0, NULL, 0}
};

static const char *const bl_sort_args[] =
{ "none", "size", "time", "version", "extension", "name", "width", NULL };
static const int bl_sort_vals[] =
{ BL_SORT_NONE, BL_SORT_SIZE, BL_SORT_TIME, BL_SORT_VERSION,
  BL_SORT_EXTENSION, BL_SORT_NAME, BL_SORT_WIDTH };

static const char *const bl_time_args[] =
{ "atime", "access", "use", "ctime", "status", "mtime", "modification",
  "birth", "creation", NULL };
static const int bl_time_vals[] =
{ BL_TIME_ATIME, BL_TIME_ATIME, BL_TIME_ATIME, BL_TIME_CTIME, BL_TIME_CTIME,
  BL_TIME_MTIME, BL_TIME_MTIME, BL_TIME_BTIME, BL_TIME_BTIME };

static const char *const bl_format_args[] =
{ "verbose", "long", "commas", "horizontal", "across", "vertical",
  "single-column", NULL };
static const int bl_format_vals[] =
{ BL_FMT_LONG, BL_FMT_LONG, BL_FMT_COMMAS, BL_FMT_HORIZONTAL,
  BL_FMT_HORIZONTAL, BL_FMT_MANY_PER_LINE, BL_FMT_ONE_PER_LINE };

static const char *const bl_when_args[] =
{ "always", "yes", "force", "never", "no", "none", "auto", "tty",
  "if-tty", NULL };
static const int bl_when_vals[] = { 2, 2, 2, 0, 0, 0, 1, 1, 1 };

static const char *const bl_indicator_args[] =
{ "none", "slash", "file-type", "classify", NULL };
static const int bl_indicator_vals[] =
{ BL_IND_NONE, BL_IND_SLASH, BL_IND_FILE_TYPE, BL_IND_CLASSIFY };

static const char *const bl_quoting_args[] =
{ "literal", "shell", "shell-always", "shell-escape", "shell-escape-always",
  "c", "c-maybe", "escape", "locale", "clocale", NULL };
static const int bl_quoting_vals[] =
{ BL_Q_LITERAL, BL_Q_SHELL, BL_Q_SHELL_ALWAYS, BL_Q_SHELL_ESCAPE,
  BL_Q_SHELL_ESCAPE_ALWAYS, BL_Q_C, BL_Q_C_MAYBE, BL_Q_ESCAPE,
  BL_Q_LOCALE, BL_Q_CLOCALE };

/* gnulib-argmatch-shaped lookup: exact match, else unambiguous prefix
   (prefixes hitting several distinct values are ambiguous).  Returns
   the matched value, or prints the GNU diagnostic and returns -1.  */
static int
bl_argmatch (const char *context, const char *arg,
             const char *const *args, const int *vals, int quiet)
{
    size_t arglen = strlen (arg);
    int matchind = -1;
    int ambiguous = 0;

    for (int i = 0; args[i]; i++)
    {
        if (strncmp (args[i], arg, arglen) == 0)
        {
            if (strlen (args[i]) == arglen)
                return vals[i];          /* exact */
            else if (matchind == -1)
                matchind = i;
            else if (vals[i] != vals[matchind])
                ambiguous = 1;
        }
    }
    if (matchind >= 0 && !ambiguous)
        return vals[matchind];

    if (!quiet)
    {
        fprintf (stderr, "ls: %s argument '%s' for '%s'\n",
                 ambiguous ? "ambiguous" : "invalid", arg, context);
        fputs ("Valid arguments are:\n", stderr);
        for (int i = 0; args[i]; i++)
        {
            if (i == 0 || vals[i] != vals[i - 1])
                fprintf (stderr, "%s  - '%s'", i == 0 ? "" : "\n", args[i]);
            else
                fprintf (stderr, ", '%s'", args[i]);
        }
        fputc ('\n', stderr);
        bl_try_help ();
    }
    return -1;
}

static long
bl_decode_line_length (const char *spec)
{
    uintmax_t val;
    int e = bl_xstrtoumax (spec, NULL, 0, &val, "");
    if (e == BL_LONGINT_OK)
        return val <= (uintmax_t) (LONG_MAX / 2) ? (long) val : 0;
    if (e == BL_LONGINT_OVERFLOW)
        return 0;
    return -1;
}

/* Long-option prefix matching for GNU-shaped getopt diagnostics.  */
static int
bl_match_long (const char *word, size_t wl, const struct option **first)
{
    int n = 0;
    *first = NULL;
    for (const struct option *op = bl_long_options; op->name; op++)
    {
        if (strncmp (op->name, word, wl) == 0)
        {
            if (strlen (op->name) == wl)
            {
                *first = op;
                return 1;       /* exact */
            }
            if (!*first)
                *first = op;
            n++;
        }
    }
    return n;
}

/* Free everything hanging off the context.  */
static void
bl_free_all (ls_opts *o)
{
    bl_clear_files (o);
    free (o->ents);
    o->ents = NULL;
    for (bl_pattern *p = o->ignore_patterns; p;)
    {
        bl_pattern *n = p->next;
        free (p);
        p = n;
    }
    o->ignore_patterns = NULL;
    for (bl_pattern *p = o->hide_patterns; p;)
    {
        bl_pattern *n = p->next;
        free (p);
        p = n;
    }
    o->hide_patterns = NULL;
    while (o->pending_dirs)
    {
        bl_pending *t = o->pending_dirs;
        o->pending_dirs = t->next;
        free (t->name);
        free (t->realname);
        free (t);
    }
    bl_seen_dir_free (o->active_dir_set);
    o->active_dir_set = NULL;
    for (bl_color_ext *e = o->color_ext_list; e;)
    {
        bl_color_ext *n = e->next;
        free (e);
        e = n;
    }
    o->color_ext_list = NULL;
    free (o->color_buf);
    o->color_buf = NULL;
    free (o->hostname);
    o->hostname = NULL;
    free (o->qbuf.p);
    o->qbuf.p = NULL;
    free (o->qbuf2.p);
    o->qbuf2.p = NULL;
    free (o->dired_obstack.v);
    o->dired_obstack.v = NULL;
    free (o->subdired_obstack.v);
    o->subdired_obstack.v = NULL;
    free (o->time_fmt_heap);
    o->time_fmt_heap = NULL;
}

static void
bl_add_pattern (bl_pattern **list, const char *pattern)
{
    bl_pattern *n = bl_xmalloc (sizeof *n);
    if (!n)
        return;
    n->pattern = pattern;
    n->next = *list;
    *list = n;
}

extern char *ls_doc[];

/* ================= the builtin ================= */

int
ls_builtin (WORD_LIST *list)
{
    ls_opts o;
    memset (&o, 0, sizeof o);
    o.qflag = -1;
    o.print_owner = 1;
    o.print_group = 1;
    o.eolbyte = '\n';
    o.deref = BL_DEREF_UNDEFINED;
    o.file_output_block_size = 1;
    o.print_dir_name = 1;
    o.first_dir = 1;
    o.long_time_fmt[0] = "%b %e  %Y";
    o.long_time_fmt[1] = "%b %e %H:%M";
    bl_init_color_defaults (&o);

    /* parse-stage tri-states */
    int format_opt = -1;
    int sort_opt = -1;
    int quoting_style_opt = -1;
    long width_opt = -1;
    long tabsize_opt = -1;
    int kibibytes_specified = 0;
    const char *time_style_option = NULL;
    int show_help = 0, show_version = 0;
    int usage_rc = -1;

    /* Build argv[] for getopt_long.  The word strings belong to bash;
       only the pointer array is ours.  */
    int argc = 1;
    for (WORD_LIST *w = list; w; w = w->next)
        argc++;
    char **argv = bl_xmalloc (((size_t) argc + 1) * sizeof *argv);
    if (argv == NULL)
    {
        builtin_error ("memory exhausted");
        return EXECUTION_FAILURE;
    }
    argv[0] = (char *) "ls";
    {
        int i = 1;
        for (WORD_LIST *w = list; w; w = w->next)
            argv[i++] = w->word->word;
        argv[i] = NULL;
    }

    /* libc getopt globals are shared with bash and sibling loadables:
       snapshot all four, reinitialize, and restore before returning.  */
    int save_optind = optind;
    int save_opterr = opterr;
    int save_optopt = optopt;
    char *save_optarg = optarg;
    optind = 0;
    opterr = 0;

    const char *optstring = getenv ("POSIXLY_CORRECT")
        ? "+:abcdfghiklmnopqrstuvw:xABCDFGHI:LNQRST:UXZ1"
        : ":abcdfghiklmnopqrstuvw:xABCDFGHI:LNQRST:UXZ1";

    while (usage_rc < 0)
    {
        int oi = -1;
        int c = getopt_long (argc, argv, optstring, bl_long_options, &oi);
        if (c == -1)
            break;

        switch (c)
        {
            case 'a': o.aflag = 1; o.Aflag = 0; break;
            case 'A': o.Aflag = 1; o.aflag = 0; break;

            case 'b': quoting_style_opt = BL_Q_ESCAPE; break;

            case 'c':
                o.cflag = 1; o.uflag = 0;
                o.time_type = BL_TIME_CTIME;
                o.explicit_time = 1;
                break;

            case 'd': o.dflag = 1; break;

            case 'f':
                /* -f: same as -a -U */
                o.aflag = 1; o.Aflag = 0;
                sort_opt = BL_SORT_NONE;
                break;

            case BL_OPT_FILE_TYPE:
                o.indicator_style = BL_IND_FILE_TYPE;
                break;

            case 'g':
                format_opt = BL_FMT_LONG;
                o.print_owner = 0;
                break;

            case 'h':
                o.file_human_output_opts = o.human_output_opts =
                    BL_HUMAN_AUTOSCALE | BL_HUMAN_SI | BL_HUMAN_BASE_1024;
                o.file_output_block_size = o.output_block_size = 1;
                break;

            case 'i': o.print_inode = 1; break;
            case 'k': kibibytes_specified = 1; break;
            case 'l': format_opt = BL_FMT_LONG; break;
            case 'm': format_opt = BL_FMT_COMMAS; break;

            case 'n':
                o.numeric_ids = 1;
                format_opt = BL_FMT_LONG;
                break;

            case 'o':
                format_opt = BL_FMT_LONG;
                o.print_group = 0;
                break;

            case 'p': o.indicator_style = BL_IND_SLASH; break;
            case 'q': o.qflag = 1; break;
            case 'r': o.rflag = 1; break;
            case 's': o.print_block_size = 1; break;
            case 't': sort_opt = BL_SORT_TIME; break;

            case 'u':
                o.uflag = 1; o.cflag = 0;
                o.time_type = BL_TIME_ATIME;
                o.explicit_time = 1;
                break;

            case 'v': sort_opt = BL_SORT_VERSION; break;

            case 'w':
                width_opt = bl_decode_line_length (optarg);
                if (width_opt < 0)
                {
                    fprintf (stderr, "ls: invalid line width: '%s'\n", optarg);
                    usage_rc = 2;
                }
                break;

            case 'x': format_opt = BL_FMT_HORIZONTAL; break;

            case 'B':
                bl_add_pattern (&o.ignore_patterns, "*~");
                bl_add_pattern (&o.ignore_patterns, ".*~");
                break;

            case 'C': format_opt = BL_FMT_MANY_PER_LINE; break;

            case 'D':
                format_opt = BL_FMT_LONG;
                o.print_hyperlink = 0;
                o.dired = 1;
                break;

            case 'F':
            {
                int i = optarg
                    ? bl_argmatch ("--classify", optarg, bl_when_args,
                                   bl_when_vals, 0)
                    : 2;
                if (i < 0)
                    usage_rc = 1;
                else if (i == 2 || (i == 1 && isatty (STDOUT_FILENO)))
                    o.indicator_style = BL_IND_CLASSIFY;
                break;
            }

            case 'G': o.print_group = 0; break;
            case 'H': o.deref = BL_DEREF_COMMAND_LINE_ARGUMENTS; break;

            case BL_OPT_DEREF_CL_SYMLINK_TO_DIR:
                o.deref = BL_DEREF_COMMAND_LINE_SYMLINK_TO_DIR;
                break;

            case 'I': bl_add_pattern (&o.ignore_patterns, optarg); break;
            case 'L': o.deref = BL_DEREF_ALWAYS; break;
            case 'N': quoting_style_opt = BL_Q_LITERAL; break;
            case 'Q': quoting_style_opt = BL_Q_C; break;
            case 'R': o.Rflag = 1; break;
            case 'S': sort_opt = BL_SORT_SIZE; break;

            case 'T':
            {
                uintmax_t v;
                if (bl_xstrtoumax (optarg, NULL, 0, &v, "") != BL_LONGINT_OK
                    || v > (uintmax_t) (LONG_MAX / 2))
                {
                    fprintf (stderr, "ls: invalid tab size: '%s'\n", optarg);
                    usage_rc = 2;
                }
                else
                    tabsize_opt = (long) v;
                break;
            }

            case 'U': sort_opt = BL_SORT_NONE; break;
            case 'X': sort_opt = BL_SORT_EXTENSION; break;

            case '1':
                /* -1 has no effect after -l.  */
                if (format_opt != BL_FMT_LONG)
                    format_opt = BL_FMT_ONE_PER_LINE;
                break;

            case BL_OPT_AUTHOR: o.print_author = 1; break;
            case BL_OPT_HIDE: bl_add_pattern (&o.hide_patterns, optarg); break;

            case BL_OPT_SORT:
                sort_opt = bl_argmatch ("--sort", optarg, bl_sort_args,
                                        bl_sort_vals, 0);
                if (sort_opt < 0)
                    usage_rc = 1;
                break;

            case BL_OPT_GROUP_DIRS:
                o.group_directories_first = 1;
                break;

            case BL_OPT_TIME:
            {
                int t = bl_argmatch ("--time", optarg, bl_time_args,
                                     bl_time_vals, 0);
                if (t < 0)
                    usage_rc = 1;
                else
                {
                    o.time_type = t;
                    o.explicit_time = 1;
                    o.cflag = (t == BL_TIME_CTIME);
                    o.uflag = (t == BL_TIME_ATIME);
                }
                break;
            }

            case BL_OPT_FORMAT:
                format_opt = bl_argmatch ("--format", optarg, bl_format_args,
                                          bl_format_vals, 0);
                if (format_opt < 0)
                    usage_rc = 1;
                break;

            case BL_OPT_FULL_TIME:
                format_opt = BL_FMT_LONG;
                time_style_option = "full-iso";
                break;

            case BL_OPT_COLOR:
            {
                int i = optarg
                    ? bl_argmatch ("--color", optarg, bl_when_args,
                                   bl_when_vals, 0)
                    : 2;
                if (i < 0)
                    usage_rc = 1;
                else
                    o.print_with_color =
                        (i == 2 || (i == 1 && isatty (STDOUT_FILENO)));
                break;
            }

            case BL_OPT_HYPERLINK:
            {
                int i = optarg
                    ? bl_argmatch ("--hyperlink", optarg, bl_when_args,
                                   bl_when_vals, 0)
                    : 2;
                if (i < 0)
                    usage_rc = 1;
                else
                    o.print_hyperlink =
                        (i == 2 || (i == 1 && isatty (STDOUT_FILENO)));
                break;
            }

            case BL_OPT_INDICATOR_STYLE:
            {
                int i = bl_argmatch ("--indicator-style", optarg,
                                     bl_indicator_args, bl_indicator_vals, 0);
                if (i < 0)
                    usage_rc = 1;
                else
                    o.indicator_style = i;
                break;
            }

            case BL_OPT_QUOTING_STYLE:
            {
                int i = bl_argmatch ("--quoting-style", optarg,
                                     bl_quoting_args, bl_quoting_vals, 0);
                if (i < 0)
                    usage_rc = 1;
                else
                    quoting_style_opt = i;
                break;
            }

            case BL_OPT_TIME_STYLE:
                time_style_option = optarg;
                break;

            case BL_OPT_SHOW_CONTROL_CHARS:
                o.qflag = 0;
                break;

            case BL_OPT_BLOCK_SIZE:
            {
                int e = bl_human_options (optarg, &o.human_output_opts,
                                          &o.output_block_size);
                if (e != BL_LONGINT_OK)
                {
                    if (e & BL_LONGINT_OVERFLOW)
                        fprintf (stderr,
                                 "ls: --block-size argument '%s' too large\n",
                                 optarg);
                    else
                        fprintf (stderr,
                                 "ls: invalid --block-size argument '%s'\n",
                                 optarg);
                    usage_rc = 2;
                }
                else
                {
                    o.file_human_output_opts = o.human_output_opts;
                    o.file_output_block_size = o.output_block_size;
                }
                break;
            }

            case BL_OPT_SI:
                o.file_human_output_opts = o.human_output_opts =
                    BL_HUMAN_AUTOSCALE | BL_HUMAN_SI;
                o.file_output_block_size = o.output_block_size = 1;
                break;

            case 'Z': o.print_scontext = 1; break;

            case BL_OPT_ZERO:
                o.eolbyte = 0;
                o.qflag = 0;
                if (format_opt != BL_FMT_LONG)
                    format_opt = BL_FMT_ONE_PER_LINE;
                o.print_with_color = 0;
                quoting_style_opt = BL_Q_LITERAL;
                break;

            case BL_OPT_HELP: show_help = 1; break;
            case BL_OPT_VERSION: show_version = 1; break;

            case ':':
            {
                const char *bad =
                    (1 <= optind - 1 && optind - 1 < argc) ? argv[optind - 1]
                                                           : "";
                if (bad[0] == '-' && bad[1] == '-')
                {
                    const struct option *m;
                    size_t wl = strcspn (bad + 2, "=");
                    bl_match_long (bad + 2, wl, &m);
                    fprintf (stderr, "ls: option '--%s' requires an argument\n",
                             m ? m->name : bad + 2);
                }
                else
                    fprintf (stderr,
                             "ls: option requires an argument -- '%c'\n",
                             optopt);
                bl_try_help ();
                usage_rc = 2;
                break;
            }

            case '?':
            default:
            {
                const char *bad =
                    (1 <= optind - 1 && optind - 1 < argc) ? argv[optind - 1]
                                                           : "";
                if (bad[0] == '-' && bad[1] == '-' && bad[2] != '\0')
                {
                    const struct option *m;
                    size_t wl = strcspn (bad + 2, "=");
                    int nm = bl_match_long (bad + 2, wl, &m);
                    if (nm == 1 && m && bad[2 + wl] == '='
                        && m->has_arg == no_argument)
                        fprintf (stderr,
                                 "ls: option '--%s' doesn't allow an argument\n",
                                 m->name);
                    else if (nm == 0)
                        fprintf (stderr, "ls: unrecognized option '%s'\n", bad);
                    else if (nm > 1)
                    {
                        fprintf (stderr,
                                 "ls: option '--%.*s' is ambiguous; possibilities:",
                                 (int) wl, bad + 2);
                        for (const struct option *op = bl_long_options;
                             op->name; op++)
                            if (strncmp (op->name, bad + 2, wl) == 0)
                                fprintf (stderr, " '--%s'", op->name);
                        fputc ('\n', stderr);
                    }
                    else
                        fprintf (stderr, "ls: unrecognized option '%s'\n", bad);
                }
                else if (optopt)
                    fprintf (stderr, "ls: invalid option -- '%c'\n", optopt);
                else
                    fprintf (stderr, "ls: unrecognized option '%s'\n", bad);
                bl_try_help ();
                usage_rc = 2;
                break;
            }
        }
    }

    int first_operand = optind;

    /* Restore the shared libc getopt state on every path from here.  */
    optind = save_optind;
    opterr = save_opterr;
    optopt = save_optopt;
    optarg = save_optarg;

    if (usage_rc >= 0)
    {
        bl_free_all (&o);
        free (argv);
        return usage_rc;
    }

    if (show_help)
    {
        for (int i = 0; ls_doc[i]; i++)
        {
            fputs (ls_doc[i], stdout);
            putchar ('\n');
        }
        fflush (stdout);
        bl_free_all (&o);
        free (argv);
        return EXECUTION_SUCCESS;
    }

    if (show_version)
    {
        printf ("ls (bash-os coreutils) 9.7-compat\n"
                "bashls loadable builtin; output-compatible with GNU"
                " coreutils 9.7 ls in the C locale.\n"
                "License MIT (bash-os); not GNU coreutils code.\n");
        fflush (stdout);
        bl_free_all (&o);
        free (argv);
        return EXECUTION_SUCCESS;
    }

    /* ---- post-parse computation (decode_switches tail) ---- */

    if (!o.output_block_size)
    {
        const char *ls_block_size = getenv ("LS_BLOCK_SIZE");
        bl_human_options (ls_block_size, &o.human_output_opts,
                          &o.output_block_size);
        if (ls_block_size || getenv ("BLOCK_SIZE"))
        {
            o.file_human_output_opts = o.human_output_opts;
            o.file_output_block_size = o.output_block_size;
        }
        if (kibibytes_specified)
        {
            o.human_output_opts = 0;
            o.output_block_size = 1024;
        }
    }

    o.format = (0 <= format_opt ? format_opt
                : isatty (STDOUT_FILENO) ? BL_FMT_MANY_PER_LINE
                                         : BL_FMT_ONE_PER_LINE);

    {
        long linelen = width_opt;
        if (o.format == BL_FMT_MANY_PER_LINE
            || o.format == BL_FMT_HORIZONTAL
            || o.format == BL_FMT_COMMAS
            || o.print_with_color)
        {
            if (linelen < 0)
            {
                struct winsize ws;
                if (isatty (STDOUT_FILENO)
                    && 0 <= ioctl (STDOUT_FILENO, TIOCGWINSZ, &ws)
                    && 0 < ws.ws_col)
                    linelen = ws.ws_col;
            }
            if (linelen < 0)
            {
                const char *p = getenv ("COLUMNS");
                if (p && *p)
                {
                    linelen = bl_decode_line_length (p);
                    if (linelen < 0)
                        fprintf (stderr,
                                 "ls: ignoring invalid width in environment "
                                 "variable COLUMNS: '%s'\n", p);
                }
            }
        }
        o.line_length = linelen < 0 ? 80 : (size_t) linelen;
    }

    o.max_idx = o.line_length / BL_MIN_COLUMN_WIDTH;
    o.max_idx += o.line_length % BL_MIN_COLUMN_WIDTH != 0;

    if (o.format == BL_FMT_MANY_PER_LINE || o.format == BL_FMT_HORIZONTAL
        || o.format == BL_FMT_COMMAS)
    {
        if (0 <= tabsize_opt)
            o.tabsize = (size_t) tabsize_opt;
        else
        {
            o.tabsize = 8;
            const char *p = getenv ("TABSIZE");
            if (p)
            {
                uintmax_t tmp;
                if (bl_xstrtoumax (p, NULL, 0, &tmp, "") == BL_LONGINT_OK
                    && tmp <= (uintmax_t) (LONG_MAX / 2))
                    o.tabsize = (size_t) tmp;
                else
                    fprintf (stderr,
                             "ls: ignoring invalid tab size in environment "
                             "variable TABSIZE: '%s'\n", p);
            }
        }
    }

    o.qmark_funny_chars = (o.qflag < 0 ? isatty (STDOUT_FILENO) : o.qflag);
    o.qflag = o.qmark_funny_chars;

    {
        int qs = quoting_style_opt;
        if (qs < 0)
        {
            const char *q_style = getenv ("QUOTING_STYLE");
            if (q_style)
            {
                qs = bl_argmatch ("$QUOTING_STYLE", q_style, bl_quoting_args,
                                  bl_quoting_vals, 1);
                if (qs < 0)
                    fprintf (stderr,
                             "ls: ignoring invalid value of environment "
                             "variable QUOTING_STYLE: '%s'\n", q_style);
            }
        }
        if (qs < 0)
            qs = isatty (STDOUT_FILENO) ? BL_Q_SHELL_ESCAPE : BL_Q_LITERAL;
        o.quoting_style = qs;

        o.align_variable_outer_quotes =
            ((o.format == BL_FMT_LONG
              || ((o.format == BL_FMT_MANY_PER_LINE
                   || o.format == BL_FMT_HORIZONTAL)
                  && o.line_length))
             && (qs == BL_Q_SHELL || qs == BL_Q_SHELL_ESCAPE
                 || qs == BL_Q_C_MAYBE));
    }

    memset (o.filename_quote_map, 0, sizeof o.filename_quote_map);
    if (o.quoting_style == BL_Q_ESCAPE)
        BL_QMAP_SET (o.filename_quote_map, ' ');
    if (BL_IND_FILE_TYPE <= o.indicator_style)
        for (const char *p = &"*=>@|"[o.indicator_style - BL_IND_FILE_TYPE];
             *p; p++)
            BL_QMAP_SET (o.filename_quote_map, *p);

    memset (o.dirname_quote_map, 0, sizeof o.dirname_quote_map);
    BL_QMAP_SET (o.dirname_quote_map, ':');

    /* --dired implies long format sans --hyperlink.  */
    o.dired &= (o.format == BL_FMT_LONG) & !o.print_hyperlink;

    if (o.eolbyte == 0 && o.dired)
    {
        fprintf (stderr, "ls: --dired and --zero are incompatible\n");
        bl_free_all (&o);
        free (argv);
        return 2;
    }

    o.sort_type = (0 <= sort_opt ? sort_opt
                   : (o.format != BL_FMT_LONG && o.explicit_time)
                   ? BL_SORT_TIME : BL_SORT_NAME);
    o.fflag = (o.sort_type == BL_SORT_NONE);
    o.Sflag = (o.sort_type == BL_SORT_SIZE);

    if (o.format == BL_FMT_LONG)
    {
        const char *style = time_style_option;
        if (!style)
            style = getenv ("TIME_STYLE");
        if (!style)
            style = "locale";

        int use_defaults = 0;
        if (strncmp (style, "posix-", 6) == 0)
        {
            /* posix- styles take effect only outside the C locale;
               bash-os runs in the C locale, so keep the defaults.  */
            use_defaults = 1;
        }
        if (!use_defaults)
        {
            if (*style == '+')
            {
                char *heap = bl_xstrdup (style + 1);
                if (heap)
                {
                    o.time_fmt_heap = heap;
                    char *nl = strchr (heap, '\n');
                    if (nl)
                    {
                        if (strchr (nl + 1, '\n'))
                        {
                            fprintf (stderr,
                                     "ls: invalid time style format '%s'\n",
                                     style + 1);
                            bl_free_all (&o);
                            free (argv);
                            return 2;
                        }
                        *nl = '\0';
                        o.long_time_fmt[0] = heap;
                        o.long_time_fmt[1] = nl + 1;
                    }
                    else
                        o.long_time_fmt[0] = o.long_time_fmt[1] = heap;
                }
            }
            else
            {
                static const char *const ts_args[] =
                { "full-iso", "long-iso", "iso", "locale", NULL };
                static const int ts_vals[] = { 0, 1, 2, 3 };
                int t = bl_argmatch ("time style", style, ts_args, ts_vals, 1);
                if (t < 0)
                {
                    int ambig = 0;
                    size_t sl = strlen (style);
                    int nm = 0;
                    for (int i = 0; ts_args[i]; i++)
                        if (strncmp (ts_args[i], style, sl) == 0)
                            nm++;
                    ambig = nm > 1;
                    fprintf (stderr, "ls: %s argument '%s' for 'time style'\n",
                             ambig ? "ambiguous" : "invalid", style);
                    fputs ("Valid arguments are:\n"
                           "  - [posix-]full-iso\n"
                           "  - [posix-]long-iso\n"
                           "  - [posix-]iso\n"
                           "  - [posix-]locale\n"
                           "  - +FORMAT (e.g., +%H:%M) for a 'date'-style"
                           " format\n", stderr);
                    bl_try_help ();
                    bl_free_all (&o);
                    free (argv);
                    return 2;
                }
                switch (t)
                {
                    case 0:
                        o.long_time_fmt[0] = o.long_time_fmt[1] =
                            "%Y-%m-%d %H:%M:%S.%N %z";
                        break;
                    case 1:
                        o.long_time_fmt[0] = o.long_time_fmt[1] =
                            "%Y-%m-%d %H:%M";
                        break;
                    case 2:
                        o.long_time_fmt[0] = "%Y-%m-%d ";
                        o.long_time_fmt[1] = "%m-%d %H:%M";
                        break;
                    default:
                        /* locale: C-locale defaults already set */
                        break;
                }
            }
        }
    }

    /* ---- main()-stage setup ---- */

    if (o.print_with_color)
        bl_parse_ls_color (&o);

    if (o.print_with_color)
        o.tabsize = 0;

    if (o.group_directories_first)
        o.check_symlink_mode = 1;
    else if (o.print_with_color)
    {
        if (bl_is_colored (&o, BLC_ORPHAN)
            || (bl_is_colored (&o, BLC_EXEC) && o.color_symlink_as_referent)
            || (bl_is_colored (&o, BLC_MISSING) && o.format == BL_FMT_LONG))
            o.check_symlink_mode = 1;
    }

    if (o.deref == BL_DEREF_UNDEFINED)
        o.deref = ((o.dflag
                    || o.indicator_style == BL_IND_CLASSIFY
                    || o.format == BL_FMT_LONG)
                   ? BL_DEREF_NEVER
                   : BL_DEREF_COMMAND_LINE_SYMLINK_TO_DIR);
    o.Lflag = (o.deref == BL_DEREF_ALWAYS);

    o.format_needs_stat = ((o.sort_type == BL_SORT_TIME)
                           | (o.sort_type == BL_SORT_SIZE)
                           | (o.format == BL_FMT_LONG)
                           | o.print_block_size | o.print_hyperlink
                           | o.print_scontext);
    o.format_needs_type = (!o.format_needs_stat
                           & (o.Rflag | o.print_with_color | o.print_scontext
                              | o.group_directories_first
                              | (o.indicator_style != BL_IND_NONE)));

    if (o.print_hyperlink)
    {
        char hostbuf[256];
        if (gethostname (hostbuf, sizeof hostbuf) == 0)
        {
            hostbuf[sizeof hostbuf - 1] = '\0';
            o.hostname = bl_xstrdup (hostbuf);
        }
    }

    /* ---- run ---- */

    bl_clear_files (&o);

    int n_files = argc - first_operand;

    if (n_files <= 0)
    {
        if (o.dflag)
            bl_gobble_file (&o, ".", BL_T_DIRECTORY, 1, NULL);
        else
            bl_queue_directory (&o, ".", NULL, 1);
    }
    else
        for (int i = first_operand; i < argc; i++)
            bl_gobble_file (&o, argv[i], BL_T_UNKNOWN, 1, NULL);

    if (o.n_used)
    {
        bl_sort_entries (&o);
        if (!o.dflag)
            bl_extract_dirs_from_files (&o, NULL, 1);
    }

    if (o.n_used)
    {
        bl_print_current_files (&o);
        if (o.pending_dirs)
            bl_outbyte (&o, '\n');
    }
    else if (n_files <= 1 && o.pending_dirs && !o.pending_dirs->next)
        o.print_dir_name = 0;

    while (o.pending_dirs)
    {
        bl_pending *t = o.pending_dirs;
        o.pending_dirs = t->next;

        if (o.Rflag && t->name == NULL)
        {
            /* marker: this subtree is done; pop the loop-detect set */
            bl_seen_dir_pop (&o.active_dir_set);
            free (t->realname);
            free (t);
            continue;
        }

        bl_print_dir (&o, t->name, t->realname, t->command_line_arg);
        free (t->name);
        free (t->realname);
        free (t);
        o.print_dir_name = 1;
    }

    if (o.print_with_color && o.used_color)
    {
        if (!(o.color_indicator[BLC_LEFT].len == 2
              && memcmp (o.color_indicator[BLC_LEFT].string, "\033[", 2) == 0
              && o.color_indicator[BLC_RIGHT].len == 1
              && o.color_indicator[BLC_RIGHT].string[0] == 'm'))
        {
            bl_put_indicator (&o, &o.color_indicator[BLC_LEFT]);
            bl_put_indicator (&o, &o.color_indicator[BLC_RIGHT]);
        }
    }

    if (o.dired)
    {
        bl_dired_dump ("//DIRED//", &o.dired_obstack);
        bl_dired_dump ("//SUBDIRED//", &o.subdired_obstack);
        printf ("//DIRED-OPTIONS// --quoting-style=%s\n",
                bl_quoting_args[o.quoting_style]);
    }

    fflush (stdout);

    int rc = o.exit_status;
    bl_free_all (&o);
    free (argv);
    return rc;
}

/* ================= help text / loadable registration =================
 * The help body mirrors GNU coreutils 9.7 `ls --help`, with a bash-os
 * footer instead of the gnu.org URLs.  `ls --help` prints exactly these
 * lines; `help bashls` renders the same array via bash, so the two
 * always agree.  */

char *ls_doc[] = {
    "Usage: ls [OPTION]... [FILE]...",
    "List information about the FILEs (the current directory by default).",
    "Sort entries alphabetically if none of -cftuvSUX nor --sort is specified.",
    "",
    "Mandatory arguments to long options are mandatory for short options too.",
    "  -a, --all                  do not ignore entries starting with .",
    "  -A, --almost-all           do not list implied . and ..",
    "      --author               with -l, print the author of each file",
    "  -b, --escape               print C-style escapes for nongraphic characters",
    "      --block-size=SIZE      with -l, scale sizes by SIZE when printing them;",
    "                             e.g., '--block-size=M'; see SIZE format below",
    "",
    "  -B, --ignore-backups       do not list implied entries ending with ~",
    "  -c                         with -lt: sort by, and show, ctime (time of last",
    "                             change of file status information);",
    "                             with -l: show ctime and sort by name;",
    "                             otherwise: sort by ctime, newest first",
    "",
    "  -C                         list entries by columns",
    "      --color[=WHEN]         color the output WHEN; more info below",
    "  -d, --directory            list directories themselves, not their contents",
    "  -D, --dired                generate output designed for Emacs' dired mode",
    "  -f                         same as -a -U",
    "  -F, --classify[=WHEN]      append indicator (one of */=>@|) to entries WHEN",
    "      --file-type            likewise, except do not append '*'",
    "      --format=WORD          across,horizontal (-x), commas (-m), long (-l),",
    "                             single-column (-1), verbose (-l), vertical (-C)",
    "",
    "      --full-time            like -l --time-style=full-iso",
    "  -g                         like -l, but do not list owner",
    "      --group-directories-first",
    "                             group directories before files",
    "  -G, --no-group             in a long listing, don't print group names",
    "  -h, --human-readable       with -l and -s, print sizes like 1K 234M 2G etc.",
    "      --si                   likewise, but use powers of 1000 not 1024",
    "  -H, --dereference-command-line",
    "                             follow symbolic links listed on the command line",
    "      --dereference-command-line-symlink-to-dir",
    "                             follow each command line symbolic link",
    "                             that points to a directory",
    "",
    "      --hide=PATTERN         do not list implied entries matching shell PATTERN",
    "                             (overridden by -a or -A)",
    "",
    "      --hyperlink[=WHEN]     hyperlink file names WHEN",
    "      --indicator-style=WORD",
    "                             append indicator with style WORD to entry names:",
    "                             none (default), slash (-p),",
    "                             file-type (--file-type), classify (-F)",
    "",
    "  -i, --inode                print the index number of each file",
    "  -I, --ignore=PATTERN       do not list implied entries matching shell PATTERN",
    "  -k, --kibibytes            default to 1024-byte blocks for file system usage;",
    "                             used only with -s and per directory totals",
    "",
    "  -l                         use a long listing format",
    "  -L, --dereference          when showing file information for a symbolic",
    "                             link, show information for the file the link",
    "                             references rather than for the link itself",
    "",
    "  -m                         fill width with a comma separated list of entries",
    "  -n, --numeric-uid-gid      like -l, but list numeric user and group IDs",
    "  -N, --literal              print entry names without quoting",
    "  -o                         like -l, but do not list group information",
    "  -p, --indicator-style=slash",
    "                             append / indicator to directories",
    "  -q, --hide-control-chars   print ? instead of nongraphic characters",
    "      --show-control-chars   show nongraphic characters as-is (the default,",
    "                             unless program is 'ls' and output is a terminal)",
    "",
    "  -Q, --quote-name           enclose entry names in double quotes",
    "      --quoting-style=WORD   use quoting style WORD for entry names:",
    "                             literal, locale, shell, shell-always,",
    "                             shell-escape, shell-escape-always, c, escape",
    "                             (overrides QUOTING_STYLE environment variable)",
    "",
    "  -r, --reverse              reverse order while sorting",
    "  -R, --recursive            list subdirectories recursively",
    "  -s, --size                 print the allocated size of each file, in blocks",
    "  -S                         sort by file size, largest first",
    "      --sort=WORD            change default 'name' sort to WORD:",
    "                               none (-U), size (-S), time (-t),",
    "                               version (-v), extension (-X), name, width",
    "",
    "      --time=WORD            select which timestamp used to display or sort;",
    "                               access time (-u): atime, access, use;",
    "                               metadata change time (-c): ctime, status;",
    "                               modified time (default): mtime, modification;",
    "                               birth time: birth, creation;",
    "                             with -l, WORD determines which time to show;",
    "                             with --sort=time, sort by WORD (newest first)",
    "",
    "      --time-style=TIME_STYLE",
    "                             time/date format with -l; see TIME_STYLE below",
    "  -t                         sort by time, newest first; see --time",
    "  -T, --tabsize=COLS         assume tab stops at each COLS instead of 8",
    "  -u                         with -lt: sort by, and show, access time;",
    "                             with -l: show access time and sort by name;",
    "                             otherwise: sort by access time, newest first",
    "",
    "  -U                         do not sort directory entries",
    "  -v                         natural sort of (version) numbers within text",
    "  -w, --width=COLS           set output width to COLS.  0 means no limit",
    "  -x                         list entries by lines instead of by columns",
    "  -X                         sort alphabetically by entry extension",
    "  -Z, --context              print any security context of each file",
    "      --zero                 end each output line with NUL, not newline",
    "  -1                         list one file per line",
    "      --help        display this help and exit",
    "      --version     output version information and exit",
    "",
    "The SIZE argument is an integer and optional unit (example: 10K is 10*1024).",
    "Units are K,M,G,T,P,E,Z,Y,R,Q (powers of 1024) or KB,MB,... (powers of 1000).",
    "Binary prefixes can be used, too: KiB=K, MiB=M, and so on.",
    "",
    "The TIME_STYLE argument can be full-iso, long-iso, iso, locale, or +FORMAT.",
    "FORMAT is interpreted like in date(1).  If FORMAT is FORMAT1<newline>FORMAT2,",
    "then FORMAT1 applies to non-recent files and FORMAT2 to recent files.",
    "TIME_STYLE prefixed with 'posix-' takes effect only outside the POSIX locale.",
    "Also the TIME_STYLE environment variable sets the default style to use.",
    "",
    "The WHEN argument defaults to 'always' and can also be 'auto' or 'never'.",
    "",
    "Using color to distinguish file types is disabled both by default and",
    "with --color=never.  With --color=auto, ls emits color codes only when",
    "standard output is connected to a terminal.  The LS_COLORS environment",
    "variable can change the settings.  Use the dircolors(1) command to set it.",
    "",
    "Exit status:",
    " 0  if OK,",
    " 1  if minor problems (e.g., cannot access subdirectory),",
    " 2  if serious trouble (e.g., cannot access command-line argument).",
    "",
    "bash-os coreutils help: see /docs/bash/ls.txt or run 'help bashls'",
    "Full GNU option surface documentation: ls(1) of GNU coreutils 9.7",
    (char *)NULL
};

struct builtin bashls_struct = {
    "bashls",
    ls_builtin,
    BUILTIN_ENABLED,
    ls_doc,
    "ls [OPTION]... [FILE]...",
    0
};
