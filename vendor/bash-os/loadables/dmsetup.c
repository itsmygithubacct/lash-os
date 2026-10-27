/* SPDX-License-Identifier: MIT */
/* dmsetup.c — low-level device-mapper control, as a bash builtin.
 *
 * Every command speaks the kernel DM ioctl ABI on /dev/mapper/control
 * directly; there is no libdevmapper. Queries (`ls`, `info`, `table`,
 * `status`, `deps`, `targets`, `version`) are unprivileged in this code.
 * Mutating commands (`create`, `load`/`reload`, `remove`, `remove_all`,
 * `suspend`, `resume`, `rename`, `message`, `clear`, `wipe_table`) fail
 * closed unless uid 0 also opts in with BASHOS_DMSETUP_ALLOW_MUTATE=1,
 * and that check runs before the control device is opened.
 *
 * Requests follow libdevmapper's layout: one struct dm_ioctl header with
 * the payload at data_start, target specs padded to 8 bytes with `next`
 * relative to the spec, and a doubling retry whenever the kernel answers
 * with DM_BUFFER_FULL_FLAG. Responses are bounds-checked before use.
 *
 * --- LICENSE --- MIT, same boilerplate as the other bash-os loadables.
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
#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <linux/dm-ioctl.h>

#include "loadables.h"

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

#define DMS_CONTROL     "/dev/mapper/control"
#define DMS_INITIAL_BUF 16384          /* libdevmapper's starting size */
#define DMS_MAX_BUF     (64u << 20)    /* stop doubling here */
#define DMS_MAX_TABLE   (16u << 20)    /* largest table text accepted */

struct dms_opts {
    int readonly, notable, noflush, nolockfs, inactive, force, deferred;
    int showkeys, setuuid, has_major, has_minor;
    unsigned long major, minor;
    const char *uuid, *table, *target;
    const char **pos;                   /* positional words, verb first */
    int npos;
};

struct dms_spec {
    unsigned long long start, length;
    char type[DM_MAX_TYPE_NAME];
    const char *params;
    size_t params_len;
};

static void
dms_usage (void)
{
    fputs ("Usage:\n\n", stderr);
    fputs ("dmsetup\n", stderr);
    fputs ("\t[--version] [-h|--help]\n", stderr);
    fputs ("\thelp\n", stderr);
    fputs ("\tcreate <dev_name> [-u|--uuid <uuid>] [-r|--readonly] [-n|--notable]\n"
           "\t       [-j|--major <major> -m|--minor <minor>] [--table <table>|<table_file>]\n", stderr);
    fputs ("\tremove [-f|--force] [--deferred] <device>...\n", stderr);
    fputs ("\tremove_all [-f|--force]\n", stderr);
    fputs ("\tsuspend [--noflush] [--nolockfs] <device>...\n", stderr);
    fputs ("\tresume <device>...\n", stderr);
    fputs ("\tload <device> [-r|--readonly] [--table <table>|<table_file>]\n", stderr);
    fputs ("\tclear <device>...\n", stderr);
    fputs ("\treload <device> [-r|--readonly] [--table <table>|<table_file>]\n", stderr);
    fputs ("\twipe_table <device>...\n", stderr);
    fputs ("\trename <device> [--setuuid] <new_name_or_uuid>\n", stderr);
    fputs ("\tmessage <device> <sector> <message>\n", stderr);
    fputs ("\tls [--target <target_type>]\n", stderr);
    fputs ("\tinfo [<device>...]\n", stderr);
    fputs ("\tdeps [--inactive] [<device>...]\n", stderr);
    fputs ("\tstatus [--target <target_type>] [--inactive] [<device>...]\n", stderr);
    fputs ("\ttable [--target <target_type>] [--inactive] [--showkeys] [<device>...]\n", stderr);
    fputs ("\ttargets\n", stderr);
    fputs ("\tversion\n", stderr);
    fputs ("<device> may be a name, or omitted when -u|--uuid names it.\n", stderr);
}

/* ---- sysfs fallback for ls/info when the control node cannot be opened ---- */

static int
dms_read_first_line (const char *path, char *buf, size_t n)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read (fd, buf, n - 1);
    close (fd);
    if (r < 0) return -1;
    buf[r > 0 ? r : 0] = '\0';
    size_t l = strlen (buf);
    while (l && (buf[l - 1] == '\n' || buf[l - 1] == '\r')) buf[--l] = '\0';
    return 0;
}

static int
dms_is_dm_dir (const char *name)
{
    return strncmp (name, "dm-", 3) == 0 && name[3] >= '0' && name[3] <= '9';
}

static int
dms_sysfs_list (int info)
{
    DIR *d = opendir ("/sys/block");
    if (!d) {
        printf ("No devices found\n");
        return EXECUTION_SUCCESS;
    }

    int found = 0;
    struct dirent *de;
    while ((de = readdir (d))) {
        if (!dms_is_dm_dir (de->d_name)) continue;
        char path[512], name[DM_NAME_LEN] = "", uuid[DM_UUID_LEN] = "";
        char suspended[16] = "0", majmin[64] = "?:?", open_count[32] = "0";
        snprintf (path, sizeof path, "/sys/block/%s/dm/name", de->d_name);
        if (dms_read_first_line (path, name, sizeof name) < 0 || name[0] == '\0')
            snprintf (name, sizeof name, "%s", de->d_name);
        snprintf (path, sizeof path, "/sys/block/%s/dev", de->d_name);
        dms_read_first_line (path, majmin, sizeof majmin);
        found = 1;
        if (!info) {
            printf ("%s\t(%s)\n", name, majmin);
            continue;
        }
        snprintf (path, sizeof path, "/sys/block/%s/dm/uuid", de->d_name);
        dms_read_first_line (path, uuid, sizeof uuid);
        snprintf (path, sizeof path, "/sys/block/%s/dm/suspended", de->d_name);
        dms_read_first_line (path, suspended, sizeof suspended);
        snprintf (path, sizeof path, "/sys/block/%s/dm/open_count", de->d_name);
        dms_read_first_line (path, open_count, sizeof open_count);
        printf ("Name:              %s\n", name);
        printf ("State:             %s\n", strcmp (suspended, "1") == 0 ? "SUSPENDED" : "ACTIVE");
        printf ("Open count:        %s\n", open_count);
        printf ("Major, minor:      %s\n", majmin);
        if (uuid[0]) printf ("UUID:              %s\n", uuid);
        putchar ('\n');
    }
    closedir (d);

    if (!found) printf ("No devices found\n");
    return EXECUTION_SUCCESS;
}

/* ---- ioctl plumbing ---- */

static const char *
dms_cmd_name (unsigned long req, uint32_t flags)
{
    switch (req) {
    case DM_VERSION: return "version";
    case DM_REMOVE_ALL: return "remove_all";
    case DM_LIST_DEVICES: return "names";
    case DM_DEV_CREATE: return "create";
    case DM_DEV_REMOVE: return "remove";
    case DM_DEV_RENAME: return "rename";
    case DM_DEV_SUSPEND: return (flags & DM_SUSPEND_FLAG) ? "suspend" : "resume";
    case DM_DEV_STATUS: return "info";
    case DM_TABLE_LOAD: return "reload";
    case DM_TABLE_CLEAR: return "clear";
    case DM_TABLE_DEPS: return "deps";
    case DM_TABLE_STATUS: return (flags & DM_STATUS_TABLE_FLAG) ? "table" : "status";
    case DM_LIST_VERSIONS: return "versions";
    case DM_TARGET_MSG: return "message";
    }
    return "unknown";
}

static void
dms_report_open_error (int error)
{
    fprintf (stderr, "%s: open failed: %s\n", DMS_CONTROL, strerror (error));
    fputs ("Failure to communicate with kernel device-mapper driver.\n", stderr);
    if (error == EACCES || error == EPERM)
        fputs ("Check that device-mapper is available in the kernel and you have permission.\n", stderr);
}

static int
dms_open_control (int quiet)
{
    int fd = open (DMS_CONTROL, O_RDWR | O_CLOEXEC);
    if (fd < 0 && !quiet) dms_report_open_error (errno);
    return fd;
}

static int
dms_set_id (struct dm_ioctl *io, const char *name, const char *uuid)
{
    if (name && *name) {
        if (strlen (name) >= sizeof io->name) {
            fprintf (stderr, "dmsetup: name \"%s\" too long\n", name);
            return -1;
        }
        strcpy (io->name, name);
    }
    if (uuid && *uuid) {
        if (strlen (uuid) >= sizeof io->uuid) {
            fprintf (stderr, "dmsetup: uuid \"%s\" too long\n", uuid);
            return -1;
        }
        strcpy (io->uuid, uuid);
    }
    return 0;
}

static struct dm_ioctl *
dms_alloc (size_t bytes, const char *name, const char *uuid, uint32_t flags,
           const void *payload, size_t payload_len)
{
    size_t need = sizeof (struct dm_ioctl) + payload_len;
    if (bytes < need) bytes = need;
    struct dm_ioctl *io = calloc (1, bytes);
    if (!io) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return NULL;
    }
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = DM_VERSION_MINOR;
    io->version[2] = DM_VERSION_PATCHLEVEL;
    io->data_size = (uint32_t) bytes;
    io->data_start = sizeof (struct dm_ioctl);
    io->flags = flags;
    if (dms_set_id (io, name, uuid) < 0) {
        free (io);
        return NULL;
    }
    if (payload_len) memcpy ((char *) io + io->data_start, payload, payload_len);
    return io;
}

static void
dms_report (unsigned long req, uint32_t flags, const char *name, const char *uuid, int err)
{
    fprintf (stderr, "device-mapper: %s ioctl on %s %s failed: %s\n",
             dms_cmd_name (req, flags), name ? name : "", uuid ? uuid : "", strerror (err));
}

/* Run one DM ioctl. With grow set, start at DMS_INITIAL_BUF and double while
   the kernel reports DM_BUFFER_FULL_FLAG. Returns the response buffer, or NULL
   with *errp set (0 when a message has already been printed). Device-absent
   (ENXIO) errors are left for the caller to word when quiet_enxio is set. */
static struct dm_ioctl *
dms_run (int fd, unsigned long req, const char *name, const char *uuid, uint32_t flags,
         const void *payload, size_t payload_len, int grow, int quiet_enxio, int *errp)
{
    size_t bytes = grow ? DMS_INITIAL_BUF : 0;
    *errp = 0;
    for (;;) {
        struct dm_ioctl *io = dms_alloc (bytes, name, uuid, flags, payload, payload_len);
        if (!io) return NULL;
        if (ioctl (fd, req, io) < 0) {
            int e = errno;
            free (io);
            if (!(quiet_enxio && e == ENXIO)) dms_report (req, flags, name, uuid, e);
            *errp = e;
            return NULL;
        }
        if (!(io->flags & DM_BUFFER_FULL_FLAG)) {
            /* never trust a returned size beyond what was allocated */
            size_t have = bytes > sizeof (struct dm_ioctl) + payload_len
                ? bytes : sizeof (struct dm_ioctl) + payload_len;
            /* ctl_ioctl copies only offsetof(data) bytes for a header-only
               reply, not sizeof(struct dm_ioctl), which includes tail padding.
               Normalize that valid empty payload to our aligned data area.
               Consumers still validate any advertised records or DATA_OUT. */
            if (io->data_size == offsetof (struct dm_ioctl, data)
                && io->data_start == sizeof (struct dm_ioctl))
                io->data_size = io->data_start;
            /* Name and UUID are fixed arrays. A missing NUL would make
               later %s walks leave the header. Records and the next-offset
               chain are 8-byte aligned; an odd data_start is not a record. */
            if (io->data_start < sizeof (struct dm_ioctl) || io->data_start > have
                || io->data_size > have || io->data_size < io->data_start
                || (io->data_start & 7U)
                || !memchr (io->name, '\0', sizeof io->name)
                || !memchr (io->uuid, '\0', sizeof io->uuid)) {
                fprintf (stderr, "dmsetup: malformed %s response (data_start %u, data_size %u)\n",
                         dms_cmd_name (req, flags), io->data_start, io->data_size);
                free (io);
                return NULL;
            }
            return io;
        }
        free (io);
        if (!grow || bytes >= DMS_MAX_BUF) {
            fprintf (stderr, "dmsetup: %s response exceeds %u bytes\n",
                     dms_cmd_name (req, flags), DMS_MAX_BUF);
            return NULL;
        }
        bytes *= 2;
    }
}

static int
dms_simple (int fd, unsigned long req, const char *name, const char *uuid, uint32_t flags)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, req, name, uuid, flags, NULL, 0, 0, 0, &err);
    if (!io) return EXECUTION_FAILURE;
    free (io);
    return EXECUTION_SUCCESS;
}

/* Response iteration, bounded by the reported data_size. */
static const char *
dms_data (const struct dm_ioctl *io)
{
    return (const char *) io + io->data_start;
}

static const char *
dms_end (const struct dm_ioctl *io)
{
    return (const char *) io + io->data_size;
}

static int
dms_bad_response (const struct dm_ioctl *io, const char *what)
{
    fprintf (stderr, "dmsetup: malformed %s response from the kernel\n", what);
    (void) io;
    return -1;
}

/* Status replies use offsets from the data area (unlike TABLE_LOAD).
   Bound each string by its own record, and reject overlapping records before
   a caller prints parameters or uses lengths to build a replacement table.
   The last record may end before its alignment padding in data_size. */
static const struct dm_target_spec *
dms_target (const struct dm_ioctl *io, size_t off, uint32_t index, const char *what)
{
    size_t total = (size_t) (dms_end (io) - dms_data (io));
    if (off > total || total - off <= sizeof (struct dm_target_spec))
        goto bad;
    const struct dm_target_spec *ts = (const struct dm_target_spec *) (dms_data (io) + off);
    size_t stop = total;
    if (index + 1 < io->target_count) {
        if (ts->next <= off + sizeof *ts || ts->next >= total || (ts->next & 7U))
            goto bad;
        stop = ts->next;
    }
    if (!memchr (ts->target_type, '\0', sizeof ts->target_type)
        || !memchr (ts + 1, '\0', stop - off - sizeof *ts))
        goto bad;
    return ts;
bad:
    dms_bad_response (io, what);
    return NULL;
}

/* Walk DM_LIST_DEVICES records. cb returns nonzero to stop with failure. */
typedef int (*dms_name_cb) (int fd, const char *name, uint64_t dev, void *arg);

static int
dms_each_name (const struct dm_ioctl *io, int fd, dms_name_cb cb, void *arg, int *count)
{
    const char *p = dms_data (io), *end = dms_end (io);
    int rc = 0;
    *count = 0;
    if (p == end) return 0;  /* kernel's empty list has no payload */
    for (;;) {
        const struct dm_name_list *nl = (const struct dm_name_list *) p;
        if ((size_t) (end - p) < sizeof *nl) return dms_bad_response (io, "names");
        size_t span = (size_t) (end - p);
        if (nl->next) {
            if (nl->next < sizeof *nl || nl->next >= span || (nl->next & 7U))
                return dms_bad_response (io, "names");
            span = nl->next;
        }
        size_t room = span - offsetof (struct dm_name_list, name);
        if (!memchr (nl->name, '\0', room)) return dms_bad_response (io, "names");
        if (nl->dev == 0 && nl->next == 0 && nl->name[0] == '\0' && *count == 0)
            return 0;   /* the kernel's empty list is one zeroed record */
        ++*count;
        if (cb (fd, nl->name, nl->dev, arg)) rc = 1;
        if (nl->next == 0) break;
        p += nl->next;
    }
    return rc;
}

static struct dm_ioctl *
dms_list (int fd)
{
    int err;
    return dms_run (fd, DM_LIST_DEVICES, NULL, NULL, 0, NULL, 0, 1, 0, &err);
}

static void
dms_no_device (void)
{
    fputs ("Device does not exist.\n", stderr);
}

/* ---- table text parsing and DM_TABLE_LOAD construction ---- */

static size_t
dms_align8 (size_t n)
{
    return (n + 7U) & ~(size_t) 7U;
}

static int
dms_parse_u64 (const char **pp, unsigned long long *out)
{
    const char *p = *pp;
    if (*p < '0' || *p > '9') return -1;
    unsigned long long v = 0;
    while (*p >= '0' && *p <= '9') {
        unsigned d = (unsigned) (*p - '0');
        if (v > (~0ULL - d) / 10) return -1;
        v = v * 10 + d;
        p++;
    }
    if (*p && *p != ' ' && *p != '\t') return -1;
    *out = v;
    *pp = p;
    return 0;
}

/* Parse one NUL-terminated line, trimmed in place. Returns 1 for a target,
   0 for a blank or comment line, -1 for an invalid line. */
static int
dms_parse_line (char *line, struct dms_spec *sp)
{
    size_t l = strlen (line);
    while (l && (line[l - 1] == ' ' || line[l - 1] == '\t' || line[l - 1] == '\r'))
        line[--l] = '\0';
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '\0' || *p == '#') return 0;

    if (dms_parse_u64 (&p, &sp->start) < 0) return -1;
    while (*p == ' ' || *p == '\t') p++;
    if (dms_parse_u64 (&p, &sp->length) < 0) return -1;
    while (*p == ' ' || *p == '\t') p++;
    size_t i = 0;
    while (*p && *p != ' ' && *p != '\t') {
        if (i + 1 >= sizeof sp->type) return -1;
        sp->type[i++] = *p++;
    }
    sp->type[i] = '\0';
    if (i == 0) return -1;
    while (*p == ' ' || *p == '\t') p++;
    sp->params = p;
    sp->params_len = strlen (p);
    return 1;
}

/* Parse table text (modified in place) into specs. */
static int
dms_parse_table (char *text, const char *src, struct dms_spec **specs, size_t *n)
{
    size_t cap = 0, count = 0, lineno = 0;
    struct dms_spec *v = NULL;
    char *line = text;
    while (line) {
        char *nl = strchr (line, '\n');
        if (nl) *nl++ = '\0';
        lineno++;
        struct dms_spec sp;
        memset (&sp, 0, sizeof sp);
        int r = dms_parse_line (line, &sp);
        if (r < 0) {
            fprintf (stderr, "dmsetup: Invalid format on line %zu of table %s\n", lineno, src);
            free (v);
            return -1;
        }
        if (r > 0) {
            if (count == cap) {
                cap = cap ? cap * 2 : 8;
                struct dms_spec *nv = realloc (v, cap * sizeof *v);
                if (!nv) {
                    fprintf (stderr, "dmsetup: out of memory\n");
                    free (v);
                    return -1;
                }
                v = nv;
            }
            v[count++] = sp;
        }
        line = nl;
    }
    *specs = v;
    *n = count;
    return 0;
}

/* Build the DM_TABLE_LOAD payload: specs back to back, each padded to 8
   bytes, `next` the distance from this spec to the following one. */
static char *
dms_table_payload (const struct dms_spec *specs, size_t n, size_t *len)
{
    size_t total = 0;
    for (size_t i = 0; i < n; i++) {
        size_t one = dms_align8 (sizeof (struct dm_target_spec) + specs[i].params_len + 1);
        if (one > DMS_MAX_BUF - sizeof (struct dm_ioctl)
            || total > DMS_MAX_BUF - sizeof (struct dm_ioctl) - one) {
            fprintf (stderr, "dmsetup: table too large\n");
            return NULL;
        }
        total += one;
    }
    char *buf = calloc (1, total ? total : 1);
    if (!buf) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return NULL;
    }
    char *p = buf;
    for (size_t i = 0; i < n; i++) {
        size_t one = dms_align8 (sizeof (struct dm_target_spec) + specs[i].params_len + 1);
        struct dm_target_spec *ts = (struct dm_target_spec *) p;
        ts->sector_start = specs[i].start;
        ts->length = specs[i].length;
        ts->status = 0;
        ts->next = (uint32_t) one;
        memcpy (ts->target_type, specs[i].type, strlen (specs[i].type) + 1);
        memcpy (p + sizeof *ts, specs[i].params, specs[i].params_len + 1);
        p += one;
    }
    *len = total;
    return buf;
}

static int
dms_load_specs (int fd, const char *name, const char *uuid, const struct dms_spec *specs,
                size_t n, uint32_t flags)
{
    size_t len = 0;
    char *payload = dms_table_payload (specs, n, &len);
    if (!payload) return EXECUTION_FAILURE;
    int err;
    struct dm_ioctl *io = dms_alloc (0, name, uuid, flags, payload, len);
    free (payload);
    if (!io) return EXECUTION_FAILURE;
    io->target_count = (uint32_t) n;
    int rc = EXECUTION_SUCCESS;
    if (ioctl (fd, DM_TABLE_LOAD, io) < 0) {
        err = errno;
        dms_report (DM_TABLE_LOAD, flags, name, uuid, err);
        rc = EXECUTION_FAILURE;
    }
    free (io);
    return rc;
}

static char *
dms_read_fd (int fd, const char *src)
{
    size_t cap = 4096, len = 0;
    char *buf = malloc (cap);
    if (!buf) return NULL;
    for (;;) {
        if (len + 1 >= cap) {
            if (cap >= DMS_MAX_TABLE) {
                fprintf (stderr, "dmsetup: table %s exceeds %u bytes\n", src, DMS_MAX_TABLE);
                free (buf);
                return NULL;
            }
            char *nb = realloc (buf, cap * 2);
            if (!nb) { free (buf); return NULL; }
            buf = nb;
            cap *= 2;
        }
        ssize_t r = read (fd, buf + len, cap - len - 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            fprintf (stderr, "dmsetup: %s: read failed: %s\n", src, strerror (errno));
            free (buf);
            return NULL;
        }
        if (r == 0) break;
        len += (size_t) r;
    }
    if (memchr (buf, '\0', len)) {
        fprintf (stderr, "dmsetup: table %s contains a NUL byte\n", src);
        free (buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/* Table text from --table, a table file (or inline text when the argument is
   not an existing file), or stdin when it is not a terminal. *text is NULL
   when no table was supplied. */
static int
dms_table_text (const struct dms_opts *o, const char *arg, char **text, const char **src)
{
    *text = NULL;
    if (o->table) {
        *src = "(--table)";
        *text = strdup (o->table);
        return *text ? 0 : -1;
    }
    if (arg) {
        struct stat st;
        if (stat (arg, &st) == 0 && !S_ISDIR (st.st_mode)) {
            int fd = open (arg, O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                fprintf (stderr, "dmsetup: %s: open failed: %s\n", arg, strerror (errno));
                return -1;
            }
            *src = arg;
            *text = dms_read_fd (fd, arg);
            close (fd);
            return *text ? 0 : -1;
        }
        *src = "(argument)";
        *text = strdup (arg);
        return *text ? 0 : -1;
    }
    if (!isatty (0)) {
        *src = "(stdin)";
        *text = dms_read_fd (0, "(stdin)");
        return *text ? 0 : -1;
    }
    return 0;
}

/* ---- queries ---- */

static int
dms_status_one (int fd, const char *name, const char *uuid, uint32_t flags, struct dm_ioctl **out)
{
    int err;
    *out = dms_run (fd, DM_DEV_STATUS, name, uuid, flags, NULL, 0, 0, 1, &err);
    if (!*out && err == ENXIO) dms_no_device ();
    return *out ? 0 : -1;
}

static int
dms_info_print (int fd, const char *name, const char *uuid)
{
    struct dm_ioctl *io;
    if (dms_status_one (fd, name, uuid, 0, &io) < 0) return EXECUTION_FAILURE;
    dev_t dev = (dev_t) io->dev;
    const char *tables = (io->flags & DM_ACTIVE_PRESENT_FLAG)
        ? ((io->flags & DM_INACTIVE_PRESENT_FLAG) ? "LIVE & INACTIVE" : "LIVE")
        : ((io->flags & DM_INACTIVE_PRESENT_FLAG) ? "INACTIVE" : "None");
    printf ("Name:              %s\n", io->name);
    printf ("State:             %s%s%s\n", (io->flags & DM_SUSPEND_FLAG) ? "SUSPENDED" : "ACTIVE",
            (io->flags & DM_READONLY_FLAG) ? " (READ-ONLY)" : "",
            (io->flags & DM_DEFERRED_REMOVE) ? " (DEFERRED REMOVE)" : "");
    printf ("Tables present:    %s\n", tables);
    printf ("Open count:        %d\n", io->open_count);
    printf ("Event number:      %u\n", io->event_nr);
    printf ("Major, minor:      %u, %u\n", major (dev), minor (dev));
    if (io->flags & DM_ACTIVE_PRESENT_FLAG)
        printf ("Number of targets: %u\n", io->target_count);
    if (io->uuid[0]) printf ("UUID:              %s\n", io->uuid);
    putchar ('\n');
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_list_cb_info (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev; (void) arg;
    return dms_info_print (fd, name, NULL) != EXECUTION_SUCCESS;
}

/* Hide the key field of crypt table lines unless --showkeys. Keyring
   references (":size:type:desc") and "-" are not secrets and stay. */
static void
dms_print_params (const char *type, const char *params, int table_mode, int showkeys)
{
    if (!table_mode || showkeys || strcmp (type, "crypt") != 0) {
        fputs (params, stdout);
        return;
    }
    const char *k = strchr (params, ' ');
    if (!k) { fputs (params, stdout); return; }
    k++;
    size_t klen = strcspn (k, " ");
    fwrite (params, 1, (size_t) (k - params), stdout);
    if (klen && k[0] != ':' && strncmp (k, "-", klen) != 0)
        for (size_t i = 0; i < klen; i++) putchar ('0');
    else
        fwrite (k, 1, klen, stdout);
    fputs (k + klen, stdout);
}

struct dms_table_arg {
    int table_mode, prefix;
    const struct dms_opts *o;
    const char *uuid;
};

/* Fetch a device's table (or status) and print each target. With
   only_count set, return the number of targets of type o->target instead. */
static int
dms_table_print (int fd, const char *name, const struct dms_table_arg *a, int *only_count)
{
    int err;
    uint32_t flags = (a->table_mode ? DM_STATUS_TABLE_FLAG : 0)
        | (a->o->inactive ? DM_QUERY_INACTIVE_TABLE_FLAG : 0);
    struct dm_ioctl *io = dms_run (fd, DM_TABLE_STATUS, name, a->uuid, flags, NULL, 0, 1, 1, &err);
    if (!io) {
        if (err == ENXIO) dms_no_device ();
        return EXECUTION_FAILURE;
    }

    size_t off = 0;
    int matched = 0, rc = EXECUTION_SUCCESS;
    for (uint32_t i = 0; i < io->target_count; i++) {
        const struct dm_target_spec *ts = dms_target (io, off, i, dms_cmd_name (DM_TABLE_STATUS, flags));
        if (!ts) {
            rc = EXECUTION_FAILURE;
            break;
        }
        const char *params = (const char *) (ts + 1);
        if (!a->o->target || !strcmp (a->o->target, ts->target_type)) {
            matched++;
            if (!only_count) {
                if (a->prefix) printf ("%s: ", name);
                printf ("%llu %llu %s ", (unsigned long long) ts->sector_start,
                        (unsigned long long) ts->length, ts->target_type);
                dms_print_params (ts->target_type, params, a->table_mode, a->o->showkeys);
                putchar ('\n');
            }
        }
        off = ts->next;
    }
    if (!only_count && a->prefix && io->target_count == 0 && !a->o->target)
        printf ("%s: \n", name);
    if (only_count) *only_count = matched;
    free (io);
    return rc;
}

static int
dms_list_cb_table (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev;
    return dms_table_print (fd, name, arg, NULL) != EXECUTION_SUCCESS;
}

static int
dms_deps_print (int fd, const char *name, const char *uuid, int prefix, int inactive)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_TABLE_DEPS, name, uuid,
                                   inactive ? DM_QUERY_INACTIVE_TABLE_FLAG : 0,
                                   NULL, 0, 1, 1, &err);
    if (!io) {
        if (err == ENXIO) dms_no_device ();
        return EXECUTION_FAILURE;
    }
    const char *p = dms_data (io), *end = dms_end (io);
    /* No selected table: the kernel returns only the fixed header. */
    if (p == end && !(io->flags & (inactive ? DM_INACTIVE_PRESENT_FLAG : DM_ACTIVE_PRESENT_FLAG))) {
        if (prefix) printf ("%s: ", name);
        printf ("0 dependencies\t:\n");
        free (io);
        return EXECUTION_SUCCESS;
    }
    const struct dm_target_deps *deps = (const struct dm_target_deps *) p;
    if ((size_t) (end - p) < sizeof *deps
        || deps->count > ((size_t) (end - p) - sizeof *deps) / sizeof deps->dev[0]) {
        dms_bad_response (io, "deps");
        free (io);
        return EXECUTION_FAILURE;
    }
    if (prefix) printf ("%s: ", name);
    printf ("%u dependencies\t:", deps->count);
    for (uint32_t i = 0; i < deps->count; i++) {
        dev_t dev = (dev_t) deps->dev[i];
        printf (" (%u, %u)", major (dev), minor (dev));
    }
    putchar ('\n');
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_list_cb_deps (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev;
    return dms_deps_print (fd, name, NULL, 1, *(int *) arg) != EXECUTION_SUCCESS;
}

struct dms_ls_arg {
    const struct dms_opts *o;
    int failed;
};

static int
dms_list_cb_ls (int fd, const char *name, uint64_t dev, void *arg)
{
    struct dms_ls_arg *la = arg;
    if (la->o->target) {
        struct dms_table_arg ta = { 1, 0, la->o, NULL };
        int n = 0;
        if (dms_table_print (fd, name, &ta, &n) != EXECUTION_SUCCESS) {
            la->failed = 1;
            return 1;
        }
        if (n == 0) return 0;
    }
    printf ("%s\t(%u:%u)\n", name, major ((dev_t) dev), minor ((dev_t) dev));
    return 0;
}

static int
dms_ls_cmd (const struct dms_opts *o)
{
    int fd = dms_open_control (1);
    if (fd < 0) {
        if (o->target) {
            dms_report_open_error (errno);
            return EXECUTION_FAILURE;
        }
        return dms_sysfs_list (0);
    }
    struct dm_ioctl *io = dms_list (fd);
    int rc = EXECUTION_FAILURE, count = 0;
    if (io) {
        struct dms_ls_arg la = { o, 0 };
        int r = dms_each_name (io, fd, dms_list_cb_ls, &la, &count);
        if (r >= 0 && !la.failed) {
            rc = EXECUTION_SUCCESS;
            if (count == 0) printf ("No devices found\n");
        }
        free (io);
    }
    close (fd);
    return rc;
}

/* Run cb for every device the kernel lists. */
static int
dms_for_all (int fd, dms_name_cb cb, void *arg)
{
    struct dm_ioctl *io = dms_list (fd);
    if (!io) return EXECUTION_FAILURE;
    int count = 0;
    int r = dms_each_name (io, fd, cb, arg, &count);
    if (r == 0 && count == 0) printf ("No devices found\n");
    free (io);
    return r == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
dms_targets_cmd (int fd)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_LIST_VERSIONS, NULL, NULL, 0, NULL, 0, 1, 0, &err);
    if (!io) return EXECUTION_FAILURE;
    const char *p = dms_data (io), *end = dms_end (io);
    int rc = EXECUTION_SUCCESS;
    while (p < end) {
        if ((size_t) (end - p) <= sizeof (struct dm_target_versions)) {
            dms_bad_response (io, "versions");
            rc = EXECUTION_FAILURE;
            break;
        }
        const struct dm_target_versions *tv = (const struct dm_target_versions *) p;
        size_t span = (size_t) (end - p);
        if (tv->next) {
            if (tv->next <= sizeof *tv || tv->next >= span || (tv->next & 7U)) {
                dms_bad_response (io, "versions");
                rc = EXECUTION_FAILURE;
                break;
            }
            span = tv->next;
        }
        if (!memchr (tv->name, '\0', span - offsetof (struct dm_target_versions, name))) {
            dms_bad_response (io, "versions");
            rc = EXECUTION_FAILURE;
            break;
        }
        if (tv->name[0])
            printf ("%-16s v%u.%u.%u\n", tv->name, tv->version[0], tv->version[1], tv->version[2]);
        if (tv->next == 0) break;
        p += tv->next;
    }
    free (io);
    return rc;
}

static int
dms_version_cmd (void)
{
    printf ("Library version:   bash-os dm-ioctl shim\n");
    int fd = dms_open_control (1);
    if (fd < 0) {
        printf ("Driver version:    unavailable\n");
        return EXECUTION_SUCCESS;
    }
    struct dm_ioctl *io = dms_alloc (0, NULL, NULL, 0, NULL, 0);
    if (!io) {
        close (fd);
        return EXECUTION_FAILURE;
    }
    if (ioctl (fd, DM_VERSION, io) == 0)
        printf ("Driver version:    %u.%u.%u\n", io->version[0], io->version[1], io->version[2]);
    else
        printf ("Driver version:    unavailable\n");
    free (io);
    close (fd);
    return EXECUTION_SUCCESS;
}

/* ---- mutations ---- */

static int
dms_mutating_allowed (const char *verb)
{
    const char *allow = getenv ("BASHOS_DMSETUP_ALLOW_MUTATE");
    if (geteuid () == 0 && allow && strcmp (allow, "1") == 0) return 1;
    fprintf (stderr, "dmsetup: %s requires root and BASHOS_DMSETUP_ALLOW_MUTATE=1\n", verb);
    return 0;
}

/* Total length of a device's live table, 0 if it has none, -1 on error. */
static long long
dms_device_size (int fd, const char *name, const char *uuid)
{
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_TABLE_STATUS, name, uuid, DM_STATUS_TABLE_FLAG,
                                   NULL, 0, 1, 1, &err);
    if (!io) {
        if (err == ENXIO) dms_no_device ();
        return -1;
    }
    size_t off = 0;
    unsigned long long total = 0;
    for (uint32_t i = 0; i < io->target_count; i++) {
        const struct dm_target_spec *ts = dms_target (io, off, i, "table");
        if (!ts) {
            free (io);
            return -1;
        }
        if (ts->sector_start != total || !ts->length || ts->length > (unsigned long long) LLONG_MAX - total) {
            dms_bad_response (io, "table geometry");
            free (io);
            return -1;
        }
        total += ts->length;
        off = ts->next;
    }
    free (io);
    return (long long) total;
}

/* libdevmapper's _error_device: replace the live table with one error
   target covering the same size, then resume (clearing on failure). */
static int
dms_error_device (int fd, const char *name, const char *uuid, int quiet_empty)
{
    long long size = dms_device_size (fd, name, uuid);
    if (size < 0) return EXECUTION_FAILURE;
    if (size == 0) {
        if (!quiet_empty)
            fprintf (stderr, "dmsetup: %s has no live table to wipe\n", name ? name : uuid);
        return EXECUTION_FAILURE;
    }
    struct dms_spec sp;
    memset (&sp, 0, sizeof sp);
    sp.start = 0;
    sp.length = (unsigned long long) size;
    strcpy (sp.type, "error");
    sp.params = "";
    sp.params_len = 0;
    if (dms_load_specs (fd, name, uuid, &sp, 1, 0) != EXECUTION_SUCCESS) return EXECUTION_FAILURE;
    if (dms_simple (fd, DM_DEV_SUSPEND, name, uuid, 0) != EXECUTION_SUCCESS) {
        dms_simple (fd, DM_TABLE_CLEAR, name, uuid, 0);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

/* Arguments after the verb: the device, unless -u names it, then the rest. */
static int
dms_device_arg (const struct dms_opts *o, const char *verb, const char **name, int *next)
{
    if (o->uuid) {
        *name = NULL;
        *next = 1;
        return 0;
    }
    if (o->npos >= 2) {
        *name = o->pos[1];
        *next = 2;
        return 0;
    }
    fprintf (stderr, "dmsetup: %s requires a device name or -u UUID\n", verb);
    return -1;
}

/* With -u, the uuid identifies the device and the name is not sent. */
static const char *
dms_id_uuid (const struct dms_opts *o, const char *name)
{
    return name ? NULL : o->uuid;
}

static int
dms_create_cmd (int fd, const struct dms_opts *o)
{
    if (o->npos < 2) {
        fprintf (stderr, "dmsetup: create requires a device name\n");
        return EXECUTION_FAILURE;
    }
    if (o->npos > 3) {
        fprintf (stderr, "dmsetup: create: too many arguments\n");
        return EXECUTION_FAILURE;
    }
    if (o->has_major != o->has_minor) {
        fprintf (stderr, "dmsetup: create: --major and --minor must be given together\n");
        return EXECUTION_FAILURE;
    }
    const char *name = o->pos[1];

    struct dms_spec *specs = NULL;
    size_t n = 0;
    char *text = NULL;
    if (!o->notable) {
        const char *src = "";
        if (dms_table_text (o, o->npos > 2 ? o->pos[2] : NULL, &text, &src) < 0) return EXECUTION_FAILURE;
        if (text && dms_parse_table (text, src, &specs, &n) < 0) {
            free (text);
            return EXECUTION_FAILURE;
        }
    }

    int err;
    uint32_t flags = 0;
    struct dm_ioctl *io = dms_alloc (0, name, o->uuid, 0, NULL, 0);
    int rc = EXECUTION_FAILURE;
    if (!io) goto out;
    if (o->has_major) {
        flags |= DM_PERSISTENT_DEV_FLAG;
        io->dev = (uint64_t) makedev ((unsigned) o->major, (unsigned) o->minor);
    }
    io->flags = flags;
    if (ioctl (fd, DM_DEV_CREATE, io) < 0) {
        err = errno;
        dms_report (DM_DEV_CREATE, flags, name, o->uuid, err);
        free (io);
        goto out;
    }
    free (io);
    rc = EXECUTION_SUCCESS;
    if (n) {
        /* like libdevmapper, a failed load or resume reverts the create */
        rc = dms_load_specs (fd, name, NULL, specs, n, o->readonly ? DM_READONLY_FLAG : 0);
        if (rc == EXECUTION_SUCCESS)
            rc = dms_simple (fd, DM_DEV_SUSPEND, name, NULL, 0);
        if (rc != EXECUTION_SUCCESS)
            dms_simple (fd, DM_DEV_REMOVE, name, NULL, 0);
    }
out:
    free (specs);
    free (text);
    return rc;
}

static int
dms_load_cmd (int fd, const struct dms_opts *o, const char *verb)
{
    const char *name;
    int next;
    if (dms_device_arg (o, verb, &name, &next) < 0) return EXECUTION_FAILURE;
    if (o->npos > next + 1) {
        fprintf (stderr, "dmsetup: %s: too many arguments\n", verb);
        return EXECUTION_FAILURE;
    }
    char *text = NULL;
    const char *src = "";
    if (dms_table_text (o, o->npos > next ? o->pos[next] : NULL, &text, &src) < 0)
        return EXECUTION_FAILURE;
    if (!text) {
        fprintf (stderr, "dmsetup: %s requires a table (--table, a file, or stdin)\n", verb);
        return EXECUTION_FAILURE;
    }
    struct dms_spec *specs = NULL;
    size_t n = 0;
    int rc = EXECUTION_FAILURE;
    if (dms_parse_table (text, src, &specs, &n) == 0)
        rc = dms_load_specs (fd, name, dms_id_uuid (o, name), specs, n,
                             o->readonly ? DM_READONLY_FLAG : 0);
    free (specs);
    free (text);
    return rc;
}

/* Apply one per-device operation to each named device (or the -u device),
   continuing past failures like dmsetup's multiple-device processing. */
static int
dms_each_device (int fd, const struct dms_opts *o, const char *verb,
                 int (*op) (int, const struct dms_opts *, const char *, const char *))
{
    if (o->npos < 2) {
        if (!o->uuid) {
            fprintf (stderr, "dmsetup: %s requires a device name or -u UUID\n", verb);
            return EXECUTION_FAILURE;
        }
        return op (fd, o, NULL, o->uuid);
    }
    int rc = EXECUTION_SUCCESS;
    for (int i = 1; i < o->npos; i++)
        if (op (fd, o, o->pos[i], NULL) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
    return rc;
}

static int
dms_op_remove (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    if (o->force) dms_error_device (fd, name, uuid, 1);   /* best effort, as libdevmapper */
    return dms_simple (fd, DM_DEV_REMOVE, name, uuid, o->deferred ? DM_DEFERRED_REMOVE : 0);
}

static int
dms_op_suspend (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    uint32_t flags = DM_SUSPEND_FLAG | (o->noflush ? DM_NOFLUSH_FLAG : 0)
        | (o->nolockfs ? DM_SKIP_LOCKFS_FLAG : 0);
    return dms_simple (fd, DM_DEV_SUSPEND, name, uuid, flags);
}

static int
dms_op_resume (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    (void) o;
    return dms_simple (fd, DM_DEV_SUSPEND, name, uuid, 0);
}

static int
dms_op_clear (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    (void) o;
    return dms_simple (fd, DM_TABLE_CLEAR, name, uuid, 0);
}

static int
dms_op_wipe (int fd, const struct dms_opts *o, const char *name, const char *uuid)
{
    (void) o;
    return dms_error_device (fd, name, uuid, 0);
}

static int
dms_list_cb_wipe (int fd, const char *name, uint64_t dev, void *arg)
{
    (void) dev; (void) arg;
    dms_error_device (fd, name, NULL, 1);
    return 0;
}

static int
dms_remove_all_cmd (int fd, const struct dms_opts *o)
{
    if (o->npos > 1) {
        fprintf (stderr, "dmsetup: remove_all takes no device arguments\n");
        return EXECUTION_FAILURE;
    }
    if (o->force) {
        struct dm_ioctl *io = dms_list (fd);
        if (!io) return EXECUTION_FAILURE;
        int count;
        int r = dms_each_name (io, fd, dms_list_cb_wipe, NULL, &count);
        free (io);
        if (r < 0) return EXECUTION_FAILURE;
    }
    return dms_simple (fd, DM_REMOVE_ALL, NULL, NULL, 0);
}

static int
dms_rename_cmd (int fd, const struct dms_opts *o)
{
    const char *name;
    int next;
    if (dms_device_arg (o, "rename", &name, &next) < 0) return EXECUTION_FAILURE;
    if (o->npos != next + 1) {
        fprintf (stderr, "dmsetup: rename requires a device and a new %s\n",
                 o->setuuid ? "uuid" : "name");
        return EXECUTION_FAILURE;
    }
    const char *newid = o->pos[next];
    size_t limit = o->setuuid ? DM_UUID_LEN : DM_NAME_LEN;
    if (!*newid || strlen (newid) >= limit) {
        fprintf (stderr, "dmsetup: new %s \"%s\" is %s\n", o->setuuid ? "uuid" : "name",
                 newid, *newid ? "too long" : "empty");
        return EXECUTION_FAILURE;
    }
    if (!o->setuuid && strchr (newid, '/')) {
        fprintf (stderr, "dmsetup: new name \"%s\" contains '/'\n", newid);
        return EXECUTION_FAILURE;
    }
    int err;
    struct dm_ioctl *io = dms_run (fd, DM_DEV_RENAME, name, dms_id_uuid (o, name),
                                   o->setuuid ? DM_UUID_FLAG : 0, newid, strlen (newid) + 1,
                                   0, 0, &err);
    if (!io) return EXECUTION_FAILURE;
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_message_cmd (int fd, const struct dms_opts *o)
{
    const char *name;
    int next;
    if (dms_device_arg (o, "message", &name, &next) < 0) return EXECUTION_FAILURE;
    if (o->npos < next + 2) {
        fprintf (stderr, "dmsetup: message requires a device, a sector and a message\n");
        return EXECUTION_FAILURE;
    }
    const char *sp = o->pos[next];
    unsigned long long sector;
    if (dms_parse_u64 (&sp, &sector) < 0 || *sp) {
        fprintf (stderr, "dmsetup: invalid sector: %s\n", o->pos[next]);
        return EXECUTION_FAILURE;
    }

    size_t mlen = 0;
    for (int i = next + 1; i < o->npos; i++) mlen += strlen (o->pos[i]) + 1;
    size_t plen = dms_align8 (sizeof (struct dm_target_msg) + mlen);
    struct dm_target_msg *msg = calloc (1, plen);
    if (!msg) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return EXECUTION_FAILURE;
    }
    msg->sector = sector;
    char *w = msg->message;
    for (int i = next + 1; i < o->npos; i++) {
        size_t l = strlen (o->pos[i]);
        memcpy (w, o->pos[i], l);
        w += l;
        *w++ = (i + 1 < o->npos) ? ' ' : '\0';
    }

    int err;
    struct dm_ioctl *io = dms_run (fd, DM_TARGET_MSG, name, dms_id_uuid (o, name), 0,
                                   msg, plen, 1, 0, &err);
    free (msg);
    if (!io) return EXECUTION_FAILURE;
    int rc = EXECUTION_SUCCESS;
    if (io->flags & DM_DATA_OUT_FLAG) {
        const char *resp = dms_data (io), *end = dms_end (io);
        const char *z = memchr (resp, '\0', (size_t) (end - resp));
        if (!z) {
            dms_bad_response (io, "message");
            rc = EXECUTION_FAILURE;
        } else if (z > resp) {
            fputs (resp, stdout);
            if (z[-1] != '\n') putchar ('\n');
        }
    }
    free (io);
    return rc;
}

/* ---- option parsing ---- */

static int
dms_opt_value (const char *w, const char **eq)
{
    *eq = strchr (w, '=');
    return w[0] == '-' && w[1] == '-' && *eq;
}

static int
dms_parse_ulong (const char *opt, const char *s, unsigned long *out)
{
    char *end;
    errno = 0;
    if (*s < '0' || *s > '9') goto bad;
    *out = strtoul (s, &end, 10);
    if (errno || *end || *out > 0xfffffUL) goto bad;
    return 0;
bad:
    fprintf (stderr, "dmsetup: invalid %s: %s\n", opt, s);
    return -1;
}

static int
dms_parse_args (WORD_LIST *list, struct dms_opts *o, int *early)
{
    int n = 0;
    for (WORD_LIST *p = list; p; p = p->next) n++;
    o->pos = calloc ((size_t) n + 1, sizeof *o->pos);
    if (!o->pos) {
        fprintf (stderr, "dmsetup: out of memory\n");
        return -1;
    }
    *early = -1;
    int opts_done = 0;
    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word ? p->word->word : NULL;
        if (!w) continue;
        if (opts_done || w[0] != '-' || !w[1]) {
            o->pos[o->npos++] = w;
            continue;
        }
        if (!strcmp (w, "--")) { opts_done = 1; continue; }
        if (!strcmp (w, "--version")) { *early = 1; return 0; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) { *early = 0; return 0; }

        if (!strcmp (w, "-r") || !strcmp (w, "--readonly")) { o->readonly = 1; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--notable")) { o->notable = 1; continue; }
        if (!strcmp (w, "--noflush")) { o->noflush = 1; continue; }
        if (!strcmp (w, "--nolockfs")) { o->nolockfs = 1; continue; }
        if (!strcmp (w, "--inactive")) { o->inactive = 1; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--force")) { o->force = 1; continue; }
        if (!strcmp (w, "--deferred")) { o->deferred = 1; continue; }
        if (!strcmp (w, "--showkeys")) { o->showkeys = 1; continue; }
        if (!strcmp (w, "--setuuid")) { o->setuuid = 1; continue; }
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose") || !strcmp (w, "--noopencount")
            || !strcmp (w, "--tree") || !strcmp (w, "--concise") || !strcmp (w, "--retry")
            || !strcmp (w, "--noudevsync") || !strcmp (w, "--noudevrules") || !strcmp (w, "-y")
            || !strcmp (w, "--yes") || !strcmp (w, "--verifyudev") || !strcmp (w, "--addnodeoncreate")
            || !strcmp (w, "--addnodeonresume") || !strcmp (w, "--ignorelockingfailure")
            || !strcmp (w, "--checks") || !strcmp (w, "--noheadings") || !strcmp (w, "-c")
            || !strcmp (w, "-C") || !strcmp (w, "--columns"))
            continue;

        /* options with a value: "--opt value" or "--opt=value" */
        const char *eq;
        char key[32];
        const char *val;
        if (dms_opt_value (w, &eq)) {
            size_t kl = (size_t) (eq - w);
            if (kl >= sizeof key) kl = sizeof key - 1;
            memcpy (key, w, kl);
            key[kl] = '\0';
            val = eq + 1;
        } else {
            snprintf (key, sizeof key, "%s", w);
            val = NULL;
        }
        static const char *const valued[] = {
            "-u", "--uuid", "--table", "--target", "-j", "--major", "-m", "--minor",
            "--manglename", "--udevcookie", "--readahead", "-o", "--options", "-O", "--sort",
            "-S", "--select", "--headings", "--separator", "--exec", "-U", "--uid",
            "-G", "--gid", "-M", "--mode", "--count", "--interval", NULL
        };
        int known = 0;
        for (int i = 0; valued[i]; i++) if (!strcmp (key, valued[i])) known = 1;
        if (!known) {
            fprintf (stderr, "dmsetup: unrecognized option '%s'\n", w);
            fputs ("Couldn't process command line.\n", stderr);
            return -1;
        }
        if (!val) {
            if (!p->next || !p->next->word || !p->next->word->word) {
                fprintf (stderr, "dmsetup: option %s requires an argument\n", w);
                fputs ("Couldn't process command line.\n", stderr);
                return -1;
            }
            p = p->next;
            val = p->word->word;
        }
        if (!strcmp (key, "-u") || !strcmp (key, "--uuid")) o->uuid = val;
        else if (!strcmp (key, "--table")) o->table = val;
        else if (!strcmp (key, "--target")) o->target = val;
        else if (!strcmp (key, "-j") || !strcmp (key, "--major")) {
            if (dms_parse_ulong ("major", val, &o->major) < 0) return -1;
            o->has_major = 1;
        } else if (!strcmp (key, "-m") || !strcmp (key, "--minor")) {
            if (dms_parse_ulong ("minor", val, &o->minor) < 0) return -1;
            o->has_minor = 1;
        }
    }
    return 0;
}

static int
dms_is_mutating (const char *verb)
{
    static const char *const verbs[] = {
        "create", "load", "reload", "remove", "remove_all", "suspend", "resume",
        "rename", "message", "clear", "wipe_table", NULL
    };
    for (int i = 0; verbs[i]; i++) if (!strcmp (verb, verbs[i])) return 1;
    return 0;
}

static int
dms_dispatch (const struct dms_opts *o)
{
    const char *verb = o->pos[0];

    if (!strcmp (verb, "help")) { dms_usage (); return EXECUTION_SUCCESS; }
    if (!strcmp (verb, "version")) return dms_version_cmd ();
    if (!strcmp (verb, "ls")) return dms_ls_cmd (o);

    /* where the device is a list of names, -u replaces the list */
    if (o->uuid && o->npos > 1 && strcmp (verb, "create") && strcmp (verb, "load")
        && strcmp (verb, "reload") && strcmp (verb, "rename") && strcmp (verb, "message")) {
        fprintf (stderr, "dmsetup: %s: give either a device name or -u UUID, not both\n", verb);
        return EXECUTION_FAILURE;
    }

    if (!strcmp (verb, "info")) {
        int fd = dms_open_control (1);
        if (fd < 0) {
            if (o->npos > 1 || o->uuid) {
                dms_report_open_error (errno);
                return EXECUTION_FAILURE;
            }
            return dms_sysfs_list (1);
        }
        int rc;
        if (o->npos > 1) {
            rc = EXECUTION_SUCCESS;
            for (int i = 1; i < o->npos; i++)
                if (dms_info_print (fd, o->pos[i], NULL) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
        } else if (o->uuid)
            rc = dms_info_print (fd, NULL, o->uuid);
        else
            rc = dms_for_all (fd, dms_list_cb_info, NULL);
        close (fd);
        return rc;
    }

    if (!strcmp (verb, "table") || !strcmp (verb, "status") || !strcmp (verb, "deps")
        || !strcmp (verb, "targets")) {
        int fd = dms_open_control (0);
        if (fd < 0) return EXECUTION_FAILURE;
        int rc = EXECUTION_SUCCESS;
        if (!strcmp (verb, "targets"))
            rc = dms_targets_cmd (fd);
        else if (!strcmp (verb, "deps")) {
            int inactive = o->inactive;
            if (o->npos > 1) {
                for (int i = 1; i < o->npos; i++)
                    if (dms_deps_print (fd, o->pos[i], NULL, 0, inactive) != EXECUTION_SUCCESS)
                        rc = EXECUTION_FAILURE;
            } else if (o->uuid)
                rc = dms_deps_print (fd, NULL, o->uuid, 0, inactive);
            else
                rc = dms_for_all (fd, dms_list_cb_deps, &inactive);
        } else {
            struct dms_table_arg ta = { !strcmp (verb, "table"), 0, o, NULL };
            if (o->npos > 1) {
                for (int i = 1; i < o->npos; i++)
                    if (dms_table_print (fd, o->pos[i], &ta, NULL) != EXECUTION_SUCCESS)
                        rc = EXECUTION_FAILURE;
            } else if (o->uuid) {
                ta.uuid = o->uuid;
                rc = dms_table_print (fd, NULL, &ta, NULL);
            } else {
                ta.prefix = 1;
                rc = dms_for_all (fd, dms_list_cb_table, &ta);
            }
        }
        close (fd);
        return rc;
    }

    if (!dms_is_mutating (verb)) {
        fputs ("Unknown command.\n", stderr);
        dms_usage ();
        return EXECUTION_FAILURE;
    }
    if (!dms_mutating_allowed (verb)) return EXECUTION_FAILURE;

    int fd = dms_open_control (0);
    if (fd < 0) return EXECUTION_FAILURE;
    int rc;
    if (!strcmp (verb, "create")) rc = dms_create_cmd (fd, o);
    else if (!strcmp (verb, "load") || !strcmp (verb, "reload")) rc = dms_load_cmd (fd, o, verb);
    else if (!strcmp (verb, "remove")) rc = dms_each_device (fd, o, verb, dms_op_remove);
    else if (!strcmp (verb, "remove_all")) rc = dms_remove_all_cmd (fd, o);
    else if (!strcmp (verb, "suspend")) rc = dms_each_device (fd, o, verb, dms_op_suspend);
    else if (!strcmp (verb, "resume")) rc = dms_each_device (fd, o, verb, dms_op_resume);
    else if (!strcmp (verb, "clear")) rc = dms_each_device (fd, o, verb, dms_op_clear);
    else if (!strcmp (verb, "wipe_table")) rc = dms_each_device (fd, o, verb, dms_op_wipe);
    else if (!strcmp (verb, "rename")) rc = dms_rename_cmd (fd, o);
    else rc = dms_message_cmd (fd, o);
    close (fd);
    return rc;
}

int
dmsetup_builtin (WORD_LIST *list)
{
    struct dms_opts o;
    memset (&o, 0, sizeof o);
    int early;
    int rc;
    if (dms_parse_args (list, &o, &early) < 0) {
        rc = EXECUTION_FAILURE;
    } else if (early == 1) {
        rc = dms_version_cmd ();
    } else if (early == 0) {
        dms_usage ();
        rc = EXECUTION_SUCCESS;
    } else if (o.npos == 0) {
        dms_usage ();
        rc = EXECUTION_FAILURE;
    } else {
        rc = dms_dispatch (&o);
        if (rc != EXECUTION_SUCCESS) fputs ("Command failed.\n", stderr);
    }
    free (o.pos);
    return sh_chkwrite (rc);
}

char *dmsetup_doc[] = {
    "Low-level device-mapper control.",
    "",
    "    dmsetup ls|info|table|status|deps|targets|version [ARGS...]",
    "    dmsetup create|load|reload|remove|remove_all|suspend|resume|rename|message|clear|wipe_table ...",
    "",
    "Speaks the DM ioctl ABI on /dev/mapper/control directly. Tables come from",
    "--table, a table file or stdin (one \"start length type params\" per line).",
    "Mutating commands require root and BASHOS_DMSETUP_ALLOW_MUTATE=1.",
    (char *) NULL
};

struct builtin dmsetup_struct = {
    "dmsetup",
    dmsetup_builtin,
    BUILTIN_ENABLED,
    dmsetup_doc,
    "dmsetup COMMAND [ARGS...]",
    0
};
