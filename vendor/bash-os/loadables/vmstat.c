/* SPDX-License-Identifier: MIT */
/* vmstat.c — procps-ng vmstat(8)-compatible reader for /proc.
 *
 *   vmstat [-a] [-f] [-s] [-t] [-n] [-w|--wide] [-S UNIT]
 *              [-h|--help|-V|--version] [DELAY [COUNT]]
 *
 *   bare         header + one snapshot row (since-boot averages, like vmstat)
 *   -a           report active/inactive memory instead of buff/cache
 *   -f           number of forks since boot (one line), then exit
 *   -s           event-counter statistics block (vmstat -s)
 *   -t           append a timestamp column
 *   -n           print the header only once (for COUNT>1)
 *   -w, --wide   wide output columns
 *   -S UNIT      memory display unit: k (1000), K (1024, default),
 *                m (1000000), M (1048576)
 *   DELAY COUNT  sampling interval / number of samples
 *
 * Column model + widths, header strings, the -s label set and the
 * %13-wide stat format all mirror procps-ng src/vmstat.c (4.0.x) so the
 * structure is byte-identical. The numeric values are computed the same
 * way procps does (since-boot for the first row, deltas/DELAY after) but
 * cannot be byte-compared against a live host vmstat (the counters move
 * between invocations).
 *
 * Disk/slab tables:
 *   -d/--disk       per-device /proc/diskstats table
 *   -D/--disk-sum   aggregate /proc/diskstats counters
 *   -p/--partition  counters for one device/partition
 *   -m/--slabs      /proc/slabinfo table
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
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
#include <limits.h>
#include <time.h>

#include "loadables.h"
#include "_bl_proc_slabinfo.h"

/* --- unit scaling (procps: cvSize = size_KB * 1024 / dataUnit) --------- */
#define BV_UNIT_k 1000UL
#define BV_UNIT_K 1024UL
#define BV_UNIT_m 1000000UL
#define BV_UNIT_M 1048576UL

static unsigned long bv_data_unit = BV_UNIT_K;
static char bv_unit_str[3] = "K";

static unsigned long
bv_unit_convert (unsigned long kib)
{
    /* meminfo values arrive in KiB; convert to bytes then to the unit. */
    double v = (double) kib * 1024.0 / (double) bv_data_unit;
    return (unsigned long) v;
}

/* --- /proc plumbing ---------------------------------------------------- */

static const char *
bv_proc_path (const char *name, char *buf, size_t bufsz)
{
    const char *root = getenv ("BASHOS_PROC_ROOT");
    if (root && *root) { snprintf (buf, bufsz, "%s/%s", root, name); return buf; }
    snprintf (buf, bufsz, "/proc/%s", name);
    return buf;
}

static int
bv_read_file (const char *path, char *out, size_t cap)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read (fd, out, cap - 1);
    close (fd);
    if (n < 0) return -1;
    out[n] = '\0';
    return (int) n;
}

typedef struct {
    /* /proc/stat cpu line */
    long long user, nice, system, idle, iowait, irq, softirq, steal,
              guest, guest_nice;
    long long intr, ctxt, btime, procs;     /* btime/procs are not rates */
    int running, blocked;
    /* /proc/vmstat */
    long long pgpgin, pgpgout, pswpin, pswpout;
} bv_sample;

static long long
bv_vmstat_field (const char *vm, const char *key)
{
    /* key like "pgpgin "; match at line start. */
    size_t klen = strlen (key);
    const char *p = vm;
    while (p && *p) {
        if (strncmp (p, key, klen) == 0)
            return strtoll (p + klen, NULL, 10);
        p = strchr (p, '\n');
        if (p) p++;
    }
    return 0;
}

static int
bv_read_sample (bv_sample *s)
{
    char buf[16384], path[512], *p;
    memset (s, 0, sizeof *s);

    if (bv_read_file (bv_proc_path ("stat", path, sizeof path), buf, sizeof buf) < 0)
        return -1;
    if ((p = strstr (buf, "cpu ")) != NULL)
        sscanf (p, "cpu %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
                &s->user, &s->nice, &s->system, &s->idle, &s->iowait,
                &s->irq, &s->softirq, &s->steal, &s->guest, &s->guest_nice);
    if ((p = strstr (buf, "\nintr ")) != NULL)  sscanf (p + 1, "intr %lld", &s->intr);
    if ((p = strstr (buf, "\nctxt ")) != NULL)  sscanf (p + 1, "ctxt %lld", &s->ctxt);
    if ((p = strstr (buf, "\nbtime ")) != NULL) sscanf (p + 1, "btime %lld", &s->btime);
    if ((p = strstr (buf, "\nprocesses ")) != NULL) sscanf (p + 1, "processes %lld", &s->procs);
    if ((p = strstr (buf, "\nprocs_running ")) != NULL) sscanf (p + 1, "procs_running %d", &s->running);
    if ((p = strstr (buf, "\nprocs_blocked ")) != NULL) sscanf (p + 1, "procs_blocked %d", &s->blocked);

    char vm[32768];
    if (bv_read_file (bv_proc_path ("vmstat", path, sizeof path), vm, sizeof vm) >= 0) {
        s->pgpgin  = bv_vmstat_field (vm, "pgpgin ");
        s->pgpgout = bv_vmstat_field (vm, "pgpgout ");
        s->pswpin  = bv_vmstat_field (vm, "pswpin ");
        s->pswpout = bv_vmstat_field (vm, "pswpout ");
    }
    return 0;
}

static long
bv_meminfo (const char *buf, const char *key)
{
    const char *p = strstr (buf, key);
    if (!p) return 0;
    return strtol (p + strlen (key), NULL, 10);
}

/* --- the procps field table (header names + normal/wide widths) -------- */

struct bv_field { const char *header; int width, wide_width; };
static struct bv_field bv_fields[] = {
    { "r",     2,  4 }, { "b",     2,  4 },
    { "swpd",  6, 12 }, { "free",  6, 12 },
    { "buff",  6, 12 }, { "cache", 6, 12 },   /* -a: "inact"/"active" */
    { "si",    4,  4 }, { "so",    4,  4 },
    { "bi",    5,  5 }, { "bo",    5,  5 },
    { "in",    4,  4 }, { "cs",    4,  4 },
    { "us",    2,  3 }, { "sy",    2,  3 },
    { "id",    2,  3 }, { "wa",    2,  3 },
    { "st",    2,  3 }, { "gu",    2,  3 },
    { NULL,    0,  0 }
};
#define BV_NFIELDS 18

static const char *bv_hdr1_normal =
  "procs -----------memory---------- ---swap-- -----io---- -system-- -------cpu-------";
static const char *bv_hdr1_wide =
  "--procs-- -----------------------memory---------------------- ---swap-- -----io---- -system-- ----------cpu----------";
static const char *bv_ts_header = " -----timestamp-----";

static void
bv_print_header (int wide, int a_option, int t_option)
{
    if (a_option) { bv_fields[4].header = "inact"; bv_fields[5].header = "active"; }
    else          { bv_fields[4].header = "buff";  bv_fields[5].header = "cache";  }

    printf ("%s", wide ? bv_hdr1_wide : bv_hdr1_normal);
    if (t_option) printf ("%s", bv_ts_header);
    printf ("\n");

    for (struct bv_field *f = bv_fields; f->header; f++) {
        printf ("%*s", wide ? f->wide_width : f->width, f->header);
        if (f[1].header) printf (" ");
    }
    if (t_option) {
        /* header2 timestamp slot: the locale %Z right-aligned to the
           timestamp_header width (minus its leading space). */
        char tz[64] = "";
        time_t now = time (NULL);
        struct tm *tm = localtime (&now);
        if (tm) strftime (tz, sizeof tz, "%Z", tm);
        printf (" %*s", (int) (strlen (bv_ts_header) - 1), tz);
    }
    printf ("\n");
}

static void
bv_print_row (const unsigned long v[BV_NFIELDS], int wide, int t_option)
{
    for (int i = 0; i < BV_NFIELDS; i++) {
        struct bv_field *f = &bv_fields[i];
        printf ("%*lu", wide ? f->wide_width : f->width, v[i]);
        if (i + 1 < BV_NFIELDS) printf (" ");
    }
    if (t_option) {
        char ts[64] = "";
        time_t now = time (NULL);
        struct tm *tm = localtime (&now);
        if (tm) strftime (ts, sizeof ts, "%Y-%m-%d %H:%M:%S", tm);
        printf (" %s", ts);
    }
    printf ("\n");
    fflush (stdout);
}

/* Compute the 18 column values for one row. PREV==CUR (or delay==0) means
   the first since-boot row: rates are total/uptime. */
static void
bv_compute (const bv_sample *prev, const bv_sample *cur, long delay,
            int a_option, unsigned long v[BV_NFIELDS])
{
    char buf[16384], path[512];
    bv_read_file (bv_proc_path ("meminfo", path, sizeof path), buf, sizeof buf);
    long memfree = bv_meminfo (buf, "MemFree:");
    long buffers = bv_meminfo (buf, "Buffers:");
    long cached  = bv_meminfo (buf, "Cached:");
    long active  = bv_meminfo (buf, "Active:");
    long inactive = bv_meminfo (buf, "Inactive:");
    long swptot  = bv_meminfo (buf, "SwapTotal:");
    long swpfree = bv_meminfo (buf, "SwapFree:");

    int first = (prev == cur);
    /* procps: the first row reports since-boot AVERAGES, i.e. counters
       divided by seconds-since-boot (uptime), not the raw totals. */
    long div;
    if (first) {
        char ub[128], upath[512];
        double up = 0;
        if (bv_read_file (bv_proc_path ("uptime", upath, sizeof upath), ub, sizeof ub) > 0)
            up = strtod (ub, NULL);
        div = (up >= 1.0) ? (long) up : 1;
    } else {
        div = (delay > 0 ? delay : 1);
    }

    long long du = cur->user - (first ? 0 : prev->user);
    long long dn = cur->nice - (first ? 0 : prev->nice);
    long long dsy = cur->system - (first ? 0 : prev->system);
    long long did = cur->idle - (first ? 0 : prev->idle);
    long long dwa = cur->iowait - (first ? 0 : prev->iowait);
    long long dirq = cur->irq - (first ? 0 : prev->irq);
    long long dsrq = cur->softirq - (first ? 0 : prev->softirq);
    long long dst = cur->steal - (first ? 0 : prev->steal);
    long long dgu = (cur->guest + cur->guest_nice)
                    - (first ? 0 : (prev->guest + prev->guest_nice));
    long long tot = du + dn + dsy + did + dwa + dirq + dsrq + dst + dgu;
    if (tot <= 0) tot = 1;
    /* procps cpu split: us=user+nice, sy=system+irq+softirq. Round to %. */
    #define PCT(x) ((unsigned long) (((x) * 100 + tot / 2) / tot))
    unsigned long us = PCT (du + dn);
    unsigned long sy = PCT (dsy + dirq + dsrq);
    unsigned long id = PCT (did);
    unsigned long wa = PCT (dwa);
    unsigned long st = PCT (dst);
    unsigned long gu = PCT (dgu);
    #undef PCT

    long long si = (cur->pswpin  - (first ? 0 : prev->pswpin))  / div;
    long long so = (cur->pswpout - (first ? 0 : prev->pswpout)) / div;
    long long bi = (cur->pgpgin  - (first ? 0 : prev->pgpgin))  / div;
    long long bo = (cur->pgpgout - (first ? 0 : prev->pgpgout)) / div;
    long long in = (cur->intr - (first ? 0 : prev->intr)) / div;
    long long cs = (cur->ctxt - (first ? 0 : prev->ctxt)) / div;

    v[0] = (unsigned long) cur->running;
    v[1] = (unsigned long) cur->blocked;
    v[2] = bv_unit_convert ((unsigned long) (swptot - swpfree));
    v[3] = bv_unit_convert ((unsigned long) memfree);
    v[4] = a_option ? bv_unit_convert ((unsigned long) inactive)
                    : bv_unit_convert ((unsigned long) buffers);
    v[5] = a_option ? bv_unit_convert ((unsigned long) active)
                    : bv_unit_convert ((unsigned long) cached);
    v[6]  = (unsigned long) si; v[7]  = (unsigned long) so;
    v[8]  = (unsigned long) bi; v[9]  = (unsigned long) bo;
    v[10] = (unsigned long) in; v[11] = (unsigned long) cs;
    v[12] = us; v[13] = sy; v[14] = id; v[15] = wa; v[16] = st; v[17] = gu;
}

/* -s : event-counter statistics block (procps sum_format). */
static int
bv_print_summary (void)
{
    char buf[16384], path[512];
    bv_sample s;
    bv_read_sample (&s);
    if (bv_read_file (bv_proc_path ("meminfo", path, sizeof path), buf, sizeof buf) < 0) {
        builtin_error ("read /proc/meminfo: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    long mtot = bv_meminfo (buf, "MemTotal:");
    long mfree = bv_meminfo (buf, "MemFree:");
    long mact = bv_meminfo (buf, "Active:");
    long miac = bv_meminfo (buf, "Inactive:");
    long mbuf = bv_meminfo (buf, "Buffers:");
    long mcac = bv_meminfo (buf, "Cached:");   /* procps "swap cache" == Cached */
    long stot = bv_meminfo (buf, "SwapTotal:");
    long sfree = bv_meminfo (buf, "SwapFree:");

    #define U(k) bv_unit_convert ((unsigned long)(k))
    printf ("%13lu %s total memory\n",    U (mtot), bv_unit_str);
    printf ("%13lu %s used memory\n",     U (mtot - mfree), bv_unit_str);
    printf ("%13lu %s active memory\n",   U (mact), bv_unit_str);
    printf ("%13lu %s inactive memory\n", U (miac), bv_unit_str);
    printf ("%13lu %s free memory\n",     U (mfree), bv_unit_str);
    printf ("%13lu %s buffer memory\n",   U (mbuf), bv_unit_str);
    printf ("%13lu %s swap cache\n",      U (mcac), bv_unit_str);
    printf ("%13lu %s total swap\n",      U (stot), bv_unit_str);
    printf ("%13lu %s used swap\n",       U (stot - sfree), bv_unit_str);
    printf ("%13lu %s free swap\n",       U (sfree), bv_unit_str);
    #undef U
    printf ("%13lld non-nice user cpu ticks\n", s.user - s.guest);
    printf ("%13lld nice user cpu ticks\n",     s.nice - s.guest_nice);
    printf ("%13lld system cpu ticks\n",        s.system);
    printf ("%13lld idle cpu ticks\n",          s.idle);
    printf ("%13lld IO-wait cpu ticks\n",       s.iowait);
    printf ("%13lld IRQ cpu ticks\n",           s.irq);
    printf ("%13lld softirq cpu ticks\n",       s.softirq);
    printf ("%13lld stolen cpu ticks\n",        s.steal);
    printf ("%13lld non-nice guest cpu ticks\n", s.guest);
    printf ("%13lld nice guest cpu ticks\n",     s.guest_nice);
    printf ("%13lld K paged in\n",   s.pgpgin);
    printf ("%13lld K paged out\n",  s.pgpgout);
    printf ("%13lld pages swapped in\n",  s.pswpin);
    printf ("%13lld pages swapped out\n", s.pswpout);
    printf ("%13lld interrupts\n",          s.intr);
    printf ("%13lld CPU context switches\n", s.ctxt);
    printf ("%13lld boot time\n",            s.btime);
    printf ("%13lld forks\n",                s.procs);
    return EXECUTION_SUCCESS;
}

static int
bv_parse_nonnegative_long (const char *s, long *out)
{
    char *end = NULL;
    long v;
    if (s == NULL || *s == '\0') return -1;
    errno = 0;
    v = strtol (s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0' || v < 0) return -1;
    *out = v;
    return 0;
}

static int
bv_set_unit (const char *u)
{
    if (!u) return -1;
    if (!strcmp (u, "k")) { bv_data_unit = BV_UNIT_k; strcpy (bv_unit_str, "k"); return 0; }
    if (!strcmp (u, "K")) { bv_data_unit = BV_UNIT_K; strcpy (bv_unit_str, "K"); return 0; }
    if (!strcmp (u, "m")) { bv_data_unit = BV_UNIT_m; strcpy (bv_unit_str, "m"); return 0; }
    if (!strcmp (u, "M")) { bv_data_unit = BV_UNIT_M; strcpy (bv_unit_str, "M"); return 0; }
    return -1;
}

typedef struct {
    int major, minor;
    char name[64];
    unsigned long long reads, read_merged, read_sectors, read_ms;
    unsigned long long writes, write_merged, write_sectors, write_ms;
    unsigned long long ios_current, io_ms, weighted_io_ms;
} bv_diskstat;

static int
bv_parse_diskstat_line (const char *line, bv_diskstat *d)
{
    memset (d, 0, sizeof *d);
    return sscanf (line, " %d %d %63s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                   &d->major, &d->minor, d->name,
                   &d->reads, &d->read_merged, &d->read_sectors, &d->read_ms,
                   &d->writes, &d->write_merged, &d->write_sectors, &d->write_ms,
                   &d->ios_current, &d->io_ms, &d->weighted_io_ms) >= 14;
}

static void
bv_print_disk_header (void)
{
    puts ("disk- ------------reads------------ ------------writes----------- -----IO------");
    puts ("disk          total merged sectors      ms  total merged sectors      ms    cur    sec");
}

static void
bv_print_disk_row (const bv_diskstat *d)
{
    printf ("%-10s %8llu %6llu %7llu %7llu %6llu %6llu %7llu %7llu %6llu %6llu\n",
            d->name,
            d->reads, d->read_merged, d->read_sectors, d->read_ms,
            d->writes, d->write_merged, d->write_sectors, d->write_ms,
            d->ios_current, d->io_ms / 1000);
}

static int
bv_print_diskstats (int summary, const char *partition)
{
    char path[512], line[1024];
    FILE *fp = fopen (bv_proc_path ("diskstats", path, sizeof path), "re");
    unsigned long long disks = 0, reads = 0, read_merged = 0, read_sectors = 0, read_ms = 0;
    unsigned long long writes = 0, write_merged = 0, write_sectors = 0, write_ms = 0;
    unsigned long long io_ms = 0, weighted_io_ms = 0;
    int found = 0;

    if (!fp) {
        builtin_error ("read /proc/diskstats: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    if (!summary)
        bv_print_disk_header ();

    while (fgets (line, sizeof line, fp)) {
        bv_diskstat d;
        if (!bv_parse_diskstat_line (line, &d))
            continue;
        if (partition && strcmp (d.name, partition) != 0)
            continue;

        found = 1;
        disks++;
        reads += d.reads;
        read_merged += d.read_merged;
        read_sectors += d.read_sectors;
        read_ms += d.read_ms;
        writes += d.writes;
        write_merged += d.write_merged;
        write_sectors += d.write_sectors;
        write_ms += d.write_ms;
        io_ms += d.io_ms;
        weighted_io_ms += d.weighted_io_ms;

        if (!summary)
            bv_print_disk_row (&d);
    }
    fclose (fp);

    if (partition && !found) {
        builtin_error ("%s: partition not found", partition);
        return EXECUTION_FAILURE;
    }

    if (summary) {
        printf ("%13llu disks\n", disks);
        printf ("%13llu total reads\n", reads);
        printf ("%13llu merged reads\n", read_merged);
        printf ("%13llu read sectors\n", read_sectors);
        printf ("%13llu milliseconds reading\n", read_ms);
        printf ("%13llu total writes\n", writes);
        printf ("%13llu merged writes\n", write_merged);
        printf ("%13llu written sectors\n", write_sectors);
        printf ("%13llu milliseconds writing\n", write_ms);
        printf ("%13llu milliseconds doing I/O\n", io_ms);
        printf ("%13llu weighted milliseconds doing I/O\n", weighted_io_ms);
    }

    return EXECUTION_SUCCESS;
}

static int
bv_print_slabs (void)
{
    blp_slabinfo slabs;
    int errnum = 0;
    int rc = blp_read_slabinfo (&slabs, &errnum);

    if (rc < 0) {
        builtin_error ("read /proc/slabinfo: %s", strerror (errnum ? errnum : errno));
        return EXECUTION_FAILURE;
    }
    if (rc > 0) {
        builtin_error ("no slabinfo entries parsed");
        return EXECUTION_FAILURE;
    }

    printf ("%-32s %12s %12s %8s %8s %8s\n",
            "Cache", "Num", "Total", "Size", "Objs", "Pages");
    for (size_t i = 0; i < slabs.len; i++) {
        const blp_slabinfo_row *row = &slabs.rows[i];
        printf ("%-32s %12llu %12llu %8llu %8llu %8llu\n",
                row->name, row->active_objs, row->num_objs, row->obj_size,
                row->objs_per_slab, row->pages_per_slab);
    }
    blp_free_slabinfo (&slabs);
    return EXECUTION_SUCCESS;
}

int
vmstat_builtin (WORD_LIST *list)
{
    int summary = 0, wide = 0, a_option = 0, f_option = 0, t_option = 0,
        one_header = 0, table_mode = 0;
    const char *partition = NULL;
    long delay = 0, count = 1;

    /* reset module-level unit state for a fresh invocation */
    bv_data_unit = BV_UNIT_K; strcpy (bv_unit_str, "K");

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-V") || !strcmp (w, "--version")) { puts ("vmstat 2.0 (bash-loadable, procps-shape)"); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-s") || !strcmp (w, "--stats")) { summary = 1; list = list->next; continue; }
        if (!strcmp (w, "-w") || !strcmp (w, "--wide")) { wide = 1; list = list->next; continue; }
        if (!strcmp (w, "-a") || !strcmp (w, "--active")) { a_option = 1; list = list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--forks")) { f_option = 1; list = list->next; continue; }
        if (!strcmp (w, "-t") || !strcmp (w, "--timestamp")) { t_option = 1; list = list->next; continue; }
        if (!strcmp (w, "-n") || !strcmp (w, "--one-header")) { one_header = 1; list = list->next; continue; }
        if (!strcmp (w, "-S") || !strcmp (w, "--unit")) {
            list = list->next;
            if (!list || bv_set_unit (list->word->word) < 0) {
                builtin_error ("-S: unit must be one of k, K, m, M");
                builtin_usage (); return EX_USAGE;
            }
            list = list->next; continue;
        }
        if (!strncmp (w, "--unit=", 7)) {
            if (bv_set_unit (w + 7) < 0) { builtin_error ("-S: unit must be one of k, K, m, M"); builtin_usage (); return EX_USAGE; }
            list = list->next; continue;
        }
        if (!strcmp (w, "-d") || !strcmp (w, "--disk")) {
            if (table_mode && table_mode != 1) { builtin_error ("%s: conflicting table mode", w); return EX_USAGE; }
            table_mode = 1; list = list->next; continue;
        }
        if (!strcmp (w, "-D") || !strcmp (w, "--disk-sum")) {
            if (table_mode && table_mode != 2) { builtin_error ("%s: conflicting table mode", w); return EX_USAGE; }
            table_mode = 2; list = list->next; continue;
        }
        if (!strcmp (w, "-p") || !strcmp (w, "--partition")) {
            if (table_mode && table_mode != 3) { builtin_error ("%s: conflicting table mode", w); return EX_USAGE; }
            list = list->next;
            if (!list) { builtin_error ("%s: requires a device or partition name", w); builtin_usage (); return EX_USAGE; }
            partition = list->word->word;
            table_mode = 3; list = list->next; continue;
        }
        if (!strncmp (w, "--partition=", 12)) {
            if (table_mode && table_mode != 3) { builtin_error ("%s: conflicting table mode", w); return EX_USAGE; }
            if (w[12] == '\0') { builtin_error ("--partition: requires a device or partition name"); builtin_usage (); return EX_USAGE; }
            partition = w + 12;
            table_mode = 3; list = list->next; continue;
        }
        if (!strcmp (w, "-m") || !strcmp (w, "--slabs")) {
            if (table_mode && table_mode != 4) { builtin_error ("%s: conflicting table mode", w); return EX_USAGE; }
            table_mode = 4; list = list->next; continue;
        }
        builtin_error ("unknown flag: %s", w);
        builtin_usage ();
        return EX_USAGE;
    }

    if (table_mode) {
        if (summary || f_option) {
            builtin_error ("disk/slab table modes cannot be combined with -s or -f");
            builtin_usage ();
            return EX_USAGE;
        }
        if (list) { builtin_error ("unexpected operand: %s", list->word->word); builtin_usage (); return EX_USAGE; }
        if (table_mode == 2) return bv_print_diskstats (1, NULL);
        if (table_mode == 3) return bv_print_diskstats (0, partition);
        if (table_mode == 4) return bv_print_slabs ();
        return bv_print_diskstats (0, NULL);
    }

    if (f_option) {
        bv_sample s; bv_read_sample (&s);
        printf ("%13lld forks\n", s.procs);
        return EXECUTION_SUCCESS;
    }
    if (summary) {
        if (list) { builtin_error ("unexpected operand: %s", list->word->word); builtin_usage (); return EX_USAGE; }
        return bv_print_summary ();
    }

    if (list) {
        if (bv_parse_nonnegative_long (list->word->word, &delay) < 0) {
            builtin_error ("invalid delay: %s", list->word->word); builtin_usage (); return EX_USAGE;
        }
        list = list->next;
    }
    if (list) {
        if (bv_parse_nonnegative_long (list->word->word, &count) < 0 || count == 0) {
            builtin_error ("invalid count: %s", list->word->word); builtin_usage (); return EX_USAGE;
        }
        list = list->next;
    }
    if (list) { builtin_error ("unexpected operand: %s", list->word->word); builtin_usage (); return EX_USAGE; }
    if (delay > 0 && count == 1) count = (long) 0x7fffffff;  /* DELAY w/o COUNT loops */

    bv_sample prev;
    bv_read_sample (&prev);
    bv_print_header (wide, a_option, t_option);

    unsigned long v[BV_NFIELDS];
    bv_compute (&prev, &prev, 1, a_option, v);   /* first row: since boot */
    bv_print_row (v, wide, t_option);

    for (long i = 1; i < count; i++) {
        if (delay > 0) sleep ((unsigned) delay);
        bv_sample cur; bv_read_sample (&cur);
        if (!one_header && (i % 22) == 0) bv_print_header (wide, a_option, t_option);
        bv_compute (&prev, &cur, delay, a_option, v);
        bv_print_row (v, wide, t_option);
        prev = cur;
    }
    return EXECUTION_SUCCESS;
}

char *vmstat_doc[] = {
    "Report virtual-memory statistics (procps vmstat shape).",
    "",
    "    vmstat [-a] [-f] [-s] [-t] [-n] [-w] [-S UNIT] [DELAY [COUNT]]",
    "",
    "    -a, --active      active/inactive memory instead of buff/cache",
    "    -f, --forks       number of forks since boot, then exit",
    "    -s, --stats       event-counter statistics block",
    "    -t, --timestamp   append a timestamp column",
    "    -n, --one-header  display the header only once",
    "    -w, --wide        wide output columns",
    "    -S, --unit UNIT   memory unit: k 1000, K 1024, m 1000000, M 1048576",
    "    -d, --disk        diskstats table",
    "    -D, --disk-sum    aggregate diskstats counters",
    "    -p, --partition D diskstats row for one device/partition",
    "    -m, --slabs       slabinfo table",
    "    -h, --help / -V, --version",
    "",
    "Columns: procs r/b, memory swpd/free/(buff|inact)/(cache|active),",
    "swap si/so, io bi/bo, system in/cs, cpu us/sy/id/wa/st/gu.",
    "First row is since-boot; later rows are deltas over DELAY seconds.",
    "Disk/slab modes read /proc/diskstats and /proc/slabinfo.",
    (char *)NULL
};

struct builtin vmstat_struct = {
    "vmstat",
    vmstat_builtin,
    BUILTIN_ENABLED,
    vmstat_doc,
    "vmstat [-afstnw] [-S UNIT] [-d|-D|-p DEV|-m] [DELAY [COUNT]]",
    0
};
