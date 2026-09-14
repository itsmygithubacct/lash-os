/* bashfree.c — free(1) via /proc/meminfo.
 *
 *   bashfree [-h] [-V] [--si] [-b] [-k] [-m] [-g] [-t] [-w] [-L] [-s SECONDS] [-c COUNT]
 *
 *   -h   human-readable (auto-scale to k/M/G)
 *   -V   print version and exit
 *   --si use powers of 1000 instead of 1024
 *   -b   bytes
 *   -k   kibibytes (default)
 *   -m   mebibytes
 *   -g   gibibytes
 *   -t   show total memory + swap line
 *   -w   wide output with separate buffers/cache columns
 *   -L   line output: SwapUse/CachUse/MemUse/MemFree (procps free)
 *   -s   repeat printing every SECONDS seconds
 *   -c   repeat printing COUNT times
 *
 * Output mirrors free(1):
 *               total       used       free     shared  buff/cache  available
 *   Mem:        ...
 *   Swap:       ...
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

#include "loadables.h"

typedef enum { BF_K, BF_B, BF_M, BF_G } bf_unit;

typedef struct {
    long total, free, available, buffers, cached, shared, sreclaimable;
    long swap_total, swap_free;
} bf_meminfo;

static const char *
bf_proc_path (const char *name, char *buf, size_t bufsz)
{
    const char *root = getenv ("BASHOS_PROC_ROOT");

    if (root && *root) {
        snprintf (buf, bufsz, "%s/%s", root, name);
        return buf;
    }
    snprintf (buf, bufsz, "/proc/%s", name);
    return buf;
}

static int
bf_read_meminfo (bf_meminfo *m)
{
    char path[512];
    int fd = open (bf_proc_path ("meminfo", path, sizeof path), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char buf[8192];
    ssize_t n = read (fd, buf, sizeof buf - 1);
    close (fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    /* Each line: "Name:     1234 kB". Values are KiB. */
    struct { const char *key; long *target; } map[] = {
        { "MemTotal:",     &m->total     },
        { "MemFree:",      &m->free      },
        { "MemAvailable:", &m->available },
        { "Buffers:",      &m->buffers   },
        { "Cached:",       &m->cached    },
        { "Shmem:",        &m->shared    },
        { "SReclaimable:",  &m->sreclaimable },
        { "SwapTotal:",    &m->swap_total },
        { "SwapFree:",     &m->swap_free  },
    };
    for (size_t i = 0; i < sizeof map / sizeof map[0]; i++) {
        char *p = strstr (buf, map[i].key);
        if (p) {
            p += strlen (map[i].key);
            *map[i].target = strtol (p, NULL, 10);
        }
    }
    return 0;
}

static void
bf_print_val (long kib, bf_unit u, int human, int si)
{
    double bytes;
    double scale;

    if (human) {
        const char *suf[] = { "B", "K", "M", "G", "T" };
        int i = 0;
        double v = (double) kib * 1024.0;
        scale = si ? 1000.0 : 1024.0;
        while (v >= scale && i < 4) { v /= scale; i++; }
        /* 11-char right-justified field (procps prints scale_size via %11s),
           so every column is a uniform 12 wide with its leading separator. */
        char hb[32];
        snprintf (hb, sizeof hb, "%.1f%s", v, suf[i]);
        printf ("%11s", hb);
        return;
    }

    bytes = (double) kib * 1024.0;
    switch (u) {
        case BF_B: printf ("%11ld", kib * 1024L); break;
        case BF_M:
            printf ("%11ld", si ? (long)(bytes / 1000000.0) : kib / 1024L);
            break;
        case BF_G:
            printf ("%11ld", si ? (long)(bytes / 1000000000.0) : kib / 1024L / 1024L);
            break;
        case BF_K:
        default:
            printf ("%11ld", si ? (long)(bytes / 1000.0) : kib);
            break;
    }
}

static int
bf_parse_count (const char *s, unsigned int *out)
{
    char *end = NULL;
    unsigned long v;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    v = strtoul (s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < 1 || v > UINT_MAX)
        return -1;

    *out = (unsigned int)v;
    return 0;
}

static int
bf_parse_seconds (const char *s, unsigned int *out)
{
    return bf_parse_count (s, out);
}

static int
bf_print_snapshot (bf_unit u, int human, int si, int total, int wide, int line)
{
    bf_meminfo m = { 0 };
    long used, cache, buff_cache, swap_used;

    if (bf_read_meminfo (&m) < 0) {
        builtin_error ("read /proc/meminfo: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    /* procps free(1) leaves Shmem inside buff/cache and the wide cache
       column: Buffers + Cached + SReclaimable. used stays MemTotal -
       MemAvailable when available is present. */
    cache = m.cached + m.sreclaimable;
    if (cache < 0)
        cache = 0;
    buff_cache = m.buffers + cache;
    if (buff_cache < 0)
        buff_cache = 0;
    used = m.available > 0 ? m.total - m.available
                            : m.total - m.free - buff_cache;
    swap_used = m.swap_total - m.swap_free;

    if (line) {
        /* Debian procps free(1) -L/--line prints four fixed labels and
           11-wide values on one row. Keep the leading space in " MemUse". */
        printf ("SwapUse "); bf_print_val (swap_used, u, human, si);
        printf (" CachUse "); bf_print_val (buff_cache, u, human, si);
        printf ("  MemUse "); bf_print_val (used, u, human, si);
        printf (" MemFree "); bf_print_val (m.free, u, human, si);
        putchar (' ');
        putchar ('\n');
        return EXECUTION_SUCCESS;
    }

    /* 15-space indent + 9-wide labels align the columns with the %11 values,
       matching procps free (label width HC_WIDTH=9, first %11, then " %11"). */
    if (wide)
        printf ("               total        used        free      shared     buffers       cache   available\n");
    else
        printf ("               total        used        free      shared  buff/cache   available\n");
    printf ("Mem:     "); bf_print_val (m.total, u, human, si);
    printf (" "); bf_print_val (used, u, human, si);
    printf (" "); bf_print_val (m.free, u, human, si);
    printf (" "); bf_print_val (m.shared, u, human, si);
    if (wide) {
        printf (" "); bf_print_val (m.buffers, u, human, si);
        printf (" "); bf_print_val (cache, u, human, si);
    } else {
        printf (" "); bf_print_val (buff_cache, u, human, si);
    }
    printf (" "); bf_print_val (m.available, u, human, si);
    putchar ('\n');

    printf ("Swap:    "); bf_print_val (m.swap_total, u, human, si);
    printf (" "); bf_print_val (swap_used, u, human, si);
    printf (" "); bf_print_val (m.swap_free, u, human, si);
    putchar ('\n');

    if (total) {
        printf ("Total:   "); bf_print_val (m.total + m.swap_total, u, human, si);
        printf (" "); bf_print_val (used + swap_used, u, human, si);
        printf (" "); bf_print_val (m.free + m.swap_free, u, human, si);
        putchar ('\n');
    }

    return EXECUTION_SUCCESS;
}

int
free_builtin (WORD_LIST *list)
{
    bf_unit u = BF_K;
    int human = 0;
    int si = 0;
    int total = 0;
    int wide = 0;
    int line = 0;
    int repeat = 0;
    int count_set = 0;
    unsigned int count = 1;
    unsigned int seconds = 1;
    while (list && list->word->word[0] == '-') {
        const char *w = list->word->word;
        if (!strcmp (w, "--help")) { builtin_usage (); return EXECUTION_SUCCESS; }
        else if (!strcmp (w, "--version")) {
            puts ("bashfree 1.0 (bash-loadable)");
            return EXECUTION_SUCCESS;
        }
        else if (!strcmp (w, "--si")) { si = 1; }
        else if (!strcmp (w, "--human")) { human = 1; }
        else if (!strcmp (w, "--bytes")) { u = BF_B; }
        else if (!strcmp (w, "--kibi")) { u = BF_K; }
        else if (!strcmp (w, "--mebi")) { u = BF_M; }
        else if (!strcmp (w, "--gibi")) { u = BF_G; }
        else if (!strcmp (w, "--total")) { total = 1; }
        else if (!strcmp (w, "--wide")) { wide = 1; }
        else if (!strcmp (w, "--line")) { line = 1; }
        else if (!strcmp (w, "-s") || !strcmp (w, "--seconds")) {
            if (list->next == NULL) {
                builtin_error ("%s requires seconds", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bf_parse_seconds (list->word->word, &seconds) < 0) {
                builtin_error ("invalid seconds: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            repeat = 1;
        }
        else if (!strcmp (w, "-c") || !strcmp (w, "--count")) {
            if (list->next == NULL) {
                builtin_error ("%s requires a count", w);
                builtin_usage ();
                return EX_USAGE;
            }
            list = list->next;
            if (bf_parse_count (list->word->word, &count) < 0) {
                builtin_error ("invalid count: %s", list->word->word);
                builtin_usage ();
                return EX_USAGE;
            }
            repeat = 1;
            count_set = 1;
        }
        else if (!strncmp (w, "-s", 2) && w[2] != '\0') {
            if (bf_parse_seconds (w + 2, &seconds) < 0) {
                builtin_error ("invalid seconds: %s", w + 2);
                builtin_usage ();
                return EX_USAGE;
            }
            repeat = 1;
        }
        else if (!strncmp (w, "--seconds=", 10)) {
            if (bf_parse_seconds (w + 10, &seconds) < 0) {
                builtin_error ("invalid seconds: %s", w + 10);
                builtin_usage ();
                return EX_USAGE;
            }
            repeat = 1;
        }
        else if (!strncmp (w, "-c", 2) && w[2] != '\0') {
            if (bf_parse_count (w + 2, &count) < 0) {
                builtin_error ("invalid count: %s", w + 2);
                builtin_usage ();
                return EX_USAGE;
            }
            repeat = 1;
            count_set = 1;
        }
        else if (!strncmp (w, "--count=", 8)) {
            if (bf_parse_count (w + 8, &count) < 0) {
                builtin_error ("invalid count: %s", w + 8);
                builtin_usage ();
                return EX_USAGE;
            }
            repeat = 1;
            count_set = 1;
        }
        else if (w[0] == '-' && w[1] != '-' && w[1] != '\0') {
            for (size_t i = 1; w[i] != '\0'; i++) {
                switch (w[i]) {
                    case 'h': human = 1; break;
                    case 'V':
                        puts ("bashfree 1.0 (bash-loadable)");
                        return EXECUTION_SUCCESS;
                    case 'b': u = BF_B; break;
                    case 'k': u = BF_K; break;
                    case 'm': u = BF_M; break;
                    case 'g': u = BF_G; break;
                    case 't': total = 1; break;
                    case 'w': wide = 1; break;
                    case 'L': line = 1; break;
                    case 's':
                        if (w[i + 1] != '\0') {
                            if (bf_parse_seconds (w + i + 1, &seconds) < 0) {
                                builtin_error ("invalid seconds: %s", w + i + 1);
                                builtin_usage ();
                                return EX_USAGE;
                            }
                        } else {
                            if (list->next == NULL) {
                                builtin_error ("-s requires seconds");
                                builtin_usage ();
                                return EX_USAGE;
                            }
                            list = list->next;
                            if (bf_parse_seconds (list->word->word, &seconds) < 0) {
                                builtin_error ("invalid seconds: %s", list->word->word);
                                builtin_usage ();
                                return EX_USAGE;
                            }
                        }
                        repeat = 1;
                        i = strlen (w) - 1;
                        break;
                    case 'c':
                        if (w[i + 1] != '\0') {
                            if (bf_parse_count (w + i + 1, &count) < 0) {
                                builtin_error ("invalid count: %s", w + i + 1);
                                builtin_usage ();
                                return EX_USAGE;
                            }
                        } else {
                            if (list->next == NULL) {
                                builtin_error ("-c requires a count");
                                builtin_usage ();
                                return EX_USAGE;
                            }
                            list = list->next;
                            if (bf_parse_count (list->word->word, &count) < 0) {
                                builtin_error ("invalid count: %s", list->word->word);
                                builtin_usage ();
                                return EX_USAGE;
                            }
                        }
                        repeat = 1;
                        count_set = 1;
                        i = strlen (w) - 1;
                        break;
                    default:
                        builtin_error ("unknown flag: -%c", w[i]);
                        builtin_usage ();
                        return EX_USAGE;
                }
            }
        }
        else {
            builtin_error ("unknown flag: %s", w);
            builtin_usage ();
            return EX_USAGE;
        }
        list = list->next;
    }

    if (list != NULL) {
        builtin_error ("unexpected operand: %s", list->word->word);
        builtin_usage ();
        return EX_USAGE;
    }

    for (unsigned int i = 0; ; i++) {
        int rc = bf_print_snapshot (u, human, si, total, wide, line);
        if (rc != EXECUTION_SUCCESS)
            return rc;
        if (count_set && i + 1 >= count)
            break;
        if (!repeat)
            break;
        putchar ('\n');
        fflush (stdout);
        sleep (seconds);
    }

    return EXECUTION_SUCCESS;
}

char *free_doc[] = {
    "Show memory usage from /proc/meminfo.",
    "",
    "    bashfree [-hbkmgVLtw] [--si] [--help|--version] [-s SECONDS|--seconds SECONDS] [-c COUNT|--count COUNT]",
    "",
    "    -h   human-readable (auto-scale K/M/G)",
    "    -V   print version and exit",
    "    --si use powers of 1000 instead of 1024",
    "    -b   bytes",
    "    -k   kibibytes (default)",
    "    -m   mebibytes",
    "    -g   gibibytes",
    "    -t   show total memory + swap line",
    "    -w   wide output with separate buffers/cache columns",
    "    -L   line output: SwapUse/CachUse/MemUse/MemFree",
    "    -s   repeat printing every SECONDS seconds",
    "    -c   repeat printing COUNT times",
    "",
    "Output: Mem (total / used / free / shared / buff_cache / available),",
    "Swap (total / used / free), and optional Total with -t.",
    (char *)NULL
};

struct builtin bashfree_struct = {
    "bashfree",
    free_builtin,
    BUILTIN_ENABLED,
    free_doc,
    "bashfree [-hbkmgVLtw] [--si] [--help|--version] [-s SECONDS|--seconds SECONDS] [-c COUNT|--count COUNT]",
    0
};
