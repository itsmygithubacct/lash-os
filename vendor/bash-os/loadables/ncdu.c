/* SPDX-License-Identifier: MIT */
/* ncdu.c — ncurses-free disk usage analyzer (ncdu-style) for bash-os.
 *
 *   ncdu [OPTION]... [PATH]
 *
 * Scans PATH (default '.') recursively, aggregating disk usage up the tree,
 * then presents an interactive full-screen browser — or, in batch mode, a
 * deterministic du-compatible listing suitable for scripting and tests.
 *
 * bash-os ships no ncurses (it is not linkable in the static-musl build), so
 * the full-screen browser is built on the shared _bl_screen module — an
 * ncurses-subset cell/window model with a diff-optimized refresh (only the
 * changed cells are emitted) and 24-bit truecolor — plus _bl_key for input.
 * Scan/aggregation semantics follow GNU du (and ncdu): disk usage =
 * st_blocks*512, apparent = st_size, hardlinks (st_nlink>1) counted once.
 *
 * Modes:
 *   (default, on a tty)   interactive browser
 *   --print  / -p         du-compatible listing: "<bytes>\t<path>" per dir,
 *                         post-order; the operand line carries the grand total
 *   --total  / -t         print the single aggregated byte count of PATH
 *   (non-tty stdout falls back to --print)
 *
 * Options:
 *   -a, --apparent-size   report apparent size (st_size) instead of disk usage
 *   -x, --one-file-system stay on the starting filesystem
 *   -p, --print           batch du-compatible listing (see above)
 *   -t, --total           batch grand-total only
 *   -h, --help            help; -V, --version
 *
 * Interactive keys:
 *   Up/Down       move selection            Right/Enter   descend into dir
 *   Left          ascend to parent          PgUp/PgDn     page
 *   Home/End      first / last              s             sort by size (default)
 *   n             sort by name              a             toggle apparent/disk
 *   q / ESC       quit
 *
 * Reference consulted (none ported verbatim): research/refs/ncdu/src/
 *   (dir_scan.c, dirlist.c, browser.c, util.c) and GNU coreutils du.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as top.c. When statically linked into
 * bash, the combined binary is governed by bash's GPL-3+.
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
#include <sys/stat.h>
#include <stdint.h>

#include "_bl_screen_screen.h"   /* ncurses-subset cell/diff TUI engine */
#include "_bl_key_bl_key.h"      /* BL_KEY_* codes returned by bls_getch */
#include "loadables.h"

/* --- options ------------------------------------------------------------ */
typedef struct {
    int apparent;     /* report st_size instead of st_blocks*512 */
    int one_fs;       /* -x: stay on the starting device */
} ndu_opt;

/* --- tree node ---------------------------------------------------------- */
typedef struct ndu_node {
    char    *name;
    off_t    disk;    /* aggregated disk bytes (st_blocks*512), deduped */
    off_t    asize;   /* aggregated apparent bytes (st_size), deduped */
    long     items;   /* count of descendant entries (excl. self) */
    int      is_dir;
    int      err;     /* could not read this directory */
    dev_t    dev;
    ino_t    ino;
    struct ndu_node  *parent;
    struct ndu_node **child;
    int      nchild, cap;
} ndu_node;

/* report value for a node, honoring --apparent-size */
static off_t
ndu_val (const ndu_node *n, const ndu_opt *o)
{
    return o->apparent ? n->asize : n->disk;
}

/* --- hardlink dedup set: open-addressing hash over (dev,ino) ------------ */
typedef struct { dev_t dev; ino_t ino; int used; } hlslot;
typedef struct { hlslot *s; size_t cap, n; } hlset;

static uint64_t
hl_hash (dev_t dev, ino_t ino)
{
    uint64_t h = (uint64_t) ino * 1099511628211ull;
    h ^= (uint64_t) dev + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
    return h ? h : 1;
}

/* Returns 1 if (dev,ino) was already present (caller should dedup), else
   inserts it and returns 0. On allocation failure returns 0 (no dedup). */
static int
hl_seen (hlset *t, dev_t dev, ino_t ino)
{
    if (t->cap == 0 || t->n * 10 >= t->cap * 7) {
        size_t ncap = t->cap ? t->cap * 2 : 256;
        hlslot *ns = (hlslot *) calloc (ncap, sizeof *ns);
        if (!ns) return 0;
        for (size_t i = 0; i < t->cap; i++) {
            if (!t->s[i].used) continue;
            uint64_t h = hl_hash (t->s[i].dev, t->s[i].ino) & (ncap - 1);
            while (ns[h].used) h = (h + 1) & (ncap - 1);
            ns[h] = t->s[i];
        }
        free (t->s); t->s = ns; t->cap = ncap;
    }
    uint64_t h = hl_hash (dev, ino) & (t->cap - 1);
    while (t->s[h].used) {
        if (t->s[h].dev == dev && t->s[h].ino == ino) return 1;
        h = (h + 1) & (t->cap - 1);
    }
    t->s[h].used = 1; t->s[h].dev = dev; t->s[h].ino = ino; t->n++;
    return 0;
}

/* --- node helpers ------------------------------------------------------- */
static ndu_node *
ndu_new (const char *name)
{
    ndu_node *n = (ndu_node *) calloc (1, sizeof *n);
    if (!n) return NULL;
    n->name = strdup (name ? name : "");
    if (!n->name) { free (n); return NULL; }
    return n;
}

static void
ndu_free (ndu_node *n)
{
    if (!n) return;
    for (int i = 0; i < n->nchild; i++) ndu_free (n->child[i]);
    free (n->child);
    free (n->name);
    free (n);
}

static int
ndu_add_child (ndu_node *p, ndu_node *c)
{
    if (p->nchild == p->cap) {
        int nc = p->cap ? p->cap * 2 : 8;
        ndu_node **nn = (ndu_node **) realloc (p->child, (size_t) nc * sizeof *nn);
        if (!nn) return -1;
        p->child = nn; p->cap = nc;
    }
    c->parent = p;
    p->child[p->nchild++] = c;
    return 0;
}

/* join "dir" + "/" + "name" into a fresh buffer (handles trailing slash). */
static char *
ndu_join (const char *dir, const char *name)
{
    size_t dl = strlen (dir), nl = strlen (name);
    int slash = (dl > 0 && dir[dl - 1] == '/') ? 0 : 1;
    char *p = (char *) malloc (dl + (size_t) slash + nl + 1);
    if (!p) return NULL;
    memcpy (p, dir, dl);
    if (slash) p[dl] = '/';
    memcpy (p + dl + slash, name, nl + 1);
    return p;
}

/* --- recursive scan ----------------------------------------------------- */
/* Scans `path` (whose basename to record is `name`), returns a node or NULL
   on OOM. dev_root is the starting device (for -x). */
static ndu_node *
ndu_scan (const char *path, const char *name, const ndu_opt *o,
          hlset *seen, dev_t dev_root)
{
    struct stat st;
    if (lstat (path, &st) != 0) {
        ndu_node *n = ndu_new (name);
        if (n) n->err = 1;
        return n;
    }

    ndu_node *n = ndu_new (name);
    if (!n) return NULL;
    n->dev = st.st_dev;
    n->ino = st.st_ino;

    off_t own_disk = (off_t) st.st_blocks * 512;
    off_t own_asize = st.st_size;

    /* Hardlink dedup: a regular file with >1 link counts once. */
    if (!S_ISDIR (st.st_mode) && st.st_nlink > 1) {
        if (hl_seen (seen, st.st_dev, st.st_ino)) {
            own_disk = 0; own_asize = 0;
        }
    }

    if (!S_ISDIR (st.st_mode)) {
        n->disk = own_disk;
        n->asize = own_asize;
        return n;
    }

    n->is_dir = 1;
    n->disk = own_disk;     /* directory's own block usage counts (du does) */
    /* GNU du --apparent-size reports a directory's own apparent size as 0
       (only files contribute st_size); disk mode still counts dir blocks. */
    n->asize = 0;

    /* -x: do not descend into a different filesystem. */
    if (o->one_fs && st.st_dev != dev_root)
        return n;

    DIR *d = opendir (path);
    if (!d) { n->err = 1; return n; }

    /* Read child names first, then closedir, then recurse — avoids holding
       an fd open per directory level (fd exhaustion on deep trees). */
    char **names = NULL; int ncap = 0, nn = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (!strcmp (de->d_name, ".") || !strcmp (de->d_name, "..")) continue;
        if (nn == ncap) {
            int c2 = ncap ? ncap * 2 : 16;
            char **t = (char **) realloc (names, (size_t) c2 * sizeof *t);
            if (!t) { n->err = 1; break; }
            names = t; ncap = c2;
        }
        names[nn] = strdup (de->d_name);
        if (!names[nn]) { n->err = 1; break; }
        nn++;
    }
    closedir (d);

    for (int i = 0; i < nn; i++) {
        char *cp = ndu_join (path, names[i]);
        if (!cp) { n->err = 1; free (names[i]); continue; }
        ndu_node *c = ndu_scan (cp, names[i], o, seen, dev_root);
        free (cp);
        free (names[i]);
        if (!c) { n->err = 1; continue; }
        if (ndu_add_child (n, c) != 0) { ndu_free (c); n->err = 1; continue; }
        n->disk  += c->disk;
        n->asize += c->asize;
        n->items += c->items + 1;
    }
    free (names);
    return n;
}

/* --- batch: du-compatible per-directory listing (post-order) ----------- */
static void
ndu_print_dirs (FILE *fp, const ndu_node *n, const char *path, const ndu_opt *o)
{
    if (!n->is_dir) return;
    for (int i = 0; i < n->nchild; i++) {
        if (!n->child[i]->is_dir) continue;
        char *cp = ndu_join (path, n->child[i]->name);
        if (cp) { ndu_print_dirs (fp, n->child[i], cp, o); free (cp); }
    }
    fprintf (fp, "%lld\t%s\n", (long long) ndu_val (n, o), path);
}

/* --- human-readable size (TUI only; ncdu-style, binary units) ---------- */
static void
ndu_human (off_t v, char *buf, size_t cap)
{
    static const char *u[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
    double d = (double) v; int i = 0;
    while (d >= 1024.0 && i < 5) { d /= 1024.0; i++; }
    if (i == 0) snprintf (buf, cap, "%5lld   B", (long long) v);
    else        snprintf (buf, cap, "%6.1f %s", d, u[i]);
}

/* ====================================================================== */
/* Interactive browser                                                    */
/* ====================================================================== */

/* Terminal lifecycle, raw mode, winsize, alt-screen, cursor and the
   diff-optimized frame emit are all owned by the shared _bl_screen module;
   ncdu just draws cells and calls bls_refresh(). */

/* sort comparators over a node's child[] */
typedef enum { NDU_SORT_SIZE, NDU_SORT_NAME } ndu_sortmode;
static ndu_sortmode ndu_sort = NDU_SORT_SIZE;
static int          ndu_sort_apparent = 0;

static int
ndu_cmp (const void *pa, const void *pb)
{
    const ndu_node *a = *(const ndu_node *const *) pa;
    const ndu_node *b = *(const ndu_node *const *) pb;
    if (ndu_sort == NDU_SORT_NAME)
        return strcmp (a->name, b->name);
    off_t va = ndu_sort_apparent ? a->asize : a->disk;
    off_t vb = ndu_sort_apparent ? b->asize : b->disk;
    if (va < vb) return 1;          /* descending */
    if (va > vb) return -1;
    return strcmp (a->name, b->name);
}

static void
ndu_sort_children (ndu_node *n, ndu_sortmode mode, int apparent)
{
    ndu_sort = mode; ndu_sort_apparent = apparent;
    if (n->nchild > 1)
        qsort (n->child, (size_t) n->nchild, sizeof n->child[0], ndu_cmp);
}

/* Draw the browser frame for `cur` into the screen's stdscr cell buffer; the
   _bl_screen diff engine emits only what changed when bls_refresh() runs.
   A 24-bit truecolor header/footer bar + colored directory rows exercise the
   new color path; on the linux console these down-convert to the 16-color
   palette automatically. */
static void
ndu_render (bls_win *win, ndu_node *cur, int sel, int top, const ndu_opt *o)
{
    int cols = bls_cols (), rows = bls_lines ();
    if (cols > 1400) cols = 1400;
    int body = rows - 2;               /* minus header + footer */
    if (body < 1) body = 1;

    bls_erase (win);

    /* compose the current full path for the header */
    char path[768]; size_t pl = 0; path[0] = '\0';
    {
        ndu_node *chain[256]; int cn = 0;
        for (ndu_node *p = cur; p && cn < 256; p = p->parent) chain[cn++] = p;
        for (int i = cn - 1; i >= 0; i--) {
            const char *nm = chain[i]->name;
            size_t add = strlen (nm);
            if (pl + add + 2 >= sizeof path) break;
            if (pl > 0 && path[pl - 1] != '/') path[pl++] = '/';
            memcpy (path + pl, nm, add); pl += add; path[pl] = '\0';
        }
    }
    char tot[32]; ndu_human (ndu_val (cur, o), tot, sizeof tot);
    char hdr[1600], bar[1600];
    snprintf (hdr, sizeof hdr, " ncdu  %s  [%s%s]  %ld items",
              path, tot, o->apparent ? " apparent" : "", cur->items);
    snprintf (bar, sizeof bar, "%-*.*s", cols, cols, hdr);
    bls_attrset (win, BLS_A_BOLD);
    bls_setfg (win, BLS_RGB (16, 16, 24));
    bls_setbg (win, BLS_RGB (120, 170, 255));
    bls_mvaddstr (win, 0, 0, bar);

    /* largest child for the bar graph */
    off_t maxv = 1;
    for (int i = 0; i < cur->nchild; i++) {
        off_t v = ndu_val (cur->child[i], o);
        if (v > maxv) maxv = v;
    }

    int shown = 0;
    for (int i = top; i < cur->nchild && shown < body; i++, shown++) {
        ndu_node *c = cur->child[i];
        char sz[32]; ndu_human (ndu_val (c, o), sz, sizeof sz);
        int barw = 10;
        off_t v = ndu_val (c, o);
        int fill = (int) ((double) v / (double) maxv * barw + 0.5);
        if (fill > barw) fill = barw;
        if (fill < 0) fill = 0;
        char gb[16]; int bi = 0;
        gb[bi++] = '[';
        for (int k = 0; k < barw; k++) gb[bi++] = k < fill ? '#' : ' ';
        gb[bi++] = ']'; gb[bi] = '\0';
        char line[1600], fit[1600];
        snprintf (line, sizeof line, "%c%c%s %s %s%s",
                  c->err ? '!' : ' ', (i == sel ? '>' : ' '), sz, gb,
                  c->name, c->is_dir ? "/" : " ");
        snprintf (fit, sizeof fit, "%-*.*s", cols, cols, line);
        bls_attrset (win, i == sel ? BLS_A_REVERSE : BLS_A_NORMAL);
        bls_setbg (win, BLS_DEFAULT);
        bls_setfg (win, c->is_dir ? BLS_RGB (120, 200, 255) : BLS_DEFAULT);
        bls_mvaddstr (win, 1 + shown, 0, fit);
    }

    /* footer */
    snprintf (bar, sizeof bar, "%-*.*s", cols, cols,
        " up/dn move  right/enter open  left up  s size  n name  a apparent  q quit");
    bls_attrset (win, BLS_A_BOLD);
    bls_setfg (win, BLS_RGB (16, 16, 24));
    bls_setbg (win, BLS_RGB (120, 170, 255));
    bls_mvaddstr (win, rows - 1, 0, bar);

    bls_attrset (win, BLS_A_NORMAL);
    bls_setfg (win, BLS_DEFAULT); bls_setbg (win, BLS_DEFAULT);
    bls_move (win, rows - 1, 0);
    bls_refresh (win);
}

static int
ndu_browse (ndu_node *root, ndu_opt *o)
{
    if (bls_init () != 0) { builtin_error ("not a terminal"); return EXECUTION_FAILURE; }
    bls_win *win = bls_stdscr ();

    ndu_node *cur = root;
    ndu_sortmode mode = NDU_SORT_SIZE;
    ndu_sort_children (cur, mode, o->apparent);
    int sel = 0, top = 0;
    int rc = EXECUTION_SUCCESS;

    for (;;) {
        int body = bls_lines () - 2; if (body < 1) body = 1;
        if (sel < 0) sel = 0;
        if (cur->nchild > 0 && sel > cur->nchild - 1) sel = cur->nchild - 1;
        if (sel < top) top = sel;
        if (sel >= top + body) top = sel - body + 1;
        if (top < 0) top = 0;

        ndu_render (win, cur, sel, top, o);

        int k = bls_getch ();
        if (k == BLS_KEY_NONE) break;
        if (k == 0x03 || k == BL_KEY_ESC || k == 'q' || k == 'Q') break;

        switch (k) {
            case BL_KEY_UP:   if (sel > 0) sel--; break;
            case BL_KEY_DOWN: if (sel < cur->nchild - 1) sel++; break;
            case BL_KEY_PGUP: sel -= body; if (sel < 0) sel = 0; break;
            case BL_KEY_PGDN: sel += body; if (sel > cur->nchild - 1) sel = cur->nchild - 1; break;
            case BL_KEY_HOME: sel = 0; break;
            case BL_KEY_END:  sel = cur->nchild - 1; break;
            case BL_KEY_RIGHT:
            case BL_KEY_RET:
            case '\r': case '\n':
                if (cur->nchild > 0 && cur->child[sel]->is_dir
                    && cur->child[sel]->nchild > 0) {
                    cur = cur->child[sel];
                    ndu_sort_children (cur, mode, o->apparent);
                    sel = 0; top = 0;
                }
                break;
            case BL_KEY_LEFT:
                if (cur->parent) {
                    ndu_node *child = cur;
                    cur = cur->parent;
                    /* restore selection to the directory we came from */
                    sel = 0;
                    for (int i = 0; i < cur->nchild; i++)
                        if (cur->child[i] == child) { sel = i; break; }
                    top = 0;
                }
                break;
            case 's': case 'S':
                mode = NDU_SORT_SIZE; ndu_sort_children (cur, mode, o->apparent);
                sel = 0; top = 0; break;
            case 'n':
                mode = NDU_SORT_NAME; ndu_sort_children (cur, mode, o->apparent);
                sel = 0; top = 0; break;
            case 'a': case 'A':
                o->apparent = !o->apparent;
                ndu_sort_children (cur, mode, o->apparent);
                break;
            default: break;
        }
    }

    bls_end ();
    return rc;
}

/* --- builtin entry ------------------------------------------------------ */
static void
ndu_help (void)
{
    puts ("Disk usage analyzer (ncdu-style, ncurses-free).");
    puts ("");
    puts ("    ncdu [OPTION]... [PATH]");
    puts ("");
    puts ("    -a, --apparent-size   report apparent size (st_size)");
    puts ("    -x, --one-file-system stay on the starting filesystem");
    puts ("    -p, --print           du-compatible listing (batch)");
    puts ("    -t, --total           print grand total only (batch)");
    puts ("    -h, --help            show this help");
    puts ("    -V, --version         show version");
    puts ("");
    puts ("Keys: up/dn move, right/enter descend, left up, s/n sort, a apparent, q quit.");
}

int
ncdu_builtin (WORD_LIST *list)
{
    ndu_opt o; memset (&o, 0, sizeof o);
    int do_print = 0, do_total = 0, end_opts = 0;
    const char *path = NULL;

    for (WORD_LIST *p = list; p; p = p->next) {
        const char *w = p->word->word;
        if (!end_opts && !strcmp (w, "--")) { end_opts = 1; continue; }
        if (!end_opts && (!strcmp (w, "-h") || !strcmp (w, "--help"))) { ndu_help (); return EXECUTION_SUCCESS; }
        if (!end_opts && (!strcmp (w, "-V") || !strcmp (w, "--version"))) {
            puts ("ncdu 1.0 (bash-loadable, ncurses-free)"); return EXECUTION_SUCCESS;
        }
        if (!end_opts && (!strcmp (w, "-a") || !strcmp (w, "--apparent-size"))) { o.apparent = 1; continue; }
        if (!end_opts && (!strcmp (w, "-x") || !strcmp (w, "--one-file-system"))) { o.one_fs = 1; continue; }
        if (!end_opts && (!strcmp (w, "-p") || !strcmp (w, "--print"))) { do_print = 1; continue; }
        if (!end_opts && (!strcmp (w, "-t") || !strcmp (w, "--total"))) { do_total = 1; continue; }
        /* combined short flags like -ax */
        if (!end_opts && w[0] == '-' && w[1] && strcmp (w, "-")) {
            int ok = 1;
            for (const char *c = w + 1; *c; c++) {
                if (*c == 'a') o.apparent = 1;
                else if (*c == 'x') o.one_fs = 1;
                else if (*c == 'p') do_print = 1;
                else if (*c == 't') do_total = 1;
                else { ok = 0; break; }
            }
            if (ok) continue;
            builtin_error ("invalid option: %s", w);
            builtin_usage (); return EX_USAGE;
        }
        if (path) { builtin_error ("only one PATH allowed"); return EX_USAGE; }
        path = w;
    }
    if (!path) path = ".";

    hlset seen; memset (&seen, 0, sizeof seen);
    struct stat rst;
    dev_t dev_root = 0;
    if (lstat (path, &rst) == 0) dev_root = rst.st_dev;

    ndu_node *root = ndu_scan (path, path, &o, &seen, dev_root);
    free (seen.s);
    if (!root) { builtin_error ("out of memory scanning %s", path); return EXECUTION_FAILURE; }

    int rc = EXECUTION_SUCCESS;
    if (do_total) {
        printf ("%lld\n", (long long) ndu_val (root, &o));
    } else if (do_print || !isatty (STDOUT_FILENO)) {
        if (root->is_dir)
            ndu_print_dirs (stdout, root, path, &o);
        else
            printf ("%lld\t%s\n", (long long) ndu_val (root, &o), path);
    } else {
        if (!root->is_dir) {
            printf ("%lld\t%s\n", (long long) ndu_val (root, &o), path);
        } else {
            rc = ndu_browse (root, &o);
        }
    }

    ndu_free (root);
    return rc;
}

char *ncdu_doc[] = {
    "Disk usage analyzer (ncdu-style, ncurses-free).",
    "",
    "    ncdu [OPTION]... [PATH]",
    "",
    "Scans PATH (default '.') and presents an interactive full-screen browser",
    "(raw termios + ANSI, no ncurses). Disk usage follows GNU du: blocks*512,",
    "hardlinks counted once. Non-tty stdout falls back to a du-compatible listing.",
    "",
    "Options:",
    "    -a, --apparent-size   report apparent size (st_size)",
    "    -x, --one-file-system stay on the starting filesystem",
    "    -p, --print           du-compatible per-directory listing (batch)",
    "    -t, --total           print grand total bytes only (batch)",
    "    -h, --help            show this help",
    "    -V, --version         show version",
    "",
    "Keys: up/dn move, right/enter descend, left up, s/n sort, a apparent, q quit.",
    (char *) NULL
};

struct builtin ncdu_struct = {
    "ncdu",
    ncdu_builtin,
    BUILTIN_ENABLED,
    ncdu_doc,
    "ncdu [-axpt] [PATH]",
    0
};
