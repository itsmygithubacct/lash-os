/* bashkmod.c — kernel-module load/unload/list as bash builtins (Stage 22).
 *
 * Wraps finit_module(2) / delete_module(2) so bash-os can load
 * out-of-tree kernel modules without forking a separate modprobe /
 * kmod userspace. Bash-os today ships a monolithic kernel (no
 * modules), so this is "future option value": the on-ramp if we
 * ever ship loadable modules.
 *
 * Verbs:
 *   bashkmod load PATH [PARAMS]
 *       open(PATH), finit_module(fd, params, 0). Needs CAP_SYS_MODULE
 *       (root in default cap set). PARAMS is a single space-separated
 *       string passed through verbatim.
 *
 *   bashkmod unload NAME
 *       delete_module(NAME, O_NONBLOCK). Returns EBUSY if module is
 *       in use; the caller must surface that to the operator.
 *
 *   bashkmod list
 *       Read /proc/modules and emit one line per loaded module:
 *       'name size refcnt deps state'. /proc/modules format is the
 *       authoritative kernel-side enumeration; matches `lsmod` output
 *       columnar layout (with 'addr' field omitted).
 *
 *   bashkmod info NAME
 *       Print key/value pairs from /sys/module/NAME/{coresize,
 *       initstate,refcnt,...}. Helpful for `which version is
 *       loaded?` checks.
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
#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include "loadables.h"

#define BK_MAX_CHAIN 256
#define BK_MAX_SOFTDEPS 32
#define BK_SOFTDEP_DEPTH_MAX 8

#ifndef SYS_finit_module
#  ifdef __x86_64__
#    define SYS_finit_module 313
#  endif
#endif
#ifndef SYS_delete_module
#  ifdef __x86_64__
#    define SYS_delete_module 176
#  endif
#endif

/* Map finit_module(2) / delete_module(2) errno values to
   operator-actionable diagnostics rather than bare strerror. */
static const char *
bk_errno_msg (int e)
{
    switch (e)
    {
    case EPERM:  return "need CAP_SYS_MODULE";
    case EBUSY:  return "module in use";
    case ENOENT: return "no such module";
    case ENOMEM: return "kernel OOM";
    case ENODEV: return "no such device or module version mismatch";
    default:     return strerror (e);
    }
}

static const char *
bk_sys_module_root (void)
{
    const char *s = getenv ("BASHKMOD_SYS_MODULE_DIR");
    return (s && *s) ? s : "/sys/module";
}

/* Resolve the modprobe modules directory. BASHKMOD_MODULES_DIR overrides
   (used by tests); otherwise /lib/modules/$(uname -r). Returns NULL on
   uname() failure (only the BASHKMOD_MODULES_DIR override can override
   the kernel's view of itself, so the env path is honored unconditionally
   when set). */
static const char *
bk_modules_dir (char *buf, size_t bufsz)
{
    const char *s = getenv ("BASHKMOD_MODULES_DIR");
    if (s && *s) return s;
    struct utsname u;
    if (uname (&u) != 0) return NULL;
    if (snprintf (buf, bufsz, "/lib/modules/%s", u.release) >= (int) bufsz)
        return NULL;
    return buf;
}

/* Strip a modules.dep path "kernel/.../foo.ko[.xz|.gz|.zst]" to "foo".
   The kernel writes both forms ("foo.ko" and "foo.ko.xz") into
   modules.dep depending on CONFIG_MODULE_COMPRESS_*; we accept both.
   Returns 0 on success, -1 if the basename overflows the output buffer. */
static int
bk_modname_from_path (const char *path, char *out, size_t outsz)
{
    const char *b = strrchr (path, '/');
    b = b ? b + 1 : path;
    size_t n = strlen (b);
    static const char *suffixes[] = {".ko.zst", ".ko.xz", ".ko.gz", ".ko", NULL};
    for (int i = 0; suffixes[i]; i++) {
        size_t sl = strlen (suffixes[i]);
        if (n >= sl && !strcmp (b + n - sl, suffixes[i])) {
            n -= sl;
            break;
        }
    }
    if (n + 1 > outsz) return -1;
    memcpy (out, b, n);
    out[n] = '\0';
    return 0;
}

static int
bk_valid_module_name (const char *name)
{
    return name && *name && !strchr (name, '/') && strcmp (name, ".") && strcmp (name, "..");
}

static int
bk_module_names_equal (const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    while (*a && *b) {
        char ca = (*a == '-') ? '_' : *a;
        char cb = (*b == '-') ? '_' : *b;
        if (ca != cb)
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int
bk_append_words (char *dst, size_t dstsz, const char *src)
{
    if (!src || !*src)
        return 0;
    size_t off = strlen (dst);
    size_t n = strlen (src);
    size_t need = n + (off ? 1 : 0);
    if (off + need + 1 > dstsz)
        return -1;
    if (off)
        dst[off++] = ' ';
    memcpy (dst + off, src, n + 1);
    return 0;
}

static void
bk_trim_newline (char *s)
{
    size_t l = strlen (s);
    while (l && (s[l - 1] == '\n' || s[l - 1] == '\r'))
        s[--l] = '\0';
}

static int
bk_finit_path (const char *verb, const char *path, const char *params)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        builtin_error ("%s: open %s: %s", verb, path, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (syscall (SYS_finit_module, fd, params ? params : "", 0) != 0) {
        int e = errno;
        close (fd);
        builtin_error ("%s: %s: %s", verb, path, bk_errno_msg (e));
        return e == EPERM ? EX_USAGE : EXECUTION_FAILURE;
    }
    close (fd);
    return EXECUTION_SUCCESS;
}

static int
bk_delete_module_name (const char *verb, const char *name)
{
    if (syscall (SYS_delete_module, name, O_NONBLOCK) != 0) {
        builtin_error ("%s %s: %s", verb, name, bk_errno_msg (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bk_load_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("load: PATH [PARAMS]"); return EX_USAGE; }
    const char *path = args->word->word;
    /* Concatenate any remaining args into a single space-separated PARAMS. */
    char params[1024];
    params[0] = '\0';
    size_t off = 0;
    for (WORD_LIST *p = args->next; p; p = p->next) {
        size_t need = strlen (p->word->word) + (off ? 1 : 0);
        if (off + need + 1 >= sizeof (params)) {
            builtin_error ("load: params too long"); return EX_USAGE;
        }
        if (off) params[off++] = ' ';
        memcpy (params + off, p->word->word, strlen (p->word->word));
        off += strlen (p->word->word);
        params[off] = '\0';
    }
    return bk_finit_path ("load", path, params);
}

static int
bk_unload_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("unload: NAME"); return EX_USAGE; }
    return bk_delete_module_name ("unload", args->word->word);
}

/* Parse /proc/modules. Format per Documentation/admin-guide/sysctl/kernel.rst:
   "name size refcnt deps_or_- state addr". We drop the address column. */
static int
bk_list_cmd (WORD_LIST *args)
{
    (void) args;
    FILE *f = fopen ("/proc/modules", "r");
    if (!f) {
        /* Monolithic kernels don't always populate /proc/modules; treat
           "no such file" as "no modules loaded" rather than an error. */
        if (errno == ENOENT) return EXECUTION_SUCCESS;
        builtin_error ("/proc/modules: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    char line[1024];
    while (fgets (line, sizeof (line), f)) {
        char name[64], deps[256], state[32];
        unsigned long size; int refcnt;
        /* /proc/modules per kernel docs always has 5 fields plus an
           optional address column. Require all 5 — accepting fewer
           would print uninitialized 'state'. */
        if (sscanf (line, "%63s %lu %d %255s %31s",
                    name, &size, &refcnt, deps, state) == 5)
            printf ("%s %lu %d %s %s\n", name, size, refcnt, deps, state);
    }
    fclose (f);
    return EXECUTION_SUCCESS;
}

static int
bk_name_cmp (const void *a, const void *b)
{
    const char *const *pa = a;
    const char *const *pb = b;
    return strcmp (*pa, *pb);
}

static void
bk_free_names (char **names, size_t n)
{
    if (!names)
        return;
    for (size_t i = 0; i < n; i++)
        free (names[i]);
    free (names);
}

static int
bk_print_params (const char *modpath)
{
    char dir[PATH_MAX];
    if (snprintf (dir, sizeof dir, "%s/parameters", modpath) >= (int) sizeof dir) {
        builtin_error ("info: parameters path too long");
        return EX_USAGE;
    }

    DIR *d = opendir (dir);
    if (!d) {
        if (errno == ENOENT)
            return EXECUTION_SUCCESS;
        builtin_error ("info: parameters: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }

    char **names = NULL;
    size_t count = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        if (strchr (de->d_name, '/'))
            continue;
        if (count == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            char **tmp = realloc (names, ncap * sizeof *names);
            if (!tmp) {
                closedir (d);
                bk_free_names (names, count);
                builtin_error ("info: parameters: out of memory");
                return EXECUTION_FAILURE;
            }
            names = tmp;
            cap = ncap;
        }
        names[count] = strdup (de->d_name);
        if (!names[count]) {
            closedir (d);
            bk_free_names (names, count);
            builtin_error ("info: parameters: out of memory");
            return EXECUTION_FAILURE;
        }
        count++;
    }
    closedir (d);

    qsort (names, count, sizeof *names, bk_name_cmp);
    for (size_t i = 0; i < count; i++) {
        char fp[PATH_MAX];
        if (snprintf (fp, sizeof fp, "%s/%s", dir, names[i]) >= (int) sizeof fp)
            continue;
        FILE *fh = fopen (fp, "r");
        if (!fh)
            continue;
        char val[256];
        if (fgets (val, sizeof val, fh)) {
            bk_trim_newline (val);
            printf ("param.%s=%s\n", names[i], val);
        } else {
            printf ("param.%s=\n", names[i]);
        }
        fclose (fh);
    }

    bk_free_names (names, count);
    return EXECUTION_SUCCESS;
}

/* Walk /sys/module/NAME/ for coresize, initstate, refcnt, version, params. */
static int
bk_info_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("info: NAME"); return EX_USAGE; }
    int params_only = 0;
    if (!strcmp (args->word->word, "-p") || !strcmp (args->word->word, "--params")) {
        params_only = 1;
        args = args->next;
        if (!args) { builtin_error ("info: NAME"); return EX_USAGE; }
    }
    if (args->next) { builtin_error ("info: too many arguments"); return EX_USAGE; }
    if (!bk_valid_module_name (args->word->word)) {
        builtin_error ("info: invalid module name");
        return EX_USAGE;
    }

    char path[PATH_MAX];
    if (snprintf (path, sizeof path, "%s/%s", bk_sys_module_root (), args->word->word) >= (int) sizeof path) {
        builtin_error ("info: module path too long");
        return EX_USAGE;
    }
    struct stat st;
    if (stat (path, &st) != 0) {
        builtin_error ("info: %s not loaded", args->word->word);
        return EXECUTION_FAILURE;
    }
    if (!S_ISDIR (st.st_mode)) {
        builtin_error ("info: %s not a module directory", args->word->word);
        return EXECUTION_FAILURE;
    }

    if (params_only)
        return bk_print_params (path);

    static const char *fields[] = {
        "coresize", "initsize", "initstate", "refcnt", "version", NULL
    };
    for (int i = 0; fields[i]; i++) {
        char fp[320];
        snprintf (fp, sizeof (fp), "%s/%s", path, fields[i]);
        FILE *fh = fopen (fp, "r");
        if (!fh) continue;
        char val[256];
        if (fgets (val, sizeof (val), fh)) {
            bk_trim_newline (val);
            printf ("%s=%s\n", fields[i], val);
        }
        fclose (fh);
    }
    return bk_print_params (path);
}

/* bashkmod deps NAME — read ${MODULES_DIR}/modules.dep (modprobe's
   authoritative dep manifest) and emit the dependency chain in load
   order, one module name per line, terminating with NAME.

   modules.dep line format (per Documentation/kbuild/modules.rst):
     kernel/path/to/foo.ko: kernel/path/dep1.ko kernel/path/dep2.ko

   The rightmost dep is the deepest (its own deps resolved by its own
   line). modprobe walks the list right-to-left for load order. We match
   that semantic and append NAME last so the caller can pipe the output
   to `while read m; do bashkmod load .../$m.ko; done`. */
/* Resolve NAME's dependency load chain from modules.dep into out[] in load
   order (deepest deps first, NAME last). Returns 0 on success, -1 if NAME has
   no modules.dep entry, -2 on environment/IO error. */
static int
bk_resolve_deps_full (const char *name, char out[][256], char paths[][PATH_MAX],
                      int max, int *count)
{
    *count = 0;
    char dbuf[PATH_MAX];
    const char *mdir = bk_modules_dir (dbuf, sizeof dbuf);
    if (!mdir) return -2;
    char dep_path[PATH_MAX];
    if (snprintf (dep_path, sizeof dep_path, "%s/modules.dep", mdir) >= (int) sizeof dep_path)
        return -2;
    FILE *f = fopen (dep_path, "r");
    if (!f) return -2;

    char line[4096];
    char modname[256];
    int found = 0;
    while (fgets (line, sizeof line, f)) {
        char *colon = strchr (line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *modpath = line;
        char *deps = colon + 1;
        if (bk_modname_from_path (modpath, modname, sizeof modname) != 0)
            continue;
        if (!bk_module_names_equal (modname, name))
            continue;
        found = 1;
        /* tokenize deps (space/tab separated); load order = rightmost first */
        char *toks[512];
        int ntoks = 0;
        char *save = NULL;
        char *t = strtok_r (deps, " \t\n\r", &save);
        while (t && ntoks < (int) (sizeof toks / sizeof toks[0])) {
            toks[ntoks++] = t;
            t = strtok_r (NULL, " \t\n\r", &save);
        }
        for (int i = ntoks - 1; i >= 0; i--) {
            char dn[256];
            if (bk_modname_from_path (toks[i], dn, sizeof dn) == 0 && *count < max) {
                snprintf (out[(*count)++], 256, "%s", dn);
                if (paths)
                    snprintf (paths[*count - 1], PATH_MAX, "%s", toks[i]);
            }
        }
        if (*count < max) {
            snprintf (out[*count], 256, "%s", modname);
            if (paths)
                snprintf (paths[*count], PATH_MAX, "%s", modpath);
            (*count)++;
        }
        break;
    }
    fclose (f);
    return found ? 0 : -1;
}

static int
bk_resolve_deps (const char *name, char out[][256], int max, int *count)
{
    return bk_resolve_deps_full (name, out, NULL, max, count);
}

static int
bk_deps_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("deps: NAME"); return EX_USAGE; }
    if (args->next) { builtin_error ("deps: too many arguments"); return EX_USAGE; }
    const char *name = args->word->word;
    if (!bk_valid_module_name (name)) {
        builtin_error ("deps: invalid module name");
        return EX_USAGE;
    }
    char chain[256][256];
    int n = 0;
    int r = bk_resolve_deps (name, chain, 256, &n);
    if (r == -2) { builtin_error ("deps: cannot read modules.dep"); return EXECUTION_FAILURE; }
    if (r == -1) { builtin_error ("deps: no dependency information for %s", name); return EXECUTION_FAILURE; }
    for (int i = 0; i < n; i++)
        printf ("%s\n", chain[i]);
    return EXECUTION_SUCCESS;
}

/* bashkmod aliases MODALIAS — read ${MODULES_DIR}/modules.alias and emit
   module names whose alias glob matches MODALIAS, preserving file order.

   modules.alias line format:
     alias pci:v00008086d000010D3sv*sd*bc*sc*i* e1000e

   Kernel modalias patterns use shell-style wildcards; fnmatch(3) is the
   right first-slice matcher for the generated depmod file. */
static int
bk_aliases_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("aliases: MODALIAS"); return EX_USAGE; }
    if (args->next) { builtin_error ("aliases: too many arguments"); return EX_USAGE; }
    const char *modalias = args->word->word;
    if (!modalias || !*modalias) {
        builtin_error ("aliases: empty modalias");
        return EX_USAGE;
    }

    char dbuf[PATH_MAX];
    const char *mdir = bk_modules_dir (dbuf, sizeof dbuf);
    if (!mdir) {
        builtin_error ("aliases: cannot determine modules directory");
        return EXECUTION_FAILURE;
    }
    char alias_path[PATH_MAX];
    if (snprintf (alias_path, sizeof alias_path, "%s/modules.alias", mdir) >= (int) sizeof alias_path) {
        builtin_error ("aliases: modules.alias path too long");
        return EX_USAGE;
    }
    FILE *f = fopen (alias_path, "r");
    if (!f) {
        builtin_error ("aliases: %s: %s", alias_path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    char line[4096];
    char **seen = NULL;
    size_t nseen = 0, cseen = 0;
    int matched = 0;
    while (fgets (line, sizeof line, f)) {
        char *save = NULL;
        char *kw = strtok_r (line, " \t\n\r", &save);
        if (!kw || kw[0] == '#')
            continue;
        if (strcmp (kw, "alias") != 0)
            continue;
        char *pattern = strtok_r (NULL, " \t\n\r", &save);
        char *module = strtok_r (NULL, " \t\n\r", &save);
        if (!pattern || !module)
            continue;
        if (fnmatch (pattern, modalias, 0) != 0)
            continue;

        int duplicate = 0;
        for (size_t i = 0; i < nseen; i++) {
            if (!strcmp (seen[i], module)) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate)
            continue;
        if (nseen == cseen) {
            size_t ncap = cseen ? cseen * 2 : 8;
            char **tmp = realloc (seen, ncap * sizeof *seen);
            if (!tmp) {
                fclose (f);
                bk_free_names (seen, nseen);
                builtin_error ("aliases: out of memory");
                return EXECUTION_FAILURE;
            }
            seen = tmp;
            cseen = ncap;
        }
        seen[nseen] = strdup (module);
        if (!seen[nseen]) {
            fclose (f);
            bk_free_names (seen, nseen);
            builtin_error ("aliases: out of memory");
            return EXECUTION_FAILURE;
        }
        printf ("%s\n", seen[nseen]);
        nseen++;
        matched = 1;
    }
    fclose (f);
    bk_free_names (seen, nseen);
    if (!matched) {
        builtin_error ("aliases: no module alias matches %s", modalias);
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bk_alias_lookup_modules_alias (const char *modalias, char *module, size_t modulesz)
{
    char dbuf[PATH_MAX];
    const char *mdir = bk_modules_dir (dbuf, sizeof dbuf);
    if (!mdir)
        return -2;
    char alias_path[PATH_MAX];
    if (snprintf (alias_path, sizeof alias_path, "%s/modules.alias", mdir) >= (int) sizeof alias_path)
        return -2;
    FILE *f = fopen (alias_path, "r");
    if (!f)
        return errno == ENOENT ? -1 : -2;

    char line[4096];
    int matched = 0;
    while (fgets (line, sizeof line, f)) {
        char *save = NULL;
        char *kw = strtok_r (line, " \t\n\r", &save);
        if (!kw || kw[0] == '#' || strcmp (kw, "alias") != 0)
            continue;
        char *pattern = strtok_r (NULL, " \t\n\r", &save);
        char *target = strtok_r (NULL, " \t\n\r", &save);
        if (!pattern || !target)
            continue;
        if (fnmatch (pattern, modalias, 0) != 0)
            continue;
        snprintf (module, modulesz, "%s", target);
        matched = 1;
        break;
    }
    fclose (f);
    return matched ? 0 : -1;
}

static int
bk_policy_builtin (const char *mdir, const char *name, int *is_builtin)
{
    char path[PATH_MAX];
    if (snprintf (path, sizeof path, "%s/modules.builtin", mdir) >= (int) sizeof path) {
        builtin_error ("policy: modules.builtin path too long");
        return EX_USAGE;
    }
    FILE *f = fopen (path, "r");
    if (!f) {
        if (errno == ENOENT) {
            *is_builtin = 0;
            return EXECUTION_SUCCESS;
        }
        builtin_error ("policy: %s: %s", path, strerror (errno));
        return EXECUTION_FAILURE;
    }

    char line[4096], modname[256];
    *is_builtin = 0;
    while (fgets (line, sizeof line, f)) {
        bk_trim_newline (line);
        if (bk_modname_from_path (line, modname, sizeof modname) == 0
            && bk_module_names_equal (modname, name)) {
            *is_builtin = 1;
            break;
        }
    }
    fclose (f);
    return EXECUTION_SUCCESS;
}

struct bk_policy {
    int blacklisted;
    char *install_cmd;
    char *remove_cmd;
    char *softdep;
    char *options;
    char *alias_pattern;
    char *alias_target;
};

static int bk_collect_policy_files (char ***files_out, size_t *nfiles_out);
static char *bk_first_word (char **cursor);
static char *bk_rest (char *s);

static int
bk_directive_has_shell_meta (const char *s)
{
    if (!s)
        return 0;
    for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
        switch (*p) {
        case '|': case '&': case ';': case '<': case '>':
        case '$': case '`': case '\\': case '"': case '\'':
        case '(': case ')': case '{': case '}': case '[': case ']':
        case '*': case '?': case '~': case '#':
        case '\n': case '\r':
            return 1;
        default:
            break;
        }
    }
    return 0;
}

static int
bk_run_directive (const char *kind, const char *cmdline)
{
    if (!cmdline || !*cmdline) {
        builtin_error ("modprobe: empty %s directive", kind);
        return EX_USAGE;
    }
    if (bk_directive_has_shell_meta (cmdline)) {
        builtin_error ("modprobe: refusing %s directive with shell metacharacters: %s",
                       kind, cmdline);
        return EX_USAGE;
    }

    char *copy = strdup (cmdline);
    if (!copy) {
        builtin_error ("modprobe: out of memory");
        return EXECUTION_FAILURE;
    }
    char *argv[64];
    int argc = 0;
    char *save = NULL;
    for (char *tok = strtok_r (copy, " \t", &save);
         tok;
         tok = strtok_r (NULL, " \t", &save)) {
        if (argc >= (int) (sizeof argv / sizeof argv[0]) - 1) {
            free (copy);
            builtin_error ("modprobe: %s directive argv too long", kind);
            return EX_USAGE;
        }
        argv[argc++] = tok;
    }
    argv[argc] = NULL;
    if (argc == 0) {
        free (copy);
        builtin_error ("modprobe: empty %s directive", kind);
        return EX_USAGE;
    }

    pid_t pid = fork ();
    if (pid < 0) {
        int e = errno;
        free (copy);
        builtin_error ("modprobe: fork %s directive: %s", kind, strerror (e));
        return EXECUTION_FAILURE;
    }
    if (pid == 0) {
        execvp (argv[0], argv);
        _exit (127);
    }

    int status = 0;
    while (waitpid (pid, &status, 0) < 0) {
        if (errno == EINTR)
            continue;
        int e = errno;
        free (copy);
        builtin_error ("modprobe: wait %s directive: %s", kind, strerror (e));
        return EXECUTION_FAILURE;
    }
    free (copy);
    if (WIFEXITED (status) && WEXITSTATUS (status) == 0)
        return EXECUTION_SUCCESS;
    if (WIFEXITED (status))
        builtin_error ("modprobe: %s directive exited %d", kind, WEXITSTATUS (status));
    else if (WIFSIGNALED (status))
        builtin_error ("modprobe: %s directive killed by signal %d", kind, WTERMSIG (status));
    else
        builtin_error ("modprobe: %s directive failed", kind);
    return EXECUTION_FAILURE;
}

static void
bk_policy_free (struct bk_policy *p)
{
    free (p->install_cmd);
    free (p->remove_cmd);
    free (p->softdep);
    free (p->options);
    free (p->alias_pattern);
    free (p->alias_target);
    memset (p, 0, sizeof *p);
}

static int
bk_policy_set (char **dst, const char *src)
{
    char *copy = strdup (src ? src : "");
    if (!copy)
        return -1;
    free (*dst);
    *dst = copy;
    return 0;
}

static int
bk_policy_append_options (struct bk_policy *p, const char *rest)
{
    if (!rest || !*rest)
        return 0;
    if (!p->options)
        return bk_policy_set (&p->options, rest);
    size_t need = strlen (p->options) + 1 + strlen (rest) + 1;
    char *tmp = malloc (need);
    if (!tmp)
        return -1;
    snprintf (tmp, need, "%s %s", p->options, rest);
    free (p->options);
    p->options = tmp;
    return 0;
}

static int
bk_softdep_split (const char *raw, char pre[][256], int *npre,
                  char post[][256], int *npost, int max)
{
    *npre = 0;
    *npost = 0;
    if (!raw || !*raw)
        return EXECUTION_SUCCESS;

    char *copy = strdup (raw);
    if (!copy) {
        builtin_error ("modprobe: out of memory");
        return EXECUTION_FAILURE;
    }

    int in_post = 0;
    char *cur = copy;
    char *tok;
    while ((tok = bk_first_word (&cur)) != NULL) {
        if (!strcmp (tok, "pre:")) {
            in_post = 0;
            continue;
        }
        if (!strcmp (tok, "post:")) {
            in_post = 1;
            continue;
        }
        if (!bk_valid_module_name (tok)) {
            free (copy);
            builtin_error ("modprobe: invalid softdep module name: %s", tok);
            return EX_USAGE;
        }
        if (in_post) {
            if (*npost >= max) {
                free (copy);
                builtin_error ("modprobe: too many softdep post modules");
                return EX_USAGE;
            }
            snprintf (post[(*npost)++], 256, "%s", tok);
        } else {
            if (*npre >= max) {
                free (copy);
                builtin_error ("modprobe: too many softdep pre modules");
                return EX_USAGE;
            }
            snprintf (pre[(*npre)++], 256, "%s", tok);
        }
    }
    free (copy);
    return EXECUTION_SUCCESS;
}

static int
bk_policy_read (const char *name, const char *request, struct bk_policy *policy)
{
    char **files = NULL;
    size_t nfiles = 0;
    memset (policy, 0, sizeof *policy);
    int rc = bk_collect_policy_files (&files, &nfiles);
    if (rc != EXECUTION_SUCCESS)
        return rc;

    FILE *f = NULL;
    for (size_t i = 0; i < nfiles; i++) {
        char line[4096];
        f = fopen (files[i], "r");
        if (!f)
            continue;
        while (fgets (line, sizeof line, f)) {
            char *cur = line;
            char *kw = bk_first_word (&cur);
            if (!kw)
                continue;
            char *mod = bk_first_word (&cur);
            if (!mod)
                continue;
            char *rest = bk_rest (cur);
            if (!strcmp (kw, "alias")) {
                char *target = bk_first_word (&cur);
                const char *req = request ? request : name;
                if (target && req && fnmatch (mod, req, 0) == 0) {
                    if (bk_policy_set (&policy->alias_pattern, mod) < 0
                        || bk_policy_set (&policy->alias_target, target) < 0)
                        goto oom;
                }
                continue;
            }
            if (!bk_module_names_equal (mod, name))
                continue;
            if (!strcmp (kw, "blacklist")) {
                policy->blacklisted = 1;
            } else if (!strcmp (kw, "install")) {
                if (bk_policy_set (&policy->install_cmd, rest) < 0)
                    goto oom;
            } else if (!strcmp (kw, "remove")) {
                if (bk_policy_set (&policy->remove_cmd, rest) < 0)
                    goto oom;
            } else if (!strcmp (kw, "softdep")) {
                if (bk_policy_set (&policy->softdep, rest) < 0)
                    goto oom;
            } else if (!strcmp (kw, "options")) {
                if (bk_policy_append_options (policy, rest) < 0)
                    goto oom;
            }
        }
        fclose (f);
        f = NULL;
    }
    bk_free_names (files, nfiles);
    return EXECUTION_SUCCESS;

oom:
    if (f)
        fclose (f);
    bk_free_names (files, nfiles);
    bk_policy_free (policy);
    builtin_error ("policy: out of memory");
    return EXECUTION_FAILURE;
}

static int
bk_add_policy_file (char ***files, size_t *nfiles, size_t *cfiles,
                    const char *dir, const char *name)
{
    char path[PATH_MAX];
    if (snprintf (path, sizeof path, "%s/%s", dir, name) >= (int) sizeof path)
        return 0;
    if (*nfiles == *cfiles) {
        size_t ncap = *cfiles ? *cfiles * 2 : 8;
        char **tmp = realloc (*files, ncap * sizeof **files);
        if (!tmp)
            return -1;
        *files = tmp;
        *cfiles = ncap;
    }
    (*files)[*nfiles] = strdup (path);
    if (!(*files)[*nfiles])
        return -1;
    (*nfiles)++;
    return 0;
}

static int
bk_collect_policy_files (char ***files_out, size_t *nfiles_out)
{
    const char *dirs = getenv ("BASHKMOD_MODPROBE_DIRS");
    const char *single = getenv ("BASHKMOD_MODPROBE_DIR");
    char fallback[PATH_MAX * 2];
    char *copy, *save = NULL, *dir;
    char **files = NULL;
    size_t nfiles = 0, cfiles = 0;

    if (!dirs || !*dirs) {
        if (single && *single)
            dirs = single;
        else {
            snprintf (fallback, sizeof fallback, "/etc/modprobe.d:/lib/modprobe.d");
            dirs = fallback;
        }
    }
    copy = strdup (dirs);
    if (!copy) {
        builtin_error ("policy: out of memory");
        return EXECUTION_FAILURE;
    }

    for (dir = strtok_r (copy, ":", &save); dir; dir = strtok_r (NULL, ":", &save)) {
        DIR *d;
        struct dirent *de;
        if (!*dir)
            continue;
        d = opendir (dir);
        if (!d) {
            if (errno == ENOENT)
                continue;
            free (copy);
            bk_free_names (files, nfiles);
            builtin_error ("policy: opendir %s: %s", dir, strerror (errno));
            return EXECUTION_FAILURE;
        }
        while ((de = readdir (d)) != NULL) {
            size_t l = strlen (de->d_name);
            if (de->d_name[0] == '.' || strchr (de->d_name, '/'))
                continue;
            if (l < 5 || strcmp (de->d_name + l - 5, ".conf") != 0)
                continue;
            if (bk_add_policy_file (&files, &nfiles, &cfiles, dir, de->d_name) < 0) {
                closedir (d);
                free (copy);
                bk_free_names (files, nfiles);
                builtin_error ("policy: out of memory");
                return EXECUTION_FAILURE;
            }
        }
        closedir (d);
    }
    free (copy);
    qsort (files, nfiles, sizeof *files, bk_name_cmp);
    *files_out = files;
    *nfiles_out = nfiles;
    return EXECUTION_SUCCESS;
}

static char *
bk_first_word (char **cursor)
{
    char *s = *cursor;
    char *start;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '\0' || *s == '#') {
        *cursor = s;
        return NULL;
    }
    start = s;
    while (*s && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r' && *s != '#')
        s++;
    if (*s) {
        *s++ = '\0';
    }
    *cursor = s;
    return start;
}

static char *
bk_rest (char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    bk_trim_newline (s);
    return s;
}

static int
bk_policy_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("policy: NAME"); return EX_USAGE; }
    if (args->next) { builtin_error ("policy: too many arguments"); return EX_USAGE; }
    const char *name = args->word->word;
    if (!bk_valid_module_name (name)) {
        builtin_error ("policy: invalid module name");
        return EX_USAGE;
    }

    char dbuf[PATH_MAX];
    const char *mdir = bk_modules_dir (dbuf, sizeof dbuf);
    if (!mdir) {
        builtin_error ("policy: cannot determine modules directory");
        return EXECUTION_FAILURE;
    }

    int is_builtin = 0;
    struct bk_policy policy;
    int rc = bk_policy_builtin (mdir, name, &is_builtin);
    if (rc != EXECUTION_SUCCESS)
        return rc;

    rc = bk_policy_read (name, name, &policy);
    if (rc != EXECUTION_SUCCESS)
        return rc;

    printf ("builtin=%s\n", is_builtin ? "yes" : "no");
    printf ("blacklist=%s\n", policy.blacklisted ? "yes" : "no");
    printf ("install=%s\n", policy.install_cmd ? policy.install_cmd : "");
    printf ("remove=%s\n", policy.remove_cmd ? policy.remove_cmd : "");
    printf ("softdep=%s\n", policy.softdep ? policy.softdep : "");
    printf ("options=%s\n", policy.options ? policy.options : "");
    printf ("alias-target=%s\n", policy.alias_target ? policy.alias_target : "");
    bk_policy_free (&policy);
    return EXECUTION_SUCCESS;
}

struct bk_modprobe_plan {
    char request[256];
    char resolved[256];
    int alias_driven;
    char alias_source[32];
    int blacklisted;
    int blacklist_enforced;
    int builtin;
    int remove;
    char params[1024];
    struct bk_policy policy;
    char chain[256][256];
    char paths[256][PATH_MAX];
    int nchain;
    char softdep_pre[BK_MAX_SOFTDEPS][256];
    int n_softdep_pre;
    char softdep_post[BK_MAX_SOFTDEPS][256];
    int n_softdep_post;
};

static void
bk_modprobe_plan_free (struct bk_modprobe_plan *plan)
{
    bk_policy_free (&plan->policy);
}

static int
bk_plan_modprobe (const char *request, int remove, WORD_LIST *params,
                  struct bk_modprobe_plan *plan)
{
    memset (plan, 0, sizeof *plan);
    snprintf (plan->request, sizeof plan->request, "%s", request);
    snprintf (plan->resolved, sizeof plan->resolved, "%s", request);
    plan->remove = remove;

    int direct_n = 0;
    char direct_chain[1][256];
    int direct_rc = bk_resolve_deps (request, direct_chain, 1, &direct_n);
    if (direct_rc != 0) {
        struct bk_policy req_policy;
        int prc = bk_policy_read (request, request, &req_policy);
        if (prc != EXECUTION_SUCCESS)
            return prc;
        if (req_policy.alias_target) {
            snprintf (plan->resolved, sizeof plan->resolved, "%s", req_policy.alias_target);
            plan->alias_driven = 1;
            snprintf (plan->alias_source, sizeof plan->alias_source, "modprobe.d");
        }
        bk_policy_free (&req_policy);
    }
    if (!plan->alias_driven && direct_rc != 0) {
        char target[256];
        if (bk_alias_lookup_modules_alias (request, target, sizeof target) == 0) {
            snprintf (plan->resolved, sizeof plan->resolved, "%s", target);
            plan->alias_driven = 1;
            snprintf (plan->alias_source, sizeof plan->alias_source, "modules.alias");
        }
    }

    int rc = bk_policy_read (plan->resolved, request, &plan->policy);
    if (rc != EXECUTION_SUCCESS)
        return rc;
    rc = bk_softdep_split (plan->policy.softdep, plan->softdep_pre,
                           &plan->n_softdep_pre, plan->softdep_post,
                           &plan->n_softdep_post, BK_MAX_SOFTDEPS);
    if (rc != EXECUTION_SUCCESS)
        return rc;
    plan->blacklisted = plan->policy.blacklisted;
    plan->blacklist_enforced = plan->alias_driven && plan->blacklisted;

    char dbuf[PATH_MAX];
    const char *mdir = bk_modules_dir (dbuf, sizeof dbuf);
    if (!mdir) {
        builtin_error ("modprobe: cannot determine modules directory");
        return EXECUTION_FAILURE;
    }
    rc = bk_policy_builtin (mdir, plan->resolved, &plan->builtin);
    if (rc != EXECUTION_SUCCESS)
        return rc;

    if (plan->policy.options && bk_append_words (plan->params, sizeof plan->params, plan->policy.options) < 0) {
        builtin_error ("modprobe: params too long");
        return EX_USAGE;
    }
    for (WORD_LIST *p = params; p; p = p->next) {
        if (bk_append_words (plan->params, sizeof plan->params, p->word->word) < 0) {
            builtin_error ("modprobe: params too long");
            return EX_USAGE;
        }
    }

    if (remove) {
        if (plan->policy.remove_cmd || plan->builtin)
            return EXECUTION_SUCCESS;
        int rr = bk_resolve_deps_full (plan->resolved, plan->chain, plan->paths,
                                       256, &plan->nchain);
        if (rr == -2)
            plan->nchain = 0;
        if (rr == -1)
            plan->nchain = 0;
        return EXECUTION_SUCCESS;
    }
    if (plan->policy.install_cmd || plan->builtin)
        return EXECUTION_SUCCESS;
    int r = bk_resolve_deps_full (plan->resolved, plan->chain, plan->paths, 256, &plan->nchain);
    if (r == -2) { builtin_error ("modprobe: cannot read modules.dep"); return EXECUTION_FAILURE; }
    if (r == -1) { builtin_error ("modprobe: module %s not found", plan->resolved); return EXECUTION_FAILURE; }
    return EXECUTION_SUCCESS;
}

static int
bk_abs_module_path (const char *mdir, const char *path, char *out, size_t outsz)
{
    int n;
    if (path[0] == '/')
        n = snprintf (out, outsz, "%s", path);
    else
        n = snprintf (out, outsz, "%s/%s", mdir, path);
    return n >= 0 && n < (int) outsz ? 0 : -1;
}

static void
bk_print_name_list (char names[][256], int count)
{
    for (int i = 0; i < count; i++)
        printf ("%s%s", i ? " " : "", names[i]);
}

static int
bk_resolve_cmd (WORD_LIST *args)
{
    if (!args) { builtin_error ("resolve: NAME [PARAMS]"); return EX_USAGE; }
    const char *name = args->word->word;
    if (!bk_valid_module_name (name)) { builtin_error ("resolve: invalid module name"); return EX_USAGE; }
    struct bk_modprobe_plan plan;
    int rc = bk_plan_modprobe (name, 0, args->next, &plan);
    if (rc != EXECUTION_SUCCESS) {
        bk_modprobe_plan_free (&plan);
        return rc;
    }
    printf ("request=%s\n", plan.request);
    printf ("resolved=%s\n", plan.resolved);
    printf ("alias=%s\n", plan.alias_driven ? "yes" : "no");
    printf ("alias-source=%s\n", plan.alias_driven ? plan.alias_source : "");
    printf ("blacklist=%s\n", plan.blacklisted ? "yes" : "no");
    printf ("blacklist-enforced=%s\n", plan.blacklist_enforced ? "yes" : "no");
    printf ("builtin=%s\n", plan.builtin ? "yes" : "no");
    printf ("install=%s\n", plan.policy.install_cmd ? plan.policy.install_cmd : "");
    printf ("remove=%s\n", plan.policy.remove_cmd ? plan.policy.remove_cmd : "");
    printf ("softdep=%s\n", plan.policy.softdep ? plan.policy.softdep : "");
    printf ("softdep-pre=");
    bk_print_name_list (plan.softdep_pre, plan.n_softdep_pre);
    printf ("\n");
    printf ("softdep-post=");
    bk_print_name_list (plan.softdep_post, plan.n_softdep_post);
    printf ("\n");
    printf ("options=%s\n", plan.params);
    printf ("deps=");
    for (int i = 0; i < plan.nchain; i++)
        printf ("%s%s", i ? " " : "", plan.chain[i]);
    printf ("\n");
    bk_modprobe_plan_free (&plan);
    return EXECUTION_SUCCESS;
}

static int bk_modprobe_apply_name (const char *name, int dry, int depth,
                                   char visited[][256], int nvisited);

static int
bk_seen_plan_name (char visited[][256], int nvisited, const char *name)
{
    for (int i = 0; i < nvisited; i++)
        if (bk_module_names_equal (visited[i], name))
            return 1;
    return 0;
}

static int
bk_modprobe_apply_chain (struct bk_modprobe_plan *plan, int dry)
{
    char dbuf[PATH_MAX];
    const char *mdir = bk_modules_dir (dbuf, sizeof dbuf);
    if (!mdir) {
        builtin_error ("modprobe: cannot determine modules directory");
        return EXECUTION_FAILURE;
    }
    for (int i = 0; i < plan->nchain; i++) {
        char full[PATH_MAX];
        if (bk_abs_module_path (mdir, plan->paths[i], full, sizeof full) != 0) {
            builtin_error ("modprobe: module path too long");
            return EX_USAGE;
        }
        const char *params = (i == plan->nchain - 1) ? plan->params : "";
        if (dry) {
            printf ("insmod %s", full);
            if (params[0])
                printf (" %s", params);
            printf ("\n");
        } else {
            int rc = bk_finit_path ("modprobe", full, params);
            if (rc != EXECUTION_SUCCESS)
                return rc;
        }
    }
    return EXECUTION_SUCCESS;
}

static int
bk_modprobe_remove_chain (struct bk_modprobe_plan *plan, int dry)
{
    if (plan->nchain <= 0) {
        if (dry) {
            printf ("rmmod %s\n", plan->resolved);
            return EXECUTION_SUCCESS;
        }
        return bk_delete_module_name ("modprobe -r", plan->resolved);
    }

    for (int i = plan->nchain - 1; i >= 0; i--) {
        if (dry) {
            printf ("rmmod %s\n", plan->chain[i]);
        } else {
            int rc = bk_delete_module_name ("modprobe -r", plan->chain[i]);
            if (rc != EXECUTION_SUCCESS)
                return rc;
        }
    }
    return EXECUTION_SUCCESS;
}

static int
bk_modprobe_apply_plan (struct bk_modprobe_plan *plan, int dry, int depth,
                        char visited[][256], int nvisited)
{
    if (plan->blacklist_enforced) {
        builtin_error ("modprobe: module %s is blacklisted for alias-driven autoload", plan->resolved);
        return EXECUTION_FAILURE;
    }
    if (depth > BK_SOFTDEP_DEPTH_MAX) {
        builtin_error ("modprobe: softdep recursion too deep at %s", plan->resolved);
        return EX_USAGE;
    }
    if (bk_seen_plan_name (visited, nvisited, plan->resolved)) {
        builtin_error ("modprobe: softdep cycle detected at %s", plan->resolved);
        return EX_USAGE;
    }
    if (nvisited >= BK_SOFTDEP_DEPTH_MAX + 1) {
        builtin_error ("modprobe: softdep recursion too deep at %s", plan->resolved);
        return EX_USAGE;
    }
    snprintf (visited[nvisited++], 256, "%s", plan->resolved);

    if (plan->remove) {
        if (dry) {
            if (plan->policy.remove_cmd)
                printf ("remove %s\n", plan->policy.remove_cmd);
            else {
                int rc = bk_modprobe_remove_chain (plan, 1);
                if (rc != EXECUTION_SUCCESS)
                    return rc;
            }
            return EXECUTION_SUCCESS;
        }
        if (plan->policy.remove_cmd)
            return bk_run_directive ("remove", plan->policy.remove_cmd);
        return bk_modprobe_remove_chain (plan, 0);
    }

    for (int i = 0; i < plan->n_softdep_pre; i++) {
        int rc = bk_modprobe_apply_name (plan->softdep_pre[i], dry, depth + 1,
                                         visited, nvisited);
        if (rc != EXECUTION_SUCCESS)
            return rc;
    }

    if (plan->policy.install_cmd) {
        if (dry)
            printf ("install %s\n", plan->policy.install_cmd);
        else {
            int rc = bk_run_directive ("install", plan->policy.install_cmd);
            if (rc != EXECUTION_SUCCESS)
                return rc;
        }
    } else if (plan->builtin) {
        if (dry)
            printf ("builtin %s\n", plan->resolved);
    } else {
        int rc = bk_modprobe_apply_chain (plan, dry);
        if (rc != EXECUTION_SUCCESS)
            return rc;
    }

    for (int i = 0; i < plan->n_softdep_post; i++) {
        int rc = bk_modprobe_apply_name (plan->softdep_post[i], dry, depth + 1,
                                         visited, nvisited);
        if (rc != EXECUTION_SUCCESS)
            return rc;
    }
    return EXECUTION_SUCCESS;
}

static int
bk_modprobe_apply_name (const char *name, int dry, int depth,
                        char visited[][256], int nvisited)
{
    struct bk_modprobe_plan plan;
    int rc = bk_plan_modprobe (name, 0, NULL, &plan);
    if (rc == EXECUTION_SUCCESS)
        rc = bk_modprobe_apply_plan (&plan, dry, depth, visited, nvisited);
    bk_modprobe_plan_free (&plan);
    return rc;
}

/* modprobe [-n|--dry-run] [-r] NAME [PARAMS...] — resolve NAME through
   modprobe.d/modules.alias policy. Dry-run prints the full ordered plan;
   non-dry executes the resolved signed-module chain through finit_module(2). */
static int
bk_modprobe_cmd (WORD_LIST *args)
{
    int dry = 0;
    int remove = 0;
    const char *name = NULL;
    WORD_LIST *params = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-n") || !strcmp (w, "--dry-run")) dry = 1;
        else if (!strcmp (w, "-r") || !strcmp (w, "--remove")) remove = 1;
        else if (!name) { name = w; params = p->next; break; }
    }
    if (!name) { builtin_error ("modprobe: [-n] [-r] NAME [PARAMS...]"); return EX_USAGE; }
    if (!bk_valid_module_name (name)) { builtin_error ("modprobe: invalid module name"); return EX_USAGE; }
    struct bk_modprobe_plan plan;
    int rc = bk_plan_modprobe (name, remove, params, &plan);
    if (rc != EXECUTION_SUCCESS) {
        bk_modprobe_plan_free (&plan);
        return rc;
    }
    char visited[BK_SOFTDEP_DEPTH_MAX + 1][256];
    rc = bk_modprobe_apply_plan (&plan, dry, 0, visited, 0);
    bk_modprobe_plan_free (&plan);
    return rc;
}

static const char *
bk_weak_modules_root (void)
{
    const char *s = getenv ("BASHKMOD_MODULES_ROOT");
    if (s && *s)
        return s;
    s = getenv ("BASHKMOD_MODULES_DIR");
    return (s && *s) ? s : "/lib/modules";
}

static int
bk_valid_tree_name (const char *name)
{
    return name && *name && !strchr (name, '/') && strcmp (name, ".") && strcmp (name, "..");
}

static int
bk_is_module_file (const char *name)
{
    size_t n = strlen (name);
    static const char *suffixes[] = {".ko.zst", ".ko.xz", ".ko.gz", ".ko", NULL};
    for (int i = 0; suffixes[i]; i++) {
        size_t sl = strlen (suffixes[i]);
        if (n >= sl && !strcmp (name + n - sl, suffixes[i]))
            return 1;
    }
    return 0;
}

static int
bk_mkdir_p (const char *path)
{
    char tmp[PATH_MAX];
    if (snprintf (tmp, sizeof tmp, "%s", path) >= (int) sizeof tmp) {
        builtin_error ("weak-modules: path too long");
        return EX_USAGE;
    }
    size_t len = strlen (tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir (tmp, 0777) != 0 && errno != EEXIST) {
            builtin_error ("weak-modules: mkdir %s: %s", tmp, strerror (errno));
            return EXECUTION_FAILURE;
        }
        *p = '/';
    }
    if (mkdir (tmp, 0777) != 0 && errno != EEXIST) {
        builtin_error ("weak-modules: mkdir %s: %s", tmp, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bk_mkdir_parent (const char *path)
{
    char tmp[PATH_MAX];
    if (snprintf (tmp, sizeof tmp, "%s", path) >= (int) sizeof tmp) {
        builtin_error ("weak-modules: path too long");
        return EX_USAGE;
    }
    char *slash = strrchr (tmp, '/');
    if (!slash)
        return EXECUTION_SUCCESS;
    *slash = '\0';
    return bk_mkdir_p (tmp);
}

static int
bk_weak_emit_one (const char *src, const char *dst, int dry)
{
    printf ("ln -s %s %s\n", src, dst);
    if (dry)
        return EXECUTION_SUCCESS;

    int rc = bk_mkdir_parent (dst);
    if (rc != EXECUTION_SUCCESS)
        return rc;

    struct stat st;
    if (lstat (dst, &st) == 0) {
        if (S_ISLNK (st.st_mode)) {
            char buf[PATH_MAX];
            ssize_t n = readlink (dst, buf, sizeof buf - 1);
            if (n >= 0) {
                buf[n] = '\0';
                if (!strcmp (buf, src))
                    return EXECUTION_SUCCESS;
            }
        }
        builtin_error ("weak-modules: %s exists", dst);
        return EXECUTION_FAILURE;
    }
    if (errno != ENOENT) {
        builtin_error ("weak-modules: lstat %s: %s", dst, strerror (errno));
        return EXECUTION_FAILURE;
    }
    if (symlink (src, dst) != 0) {
        builtin_error ("weak-modules: symlink %s: %s", dst, strerror (errno));
        return EXECUTION_FAILURE;
    }
    return EXECUTION_SUCCESS;
}

static int
bk_weak_walk (const char *srcdir, const char *rel, const char *dstdir,
              int dry, int *count)
{
    DIR *d = opendir (srcdir);
    if (!d) {
        builtin_error ("weak-modules: opendir %s: %s", srcdir, strerror (errno));
        return EXECUTION_FAILURE;
    }

    char **names = NULL;
    size_t nnames = 0, cnames = 0;
    struct dirent *de;
    while ((de = readdir (d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        if (nnames == cnames) {
            size_t ncap = cnames ? cnames * 2 : 16;
            char **tmp = realloc (names, ncap * sizeof *names);
            if (!tmp) {
                closedir (d);
                bk_free_names (names, nnames);
                builtin_error ("weak-modules: out of memory");
                return EXECUTION_FAILURE;
            }
            names = tmp;
            cnames = ncap;
        }
        names[nnames] = strdup (de->d_name);
        if (!names[nnames]) {
            closedir (d);
            bk_free_names (names, nnames);
            builtin_error ("weak-modules: out of memory");
            return EXECUTION_FAILURE;
        }
        nnames++;
    }
    closedir (d);
    qsort (names, nnames, sizeof *names, bk_name_cmp);

    int rc = EXECUTION_SUCCESS;
    for (size_t i = 0; i < nnames; i++) {
        char src[PATH_MAX], child_rel[PATH_MAX], dst[PATH_MAX];
        if (snprintf (src, sizeof src, "%s/%s", srcdir, names[i]) >= (int) sizeof src
            || snprintf (child_rel, sizeof child_rel, "%s%s%s",
                         rel && *rel ? rel : "", rel && *rel ? "/" : "", names[i]) >= (int) sizeof child_rel) {
            builtin_error ("weak-modules: path too long");
            rc = EX_USAGE;
            break;
        }
        struct stat st;
        if (lstat (src, &st) != 0) {
            builtin_error ("weak-modules: lstat %s: %s", src, strerror (errno));
            rc = EXECUTION_FAILURE;
            break;
        }
        if (S_ISDIR (st.st_mode)) {
            if (!strcmp (names[i], "weak-updates"))
                continue;
            rc = bk_weak_walk (src, child_rel, dstdir, dry, count);
            if (rc != EXECUTION_SUCCESS)
                break;
        } else if ((S_ISREG (st.st_mode) || S_ISLNK (st.st_mode)) && bk_is_module_file (names[i])) {
            if (snprintf (dst, sizeof dst, "%s/%s", dstdir, child_rel) >= (int) sizeof dst) {
                builtin_error ("weak-modules: path too long");
                rc = EX_USAGE;
                break;
            }
            rc = bk_weak_emit_one (src, dst, dry);
            if (rc != EXECUTION_SUCCESS)
                break;
            (*count)++;
        }
    }
    bk_free_names (names, nnames);
    return rc;
}

static int
bk_weak_modules_cmd (WORD_LIST *args)
{
    int dry = 0;
    const char *srcver = NULL, *dstver = NULL;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word->word;
        if (!strcmp (w, "-n") || !strcmp (w, "--dry-run")) {
            dry = 1;
        } else if (!srcver) {
            srcver = w;
        } else if (!dstver) {
            dstver = w;
        } else {
            builtin_error ("weak-modules: [-n] SRCVER DSTVER");
            return EX_USAGE;
        }
    }
    if (!bk_valid_tree_name (srcver) || !bk_valid_tree_name (dstver)) {
        builtin_error ("weak-modules: [-n] SRCVER DSTVER");
        return EX_USAGE;
    }

    const char *root = bk_weak_modules_root ();
    char src[PATH_MAX], dst[PATH_MAX];
    if (snprintf (src, sizeof src, "%s/%s", root, srcver) >= (int) sizeof src
        || snprintf (dst, sizeof dst, "%s/%s/weak-updates", root, dstver) >= (int) sizeof dst) {
        builtin_error ("weak-modules: path too long");
        return EX_USAGE;
    }
    if (!dry) {
        int rc = bk_mkdir_p (dst);
        if (rc != EXECUTION_SUCCESS)
            return rc;
    }
    int count = 0;
    return bk_weak_walk (src, "", dst, dry, &count);
}

int
bashkmod_builtin (WORD_LIST *list)
{
    if (!list) { builtin_usage (); return EX_USAGE; }
    const char *cmd = list->word->word;
    WORD_LIST *args = list->next;
    if (!strcmp (cmd, "load"))   return bk_load_cmd (args);
    if (!strcmp (cmd, "modprobe")) return bk_modprobe_cmd (args);
    if (!strcmp (cmd, "resolve")) return bk_resolve_cmd (args);
    if (!strcmp (cmd, "unload")) return bk_unload_cmd (args);
    if (!strcmp (cmd, "list"))   return bk_list_cmd (args);
    if (!strcmp (cmd, "info"))   return bk_info_cmd (args);
    if (!strcmp (cmd, "deps"))   return bk_deps_cmd (args);
    if (!strcmp (cmd, "aliases") || !strcmp (cmd, "modalias"))
        return bk_aliases_cmd (args);
    if (!strcmp (cmd, "policy")) return bk_policy_cmd (args);
    if (!strcmp (cmd, "weak-modules")) return bk_weak_modules_cmd (args);
    builtin_error ("unknown verb: %s (try load/modprobe/resolve/unload/list/info/deps/aliases/policy/weak-modules)", cmd);
    return EX_USAGE;
}

char *bashkmod_doc[] = {
    "Load/unload/list kernel modules without forking modprobe.",
    "",
    "    bashkmod load PATH [PARAMS]",
    "        finit_module(open(PATH), PARAMS, 0). Needs CAP_SYS_MODULE.",
    "    bashkmod modprobe [-n|--dry-run] [-r] NAME [PARAMS...]",
    "        Resolve NAME through modprobe.d/modules.alias policy and emit the",
    "        action plan. Alias-driven autoload is blocked by blacklist policy;",
    "        explicit NAME is not. Non-dry load walks the deps/softdep chain",
    "        through finit_module(2); install/remove command strings replace",
    "        module action via argv-split exec, refusing shell metacharacters.",
    "    bashkmod resolve NAME [PARAMS...]",
    "        Print the policy decision without acting, including softdep-pre/post.",
    "    bashkmod unload NAME",
    "        delete_module(NAME, O_NONBLOCK). EBUSY if in use.",
    "    bashkmod list",
    "        Parse /proc/modules; emit 'name size refcnt deps state'.",
    "    bashkmod info [-p|--params] NAME",
    "        Print /sys/module/NAME/{coresize,initstate,refcnt,version,parameters/*}.",
    "    bashkmod deps NAME",
    "        Parse ${BASHKMOD_MODULES_DIR or /lib/modules/$(uname -r)}/modules.dep",
    "        and emit the dependency chain in load order, ending with NAME.",
    "    bashkmod aliases MODALIAS",
    "        Parse modules.alias and emit matching module names in file order.",
    "    bashkmod policy NAME",
    "        Report modules.builtin and modprobe.d alias/blacklist/install/remove/options/softdep policy.",
    "    bashkmod weak-modules [-n|--dry-run] SRCVER DSTVER",
    "        Plan or create weak-updates symlinks from SRCVER modules to DSTVER.",
    "",
    "Bash-os ships a monolithic kernel by default — `list` returns",
    "empty, `load` requires an out-of-tree .ko built against the",
    "running kernel's vermagic.",
    (char *)NULL
};

struct builtin bashkmod_struct = {
    "bashkmod",
    bashkmod_builtin,
    BUILTIN_ENABLED,
    bashkmod_doc,
    "bashkmod load|modprobe|resolve|unload|list|info|deps|aliases|policy|weak-modules ARGS",
    0
};
