/* SPDX-License-Identifier: MIT */
/* dmsetup.c — low-level device-mapper control, as a bash builtin.
 *
 * Non-destructive commands (`ls`, `info`, `table`, `status`, `deps`,
 * `targets`, `version`) use the kernel DM ioctl ABI directly. Mutating
 * commands fail closed unless uid 0 also opts in with
 * BASHOS_DMSETUP_ALLOW_MUTATE=1.
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
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <linux/dm-ioctl.h>

#include "loadables.h"

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

#define DMS_BUFSZ 65536

static void
dms_usage (void)
{
    fputs ("Usage:\n\n", stderr);
    fputs ("dmsetup\n", stderr);
    fputs ("\t[--version] [-h|--help]\n", stderr);
    fputs ("\thelp\n", stderr);
    fputs ("\tcreate <dev_name>\n", stderr);
    fputs ("\tremove <device>...\n", stderr);
    fputs ("\tremove_all\n", stderr);
    fputs ("\tsuspend <device>...\n", stderr);
    fputs ("\tresume <device>...\n", stderr);
    fputs ("\tload <device> [<table>|<table_file>]\n", stderr);
    fputs ("\tclear <device>\n", stderr);
    fputs ("\treload <device> [<table>|<table_file>]\n", stderr);
    fputs ("\twipe_table <device>...\n", stderr);
    fputs ("\trename <device> <new_name>\n", stderr);
    fputs ("\tmessage <device> <sector> <message>\n", stderr);
    fputs ("\tls [--target <target_type>] [-o <options>] [--tree]\n", stderr);
    fputs ("\tinfo [<device>...]\n", stderr);
    fputs ("\tdeps [-o <options>] [<device>...]\n", stderr);
    fputs ("\tstatus [<device>...]\n", stderr);
    fputs ("\ttable [<device>...] [--showkeys]\n", stderr);
    fputs ("\ttargets\n", stderr);
    fputs ("\tversion\n", stderr);
}

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
dms_sysfs_ls (void)
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
        char path[512], name[DM_NAME_LEN] = "", majmin[64] = "?:?";
        snprintf (path, sizeof path, "/sys/block/%s/dm/name", de->d_name);
        if (dms_read_first_line (path, name, sizeof name) < 0 || name[0] == '\0')
            snprintf (name, sizeof name, "%s", de->d_name);
        snprintf (path, sizeof path, "/sys/block/%s/dev", de->d_name);
        dms_read_first_line (path, majmin, sizeof majmin);
        printf ("%s\t(%s)\n", name, majmin);
        found = 1;
    }
    closedir (d);

    if (!found) printf ("No devices found\n");
    return EXECUTION_SUCCESS;
}

static int
dms_sysfs_info (void)
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
        snprintf (path, sizeof path, "/sys/block/%s/dm/uuid", de->d_name);
        dms_read_first_line (path, uuid, sizeof uuid);
        snprintf (path, sizeof path, "/sys/block/%s/dm/suspended", de->d_name);
        dms_read_first_line (path, suspended, sizeof suspended);
        snprintf (path, sizeof path, "/sys/block/%s/dm/open_count", de->d_name);
        dms_read_first_line (path, open_count, sizeof open_count);
        snprintf (path, sizeof path, "/sys/block/%s/dev", de->d_name);
        dms_read_first_line (path, majmin, sizeof majmin);

        printf ("Name:              %s\n", name);
        printf ("State:             %s\n", strcmp (suspended, "1") == 0 ? "SUSPENDED" : "ACTIVE");
        printf ("Open count:        %s\n", open_count);
        printf ("Major, minor:      %s\n", majmin);
        printf ("UUID:              %s\n\n", uuid);
        found = 1;
    }
    closedir (d);

    if (!found) printf ("No devices found\n");
    return EXECUTION_SUCCESS;
}

static int
dms_open_control_quiet (void)
{
    return open ("/dev/mapper/control", O_RDWR | O_CLOEXEC);
}

static int
dms_open_control (void)
{
    int fd = dms_open_control_quiet ();
    if (fd < 0) {
        fprintf (stderr, "/dev/mapper/control: open failed: %s\n", strerror (errno));
        fputs ("Failure to communicate with kernel device-mapper driver.\n", stderr);
        fputs ("Command failed.\n", stderr);
    }
    return fd;
}

static struct dm_ioctl *
dms_ioctl_buf (size_t bytes, const char *name)
{
    struct dm_ioctl *io = calloc (1, bytes);
    if (!io) {
        builtin_error ("calloc: %s", strerror (errno));
        return NULL;
    }
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = DM_VERSION_MINOR;
    io->version[2] = DM_VERSION_PATCHLEVEL;
    io->data_size = bytes;
    io->data_start = sizeof (struct dm_ioctl);
    if (name && *name) {
        strncpy (io->name, name, sizeof io->name - 1);
    }
    return io;
}

static int
dms_ioctl (int fd, unsigned long req, struct dm_ioctl *io, const char *what)
{
    if (ioctl (fd, req, io) < 0) {
        fprintf (stderr, "%s: %s\n", what, strerror (errno));
        fputs ("Command failed.\n", stderr);
        return -1;
    }
    return 0;
}

static int
dms_list_devices_ioctl (int fd)
{
    struct dm_ioctl *io = dms_ioctl_buf (DMS_BUFSZ, NULL);
    if (!io) return EXECUTION_FAILURE;
    if (dms_ioctl (fd, DM_LIST_DEVICES, io, "DM_LIST_DEVICES") < 0) {
        free (io);
        return EXECUTION_FAILURE;
    }

    if (io->target_count == 0) {
        printf ("No devices found\n");
        free (io);
        return EXECUTION_SUCCESS;
    }

    char *base = (char *) io + io->data_start;
    struct dm_name_list *nl = (struct dm_name_list *) base;
    for (uint32_t i = 0; i < io->target_count; i++) {
        dev_t dev = (dev_t) nl->dev;
        printf ("%s\t(%u:%u)\n", nl->name, major (dev), minor (dev));
        if (nl->next == 0) break;
        nl = (struct dm_name_list *) ((char *) nl + nl->next);
    }

    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_info_one (int fd, const char *name)
{
    struct dm_ioctl *io = dms_ioctl_buf (DMS_BUFSZ, name);
    if (!io) return EXECUTION_FAILURE;
    if (dms_ioctl (fd, DM_DEV_STATUS, io, "DM_DEV_STATUS") < 0) {
        free (io);
        return EXECUTION_FAILURE;
    }
    dev_t dev = (dev_t) io->dev;
    printf ("Name:              %s\n", io->name);
    printf ("State:             %s\n", (io->flags & DM_SUSPEND_FLAG) ? "SUSPENDED" : "ACTIVE");
    printf ("Open count:        %d\n", io->open_count);
    printf ("Event number:      %u\n", io->event_nr);
    printf ("Major, minor:      %u, %u\n", major (dev), minor (dev));
    printf ("Number of targets: %u\n", io->target_count);
    printf ("UUID:              %s\n\n", io->uuid);
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_info_ioctl (int fd, WORD_LIST *args)
{
    if (args) {
        int rc = EXECUTION_SUCCESS;
        for (WORD_LIST *p = args; p; p = p->next)
            if (p->word && p->word->word && dms_info_one (fd, p->word->word) != EXECUTION_SUCCESS)
                rc = EXECUTION_FAILURE;
        return rc;
    }

    struct dm_ioctl *io = dms_ioctl_buf (DMS_BUFSZ, NULL);
    if (!io) return EXECUTION_FAILURE;
    if (dms_ioctl (fd, DM_LIST_DEVICES, io, "DM_LIST_DEVICES") < 0) {
        free (io);
        return EXECUTION_FAILURE;
    }
    if (io->target_count == 0) {
        printf ("No devices found\n");
        free (io);
        return EXECUTION_SUCCESS;
    }

    int rc = EXECUTION_SUCCESS;
    char *base = (char *) io + io->data_start;
    struct dm_name_list *nl = (struct dm_name_list *) base;
    for (uint32_t i = 0; i < io->target_count; i++) {
        if (dms_info_one (fd, nl->name) != EXECUTION_SUCCESS) rc = EXECUTION_FAILURE;
        if (nl->next == 0) break;
        nl = (struct dm_name_list *) ((char *) nl + nl->next);
    }
    free (io);
    return rc;
}

static int
dms_table_one (int fd, const char *name, int table_mode)
{
    struct dm_ioctl *io = dms_ioctl_buf (DMS_BUFSZ, name);
    if (!io) return EXECUTION_FAILURE;
    if (table_mode) io->flags |= DM_STATUS_TABLE_FLAG;
    if (dms_ioctl (fd, DM_TABLE_STATUS, io, "DM_TABLE_STATUS") < 0) {
        free (io);
        return EXECUTION_FAILURE;
    }

    char *first = (char *) io + io->data_start;
    struct dm_target_spec *ts = (struct dm_target_spec *) first;
    for (uint32_t i = 0; i < io->target_count; i++) {
        const char *params = (const char *) (ts + 1);
        printf ("%llu %llu %s %s\n",
                (unsigned long long) ts->sector_start,
                (unsigned long long) ts->length,
                ts->target_type,
                params);
        if (ts->next == 0) break;
        ts = (struct dm_target_spec *) (first + ts->next);
    }
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_table_ioctl (int fd, WORD_LIST *args, int table_mode)
{
    if (!args) return dms_list_devices_ioctl (fd);
    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = args; p; p = p->next)
        if (p->word && p->word->word && dms_table_one (fd, p->word->word, table_mode) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
    return rc;
}

static int
dms_deps_one (int fd, const char *name)
{
    struct dm_ioctl *io = dms_ioctl_buf (DMS_BUFSZ, name);
    if (!io) return EXECUTION_FAILURE;
    if (dms_ioctl (fd, DM_TABLE_DEPS, io, "DM_TABLE_DEPS") < 0) {
        free (io);
        return EXECUTION_FAILURE;
    }
    struct dm_target_deps *deps = (struct dm_target_deps *) ((char *) io + io->data_start);
    printf ("%s: %u dependencies\t:", name, deps->count);
    for (uint32_t i = 0; i < deps->count; i++) {
        dev_t dev = (dev_t) deps->dev[i];
        printf (" (%u, %u)", major (dev), minor (dev));
    }
    putchar ('\n');
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_deps_ioctl (int fd, WORD_LIST *args)
{
    if (!args) return dms_list_devices_ioctl (fd);
    int rc = EXECUTION_SUCCESS;
    for (WORD_LIST *p = args; p; p = p->next)
        if (p->word && p->word->word && dms_deps_one (fd, p->word->word) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
    return rc;
}

static int
dms_targets_ioctl (int fd)
{
    struct dm_ioctl *io = dms_ioctl_buf (DMS_BUFSZ, NULL);
    if (!io) return EXECUTION_FAILURE;
    if (dms_ioctl (fd, DM_LIST_VERSIONS, io, "DM_LIST_VERSIONS") < 0) {
        free (io);
        return EXECUTION_FAILURE;
    }

    char *base = (char *) io + io->data_start;
    struct dm_target_versions *tv = (struct dm_target_versions *) base;
    for (uint32_t i = 0; i < io->target_count; i++) {
        printf ("%-16s v%u.%u.%u\n", tv->name, tv->version[0], tv->version[1], tv->version[2]);
        if (tv->next == 0) break;
        tv = (struct dm_target_versions *) ((char *) tv + tv->next);
    }
    free (io);
    return EXECUTION_SUCCESS;
}

static int
dms_version_cmd (void)
{
    printf ("Library version:   bash-os dm-ioctl shim\n");
    int fd = open ("/dev/mapper/control", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf ("Driver version:    unavailable\n");
        return EXECUTION_SUCCESS;
    }

    struct dm_ioctl *io = dms_ioctl_buf (sizeof (struct dm_ioctl), NULL);
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

static int
dms_mutating_allowed (const char *verb)
{
    const char *allow = getenv ("BASHOS_DMSETUP_ALLOW_MUTATE");
    if (geteuid () == 0 && allow && strcmp (allow, "1") == 0) return 1;
    fprintf (stderr, "dmsetup: %s requires root and BASHOS_DMSETUP_ALLOW_MUTATE=1\n", verb);
    return 0;
}

static int
dms_mutating_stub (const char *verb)
{
    if (!dms_mutating_allowed (verb)) return EXECUTION_FAILURE;
    fprintf (stderr, "dmsetup: %s mutating backend is not implemented in this bash-os build\n", verb);
    return EXECUTION_FAILURE;
}

static size_t
dms_align8 (size_t n)
{
    return (n + 7U) & ~7U;
}

static int
dms_table_parts (const char *table, unsigned long long *start,
                 unsigned long long *length, char *target, size_t target_sz,
                 const char **params)
{
    char *end = NULL;
    const char *p = table;

    while (*p == ' ' || *p == '\t') p++;
    errno = 0;
    *start = strtoull (p, &end, 10);
    if (errno || end == p) return -1;
    p = end;

    while (*p == ' ' || *p == '\t') p++;
    errno = 0;
    *length = strtoull (p, &end, 10);
    if (errno || end == p) return -1;
    p = end;

    while (*p == ' ' || *p == '\t') p++;
    size_t i = 0;
    while (*p && *p != ' ' && *p != '\t') {
        if (i + 1 < target_sz) target[i++] = *p;
        p++;
    }
    target[i] = '\0';
    if (target[0] == '\0') return -1;

    while (*p == ' ' || *p == '\t') p++;
    *params = p;
    return 0;
}

static int
dms_load_table (int fd, const char *name, const char *table)
{
    unsigned long long start = 0, length = 0;
    char target[DM_MAX_TYPE_NAME] = "";
    const char *params = "";
    if (dms_table_parts (table, &start, &length, target, sizeof target, &params) < 0) {
        fprintf (stderr, "dmsetup: invalid table line\n");
        return EXECUTION_FAILURE;
    }

    size_t param_len = strlen (params) + 1;
    size_t spec_len = dms_align8 (sizeof (struct dm_target_spec) + param_len);
    size_t bytes = sizeof (struct dm_ioctl) + spec_len;
    struct dm_ioctl *io = dms_ioctl_buf (bytes, name);
    if (!io) return EXECUTION_FAILURE;
    io->target_count = 1;

    struct dm_target_spec *spec = (struct dm_target_spec *) ((char *) io + io->data_start);
    spec->sector_start = start;
    spec->length = length;
    spec->status = 0;
    spec->next = (uint32_t) spec_len;
    strncpy (spec->target_type, target, sizeof spec->target_type - 1);
    memcpy ((char *) (spec + 1), params, param_len);

    int rc = dms_ioctl (fd, DM_TABLE_LOAD, io, "DM_TABLE_LOAD") < 0
        ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    free (io);
    return rc;
}

static int
dms_resume_device (int fd, const char *name)
{
    struct dm_ioctl *io = dms_ioctl_buf (sizeof (struct dm_ioctl), name);
    if (!io) return EXECUTION_FAILURE;
    int rc = dms_ioctl (fd, DM_DEV_SUSPEND, io, "DM_DEV_SUSPEND") < 0
        ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    free (io);
    return rc;
}

static int
dms_simple_device_cmd (int fd, const char *name, unsigned long req, const char *label, uint32_t flags)
{
    struct dm_ioctl *io = dms_ioctl_buf (sizeof (struct dm_ioctl), name);
    if (!io) return EXECUTION_FAILURE;
    io->flags = flags;
    int rc = dms_ioctl (fd, req, io, label) < 0 ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    free (io);
    return rc;
}

static int
dms_first_device_and_table (WORD_LIST *args, const char **name, const char **table, int *notable)
{
    *name = NULL;
    *table = NULL;
    *notable = 0;

    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word ? p->word->word : NULL;
        if (!w) continue;
        if (!strcmp (w, "-n") || !strcmp (w, "--notable")) {
            *notable = 1;
            continue;
        }
        if (!strcmp (w, "--table")) {
            if (!p->next || !p->next->word || !p->next->word->word) return -1;
            *table = p->next->word->word;
            p = p->next;
            continue;
        }
        if (w[0] == '-') {
            if ((!strcmp (w, "-u") || !strcmp (w, "--uuid") || !strcmp (w, "--readahead"))
                && p->next)
                p = p->next;
            continue;
        }
        if (!*name) *name = w;
        else if (!*table) *table = w;
    }

    return *name ? 0 : -1;
}

static int
dms_create_cmd (WORD_LIST *args)
{
    const char *name, *table;
    int notable;
    if (dms_first_device_and_table (args, &name, &table, &notable) < 0) {
        fprintf (stderr, "dmsetup: create requires a device name\n");
        return EXECUTION_FAILURE;
    }

    int fd = dms_open_control ();
    if (fd < 0) return EXECUTION_FAILURE;
    int rc = dms_simple_device_cmd (fd, name, DM_DEV_CREATE, "DM_DEV_CREATE", 0);
    if (rc == EXECUTION_SUCCESS && !notable && table && *table) {
        rc = dms_load_table (fd, name, table);
        if (rc == EXECUTION_SUCCESS) rc = dms_resume_device (fd, name);
        if (rc != EXECUTION_SUCCESS)
            dms_simple_device_cmd (fd, name, DM_DEV_REMOVE, "DM_DEV_REMOVE", 0);
    }
    close (fd);
    return rc;
}

static int
dms_load_cmd (WORD_LIST *args)
{
    const char *name, *table;
    int notable;
    if (dms_first_device_and_table (args, &name, &table, &notable) < 0 || !table || !*table) {
        fprintf (stderr, "dmsetup: load requires a device name and table\n");
        return EXECUTION_FAILURE;
    }
    (void) notable;

    int fd = dms_open_control ();
    if (fd < 0) return EXECUTION_FAILURE;
    int rc = dms_load_table (fd, name, table);
    close (fd);
    return rc;
}

static int
dms_each_device_cmd (WORD_LIST *args, unsigned long req, const char *label, uint32_t flags)
{
    int fd = dms_open_control ();
    if (fd < 0) return EXECUTION_FAILURE;

    int rc = EXECUTION_SUCCESS;
    int saw = 0;
    for (WORD_LIST *p = args; p; p = p->next) {
        const char *w = p->word ? p->word->word : NULL;
        if (!w) continue;
        if (w[0] == '-') continue;
        saw = 1;
        if (dms_simple_device_cmd (fd, w, req, label, flags) != EXECUTION_SUCCESS)
            rc = EXECUTION_FAILURE;
    }
    if (!saw) {
        fprintf (stderr, "dmsetup: device name required\n");
        rc = EXECUTION_FAILURE;
    }
    close (fd);
    return rc;
}

static int
dms_remove_all_cmd (void)
{
    int fd = dms_open_control ();
    if (fd < 0) return EXECUTION_FAILURE;
    struct dm_ioctl *io = dms_ioctl_buf (sizeof (struct dm_ioctl), NULL);
    if (!io) {
        close (fd);
        return EXECUTION_FAILURE;
    }
    int rc = dms_ioctl (fd, DM_REMOVE_ALL, io, "DM_REMOVE_ALL") < 0
        ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
    free (io);
    close (fd);
    return rc;
}

static int
dms_mutating_cmd (const char *verb, WORD_LIST *args)
{
    if (!dms_mutating_allowed (verb)) return EXECUTION_FAILURE;

    if (!strcmp (verb, "create")) return dms_create_cmd (args);
    if (!strcmp (verb, "load") || !strcmp (verb, "reload")) return dms_load_cmd (args);
    if (!strcmp (verb, "remove")) return dms_each_device_cmd (args, DM_DEV_REMOVE, "DM_DEV_REMOVE", 0);
    if (!strcmp (verb, "remove_all")) return dms_remove_all_cmd ();
    if (!strcmp (verb, "suspend")) return dms_each_device_cmd (args, DM_DEV_SUSPEND, "DM_DEV_SUSPEND", DM_SUSPEND_FLAG);
    if (!strcmp (verb, "resume")) return dms_each_device_cmd (args, DM_DEV_SUSPEND, "DM_DEV_SUSPEND", 0);
    if (!strcmp (verb, "clear") || !strcmp (verb, "wipe_table"))
        return dms_each_device_cmd (args, DM_TABLE_CLEAR, "DM_TABLE_CLEAR", 0);
    return dms_mutating_stub (verb);
}

int
dmsetup_builtin (WORD_LIST *list)
{
    if (!list) {
        dms_usage ();
        return EXECUTION_FAILURE;
    }

    while (list && list->word && list->word->word
           && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--version")) return dms_version_cmd ();
        if (!strcmp (w, "-h") || !strcmp (w, "--help")) { dms_usage (); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-v") || !strcmp (w, "--verbose") || !strcmp (w, "-f") || !strcmp (w, "--force")
            || !strcmp (w, "-r") || !strcmp (w, "--readonly") || !strcmp (w, "--noopencount")
            || !strcmp (w, "--noflush") || !strcmp (w, "--nolockfs") || !strcmp (w, "--inactive")
            || !strcmp (w, "-c") || !strcmp (w, "-C") || !strcmp (w, "--columns")
            || !strcmp (w, "--noheadings") || !strcmp (w, "--tree") || !strcmp (w, "--showkeys")
            || !strcmp (w, "--concise") || !strcmp (w, "--deferred") || !strcmp (w, "--retry")) {
            list = list->next;
            continue;
        }
        if (!strcmp (w, "--manglename") || !strcmp (w, "--udevcookie") || !strcmp (w, "--readahead")
            || !strcmp (w, "-o") || !strcmp (w, "--options") || !strcmp (w, "-O") || !strcmp (w, "--sort")
            || !strcmp (w, "-S") || !strcmp (w, "--select") || !strcmp (w, "--headings")
            || !strcmp (w, "--separator") || !strcmp (w, "--target") || !strcmp (w, "--exec")
            || !strcmp (w, "-j") || !strcmp (w, "--major") || !strcmp (w, "-m") || !strcmp (w, "--minor")
            || !strcmp (w, "-u") || !strcmp (w, "--uuid")) {
            if (!list->next) {
                fprintf (stderr, "dmsetup: option %s requires an argument\n", w);
                fputs ("Couldn't process command line.\n", stderr);
                return EXECUTION_FAILURE;
            }
            list = list->next->next;
            continue;
        }
        fprintf (stderr, "dmsetup: unrecognized option '%s'\n", w);
        fputs ("Couldn't process command line.\n", stderr);
        return EXECUTION_FAILURE;
    }

    if (!list || !list->word || !list->word->word) {
        dms_usage ();
        return EXECUTION_FAILURE;
    }

    const char *verb = list->word->word;
    WORD_LIST *args = list->next;

    if (!strcmp (verb, "help")) { dms_usage (); return EXECUTION_SUCCESS; }
    if (!strcmp (verb, "version")) return dms_version_cmd ();
    if (!strcmp (verb, "ls")) {
        int fd = dms_open_control_quiet ();
        if (fd < 0) return dms_sysfs_ls ();
        int rc = dms_list_devices_ioctl (fd);
        close (fd);
        return rc;
    }
    if (!strcmp (verb, "info")) {
        int fd = dms_open_control_quiet ();
        if (fd < 0) return dms_sysfs_info ();
        int rc = dms_info_ioctl (fd, args);
        close (fd);
        return rc;
    }
    if (!strcmp (verb, "table") || !strcmp (verb, "status")
        || !strcmp (verb, "deps") || !strcmp (verb, "targets")) {
        int fd = dms_open_control ();
        if (fd < 0) return EXECUTION_FAILURE;
        int rc;
        if (!strcmp (verb, "table")) rc = dms_table_ioctl (fd, args, 1);
        else if (!strcmp (verb, "status")) rc = dms_table_ioctl (fd, args, 0);
        else if (!strcmp (verb, "deps")) rc = dms_deps_ioctl (fd, args);
        else rc = dms_targets_ioctl (fd);
        close (fd);
        return rc;
    }

    if (!strcmp (verb, "create") || !strcmp (verb, "load") || !strcmp (verb, "remove")
        || !strcmp (verb, "remove_all") || !strcmp (verb, "suspend") || !strcmp (verb, "resume")
        || !strcmp (verb, "rename") || !strcmp (verb, "message") || !strcmp (verb, "clear")
        || !strcmp (verb, "wipe_table") || !strcmp (verb, "reload"))
        return dms_mutating_cmd (verb, args);

    fputs ("Unknown command.\n", stderr);
    dms_usage ();
    return EXECUTION_FAILURE;
}

char *dmsetup_doc[] = {
    "Low-level device-mapper control.",
    "",
    "    dmsetup ls|info|table|status|deps|targets|version [ARGS...]",
    "    dmsetup create|load|remove|remove_all|suspend|resume|rename|message|clear|wipe_table|reload ...",
    "",
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
