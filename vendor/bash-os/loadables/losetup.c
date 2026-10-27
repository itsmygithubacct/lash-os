/* SPDX-License-Identifier: MIT */
/* losetup.c — set up and control loop devices, as a bash builtin.
 *
 *   losetup [-l|-a]                 list active loop devices
 *   losetup -f                      print the first free loop device
 *   losetup -f --show [-r] [-P] [-o OFF] [--sizelimit N] FILE   attach FILE
 *   losetup /dev/loopN [-r] [-P] [-o OFF] FILE                  attach to a device
 *   losetup -d /dev/loopN           detach
 *   losetup -j FILE                 list loops backed by FILE
 *
 * Attach/detach require suitable permissions. Listing reads /sys/block/loop*.
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
#include <limits.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/loop.h>

#include "loadables.h"

#ifndef LOOP_CTL_GET_FREE
#  define LOOP_CTL_GET_FREE 0x4C82
#endif

static int
parse_bytes (const char *s, uint64_t *out)
{
    char *end;
    if (!*s || *s == '-' || isspace ((unsigned char) *s)) return -1;
    errno = 0;
    unsigned long long value = strtoull (s, &end, 0);
    if (errno || end == s || *end || value > UINT64_MAX) return -1;
    *out = (uint64_t) value;
    return 0;
}

static int
read_first_line (const char *path, char *buf, size_t n)
{
    int fd = open (path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t r = read (fd, buf, n - 1);
    int saved = errno;
    close (fd);
    if (r < 0) { errno = saved; return -1; }
    buf[r > 0 ? r : 0] = '\0';
    size_t l = strlen (buf);
    while (l && (buf[l-1] == '\n' || buf[l-1] == '\r')) buf[--l] = '\0';
    return 0;
}

/* List loop devices. If only_backing != NULL, restrict to loops backed by it. */
static int
list_loops (int header, const char *only_backing)
{
    if (header) printf ("%-14s %5s %9s %4s %s\n", "NAME", "RO", "OFFSET", "DIO", "BACK-FILE");
    DIR *d = opendir ("/sys/block");
    /* No block layer (CONFIG_BLOCK off) means zero loop devices, not an error;
       the header above still prints, matching util-linux's unconditional header. */
    if (!d) {
        if (errno == ENOENT) return EXECUTION_SUCCESS;
        builtin_error ("/sys/block: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    struct dirent *de;
    while ((de = readdir (d))) {
        if (strncmp (de->d_name, "loop", 4) != 0) continue;
        const char *digit = de->d_name + 4;
        if (!isdigit ((unsigned char)*digit)) continue;
        while (isdigit ((unsigned char)*digit)) digit++;
        if (*digit) continue;
        char path[512], back[PATH_MAX + 1] = "", off[64] = "0", ro[8] = "0", dio[8] = "0";
        snprintf (path, sizeof path, "/sys/block/%s/loop/backing_file", de->d_name);
        if (read_first_line (path, back, sizeof back) < 0 || back[0] == '\0')
            continue;  /* not an attached loop */
        if (only_backing && strcmp (back, only_backing) != 0) {
            struct stat a, b;
            if (stat (back, &a) < 0 || stat (only_backing, &b) < 0 ||
                a.st_dev != b.st_dev || a.st_ino != b.st_ino) continue;
        }
        snprintf (path, sizeof path, "/sys/block/%s/loop/offset", de->d_name);
        read_first_line (path, off, sizeof off);
        snprintf (path, sizeof path, "/sys/block/%s/ro", de->d_name);
        read_first_line (path, ro, sizeof ro);
        snprintf (path, sizeof path, "/sys/block/%s/loop/dio", de->d_name);
        read_first_line (path, dio, sizeof dio);
        printf ("/dev/%-9s %5s %9s %4s %s\n", de->d_name, ro, off, dio, back);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

static int
get_free (char *out, size_t n)
{
    int ctl = open ("/dev/loop-control", O_RDWR | O_CLOEXEC);
    if (ctl < 0) { builtin_error ("/dev/loop-control: %s", strerror (errno)); return -1; }
    int idx = ioctl (ctl, LOOP_CTL_GET_FREE);
    int saved = errno;
    close (ctl);
    if (idx < 0) { builtin_error ("LOOP_CTL_GET_FREE: %s", strerror (saved)); return -1; }
    snprintf (out, n, "/dev/loop%d", idx);
    return 0;
}

static int
attach (const char *loopdev, const char *file, uint64_t offset, uint64_t sizelimit, int readonly, int partscan)
{
    int ffd = open (file, (readonly ? O_RDONLY : O_RDWR) | O_CLOEXEC);
    if (ffd < 0 && !readonly && (errno == EACCES || errno == EROFS)) {
        ffd = open (file, O_RDONLY | O_CLOEXEC);
        if (ffd >= 0) readonly = 1;
    }
    if (ffd < 0) { builtin_error ("%s: %s", file, strerror (errno)); return -1; }
    int lfd = open (loopdev, (readonly ? O_RDONLY : O_RDWR) | O_CLOEXEC);
    if (lfd < 0) { builtin_error ("%s: %s", loopdev, strerror (errno)); close (ffd); return -1; }

    if (ioctl (lfd, LOOP_SET_FD, ffd) < 0) {
        builtin_error ("%s: LOOP_SET_FD: %s", loopdev, strerror (errno));
        close (lfd); close (ffd); return -1;
    }
    struct loop_info64 info;
    memset (&info, 0, sizeof info);
    info.lo_offset = offset;
    info.lo_sizelimit = sizelimit;
    if (readonly) info.lo_flags |= LO_FLAGS_READ_ONLY;
    if (partscan)  info.lo_flags |= LO_FLAGS_PARTSCAN;
    strncpy ((char *) info.lo_file_name, file, sizeof info.lo_file_name - 1);
    if (ioctl (lfd, LOOP_SET_STATUS64, &info) < 0) {
        builtin_error ("%s: LOOP_SET_STATUS64: %s", loopdev, strerror (errno));
        /* We own this association only after our LOOP_SET_FD succeeded. */
        if (ioctl (lfd, LOOP_CLR_FD, 0) < 0)
            builtin_error ("%s: rollback LOOP_CLR_FD: %s", loopdev, strerror (errno));
        close (lfd); close (ffd); return -1;
    }
    close (lfd); close (ffd);
    return 0;
}

static int
losetup_run (WORD_LIST *list)
{
    int do_list = 0, do_free = 0, do_show = 0, do_detach = 0;
    int readonly = 0, partscan = 0, config_options = 0;
    uint64_t offset = 0, sizelimit = 0;
    const char *j_arg = NULL;
    const char *loopdev = NULL, *file = NULL;

    int end_options = 0;
    while (list) {
        const char *w = list->word->word;
        if (!end_options && !strcmp (w, "--")) {
            end_options = 1; list = list->next; continue;
        }
        if (end_options || w[0] != '-' || !w[1]) {
            if (!loopdev) loopdev = w;
            else if (!file) file = w;
            else { builtin_error ("too many operands"); return EX_USAGE; }
            list = list->next; continue;
        }
        if (!strcmp (w, "--help")) { extern char *losetup_doc[]; for (char **lp = losetup_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-l") || !strcmp (w, "-a") || !strcmp (w, "--list") || !strcmp (w, "--all")) { do_list = 1; list = list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--find")) { do_free = 1; list = list->next; continue; }
        if (!strcmp (w, "--show")) { do_show = 1; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--detach")) { do_detach = 1; list = list->next; continue; }
        if (!strcmp (w, "-r") || !strcmp (w, "--read-only")) { readonly = 1; config_options = 1; list = list->next; continue; }
        if (!strcmp (w, "-P") || !strcmp (w, "--partscan")) { partscan = 1; config_options = 1; list = list->next; continue; }
        if (!strcmp (w, "-o") || !strcmp (w, "--offset") || !strcmp (w, "--sizelimit")) {
            if (!list->next) { builtin_error ("%s requires an argument", w); return EX_USAGE; }
            list = list->next;
            uint64_t *target = !strcmp (w, "--sizelimit") ? &sizelimit : &offset;
            if (parse_bytes (list->word->word, target) < 0) {
                builtin_error ("%s: invalid byte count: %s", w, list->word->word);
                return EX_USAGE;
            }
            config_options = 1;
            list = list->next;
            continue;
        }
        if (!strcmp (w, "-j") || !strcmp (w, "--associated")) { if (!list->next){builtin_error("-j requires an argument");return EX_USAGE;} list=list->next; j_arg=list->word->word; list=list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    int modes = !!(do_list || j_arg) + !!do_free + !!do_detach;
    if (modes > 1 || (do_detach && (file || do_show || config_options)) ||
        (do_free && file) || (do_list && loopdev) || (j_arg && loopdev) ||
        (do_show && !do_free && !(loopdev && file))) {
        builtin_error ("incompatible options or operands"); return EX_USAGE;
    }

    if (j_arg)                       return list_loops (1, j_arg);
    if (do_detach) {
        const char *dev = loopdev;
        if (!dev) { builtin_error ("-d requires a loop device"); return EX_USAGE; }
        int fd = open (dev, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { builtin_error ("%s: %s", dev, strerror (errno)); return EXECUTION_FAILURE; }
        int rc = ioctl (fd, LOOP_CLR_FD, 0);
        int saved = errno;
        close (fd);
        if (rc < 0) { builtin_error ("%s: LOOP_CLR_FD: %s", dev, strerror (saved)); return EXECUTION_FAILURE; }
        return EXECUTION_SUCCESS;
    }

    if (do_free && (do_show || loopdev)) {
        /* -f --show FILE  (or -f FILE): find a free device and attach. */
        const char *f = loopdev;
        if (!f) { builtin_error ("-f --show requires a FILE"); return EX_USAGE; }
        char dev[64];
        if (get_free (dev, sizeof dev) < 0) return EXECUTION_FAILURE;
        if (attach (dev, f, offset, sizelimit, readonly, partscan) < 0) return EXECUTION_FAILURE;
        if (do_show) printf ("%s\n", dev);
        return EXECUTION_SUCCESS;
    }
    if (do_free) {
        char dev[64];
        if (get_free (dev, sizeof dev) < 0) return EXECUTION_FAILURE;
        printf ("%s\n", dev);
        return EXECUTION_SUCCESS;
    }

    if (loopdev && file) {
        if (attach (loopdev, file, offset, sizelimit, readonly, partscan) < 0) return EXECUTION_FAILURE;
        if (do_show) printf ("%s\n", loopdev);
        return EXECUTION_SUCCESS;
    }

    if (do_list || !loopdev) return list_loops (1, NULL);

    builtin_usage ();
    return EX_USAGE;
}

int
losetup_builtin (WORD_LIST *list)
{
    /* stdio error indicators survive calls in the same shell. */
    clearerr (stdout);
    int rc = losetup_run (list);
    if (fflush (stdout) == EOF || ferror (stdout)) {
        builtin_error ("write error: %s", strerror (errno));
        return EXECUTION_FAILURE;
    }
    return rc;
}

char *losetup_doc[] = {
    "Set up and control loop devices.",
    "",
    "    losetup [-l|-a]                 list active loop devices",
    "    losetup -f                      print the first free loop device",
    "    losetup -f --show [-r] [-P] [-o N] [--sizelimit N] FILE   attach FILE",
    "    losetup /dev/loopN [-r] [-P] [-o N] FILE                  attach to a device",
    "    losetup -d /dev/loopN           detach",
    "    losetup -j FILE                 list loops backed by FILE",
    "",
    "Attach/detach require suitable permissions; listing reads /sys/block/loop*.",
    (char *) NULL
};

struct builtin losetup_struct = {
    "losetup",
    losetup_builtin,
    BUILTIN_ENABLED,
    losetup_doc,
    "losetup [-l|-a|-f|-d|-j] [--show] [-r] [-P] [-o OFF] [--sizelimit N] [loopdev] [file]",
    0
};
