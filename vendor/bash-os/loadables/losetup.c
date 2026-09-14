/* SPDX-License-Identifier: MIT */
/* losetup.c — set up and control loop devices, as a bash builtin.
 *
 *   losetup [-l|-a]                 list active loop devices
 *   losetup -f                      print the first free loop device
 *   losetup -f --show [-r] [-o OFF] [--sizelimit N] FILE   attach FILE
 *   losetup /dev/loopN [-r] [-o OFF] FILE                  attach to a device
 *   losetup -d /dev/loopN           detach
 *   losetup -j FILE                 list loops backed by FILE
 *
 * Attach/detach require root. Listing reads /sys/block/loop*.
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
#include <linux/loop.h>

#include "loadables.h"

#ifndef LOOP_CTL_GET_FREE
#  define LOOP_CTL_GET_FREE 0x4C82
#endif

static int
read_first_line (const char *path, char *buf, size_t n)
{
    int fd = open (path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read (fd, buf, n - 1);
    close (fd);
    if (r < 0) return -1;
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
    if (!d) return EXECUTION_SUCCESS;
    struct dirent *de;
    while ((de = readdir (d))) {
        if (strncmp (de->d_name, "loop", 4) != 0) continue;
        if (de->d_name[4] < '0' || de->d_name[4] > '9') continue;
        char path[512], back[512] = "", off[64] = "0", ro[8] = "0";
        snprintf (path, sizeof path, "/sys/block/%s/loop/backing_file", de->d_name);
        if (read_first_line (path, back, sizeof back) < 0 || back[0] == '\0')
            continue;  /* not an attached loop */
        if (only_backing && strcmp (back, only_backing) != 0) continue;
        snprintf (path, sizeof path, "/sys/block/%s/loop/offset", de->d_name);
        read_first_line (path, off, sizeof off);
        snprintf (path, sizeof path, "/sys/block/%s/ro", de->d_name);
        read_first_line (path, ro, sizeof ro);
        printf ("/dev/%-9s %5s %9s %4s %s\n", de->d_name, ro, off, "0", back);
    }
    closedir (d);
    return EXECUTION_SUCCESS;
}

static int
get_free (char *out, size_t n)
{
    int ctl = open ("/dev/loop-control", O_RDWR);
    if (ctl < 0) { builtin_error ("/dev/loop-control: %s", strerror (errno)); return -1; }
    int idx = ioctl (ctl, LOOP_CTL_GET_FREE);
    close (ctl);
    if (idx < 0) { builtin_error ("LOOP_CTL_GET_FREE: %s", strerror (errno)); return -1; }
    snprintf (out, n, "/dev/loop%d", idx);
    return 0;
}

static int
attach (const char *loopdev, const char *file, uint64_t offset, uint64_t sizelimit, int readonly, int partscan)
{
    int ffd = open (file, readonly ? O_RDONLY : O_RDWR);
    if (ffd < 0 && !readonly) ffd = open (file, O_RDONLY);
    if (ffd < 0) { builtin_error ("%s: %s", file, strerror (errno)); return -1; }
    int lfd = open (loopdev, readonly ? O_RDONLY : O_RDWR);
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
        ioctl (lfd, LOOP_CLR_FD, 0);
        close (lfd); close (ffd); return -1;
    }
    close (lfd); close (ffd);
    return 0;
}

int
losetup_builtin (WORD_LIST *list)
{
    int do_list = 0, do_free = 0, do_show = 0, do_detach = 0;
    int readonly = 0, partscan = 0;
    uint64_t offset = 0, sizelimit = 0;
    const char *j_arg = NULL;
    const char *loopdev = NULL, *file = NULL;

    while (list && list->word->word[0] == '-' && list->word->word[1]) {
        const char *w = list->word->word;
        if (!strcmp (w, "--")) { list = list->next; break; }
        if (!strcmp (w, "--help")) { extern char *losetup_doc[]; for (char **lp = losetup_doc; *lp; lp++) puts (*lp); return EXECUTION_SUCCESS; }
        if (!strcmp (w, "-l") || !strcmp (w, "-a") || !strcmp (w, "--list") || !strcmp (w, "--all")) { do_list = 1; list = list->next; continue; }
        if (!strcmp (w, "-f") || !strcmp (w, "--find")) { do_free = 1; list = list->next; continue; }
        if (!strcmp (w, "--show")) { do_show = 1; list = list->next; continue; }
        if (!strcmp (w, "-d") || !strcmp (w, "--detach")) { do_detach = 1; list = list->next; continue; }
        if (!strcmp (w, "-r") || !strcmp (w, "--read-only")) { readonly = 1; list = list->next; continue; }
        if (!strcmp (w, "-P") || !strcmp (w, "--partscan")) { partscan = 1; list = list->next; continue; }
        if (!strcmp (w, "-o") || !strcmp (w, "--offset")) { if (!list->next){builtin_error("-o requires an argument");return EX_USAGE;} list=list->next; offset=strtoull(list->word->word,NULL,0); list=list->next; continue; }
        if (!strcmp (w, "--sizelimit")) { if (!list->next){builtin_error("--sizelimit requires an argument");return EX_USAGE;} list=list->next; sizelimit=strtoull(list->word->word,NULL,0); list=list->next; continue; }
        if (!strcmp (w, "-j") || !strcmp (w, "--associated")) { if (!list->next){builtin_error("-j requires an argument");return EX_USAGE;} list=list->next; j_arg=list->word->word; list=list->next; continue; }
        builtin_error ("unknown option: %s", w); builtin_usage (); return EX_USAGE;
    }

    /* Positionals: [loopdev] [file], or just [file] with -f --show. */
    if (list) { loopdev = list->word->word; list = list->next; }
    if (list) { file = list->word->word; list = list->next; }

    if (j_arg)                       return list_loops (1, j_arg);
    if (do_detach) {
        const char *dev = loopdev;
        if (!dev) { builtin_error ("-d requires a loop device"); return EX_USAGE; }
        int fd = open (dev, O_RDONLY);
        if (fd < 0) { builtin_error ("%s: %s", dev, strerror (errno)); return EXECUTION_FAILURE; }
        int rc = ioctl (fd, LOOP_CLR_FD, 0);
        close (fd);
        if (rc < 0) { builtin_error ("%s: LOOP_CLR_FD: %s", dev, strerror (errno)); return EXECUTION_FAILURE; }
        return EXECUTION_SUCCESS;
    }

    if (do_free && (do_show || file || (loopdev && !file))) {
        /* -f --show FILE  (or -f FILE): find a free device and attach. */
        const char *f = file ? file : loopdev;
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

char *losetup_doc[] = {
    "Set up and control loop devices.",
    "",
    "    losetup [-l|-a]                 list active loop devices",
    "    losetup -f                      print the first free loop device",
    "    losetup -f --show [-r] [-o N] [--sizelimit N] FILE   attach FILE",
    "    losetup /dev/loopN [-r] [-o N] FILE                  attach to a device",
    "    losetup -d /dev/loopN           detach",
    "    losetup -j FILE                 list loops backed by FILE",
    "",
    "Attach/detach require root; listing reads /sys/block/loop*.",
    (char *) NULL
};

struct builtin losetup_struct = {
    "losetup",
    losetup_builtin,
    BUILTIN_ENABLED,
    losetup_doc,
    "losetup [-l|-a|-f|-d|-j] [--show] [-r] [-o OFF] [--sizelimit N] [loopdev] [file]",
    0
};
