/* SPDX-License-Identifier: MIT */
/* _bl_proc/slabinfo.c — shared /proc/slabinfo parser. */

#include "_bl_proc_slabinfo.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *
blp_proc_path(const char *name, char *buf, size_t bufsz)
{
    const char *root = getenv("BASHOS_PROC_ROOT");
    if (root && *root) {
        snprintf(buf, bufsz, "%s/%s", root, name);
        return buf;
    }
    snprintf(buf, bufsz, "/proc/%s", name);
    return buf;
}

void
blp_free_slabinfo(blp_slabinfo *info)
{
    if (!info)
        return;
    free(info->rows);
    info->rows = NULL;
    info->len = 0;
    info->cap = 0;
}

static int
blp_append_slab(blp_slabinfo *out, const blp_slabinfo_row *row, int *errnum)
{
    if (out->len == out->cap) {
        size_t ncap = out->cap ? out->cap * 2 : 128;
        blp_slabinfo_row *nrows = realloc(out->rows, ncap * sizeof(*nrows));
        if (!nrows) {
            if (errnum)
                *errnum = ENOMEM;
            return -1;
        }
        out->rows = nrows;
        out->cap = ncap;
    }
    out->rows[out->len++] = *row;
    return 0;
}

int
blp_read_slabinfo(blp_slabinfo *out, int *errnum)
{
    char path[512], line[4096];
    FILE *fp;

    if (errnum)
        *errnum = 0;
    out->rows = NULL;
    out->len = 0;
    out->cap = 0;

    fp = fopen(blp_proc_path("slabinfo", path, sizeof path), "re");
    if (!fp) {
        if (errnum)
            *errnum = errno;
        return -1;
    }

    while (fgets(line, sizeof line, fp)) {
        blp_slabinfo_row row;
        if (line[0] == '#' || strncmp(line, "slabinfo", 8) == 0)
            continue;
        memset(&row, 0, sizeof row);
        if (sscanf(line, " %127s %llu %llu %llu %llu %llu",
                   row.name, &row.active_objs, &row.num_objs,
                   &row.obj_size, &row.objs_per_slab,
                   &row.pages_per_slab) != 6)
            continue;
        if (blp_append_slab(out, &row, errnum) < 0) {
            fclose(fp);
            blp_free_slabinfo(out);
            return -1;
        }
    }
    fclose(fp);

    return out->len ? 0 : 1;
}
