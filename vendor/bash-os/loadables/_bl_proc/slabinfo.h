/* SPDX-License-Identifier: MIT */
/* _bl_proc/slabinfo.h — shared /proc/slabinfo reader for procps-shape tools.
 *
 * Packaging: vendored under scripts/loadables/_bl_proc/. The build flattens
 * this to builtins/_bl_proc_slabinfo.{c,h}; consumers include:
 *
 *   #include "_bl_proc_slabinfo.h"
 */
#ifndef _BL_PROC_SLABINFO_H
#define _BL_PROC_SLABINFO_H

#include <stddef.h>

typedef struct {
    char name[128];
    unsigned long long active_objs;
    unsigned long long num_objs;
    unsigned long long obj_size;
    unsigned long long objs_per_slab;
    unsigned long long pages_per_slab;
} blp_slabinfo_row;

typedef struct {
    blp_slabinfo_row *rows;
    size_t len;
    size_t cap;
} blp_slabinfo;

const char *blp_proc_path(const char *name, char *buf, size_t bufsz);
int blp_read_slabinfo(blp_slabinfo *out, int *errnum);
void blp_free_slabinfo(blp_slabinfo *info);

#endif /* _BL_PROC_SLABINFO_H */
