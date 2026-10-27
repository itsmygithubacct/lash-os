/* SPDX-License-Identifier: MIT */
#ifndef BASHOS_PAX_STREAM_H
#define BASHOS_PAX_STREAM_H
#include <stdio.h>
struct bashos_pax_read_options {
    int extract, verbose, tar_mode, to_stdout, preserve;
    unsigned strip;
    const char **members;
    size_t count;
};
int bashos_pax_read(FILE *, const struct bashos_pax_read_options *);
struct bashos_pax_hardlink;
/* Zero-initialize once per output archive and clear on every exit path. */
struct bashos_pax_write_context {
    struct bashos_pax_hardlink *links;
    int no_recurse;
};
void bashos_pax_write_clear(struct bashos_pax_write_context *);
int bashos_pax_write_member_context(FILE *, const char *, struct bashos_pax_write_context *);
int bashos_pax_write_member(FILE *, const char *, int no_recurse);
#endif
