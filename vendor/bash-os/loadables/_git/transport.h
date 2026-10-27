/* SPDX-License-Identifier: MIT */
/* _git/transport.h — moving objects and refs between two repositories.
 *
 * What clone, fetch and push need when both ends are directories on this
 * machine: every object a set of commits reaches, copied into another
 * object store, and the refs that name them. Objects already at the far end
 * are not copied again, which is what makes a fetch cheap.
 *
 * Nothing here speaks a protocol; that is for the phase that follows.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_TRANSPORT_H
#define BASH_OS_GIT_TRANSPORT_H

#include <stddef.h>

#include "odb.h"

/* Copy every object reachable from ROOTS out of FROM and into OBJECTS_DIR,
   skipping what INTO already has. Counts what was copied, when asked.
   Returns 0, or -1. */
int bgit_copy_objects (bgit_odb *from, bgit_odb *into, const char *objects_dir,
                       const char *const *roots, size_t n_roots,
                       size_t *copied);

/* Name every object ROOTS reaches that STOP does not: what one end must
   send the other, given what the other says it already has. The ids are
   returned in the order the walk found them, for the caller to free.
   Returns 0, or -1. */
int bgit_reachable_objects (bgit_odb *odb, const char *const *roots,
                            size_t n_roots, const char *const *stop,
                            size_t n_stop, char (**ids)[41], size_t *n_ids);

#endif /* BASH_OS_GIT_TRANSPORT_H */
