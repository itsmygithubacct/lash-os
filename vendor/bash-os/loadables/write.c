/* SPDX-License-Identifier: MIT */
/* write.c — companion translation unit for the write alias.
 *
 * The actual write builtin entrypoint and struct live in
 * wall.c, which exports wall_struct and write_struct
 * because the two commands share one source file (MISSING_LOADABLES
 * T2 / ML-T2-14). This file exists only so the loadable staging step
 * (patch-bash-loadables.sh's `cp examples/loadables/${name}.c`) has a
 * file at the expected path without defining duplicate symbols.
 *
 * Same idiom used by col.c / colrm.c (ML-T2-11) and
 * whiptail.c.
 */
