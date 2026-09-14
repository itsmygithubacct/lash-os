/* SPDX-License-Identifier: MIT */
/* col.c — companion translation unit for the col alias.
 *
 * The actual col builtin entrypoint and struct live in
 * bashcolumn.c, which exports bashcolumn_struct, col_struct, and
 * bashcolrm_struct because the three commands share one source file
 * (MISSING_LOADABLES T2 / ML-T2-11). This file exists only so the
 * loadable staging step (patch-bash-loadables.sh's
 * `cp examples/loadables/${name}.c`) has a file at the expected path
 * without defining duplicate symbols.
 */
