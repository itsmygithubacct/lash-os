/* SPDX-License-Identifier: MIT */
/* colrm.c — companion translation unit for the colrm alias.
 *
 * The actual colrm builtin entrypoint and struct live in
 * bashcolumn.c, which exports bashcolumn_struct, bashcol_struct, and
 * colrm_struct because the three commands share one source file
 * (MISSING_LOADABLES T2 / ML-T2-11). This file exists only so the
 * loadable staging step (patch-bash-loadables.sh's
 * `cp examples/loadables/${name}.c`) has a file at the expected path
 * without defining duplicate symbols.
 */
