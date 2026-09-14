/* SPDX-License-Identifier: MIT */
/* whiptail.c - companion translation unit for the whiptail alias.
 *
 * The actual whiptail builtin entrypoint and struct live in
 * dialog.c, which exports both dialog_struct and whiptail_struct
 * because the two commands share the same implementation. This file exists
 * so the loadable staging/build list can keep a one-name/one-source-file
 * invariant for the whiptail entry without defining duplicate symbols.
 */
