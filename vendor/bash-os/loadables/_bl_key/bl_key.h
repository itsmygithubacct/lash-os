/* SPDX-License-Identifier: MIT */
/* _bl_key/bl_key.h — shared CSI/SS3 keypress decoder for interactive
 *                      bash-os builtins (less, more, nano, vi, top,
 *                      dialog, whiptail, screen).
 *
 * Provenance: lifted from `bv_read_key` in scripts/loadables/bashvi.c
 * (the most-exercised raw-input path in the tree). Vendored under the
 * project's `_<lib>/` convention; patch-bash-loadables.sh flattens
 * `_bl_key/bl_key.{c,h}` into `builtins/_bl_key_bl_key.{c,h}` and
 * loadables include via the flattened name:
 *
 *   #include "_bl_key_bl_key.h"
 *
 * Why a shared helper: arrow / Page / Home / End / Delete arrive as
 * multi-byte CSI sequences (e.g. ESC [ A) or SS3 sequences (ESC O A).
 * A naive `read(fd, &c, 1)` returns only the leading ESC; subsequent
 * bytes are dropped or misdispatched on the next iteration. Every
 * interactive bash-os builtin that wants keyboard navigation needs
 * the same decoder, so we ship one canonical implementation.
 *
 * API contract:
 *   - bl_read_key(fd) blocks on the first byte; uses a 50 ms grace
 *     window to disambiguate bare ESC from ESC-prefixed sequences,
 *     then up to 200 ms per follow-up byte while assembling a CSI.
 *   - Returns ASCII byte value (0..127) for plain keys, BL_KEY_*
 *     constants (≥0x100) for special keys, BL_KEY_NONE on EOF.
 *   - Single-byte pushback supports the ESC+key case (e.g. bashvi's
 *     `ESC :` to enter COMMAND mode). One byte of pushback only.
 *   - Pushback state is module-static. Call bl_key_reset() at the
 *     start of each interactive session to clear any leftover state.
 *
 * License: MIT, matching the rest of the project. */

#ifndef _BL_KEY_BL_KEY_H
#define _BL_KEY_BL_KEY_H

/* Special-key constants. Values ≥ 0x100 so they're distinguishable
 * from plain ASCII bytes returned as-is.
 *
 * BL_KEY_ESC is 27 (the literal ESC byte) intentionally — callers
 * that want to treat ESC as the byte `0x1b` can compare directly,
 * and callers that want to treat it as a named key can compare to
 * BL_KEY_ESC. The historical bashvi behavior is preserved. */
enum {
    BL_KEY_NONE   = 0,
    BL_KEY_ESC    = 27,
    BL_KEY_UP     = 0x101,
    BL_KEY_DOWN   = 0x102,
    BL_KEY_LEFT   = 0x103,
    BL_KEY_RIGHT  = 0x104,
    BL_KEY_HOME   = 0x105,
    BL_KEY_END    = 0x106,
    BL_KEY_BS     = 0x107,   /* 0x7f or 0x08 */
    BL_KEY_RET    = 0x108,   /* CR or LF */
    BL_KEY_DEL    = 0x109,   /* CSI 3 ~ */
    BL_KEY_PGUP   = 0x10a,   /* CSI 5 ~ */
    BL_KEY_PGDN   = 0x10b,   /* CSI 6 ~ */
    BL_KEY_INS    = 0x10c,   /* CSI 2 ~ */
    BL_KEY_TAB    = 0x10d,
    BL_KEY_F1     = 0x110,
    BL_KEY_F2     = 0x111,
    BL_KEY_F3     = 0x112,
    BL_KEY_F4     = 0x113,
    /* Bracketed paste markers (DEC private mode 2004). The terminal
     * wraps pasted content in ESC[200~ ... ESC[201~ when paste mode
     * is enabled. We expose START/END as discrete keys so consumers
     * can either ignore them (pagers) or switch to a paste-buffer
     * accumulator (editors). Default consumer behavior is "treat as
     * BL_KEY_NONE" — see callers. */
    BL_KEY_PASTE_START = 0x120,
    BL_KEY_PASTE_END   = 0x121
};

/* Read one key from `fd`. See contract in the file header. */
int bl_read_key (int fd);

/* Push back one byte so the next bl_read_key call returns it (post-
 * ESC peek/restore). Only one byte of state. */
void bl_pushback (unsigned char b);

/* Clear any pushback state. Call at session start. */
void bl_key_reset (void);

#endif /* _BL_KEY_BL_KEY_H */
