/* SPDX-License-Identifier: MIT */
/* _bl_key/bl_key.c — shared CSI/SS3 keypress decoder (impl).
 * See _bl_key/bl_key.h for API contract + provenance. */

#include "_bl_key_bl_key.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

/* Bracketed-paste mode markers. The terminal wraps pasted content
 * between these when DEC private mode 2004 is enabled by the active
 * application. The decoder surfaces START/END as discrete BL_KEY_*
 * codes; the wrapped content arrives byte-by-byte through subsequent
 * bl_read_key() calls (as plain ASCII or per-key codes). */
#define BL_PASTE_PARAM_START 200
#define BL_PASTE_PARAM_END   201

/* Total time budget for assembling one CSI sequence after the leading
 * ESC[ / ESCO is seen. Caps the ~6.4s worst case (32 bytes × 200 ms
 * per-byte) a malicious sender could otherwise impose. 400 ms is
 * comfortably more than any human-typed sequence or terminal-driver
 * burst. */
#define BL_CSI_TOTAL_BUDGET_MS 400

/* Module-static pushback state. One byte of capacity is enough for
 * the historical ESC+command-char flow used by bashvi (the only
 * caller that needs pushback in practice). Callers that want a clean
 * slate between sessions should call bl_key_reset(). */
static int bl_pushback_valid = 0;
static unsigned char bl_pushback_byte = 0;

void
bl_pushback (unsigned char b)
{
    bl_pushback_byte = b;
    bl_pushback_valid = 1;
}

void
bl_key_reset (void)
{
    bl_pushback_valid = 0;
    bl_pushback_byte = 0;
}

/* Read one byte from fd with a millisecond timeout. Returns 1 on
 * success (byte stored in *out), 0 on timeout, -1 on read error.
 * Uses poll(2) so a bare ESC keypress doesn't hang the loop. */
static int
bl_read_byte_to (int fd, int ms, unsigned char *out)
{
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    int r = poll (&p, 1, ms);
    if (r <= 0) return r;
    ssize_t n = read (fd, out, 1);
    return (n == 1) ? 1 : -1;
}

int
bl_read_key (int fd)
{
    unsigned char b;

    /* Drain pushback first (post-ESC peek/restore flow). */
    if (bl_pushback_valid) {
        b = bl_pushback_byte;
        bl_pushback_valid = 0;
    } else {
        /* Retry on EINTR (signal interrupted read) and EAGAIN/EWOULDBLOCK
         * (caller might be using O_NONBLOCK behind our back — we model
         * "no data yet" as "wait for poll-readable byte" rather than
         * EOF). EAGAIN/EWOULDBLOCK loops via poll so we don't busy-spin. */
        for (;;) {
            ssize_t n = read (fd, &b, 1);
            if (n == 1) break;
            if (n == 0) return BL_KEY_NONE;   /* EOF */
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
                int pr = poll (&p, 1, -1);   /* block until ready */
                if (pr < 0 && errno != EINTR) return BL_KEY_NONE;
                continue;
            }
            return BL_KEY_NONE;
        }
    }

    /* Plain-byte shortcuts for keys with no escape prefix. */
    if (b == 0x7f || b == 0x08) return BL_KEY_BS;
    if (b == 0x0d || b == 0x0a) return BL_KEY_RET;
    if (b == 0x09)              return BL_KEY_TAB;

    if (b == 0x1b) {
        /* ESC: 50 ms grace to disambiguate bare ESC from a sequence. */
        unsigned char b2;
        if (bl_read_byte_to (fd, 50, &b2) <= 0) return BL_KEY_ESC;

        if (b2 == '[' || b2 == 'O') {
            /* CSI (`ESC [`) or SS3 (`ESC O`) sequence. Collect
             * parameter bytes (0x20-0x3F) until the final byte
             * (0x40-0x7E). Per-byte 200 ms timeout breaks a slow
             * link gracefully; a TOTAL ~400 ms budget (tracked
             * against CLOCK_MONOTONIC) caps the worst-case time a
             * malicious sender could keep us in this loop with
             * legitimate-looking parameter bytes. */
            unsigned char fb = 0;
            char param[32];
            size_t plen = 0;
            struct timespec ts0;
            clock_gettime (CLOCK_MONOTONIC, &ts0);
            for (;;) {
                struct timespec tn;
                clock_gettime (CLOCK_MONOTONIC, &tn);
                long elapsed_ms = (tn.tv_sec - ts0.tv_sec) * 1000
                                + (tn.tv_nsec - ts0.tv_nsec) / 1000000;
                if (elapsed_ms >= BL_CSI_TOTAL_BUDGET_MS) break;
                unsigned char c;
                int rem = BL_CSI_TOTAL_BUDGET_MS - (int) elapsed_ms;
                int slice = rem < 200 ? rem : 200;
                if (bl_read_byte_to (fd, slice, &c) <= 0) break;
                if (c >= 0x40 && c <= 0x7e) { fb = c; break; }
                if (plen + 1 < sizeof param)
                    param[plen++] = (char) c;
                else
                    break;
            }
            param[plen] = '\0';
            switch (fb) {
            case 'A': return BL_KEY_UP;
            case 'B': return BL_KEY_DOWN;
            case 'C': return BL_KEY_RIGHT;
            case 'D': return BL_KEY_LEFT;
            case 'H': return BL_KEY_HOME;
            case 'F': return BL_KEY_END;
            case 'P': return BL_KEY_F1;
            case 'Q': return BL_KEY_F2;
            case 'R': return BL_KEY_F3;
            case 'S': return BL_KEY_F4;
            case '~':
                if (plen > 0) {
                    /* atoi() stops at the first non-digit; safe on
                     * `5` / `15;2` etc. We ignore the modifier
                     * (`;N` suffix) in v1 — no callers want shift-
                     * arrow distinction yet. */
                    int code = atoi (param);
                    if (code == 1 || code == 7) return BL_KEY_HOME;
                    if (code == 2)              return BL_KEY_INS;
                    if (code == 3)              return BL_KEY_DEL;
                    if (code == 4 || code == 8) return BL_KEY_END;
                    if (code == 5)              return BL_KEY_PGUP;
                    if (code == 6)              return BL_KEY_PGDN;
                    if (code == 11 || code == 15) return BL_KEY_F1;
                    if (code == 12 || code == 17) return BL_KEY_F2;
                    if (code == 13 || code == 18) return BL_KEY_F3;
                    if (code == 14 || code == 19) return BL_KEY_F4;
                    /* Bracketed-paste markers (DEC mode 2004). The
                     * wrapped content arrives as subsequent bytes;
                     * consumers that don't enable paste mode normally
                     * won't see these because the terminal only emits
                     * them when paste mode is on, but defensive
                     * surfacing keeps stray markers out of consumer
                     * state if a parent left mode 2004 enabled. */
                    if (code == BL_PASTE_PARAM_START) return BL_KEY_PASTE_START;
                    if (code == BL_PASTE_PARAM_END)   return BL_KEY_PASTE_END;
                }
                return BL_KEY_ESC;
            default:
                return BL_KEY_ESC;
            }
        }

        /* ESC + non-CSI byte. Push the byte back so the next
         * bl_read_key call returns it; report this call as bare
         * ESC. Preserves the bashvi `ESC :` → enter COMMAND mode
         * flow. */
        bl_pushback (b2);
        return BL_KEY_ESC;
    }

    return (int) b;
}
