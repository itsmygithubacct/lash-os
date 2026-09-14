/* SPDX-License-Identifier: MIT */
/* halt.c — Halt the system via reboot(2). bash-os loadable (MIT).
 * Replaces busybox halt so the appliance ships no busybox (plan D22).
 * The shared body is in common/reboot-impl.h (reboot/halt/poweroff are one
 * reboot(2) wrapper differing only in the RB_* command). */
#include "reboot-impl.h"

REBOOT_BUILTIN (halt, RB_HALT_SYSTEM, "Halt")
