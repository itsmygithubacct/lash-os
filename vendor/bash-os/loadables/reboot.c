/* SPDX-License-Identifier: MIT */
/* reboot.c — Reboot the system via reboot(2). bash-os loadable (MIT).
 * Replaces busybox reboot so the appliance ships no busybox (plan D22).
 * The shared body is in common/reboot-impl.h (reboot/halt/poweroff are one
 * reboot(2) wrapper differing only in the RB_* command). */
#include "reboot-impl.h"

REBOOT_BUILTIN (reboot, RB_AUTOBOOT, "Reboot")
