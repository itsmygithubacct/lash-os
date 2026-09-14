/* SPDX-License-Identifier: MIT */
/* sudo.c - sudo-shaped entry point for doas.c. */

#include <config.h>

#include "loadables.h"

int bashdoas_dispatch (int is_sudo, WORD_LIST *list);

int
sudo_builtin (WORD_LIST *list)
{
  return bashdoas_dispatch (1, list);
}

char *sudo_doc[] = {
  "sudo - conservative sudo front-end backed by doas policy",
  "usage: sudo [-n] [-u USER] [-g GROUP] [-s|-i] [VAR=value ...] command [args...]",
  "       sudo -l|-ll       (sudoers list mode is rendered by sudo.sh)",
  "       sudo -e FILE...     (sudoedit: edit one or more files via the kernel authority)",
  "       sudo -k|-K|-v",
  "Supports sudo -l/-ll via the wrapper and -g/--group when policy permits it.",
  "Refuses sudo-only semantics such as -E, -S, -A, prompts.",
  "sudoedit (-e/--edit): the kernel safe-opens each policy-bound target, you edit",
  "  private copies AS YOURSELF, then the authority atomically copies them back",
  "  (up to 16 files; the multi-file copyback is not atomic across files).",
  "Non-root callers use v2 authority when available, otherwise external doas.",
  (char *) 0
};

struct builtin sudo_struct = {
  "sudo",
  sudo_builtin,
  BUILTIN_ENABLED,
  sudo_doc,
  "sudo [-n] [-u USER] [-g GROUP] command [args...]",
  0
};
