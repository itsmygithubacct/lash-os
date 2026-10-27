/* SPDX-License-Identifier: MIT */
/* Shared by two independently selectable/loadable command names. */
#ifndef BASH_OS_CLEAR_IMPL_H
#define BASH_OS_CLEAR_IMPL_H

#include <config.h>
#include <stdio.h>
#include <string.h>
#include "loadables.h"
#include "bashgetopt.h"

/* A deliberately finite table: no terminal database is needed in a static
   image. Keep the visible-screen and E3 capabilities separate for -x.
   VT100/VT102 serial-line padding is intentionally omitted. */
static const struct {
  const char *name;
  const char *screen;
  int scrollback;
} bashclear_terms[] = {
  { "xterm",                 "\033[H\033[2J", 1 },
  { "xterm-256color",        "\033[H\033[2J", 1 },
  { "xterm-color",           "\033[H\033[2J", 0 },
  { "xterm-kitty",           "\033[H\033[2J", 0 },
  { "alacritty",             "\033[H\033[2J", 1 },
  { "foot",                  "\033[H\033[2J", 1 },
  { "foot-direct",           "\033[H\033[2J", 1 },
  { "screen",                "\033[H\033[J",  0 },
  { "screen-256color",       "\033[H\033[J",  0 },
  { "screen.xterm-256color", "\033[H\033[2J", 0 },
  { "tmux",                  "\033[H\033[J",  1 },
  { "tmux-256color",         "\033[H\033[J",  1 },
  { "linux",                 "\033[H\033[J",  1 },
  { "vt100",                 "\033[H\033[J",  0 },
  { "vt102",                 "\033[H\033[J",  0 },
  { "vt220",                 "\033[H\033[J",  0 },
  { "ansi",                  "\033[H\033[J",  0 },
  { "rxvt",                  "\033[H\033[2J", 0 },
  { "rxvt-unicode",          "\033[H\033[2J", 0 },
  { "rxvt-unicode-256color", "\033[H\033[2J", 0 },
  { "st",                    "\033[H\033[2J", 0 },
  { "st-256color",           "\033[H\033[2J", 0 },
  { NULL, NULL, 0 }
};

static int
bashclear_version (void)
{
  puts ("bashclear 0.1.1 (bash-os; built-in terminal table)");
  return sh_chkwrite (EXECUTION_SUCCESS);
}

static int
bashclear_run (WORD_LIST *list)
{
  const char *term = get_string_value ("TERM");
  int opt, keep_scrollback = 0, i;

  if (list && !list->next && !strcmp (list->word->word, "--version"))
    return bashclear_version ();

  reset_internal_getopt ();
  while ((opt = internal_getopt (list, "T:Vx")) != -1)
    {
      switch (opt)
        {
        case 'T': term = list_optarg; break;
        case 'V': return bashclear_version ();
        case 'x': keep_scrollback = 1; break;
        case GETOPT_HELP:
          builtin_help ();
          return sh_chkwrite (EXECUTION_SUCCESS);
        default:
          builtin_usage ();
          return EXECUTION_FAILURE;
        }
    }
  if (loptend)
    {
      builtin_usage ();
      return EXECUTION_FAILURE;
    }

  if (!term)
    {
      builtin_error ("TERM is not set (use -T TERM)");
      return EXECUTION_FAILURE;
    }
  if (!strcmp (term, "dumb"))
    return EXECUTION_FAILURE;
  for (i = 0; bashclear_terms[i].name; i++)
    if (!strcmp (term, bashclear_terms[i].name))
      {
        fputs (bashclear_terms[i].screen, stdout);
        if (bashclear_terms[i].scrollback && !keep_scrollback)
          fputs ("\033[3J", stdout);
        /* Flush now, report redirection errors, and recover stdout for the
           next builtin using Bash's existing output-error handling. */
        return sh_chkwrite (EXECUTION_SUCCESS);
      }
  builtin_error ("unsupported terminal type: %s", term);
  return EXECUTION_FAILURE;
}

#define BASHCLEAR_BUILTIN(fn) \
  int fn##_builtin (WORD_LIST *list) { return bashclear_run (list); } \
  char *fn##_doc[] = { \
    "Clear the terminal screen and, where supported, its scrollback.", \
    "", \
    #fn " [-x] [-T TERM] | -V | --version | --help", \
    "-T TERM overrides the shell's TERM variable; -x keeps scrollback.", \
    "-V/--version reports bashclear's version, not an ncurses version.", \
    "Writes control bytes to stdout, including when redirected; no newline.", \
    "", \
    "Built-in terminal names (no external terminfo database or padding):", \
    "  xterm, xterm-256color, xterm-color, xterm-kitty, alacritty, foot,", \
    "  foot-direct, screen, screen-256color, screen.xterm-256color, tmux,", \
    "  tmux-256color, linux, vt100, vt102, vt220, ansi, rxvt, rxvt-unicode,", \
    "  rxvt-unicode-256color, st, st-256color.", \
    "Scrollback clearing: xterm, xterm-256color, alacritty, foot, foot-direct,", \
    "tmux, tmux-256color and linux. Other names clear only the visible screen.", \
    "", \
    "Exit status: 0 on success; 1 for output errors, unset/unsupported TERM", \
    "or dumb (no output), and invalid options or operands.", \
    "clear and bashclear implement the same command and work independently.", \
    (char *)NULL \
  }; \
  struct builtin fn##_struct = { \
    #fn, fn##_builtin, BUILTIN_ENABLED, fn##_doc, \
    #fn " [-x] [-T TERM] | -V | --version | --help", 0 \
  };

#endif
