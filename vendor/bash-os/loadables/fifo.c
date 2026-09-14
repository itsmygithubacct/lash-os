/* SPDX-License-Identifier: MIT */
/* fifo.c - small shared input FIFO for the ncurses-input proposal.
 *
 * Phase 1 foundation only: a process-local, module-static ring buffer
 * of int events. It is intentionally independent of terminal input,
 * ESC timing, terminfo, mouse decoding, and wide-character handling.
 *
 * Verbs:
 *   fifo push INT [INT...]
 *   fifo pull
 *   fifo peek
 *   fifo unget INT [INT...]
 *   fifo clear
 *   fifo depth
 *
 * Ring size is 64 entries, matching the proposal's shared input FIFO
 * size. `push` appends to the tail. `pull` removes from the head.
 * `unget` prepends so the next `pull` returns that value. `peek`
 * advances an independent peek cursor but does not consume data; any
 * mutating operation resets the peek cursor to the current head.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

#define BASHFIFO_CAP 64

static int bf_ring[BASHFIFO_CAP];
static int bf_head;
static int bf_tail;
static int bf_count;
static int bf_peek;
static int bf_peek_count;

extern char *fifo_doc[];

static void
bf_reset_peek (void)
{
  bf_peek = bf_head;
  bf_peek_count = 0;
}

static int
bf_parse_int (const char *s, int *out)
{
  char *end = NULL;
  long v;

  if (!s || !*s)
    return -1;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno == ERANGE || end == s || *end != '\0' || v < INT_MIN || v > INT_MAX)
    return -1;
  *out = (int) v;
  return 0;
}

static int
bf_push_one (int v)
{
  if (bf_count >= BASHFIFO_CAP)
    return -1;
  bf_ring[bf_tail] = v;
  bf_tail = (bf_tail + 1) % BASHFIFO_CAP;
  bf_count++;
  bf_reset_peek ();
  return 0;
}

static int
bf_unget_one (int v)
{
  if (bf_count >= BASHFIFO_CAP)
    return -1;
  bf_head = (bf_head + BASHFIFO_CAP - 1) % BASHFIFO_CAP;
  bf_ring[bf_head] = v;
  bf_count++;
  bf_reset_peek ();
  return 0;
}

static int
bf_pull_one (int *out)
{
  if (bf_count <= 0)
    return -1;
  *out = bf_ring[bf_head];
  bf_head = (bf_head + 1) % BASHFIFO_CAP;
  bf_count--;
  if (bf_count == 0)
    bf_tail = bf_head;
  bf_reset_peek ();
  return 0;
}

static int
bf_peek_one (int *out)
{
  if (bf_count <= 0 || bf_peek_count >= bf_count)
    return -1;
  *out = bf_ring[bf_peek];
  bf_peek = (bf_peek + 1) % BASHFIFO_CAP;
  bf_peek_count++;
  return 0;
}

static int
bf_word_count (WORD_LIST *list)
{
  int n = 0;
  for (; list; list = list->next)
    n++;
  return n;
}

static int
bf_push_words (WORD_LIST *list, int unget)
{
  int n = bf_word_count (list);
  int values[BASHFIFO_CAP];
  int i = 0;

  if (n <= 0)
    {
      builtin_error ("%s: missing INT", unget ? "unget" : "push");
      return EX_USAGE;
    }
  if (n > BASHFIFO_CAP || bf_count + n > BASHFIFO_CAP)
    {
      builtin_error ("%s: FIFO capacity exceeded (cap=%d depth=%d add=%d)",
                     unget ? "unget" : "push", BASHFIFO_CAP, bf_count, n);
      return EX_USAGE;
    }
  for (WORD_LIST *p = list; p; p = p->next, i++)
    {
      if (bf_parse_int (p->word->word, &values[i]) < 0)
        {
          builtin_error ("%s: invalid integer: %s",
                         unget ? "unget" : "push", p->word->word);
          return EX_USAGE;
        }
    }

  if (unget)
    {
      for (i = n - 1; i >= 0; i--)
        bf_unget_one (values[i]);
    }
  else
    {
      for (i = 0; i < n; i++)
        bf_push_one (values[i]);
    }
  return EXECUTION_SUCCESS;
}

int
fifo_builtin (WORD_LIST *list)
{
  const char *verb;
  int v;

  if (!list)
    {
      builtin_usage ();
      return EX_USAGE;
    }

  verb = list->word->word;
  list = list->next;

  if (!strcmp (verb, "push"))
    return bf_push_words (list, 0);

  if (!strcmp (verb, "unget"))
    return bf_push_words (list, 1);

  if (!strcmp (verb, "pull"))
    {
      if (list)
        {
          builtin_error ("pull: unexpected argument: %s", list->word->word);
          return EX_USAGE;
        }
      if (bf_pull_one (&v) < 0)
        return EXECUTION_FAILURE;
      printf ("%d\n", v);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "peek"))
    {
      if (list)
        {
          builtin_error ("peek: unexpected argument: %s", list->word->word);
          return EX_USAGE;
        }
      if (bf_peek_one (&v) < 0)
        return EXECUTION_FAILURE;
      printf ("%d\n", v);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "clear"))
    {
      if (list)
        {
          builtin_error ("clear: unexpected argument: %s", list->word->word);
          return EX_USAGE;
        }
      bf_head = bf_tail = bf_count = 0;
      bf_reset_peek ();
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "depth"))
    {
      if (list)
        {
          builtin_error ("depth: unexpected argument: %s", list->word->word);
          return EX_USAGE;
        }
      printf ("%d\n", bf_count);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "-h") || !strcmp (verb, "--help"))
    {
      for (int i = 0; fifo_doc[i]; i++)
        puts (fifo_doc[i]);
      return EXECUTION_SUCCESS;
    }

  builtin_error ("unknown verb: %s", verb);
  builtin_usage ();
  return EX_USAGE;
}

char *fifo_doc[] = {
  "Shared 64-entry input FIFO for ncurses-input loadables.",
  "",
  "    fifo push INT [INT...]      append events to tail",
  "    fifo pull                   consume and print head event",
  "    fifo peek                   print next event without consuming",
  "    fifo unget INT [INT...]     prepend events before head",
  "    fifo clear                  empty the FIFO",
  "    fifo depth                  print queued event count",
  "",
  "Entries are signed int values. Mutating verbs reset the peek cursor.",
  (char *) NULL
};

struct builtin fifo_struct = {
  "fifo",
  fifo_builtin,
  BUILTIN_ENABLED,
  fifo_doc,
  "fifo push|pull|peek|unget|clear|depth ARGS",
  0
};
