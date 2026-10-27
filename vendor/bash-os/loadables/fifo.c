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
 * successful mutating operation resets the peek cursor to the current head.
 * Invalid requests and failed output leave the queue and cursor unchanged.
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
  const char *p;
  long v;

  if (!s || !*s)
    return -1;
  p = s;
  if (*p == '+' || *p == '-')
    p++;
  if (!*p)
    return -1;
  for (; *p; p++)
    if (*p < '0' || *p > '9')
      return -1;
  errno = 0;
  v = strtol (s, &end, 10);
  if (errno == ERANGE || end == s || *end != '\0' || v < INT_MIN || v > INT_MAX)
    return -1;
  *out = (int) v;
  return 0;
}

/* Flush before committing a pull/peek: even a buffered write can fail. */
static int
bf_output_status (int failed)
{
  if (fflush (stdout) == EOF || ferror (stdout))
    failed = 1;
  if (failed)
    {
      int saved_errno = errno;
      clearerr (stdout);
      builtin_error ("write error: %s", strerror (saved_errno ? saved_errno : EIO));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bf_print_int (int v)
{
  return bf_output_status (printf ("%d\n", v) < 0);
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
bf_pull_one (void)
{
  if (bf_count <= 0)
    return -1;
  if (bf_print_int (bf_ring[bf_head]) != EXECUTION_SUCCESS)
    return -1;
  bf_head = (bf_head + 1) % BASHFIFO_CAP;
  bf_count--;
  if (bf_count == 0)
    bf_tail = bf_head;
  bf_reset_peek ();
  return 0;
}

static int
bf_peek_one (void)
{
  if (bf_count <= 0 || bf_peek_count >= bf_count)
    return -1;
  if (bf_print_int (bf_ring[bf_peek]) != EXECUTION_SUCCESS)
    return -1;
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
      if (bf_pull_one () < 0)
        return EXECUTION_FAILURE;
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "peek"))
    {
      if (list)
        {
          builtin_error ("peek: unexpected argument: %s", list->word->word);
          return EX_USAGE;
        }
      if (bf_peek_one () < 0)
        return EXECUTION_FAILURE;
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
      return bf_print_int (bf_count);
    }

  if (!strcmp (verb, "-h") || !strcmp (verb, "--help"))
    {
      int failed = 0;
      if (list)
        {
          builtin_error ("%s: unexpected argument: %s", verb, list->word->word);
          return EX_USAGE;
        }
      for (int i = 0; fifo_doc[i]; i++)
        if (puts (fifo_doc[i]) == EOF)
          {
            failed = 1;
            break;
          }
      return bf_output_status (failed);
    }

  builtin_error ("unknown verb: %s", verb);
  builtin_usage ();
  return EX_USAGE;
}

char *fifo_doc[] = {
  "Process-local 64-entry input FIFO of signed int events.",
  "",
  "    fifo push INT [INT...]      append events to tail",
  "    fifo pull                   consume and print head event",
  "    fifo peek                   print next event without consuming",
  "    fifo unget INT [INT...]     prepend events before head",
  "    fifo clear                  empty the FIFO",
  "    fifo depth                  print queued event count",
  "",
  "INT is optional + or - followed by decimal digits, within C int bounds.",
  "push and unget preserve argument order and reject a whole invalid batch.",
  "Successful push, unget, pull and clear reset the peek cursor to the head.",
  "depth and failed operations preserve the cursor; exhausted peek returns 1.",
  "Status: 0 success; 1 empty/exhausted or output error; 2 invalid request.",
  "Failed output preserves the queue and cursor (partial output is possible).",
  "State persists in this shell; subshells inherit a private copy.",
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
