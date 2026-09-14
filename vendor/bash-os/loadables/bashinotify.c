/* bashinotify.c — filesystem watch via inotify(7). Loadable for bash.
 *
 * Polling stat(2) mtimes in a sleep loop is wasteful (CPU + power
 * on idle systems) and racy (misses events between polls).
 * inotify_init1/add_watch/read are the kernel-supported answer.
 *
 * Subcommands:
 *     bashinotify add PATH MASK         add watch, print wd
 *                                          MASK = comma list:
 *                                            modify create delete
 *                                            move move-from move-to
 *                                            attrib close-write
 *                                            close-nowrite open access
 *                                            delete-self move-self
 *                                            unmount all
 *     bashinotify rm WD                 inotify_rm_watch
 *     bashinotify wait [-t MS] [-n N]   read pending events; one
 *                                          line per: "WD EVS NAME"
 *                                          (EVS = comma-separated names)
 *     bashinotify close                 destroy the inotify fd
 *                                          (next add re-creates it)
 *
 * Single global inotify fd held in static state. Cross-call by design
 * (so add/wait pairs reference the same instance).
 *
 * Companion docs:
 *     /docs/bash/bashinotify.txt
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/inotify.h>

#include "loadables.h"

static int g_ifd = -1;

struct mask_name { const char *name; uint32_t flag; };
static const struct mask_name MASKS[] = {
  { "access",        IN_ACCESS },
  { "modify",        IN_MODIFY },
  { "attrib",        IN_ATTRIB },
  { "close-write",   IN_CLOSE_WRITE },
  { "close-nowrite", IN_CLOSE_NOWRITE },
  { "close",         IN_CLOSE },
  { "open",          IN_OPEN },
  { "move-from",     IN_MOVED_FROM },
  { "move-to",       IN_MOVED_TO },
  { "move",          IN_MOVE },
  { "create",        IN_CREATE },
  { "delete",        IN_DELETE },
  { "delete-self",   IN_DELETE_SELF },
  { "move-self",     IN_MOVE_SELF },
  { "unmount",       IN_UNMOUNT },
  { "all",           IN_ALL_EVENTS },
  { NULL, 0 }
};

/* Parse comma-separated mask names → bitmask. Returns 0 on error. */
static uint32_t
bin_parse_mask (const char *spec)
{
  char *copy = strdup (spec);
  if (!copy) return 0;
  uint32_t m = 0;
  char *save = NULL;
  for (char *tok = strtok_r (copy, ",", &save); tok; tok = strtok_r (NULL, ",", &save))
    {
      while (*tok == ' ') tok++;
      char *e = tok + strlen (tok);
      while (e > tok && (e[-1] == ' ' || e[-1] == '\n')) *--e = '\0';
      int found = 0;
      for (const struct mask_name *mn = MASKS; mn->name; mn++)
        if (strcmp (tok, mn->name) == 0)
          { m |= mn->flag; found = 1; break; }
      if (!found)
        { builtin_error ("unknown mask name: %s", tok); free (copy); return 0; }
    }
  free (copy);
  return m;
}

/* Print a comma-separated list of mask names matching `mask`. */
static void
bin_emit_mask_names (uint32_t mask)
{
  int first = 1;
  /* Most-specific names first; "all" / "close" / "move" are aggregates
     that overlap their components — emit components only. */
  static const struct mask_name *EMIT[] = {
    /* Skip aggregate entries; emit only the leaves. */
    NULL
  };
  (void) EMIT;
  static const struct mask_name leaves[] = {
    { "access",        IN_ACCESS },
    { "modify",        IN_MODIFY },
    { "attrib",        IN_ATTRIB },
    { "close-write",   IN_CLOSE_WRITE },
    { "close-nowrite", IN_CLOSE_NOWRITE },
    { "open",          IN_OPEN },
    { "move-from",     IN_MOVED_FROM },
    { "move-to",       IN_MOVED_TO },
    { "create",        IN_CREATE },
    { "delete",        IN_DELETE },
    { "delete-self",   IN_DELETE_SELF },
    { "move-self",     IN_MOVE_SELF },
    { "unmount",       IN_UNMOUNT },
    /* Reporter-only flags from the kernel. */
    { "ignored",       IN_IGNORED },
    { "isdir",         IN_ISDIR },
    { "q-overflow",    IN_Q_OVERFLOW },
    { NULL, 0 }
  };
  for (const struct mask_name *mn = leaves; mn->name; mn++)
    if (mask & mn->flag)
      {
        if (!first) putchar (',');
        fputs (mn->name, stdout);
        first = 0;
      }
  if (first) fputs ("none", stdout);
}

static int
bin_ensure_fd (void)
{
  if (g_ifd >= 0) return 0;
  g_ifd = inotify_init1 (IN_CLOEXEC | IN_NONBLOCK);
  if (g_ifd < 0)
    {
      builtin_error ("inotify_init1: %s", strerror (errno));
      return -1;
    }
  return 0;
}

static int
bin_add (WORD_LIST *args)
{
  if (!args || !args->next) { builtin_error ("add needs PATH MASK [WDVAR]"); return EX_USAGE; }
  const char *path = args->word->word;
  const char *mask_spec = args->next->word->word;
  const char *wdvar = (args->next->next) ? args->next->next->word->word : NULL;
  if (bin_ensure_fd () < 0) return EXECUTION_FAILURE;
  uint32_t mask = bin_parse_mask (mask_spec);
  if (mask == 0) return EX_USAGE;
  int wd = inotify_add_watch (g_ifd, path, mask);
  if (wd < 0) { builtin_error ("inotify_add_watch %s: %s", path, strerror (errno)); return EXECUTION_FAILURE; }
  /* Same caveat as bashio open: when called inside `$(...)`, the
     loadable's static `g_ifd` lives in the subshell's process and
     dies on subshell exit. WDVAR binding is the supported way to
     receive the wd while keeping the inotify fd in the parent
     shell's process. Stdout output is kept for one-shot uses inside
     a subshell that handles its own wait+rm. */
  if (wdvar)
    {
      char buf[32];
      snprintf (buf, sizeof buf, "%d", wd);
      builtin_bind_variable ((char *) wdvar, buf, 0);
    }
  else
    printf ("%d\n", wd);
  return EXECUTION_SUCCESS;
}

static int
bin_rm (WORD_LIST *args)
{
  if (!args) { builtin_error ("rm needs WD"); return EX_USAGE; }
  if (g_ifd < 0) { builtin_error ("rm: no inotify fd"); return EXECUTION_FAILURE; }
  int wd = atoi (args->word->word);
  if (inotify_rm_watch (g_ifd, wd) < 0)
    { builtin_error ("inotify_rm_watch: %s", strerror (errno)); return EXECUTION_FAILURE; }
  return EXECUTION_SUCCESS;
}

static int
bin_close (WORD_LIST *args)
{
  (void) args;
  if (g_ifd >= 0) { close (g_ifd); g_ifd = -1; }
  return EXECUTION_SUCCESS;
}

static int
bin_wait (WORD_LIST *args)
{
  int timeout_ms = -1;
  int max_events = -1;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (strcmp (w, "-t") == 0)
        { if (!p->next) { builtin_error ("-t needs MS"); return EX_USAGE; }
          p = p->next; timeout_ms = atoi (p->word->word); }
      else if (strcmp (w, "-n") == 0)
        { if (!p->next) { builtin_error ("-n needs MAX"); return EX_USAGE; }
          p = p->next; max_events = atoi (p->word->word); }
      else { builtin_error ("wait: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (g_ifd < 0)
    { builtin_error ("wait: no watches added; call `add` first"); return EXECUTION_FAILURE; }

  if (timeout_ms != 0)
    {
      struct pollfd pfd = { .fd = g_ifd, .events = POLLIN };
      int r;
      do { r = poll (&pfd, 1, timeout_ms); } while (r < 0 && errno == EINTR);
      if (r < 0) { builtin_error ("poll: %s", strerror (errno)); return EXECUTION_FAILURE; }
      if (r == 0) return EXECUTION_SUCCESS;  /* timeout, no output */
    }

  /* Drain pending events. inotify_event is variable-length (name field
     length stored in `len`). Read into a generously-sized buffer.
     Linux guarantees a read returns whole events, never partial. */
  char buf[16 * 1024] __attribute__ ((aligned (__alignof__ (struct inotify_event))));
  int emitted = 0;
  while (max_events < 0 || emitted < max_events)
    {
      ssize_t n = read (g_ifd, buf, sizeof buf);
      if (n < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          if (errno == EINTR) continue;
          builtin_error ("read inotify: %s", strerror (errno));
          return EXECUTION_FAILURE;
        }
      if (n == 0) break;
      char *p = buf;
      while (p < buf + n)
        {
          /* Bound check before deref: a malformed (or partial) event
             whose declared len would walk past buf+n means we'd read
             past the read() result. Linux guarantees whole events on
             read so this branch should never fire — defense-in-depth. */
          if (p + sizeof (struct inotify_event) > buf + n) break;
          struct inotify_event *ev = (struct inotify_event *) p;
          if (p + sizeof (struct inotify_event) + ev->len > buf + n) break;
          printf ("%d ", ev->wd);
          bin_emit_mask_names (ev->mask);
          if (ev->cookie) printf (" cookie=%u", ev->cookie);
          if (ev->len > 0)
            {
              /* %.*s caps the read at ev->len even if the name has no
                 NUL byte before its declared end (defense-in-depth;
                 the kernel does NUL-terminate). */
              printf (" %.*s", (int) ev->len, ev->name);
            }
          putchar ('\n');
          emitted++;
          p += sizeof (struct inotify_event) + ev->len;
          if (max_events > 0 && emitted >= max_events) break;
        }
      /* Don't loop again unless we drained the full buffer. */
      if ((size_t) n < sizeof buf) break;
    }
  fflush (stdout);
  return EXECUTION_SUCCESS;
}

int
bashinotify_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (strcmp (cmd, "add")   == 0) return bin_add (args);
  if (strcmp (cmd, "rm")    == 0) return bin_rm (args);
  if (strcmp (cmd, "wait")  == 0) return bin_wait (args);
  if (strcmp (cmd, "close") == 0) return bin_close (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *bashinotify_doc[] = {
  "Filesystem watch via inotify(7).",
  "",
  "    bashinotify add PATH MASK     add a watch, print the wd",
  "                                  MASK is comma-separated:",
  "                                    modify create delete attrib",
  "                                    move move-from move-to",
  "                                    open access close-write",
  "                                    close-nowrite delete-self",
  "                                    move-self unmount all",
  "    bashinotify rm WD             stop watching",
  "    bashinotify wait [-t MS] [-n N]",
  "                                  read pending events; one line",
  "                                  per event: \"WD EVENT_NAMES NAME\"",
  "                                  -t MS: timeout (0=no wait, default=block)",
  "                                  -n N:  max events to emit per call",
  "    bashinotify close             destroy the inotify fd",
  "",
  "Single inotify fd held in loadable state across calls.",
  (char *)NULL
};

struct builtin bashinotify_struct = {
  "bashinotify",
  bashinotify_builtin,
  BUILTIN_ENABLED,
  bashinotify_doc,
  "bashinotify add|rm|wait|close ARGS...",
  0
};
