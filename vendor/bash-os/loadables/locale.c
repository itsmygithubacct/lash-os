/* SPDX-License-Identifier: MIT */
/* locale.c - minimal LC_* environment plumbing for bash-os. */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "loadables.h"

static const char *cats[] = {
  "ALL", "CTYPE", "NUMERIC", "TIME", "COLLATE", "MONETARY", "MESSAGES",
  "PAPER", "NAME", "ADDRESS", "TELEPHONE", "MEASUREMENT", "IDENTIFICATION", NULL
};

static int
recognized_locale (const char *s)
{
  return s && (!strcmp (s, "C") || !strcmp (s, "POSIX") || !strcmp (s, "C.UTF-8")
               || !strcmp (s, "C.utf8") || !strcmp (s, "C.UTF8"));
}

static const char *
canonical_locale (const char *s)
{
  if (!s) return NULL;
  if (!strcmp (s, "C.utf8") || !strcmp (s, "C.UTF8")) return "C.UTF-8";
  return s;
}

static int
known_cat (const char *s)
{
  int i;
  for (i = 0; cats[i]; i++)
    if (!strcmp (cats[i], s)) return 1;
  return 0;
}

static const char *
var_value (const char *name)
{
  const char *v = getenv (name);
  if (!v || !*v)
    {
      SHELL_VAR *sv = find_variable (name);
      if (sv) v = get_variable_value (sv);
    }
  return (v && *v) ? v : NULL;
}

static const char *
effective_locale (const char *cat)
{
  const char *v = var_value ("LC_ALL");
  char name[80];

  if (v) return v;
  if (cat && strcmp (cat, "ALL"))
    {
      snprintf (name, sizeof name, "LC_%s", cat);
      v = var_value (name);
      if (v) return v;
    }
  v = var_value ("LANG");
  return v ? v : "C";
}

static void
upper_copy (char *dst, size_t dstsz, const char *src)
{
  size_t i;
  for (i = 0; i + 1 < dstsz && src && src[i]; i++)
    dst[i] = (char) toupper ((unsigned char) src[i]);
  dst[i] = '\0';
}

int
locale_builtin (WORD_LIST *list)
{
  const char *verb;
  int i;

  if (!list) { builtin_error ("usage: locale set|current|validate"); return EX_USAGE; }
  verb = list->word->word;
  list = list->next;

  if (!strcmp (verb, "validate"))
    {
      if (!list) { builtin_error ("validate needs VALUE"); return EX_USAGE; }
      if (recognized_locale (list->word->word)) return EXECUTION_SUCCESS;
      builtin_error ("unsupported locale: %s (supported: C, POSIX, C.UTF-8)",
                     list->word->word);
      return EXECUTION_FAILURE;
    }

  if (!strcmp (verb, "current"))
    {
      char name[64];
      const char *v;
      if (list)
        {
          char cat[64];
          upper_copy (cat, sizeof cat, list->word->word);
          if (!strncmp (cat, "LC_", 3)) memmove (cat, cat + 3, strlen (cat + 3) + 1);
          if (!strcmp (cat, "LANG"))
            {
              printf ("LANG=%s\n", effective_locale (NULL));
              return EXECUTION_SUCCESS;
            }
          if (!known_cat (cat)) { builtin_error ("unknown category: %s", cat); return EX_USAGE; }
          snprintf (name, sizeof name, "LC_%s", cat);
          printf ("%s=%s\n", name, effective_locale (cat));
          return EXECUTION_SUCCESS;
        }
      for (i = 0; cats[i]; i++)
        {
          snprintf (name, sizeof name, "LC_%s", cats[i]);
          printf ("%s=%s\n", name, effective_locale (cats[i]));
        }
      v = var_value ("LANG");
      if (v) printf ("LANG=%s\n", v);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "set"))
    {
      char cat[64], name[80];
      const char *val;
      if (!list || !list->next) { builtin_error ("set needs CATEGORY VALUE"); return EX_USAGE; }
      upper_copy (cat, sizeof cat, list->word->word);
      if (!strncmp (cat, "LC_", 3)) memmove (cat, cat + 3, strlen (cat + 3) + 1);
      val = canonical_locale (list->next->word->word);
      if (!known_cat (cat)) { builtin_error ("unknown category: %s", cat); return EX_USAGE; }
      if (!recognized_locale (val))
        {
          builtin_error ("unsupported locale: %s (supported: C, POSIX, C.UTF-8)",
                         list->next->word->word);
          return EXECUTION_FAILURE;
        }
      if (!strcmp (cat, "ALL"))
        {
          setenv ("LC_ALL", val, 1);
          builtin_bind_variable ("LC_ALL", (char *) val, 0);
        }
      else
        {
          snprintf (name, sizeof name, "LC_%s", cat);
          setenv (name, val, 1);
          builtin_bind_variable (name, (char *) val, 0);
        }
      return EXECUTION_SUCCESS;
    }

  builtin_error ("unknown verb: %s", verb);
  builtin_usage ();
  return EX_USAGE;
}

char *locale_doc[] = {
  "Minimal LC_* environment plumbing for bash-os.",
  "",
  "    locale set CATEGORY VALUE",
  "    locale current",
  "    locale validate VALUE",
  "",
  "Recognized locale values: C, POSIX, C.UTF-8. Other names are rejected;",
  "core bash-os does not ship locale data.",
  (char *)NULL
};

struct builtin locale_struct = {
  "locale",
  locale_builtin,
  BUILTIN_ENABLED,
  locale_doc,
  "locale set|current|validate",
  0
};
