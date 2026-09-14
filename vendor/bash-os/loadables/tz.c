/* SPDX-License-Identifier: MIT */
/* tz.c - curated timezone conversion builtin for bash-os.
 *
 * Stage 45.A v1: common zones with compact built-in DST rules. This is
 * intentionally smaller than shipping full IANA tzdata in core bash-os.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>

#include "loadables.h"

#define BASHTZ_RUNTIME_NAME_LEN 63
#define BASHTZ_RUNTIME_ABBR_LEN 15
#define BASHTZ_PATH_BUF         4096
#define BASHTZ_DEFAULT_ZONE_DIR "/etc/bash-os/zones.d"

typedef struct zoneinfo {
  const char *name;
  int std_off;
  int dst_off;
  const char *std_abbr;
  const char *dst_abbr;
  int rule;
} zoneinfo;

enum { RULE_NONE, RULE_US, RULE_EU, RULE_AU };

static const zoneinfo zones[] = {
  { "UTC", 0, 0, "UTC", "UTC", RULE_NONE },
  { "Etc/UTC", 0, 0, "UTC", "UTC", RULE_NONE },
  { "GMT", 0, 0, "GMT", "GMT", RULE_NONE },
  { "America/New_York", -5 * 3600, -4 * 3600, "EST", "EDT", RULE_US },
  { "America/Los_Angeles", -8 * 3600, -7 * 3600, "PST", "PDT", RULE_US },
  { "America/Chicago", -6 * 3600, -5 * 3600, "CST", "CDT", RULE_US },
  { "Europe/London", 0, 1 * 3600, "GMT", "BST", RULE_EU },
  { "Europe/Berlin", 1 * 3600, 2 * 3600, "CET", "CEST", RULE_EU },
  { "Asia/Tokyo", 9 * 3600, 9 * 3600, "JST", "JST", RULE_NONE },
  { "Asia/Shanghai", 8 * 3600, 8 * 3600, "CST", "CST", RULE_NONE },
  { "Asia/Singapore", 8 * 3600, 8 * 3600, "SGT", "SGT", RULE_NONE },
  { "Australia/Sydney", 10 * 3600, 11 * 3600, "AEST", "AEDT", RULE_AU },
  { NULL, 0, 0, NULL, NULL, 0 }
};

/* Operator-drop runtime zone slot. The C struct stores const-char-*
   fields; the buffers below back those pointers across a single
   find_zone() call. Not re-entrant — tz is bash-internal and bash
   is single-threaded. */
static char rt_name[BASHTZ_RUNTIME_NAME_LEN + 1];
static char rt_std_abbr[BASHTZ_RUNTIME_ABBR_LEN + 1];
static char rt_dst_abbr[BASHTZ_RUNTIME_ABBR_LEN + 1];
static zoneinfo rt_zone;

static char *
bashtz_strip_ws (char *s)
{
  char *p = s;
  while (*p && isspace ((unsigned char) *p)) p++;
  char *end = p + strlen (p);
  while (end > p && isspace ((unsigned char) end[-1])) end--;
  *end = '\0';
  return p;
}

/* Parse a single-zone sidecar file. Format: lines of `key = value`,
   `#` comments and blank lines ignored. Required keys: `name`,
   `std_off`. Optional: `dst_off` (defaults to std_off), `std_abbr`,
   `dst_abbr`, `rule` (none|fixed|us|eu|au). On success populates
   rt_zone and returns 0; on any failure returns -1 (caller treats as
   "no such zone"). Unknown keys reject so typos surface loudly rather
   than silently using a wrong offset. */
static int
bashtz_parse_zone_file (const char *path)
{
  FILE *fp = fopen (path, "r");
  if (!fp) return -1;
  rt_name[0] = '\0';
  rt_std_abbr[0] = '\0';
  rt_dst_abbr[0] = '\0';
  rt_zone.name = NULL;
  rt_zone.std_off = 0;
  rt_zone.dst_off = 0;
  rt_zone.std_abbr = NULL;
  rt_zone.dst_abbr = NULL;
  rt_zone.rule = RULE_NONE;
  int got_name = 0, got_std_off = 0, got_dst_off = 0, got_std_abbr = 0;
  char line[256];
  while (fgets (line, sizeof line, fp))
    {
      char *p = bashtz_strip_ws (line);
      if (*p == '\0' || *p == '#') continue;
      char *eq = strchr (p, '=');
      if (!eq) { fclose (fp); return -1; }
      *eq = '\0';
      char *key = bashtz_strip_ws (p);
      char *val = bashtz_strip_ws (eq + 1);
      if (!strcasecmp (key, "name"))
        {
          if (*val == '\0' || strlen (val) > BASHTZ_RUNTIME_NAME_LEN)
            { fclose (fp); return -1; }
          strncpy (rt_name, val, BASHTZ_RUNTIME_NAME_LEN);
          rt_name[BASHTZ_RUNTIME_NAME_LEN] = '\0';
          rt_zone.name = rt_name;
          got_name = 1;
        }
      else if (!strcasecmp (key, "std_off") || !strcasecmp (key, "dst_off"))
        {
          char *end = NULL;
          long v = strtol (val, &end, 10);
          if (end == val || *end != '\0' || v < -50400 || v > 50400)
            { fclose (fp); return -1; }
          if (!strcasecmp (key, "std_off"))
            { rt_zone.std_off = (int) v; got_std_off = 1; }
          else
            { rt_zone.dst_off = (int) v; got_dst_off = 1; }
        }
      else if (!strcasecmp (key, "std_abbr"))
        {
          if (strlen (val) > BASHTZ_RUNTIME_ABBR_LEN) { fclose (fp); return -1; }
          strncpy (rt_std_abbr, val, BASHTZ_RUNTIME_ABBR_LEN);
          rt_std_abbr[BASHTZ_RUNTIME_ABBR_LEN] = '\0';
          rt_zone.std_abbr = rt_std_abbr;
          got_std_abbr = 1;
        }
      else if (!strcasecmp (key, "dst_abbr"))
        {
          if (strlen (val) > BASHTZ_RUNTIME_ABBR_LEN) { fclose (fp); return -1; }
          strncpy (rt_dst_abbr, val, BASHTZ_RUNTIME_ABBR_LEN);
          rt_dst_abbr[BASHTZ_RUNTIME_ABBR_LEN] = '\0';
          rt_zone.dst_abbr = rt_dst_abbr;
        }
      else if (!strcasecmp (key, "rule"))
        {
          if (!strcasecmp (val, "us")) rt_zone.rule = RULE_US;
          else if (!strcasecmp (val, "eu")) rt_zone.rule = RULE_EU;
          else if (!strcasecmp (val, "au")) rt_zone.rule = RULE_AU;
          else if (!strcasecmp (val, "none") || !strcasecmp (val, "fixed")
                   || *val == '\0')
            rt_zone.rule = RULE_NONE;
          else { fclose (fp); return -1; }
        }
      else
        { fclose (fp); return -1; }
    }
  fclose (fp);
  if (!got_name || !got_std_off) return -1;
  if (!got_dst_off) rt_zone.dst_off = rt_zone.std_off;
  if (!got_std_abbr)
    {
      strcpy (rt_std_abbr, "?");
      rt_zone.std_abbr = rt_std_abbr;
    }
  if (!rt_zone.dst_abbr) rt_zone.dst_abbr = rt_zone.std_abbr;
  return 0;
}

/* Look up `name` against the baked-in table; on miss, try
   $BASHTZ_ZONE_DIR/<name-with-/-as-_>. Returns NULL if neither hits. */
static const zoneinfo *
bashtz_lookup_named (const char *name)
{
  int i;
  for (i = 0; zones[i].name; i++)
    if (!strcmp (zones[i].name, name)) return &zones[i];
  size_t n = strlen (name);
  if (n == 0 || n > BASHTZ_RUNTIME_NAME_LEN) return NULL;
  const char *zdir = getenv ("BASHTZ_ZONE_DIR");
  if (!zdir || !*zdir) zdir = BASHTZ_DEFAULT_ZONE_DIR;
  char safe[BASHTZ_RUNTIME_NAME_LEN + 1];
  size_t j;
  for (j = 0; j <= n; j++)
    safe[j] = (name[j] == '/') ? '_' : name[j];
  char path[BASHTZ_PATH_BUF];
  int w = snprintf (path, sizeof path, "%s/%s", zdir, safe);
  if (w <= 0 || (size_t) w >= sizeof path) return NULL;
  if (bashtz_parse_zone_file (path) == 0) return &rt_zone;
  return NULL;
}

/* Precedence (highest wins):
     1. explicit zone arg (-z FLAG or `info ZONE` positional)
     2. $TZ env (treated as named-zone lookup, same as #1)
     3. $BASHTZ_ZONE_FILE (one-shot operator-drop file, no name lookup)
     4. baked-in "UTC" default
   For #1 and #2 the named-lookup chain is: baked-in table → then
   $BASHTZ_ZONE_DIR/<name-with-/-as-_> (default /etc/bash-os/zones.d).
   #3 wins only when neither -z nor $TZ supplied a name — explicit
   names always take precedence over the file-as-zone fixture so a
   `-z America/New_York` user-flag is never silently overridden. */
static const zoneinfo *
find_zone (const char *name)
{
  int name_was_explicit = (name && *name);
  if (!name_was_explicit)
    {
      const char *tz_env = getenv ("TZ");
      if (tz_env && *tz_env) name = tz_env;
    }
  if (name && *name) return bashtz_lookup_named (name);
  const char *zfile = getenv ("BASHTZ_ZONE_FILE");
  if (zfile && *zfile)
    return bashtz_parse_zone_file (zfile) == 0 ? &rt_zone : NULL;
  return bashtz_lookup_named ("UTC");
}

static int
dow_utc (int y, int m, int d)
{
  struct tm t;
  memset (&t, 0, sizeof t);
  t.tm_year = y - 1900;
  t.tm_mon = m - 1;
  t.tm_mday = d;
  timegm (&t);
  return t.tm_wday;
}

static int
nth_sunday (int y, int m, int nth)
{
  int first = dow_utc (y, m, 1);
  return 1 + ((7 - first) % 7) + 7 * (nth - 1);
}

static int
last_sunday (int y, int m)
{
  static const int mdays[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
  int last = mdays[m];
  if (m == 2 && ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0))) last = 29;
  return last - dow_utc (y, m, last);
}

static time_t
utc_of_local (int y, int m, int d, int hh, int mm, int ss, int offset)
{
  struct tm t;
  memset (&t, 0, sizeof t);
  t.tm_year = y - 1900;
  t.tm_mon = m - 1;
  t.tm_mday = d;
  t.tm_hour = hh;
  t.tm_min = mm;
  t.tm_sec = ss;
  return timegm (&t) - offset;
}

static int
zone_offset (const zoneinfo *z, time_t ts, const char **abbr)
{
  struct tm g;
  int y;
  time_t start, end;
  if (z->rule == RULE_NONE || z->std_off == z->dst_off)
    {
      if (abbr) *abbr = z->std_abbr;
      return z->std_off;
    }
  gmtime_r (&ts, &g);
  y = g.tm_year + 1900;
  if (z->rule == RULE_US)
    {
      start = utc_of_local (y, 3, nth_sunday (y, 3, 2), 2, 0, 0, z->std_off);
      end = utc_of_local (y, 11, nth_sunday (y, 11, 1), 2, 0, 0, z->dst_off);
      if (ts >= start && ts < end) { if (abbr) *abbr = z->dst_abbr; return z->dst_off; }
    }
  else if (z->rule == RULE_EU)
    {
      start = utc_of_local (y, 3, last_sunday (y, 3), 1, 0, 0, 0);
      end = utc_of_local (y, 10, last_sunday (y, 10), 1, 0, 0, 0);
      if (ts >= start && ts < end) { if (abbr) *abbr = z->dst_abbr; return z->dst_off; }
    }
  else if (z->rule == RULE_AU)
    {
      time_t start_cur = utc_of_local (y, 10, nth_sunday (y, 10, 1), 2, 0, 0, z->std_off);
      time_t end_next = utc_of_local (y + 1, 4, nth_sunday (y + 1, 4, 1), 3, 0, 0, z->dst_off);
      time_t start_prev = utc_of_local (y - 1, 10, nth_sunday (y - 1, 10, 1), 2, 0, 0, z->std_off);
      time_t end_cur = utc_of_local (y, 4, nth_sunday (y, 4, 1), 3, 0, 0, z->dst_off);
      if ((ts >= start_cur && ts < end_next) || (ts >= start_prev && ts < end_cur))
        { if (abbr) *abbr = z->dst_abbr; return z->dst_off; }
    }
  if (abbr) *abbr = z->std_abbr;
  return z->std_off;
}

static void
fmt_offset (int off, char *buf, size_t n)
{
  char sign = '+';
  if (off < 0) { sign = '-'; off = -off; }
  snprintf (buf, n, "%c%02d%02d", sign, off / 3600, (off % 3600) / 60);
}

static int
render_time (time_t ts, const zoneinfo *z, const char *var)
{
  int off;
  const char *abbr;
  struct tm tm;
  char out[128], obuf[16];
  off = zone_offset (z, ts, &abbr);
  gmtime_r (&(time_t){ ts + off }, &tm);
  fmt_offset (off, obuf, sizeof obuf);
  snprintf (out, sizeof out, "%04d-%02d-%02d %02d:%02d:%02d %s %s",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, abbr, obuf);
  if (var) builtin_bind_variable ((char *) var, out, 0);
  else puts (out);
  return EXECUTION_SUCCESS;
}

static int
parse_with_numeric_offset (const char *s, time_t *out)
{
  int y, mo, d, h, mi, se = 0, oh, om;
  char sign;
  int matched;
  se = 0;
  matched = sscanf (s, "%d-%d-%d %d:%d:%d %c%d", &y, &mo, &d, &h, &mi, &se, &sign, &oh);
  if (matched >= 7 && sign != '+' && sign != '-')
    return -1;  /* %c ate ':' instead of a sign char */
  if (matched < 7)
    {
      se = 0;
      matched = sscanf (s, "%d-%d-%d %d:%d %c%d", &y, &mo, &d, &h, &mi, &sign, &oh);
      if (matched < 7 || (sign != '+' && sign != '-')) return -1;
    }
  om = oh % 100;
  oh = oh / 100;
  if (sign == '-') oh = -oh, om = -om;
  *out = utc_of_local (y, mo, d, h, mi, se, oh * 3600 + om * 60);
  return 0;
}

int
tz_builtin (WORD_LIST *list)
{
  const char *verb, *zone = NULL, *var = NULL;
  const zoneinfo *z;
  time_t ts;
  int i;

  if (!list) { builtin_error ("usage: tz now|convert|parse|list|info"); return EX_USAGE; }
  verb = list->word->word;
  list = list->next;

  if (!strcmp (verb, "list"))
    {
      for (i = 0; zones[i].name; i++) puts (zones[i].name);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "now"))
    {
      while (list)
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-z") && list->next) { list = list->next; zone = list->word->word; }
          else if (!strcmp (w, "-V") && list->next) { list = list->next; var = list->word->word; }
          else { builtin_error ("unknown now arg: %s", w); builtin_usage (); return EX_USAGE; }
          list = list->next;
        }
      z = find_zone (zone);
      if (!z) { builtin_error ("unknown zone: %s", zone ? zone : getenv ("TZ")); return EXECUTION_FAILURE; }
      return render_time (time (NULL), z, var);
    }

  if (!strcmp (verb, "convert"))
    {
      if (!list) { builtin_error ("convert needs UNIX_TS"); return EX_USAGE; }
      char *end = NULL;
      ts = (time_t) strtoll (list->word->word, &end, 10);
      if (end == list->word->word || *end != '\0')
        { builtin_error ("convert needs numeric UNIX_TS"); return EX_USAGE; }
      list = list->next;
      while (list)
        {
          const char *w = list->word->word;
          if (!strcmp (w, "-z") && list->next) { list = list->next; zone = list->word->word; }
          else if (!strcmp (w, "-V") && list->next) { list = list->next; var = list->word->word; }
          else { builtin_error ("unknown convert arg: %s", w); builtin_usage (); return EX_USAGE; }
          list = list->next;
        }
      z = find_zone (zone);
      if (!z) { builtin_error ("unknown zone: %s", zone ? zone : getenv ("TZ")); return EXECUTION_FAILURE; }
      return render_time (ts, z, var);
    }

  if (!strcmp (verb, "parse"))
    {
      if (!list) { builtin_error ("parse needs DATE"); return EX_USAGE; }
      if (parse_with_numeric_offset (list->word->word, &ts) < 0)
        { builtin_error ("parse accepts 'YYYY-MM-DD HH:MM[:SS] +/-HHMM'"); return EX_USAGE; }
      list = list->next;
      if (list && !strcmp (list->word->word, "-V") && list->next)
        var = list->next->word->word;
      char buf[64];
      snprintf (buf, sizeof buf, "%lld", (long long) ts);
      if (var) builtin_bind_variable ((char *) var, buf, 0);
      else puts (buf);
      return EXECUTION_SUCCESS;
    }

  if (!strcmp (verb, "info"))
    {
      const char *abbr;
      int off;
      if (!list) { builtin_error ("info needs ZONE"); return EX_USAGE; }
      z = find_zone (list->word->word);
      if (!z) { builtin_error ("unknown zone: %s", list->word->word); return EXECUTION_FAILURE; }
      off = zone_offset (z, time (NULL), &abbr);
      char obuf[16];
      fmt_offset (off, obuf, sizeof obuf);
      printf ("name=%s\noffset=%s\nabbr=%s\nrule=%s\n", z->name, obuf, abbr,
              z->rule == RULE_US ? "us" : z->rule == RULE_EU ? "eu" :
              z->rule == RULE_AU ? "au" : "fixed");
      return EXECUTION_SUCCESS;
    }

  builtin_error ("unknown verb: %s", verb);
  builtin_usage ();
  return EX_USAGE;
}

char *tz_doc[] = {
  "Curated timezone conversion helper.",
  "",
  "    tz now [-z ZONE] [-V VAR]",
  "    tz convert UNIX_TS [-z ZONE] [-V VAR]",
  "    tz parse 'YYYY-MM-DD HH:MM[:SS] +/-HHMM' [-V VAR]",
  "    tz list",
  "    tz info ZONE",
  "",
  "Core bash-os bakes common zones only; full tzdata is a larger variant feature.",
  "",
  "Operator-drop runtime zones (Stage 45.A):",
  "  $BASHTZ_ZONE_FILE  one-shot sidecar file (used when neither -z nor",
  "                     $TZ names a zone). Format: key=value lines, '#'",
  "                     comments; required keys 'name' and 'std_off';",
  "                     optional 'dst_off' (default = std_off), 'std_abbr',",
  "                     'dst_abbr' (default = std_abbr), and 'rule'",
  "                     (none|fixed|us|eu|au).",
  "  $BASHTZ_ZONE_DIR   fallback directory for named-zone lookups that",
  "                     miss the baked-in table (default /etc/bash-os/zones.d).",
  "                     Filename = zone-name with '/' replaced by '_'.",
  "Both env paths are operator-controlled; no tzdata is shipped in core.",
  (char *)NULL
};

struct builtin tz_struct = {
  "tz",
  tz_builtin,
  BUILTIN_ENABLED,
  tz_doc,
  "tz now|convert|parse|list|info",
  0
};
