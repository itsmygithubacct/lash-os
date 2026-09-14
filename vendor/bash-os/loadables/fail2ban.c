/* SPDX-License-Identifier: MIT */
/* fail2ban.c - native control-plane parser/helper for the bash-os
 * fail2ban-class engine (Debian-server-parity AUDIT-6.6, design Q6).
 *
 *   fail2ban selftest
 *   fail2ban parse-command VERB [ARG...]
 *   fail2ban validate-ip   IP
 *   fail2ban validate-jail JAIL
 *   fail2ban format-status DB [JAIL]
 *
 * Control-plane ONLY: it parses/validates the accepted fail2ban-client argv
 * subset, validates IP/jail tokens, and formats the persistent ban.db into the
 * exact `fail2ban-client status` output shape. It owns NO firewall knowledge —
 * fw remains the sole firewall actor (design "Out of scope") — and it does
 * not mutate the db. The shell scripts (fail2ban-client.sh / fail2ban.sh) stay
 * as compatibility wrappers and fall back to pure shell when this loadable is
 * absent.
 *
 * Validators replicate lib/fail2ban-db.sh exactly so the loadable and shell
 * paths agree byte-for-byte under the differential TAP:
 *   IPv4  ^[0-9]{1,3}(\.[0-9]{1,3}){3}$
 *   IPv6  ^[0-9A-Fa-f:]+$  AND contains ':'
 *   jail  ^[A-Za-z0-9_.-]{1,64}$
 * The ban.db format is TAB-separated `<ip>\t<jail>\t<epoch>` per line; status
 * formatting mirrors fail2ban-client.sh cmd_status (sorted-unique jail list,
 * file-order banned-IP list, single-space joins with no trailing space).
 *
 * Exit: 0 ok, 1 operational failure, 2 usage / out-of-subset / invalid token.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loadables.h"

#define F2B_MAX_LINE   1024
#define F2B_MAX_BANS   200000

/* ---- validators (replicate lib/fail2ban-db.sh) ---- */

static int
f2b_valid_ip (const char *ip)
{
  if (ip == NULL || ip[0] == '\0')
    return 0;

  /* IPv4: four 1-3 digit groups separated by single dots. */
  {
    const char *p = ip;
    int groups = 0, digits;
    int ok = 1;
    while (ok)
      {
        digits = 0;
        while (*p >= '0' && *p <= '9') { p++; digits++; }
        if (digits < 1 || digits > 3) { ok = 0; break; }
        groups++;
        if (*p == '.') { p++; continue; }
        if (*p == '\0') break;
        ok = 0;
      }
    if (ok && groups == 4 && *p == '\0')
      return 1;
  }

  /* IPv6 (bracket-free): only hex digits and colons, and at least one colon. */
  {
    int has_colon = 0;
    const char *p;
    for (p = ip; *p; p++)
      {
        if (*p == ':') { has_colon = 1; continue; }
        if (!isxdigit ((unsigned char) *p))
          return 0;
      }
    if (has_colon)
      return 1;
  }
  return 0;
}

static int
f2b_valid_jail (const char *j)
{
  size_t n, i;
  if (j == NULL)
    return 0;
  n = strlen (j);
  if (n < 1 || n > 64)
    return 0;
  for (i = 0; i < n; i++)
    {
      int c = (unsigned char) j[i];
      if (!(isalnum (c) || c == '_' || c == '.' || c == '-'))
        return 0;
    }
  return 1;
}

/* ---- accepted fail2ban-client argv subset (replicate fail2ban-client.sh) ---- */

static int
f2b_in_subset (const char *verb)
{
  return verb && (!strcmp (verb, "status") || !strcmp (verb, "banip")
                  || !strcmp (verb, "unbanip") || !strcmp (verb, "reload"));
}

static int
f2b_known_unsupported (const char *verb)
{
  /* commands fail2ban-client.sh explicitly rejects as out-of-subset */
  return verb && (!strcmp (verb, "set") || !strcmp (verb, "get")
                  || !strcmp (verb, "start") || !strcmp (verb, "stop")
                  || !strcmp (verb, "add") || !strcmp (verb, "ping")
                  || !strcmp (verb, "reload-all"));
}

/* ---- ban.db parsing + status formatting ---- */

struct f2b_ban { char *ip; char *jail; };

static void
f2b_free_bans (struct f2b_ban *b, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) { free (b[i].ip); free (b[i].jail); }
  free (b);
}

/* Read DB into a bounded array of {ip,jail}. Returns count, or -1 on a read
 * error other than "missing file" (missing file => 0 bans, like the shell). */
static long
f2b_read_db (const char *path, struct f2b_ban **out)
{
  FILE *fp;
  char line[F2B_MAX_LINE];
  struct f2b_ban *bans = NULL;
  size_t cap = 0, n = 0;

  *out = NULL;
  fp = fopen (path, "r");
  if (fp == NULL)
    return (errno == ENOENT) ? 0 : -1;

  while (fgets (line, sizeof line, fp))
    {
      char *tab1, *tab2, *nl;
      if (n >= F2B_MAX_BANS)
        break;
      nl = strchr (line, '\n');
      if (nl) *nl = '\0';
      else { int c; while ((c = fgetc (fp)) != '\n' && c != EOF) ; } /* drop overlong tail */
      if (line[0] == '\0')
        continue;
      tab1 = strchr (line, '\t');
      if (tab1 == NULL)
        continue;                         /* malformed: no jail field */
      *tab1 = '\0';
      tab2 = strchr (tab1 + 1, '\t');
      if (tab2) *tab2 = '\0';             /* epoch (ignored) trimmed off */
      if (line[0] == '\0' || (tab1 + 1)[0] == '\0')
        continue;                         /* empty ip or jail */
      if (n == cap)
        {
          size_t ncap = cap ? cap * 2 : 64;
          struct f2b_ban *nb = realloc (bans, ncap * sizeof *nb);
          if (nb == NULL) { f2b_free_bans (bans, n); fclose (fp); return -1; }
          bans = nb; cap = ncap;
        }
      bans[n].ip = strdup (line);
      bans[n].jail = strdup (tab1 + 1);
      if (bans[n].ip == NULL || bans[n].jail == NULL)
        { free (bans[n].ip); free (bans[n].jail); f2b_free_bans (bans, n); fclose (fp); return -1; }
      n++;
    }
  fclose (fp);
  *out = bans;
  return (long) n;
}

static int
f2b_cmp_str (const void *a, const void *b)
{
  return strcmp (*(const char *const *) a, *(const char *const *) b);
}

/* Print `<items joined by single space, no trailing space>` then newline. */
static void
f2b_print_joined (char **items, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++)
    {
      if (i) putchar (' ');
      fputs (items[i], stdout);
    }
  putchar ('\n');
}

static int
f2b_format_status (const char *db, const char *jail)
{
  struct f2b_ban *bans;
  long n;

  n = f2b_read_db (db, &bans);
  if (n < 0)
    { builtin_error ("format-status: cannot read db: %s", db); return EXECUTION_FAILURE; }

  if (jail == NULL)
    {
      /* distinct jails, sorted-unique (mirrors f2b_db_jails | sort -u) */
      char **jails = NULL;
      size_t jn = 0, uniq = 0, i;
      if (n > 0)
        {
          jails = malloc ((size_t) n * sizeof *jails);
          if (jails == NULL) { f2b_free_bans (bans, (size_t) n); builtin_error ("oom"); return EXECUTION_FAILURE; }
          for (i = 0; i < (size_t) n; i++) jails[jn++] = bans[i].jail;
          qsort (jails, jn, sizeof *jails, f2b_cmp_str);
          for (i = 0; i < jn; i++)
            if (i == 0 || strcmp (jails[i], jails[uniq - 1]) != 0)
              jails[uniq++] = jails[i];
        }
      printf ("Status\n");
      printf ("|- Number of jails:\t%zu\n", uniq);
      printf ("`- Jail list:\t");
      f2b_print_joined (jails, uniq);
      free (jails);
      f2b_free_bans (bans, (size_t) (n < 0 ? 0 : n));
      return EXECUTION_SUCCESS;
    }

  if (!f2b_valid_jail (jail))
    { f2b_free_bans (bans, (size_t) n); builtin_error ("format-status: invalid jail name: %s", jail); return EX_USAGE; }

  /* banned IPs for one jail, in file order (mirrors f2b_db_list JAIL) */
  {
    char **ips = NULL;
    size_t cnt = 0, i;
    if (n > 0)
      {
        ips = malloc ((size_t) n * sizeof *ips);
        if (ips == NULL) { f2b_free_bans (bans, (size_t) n); builtin_error ("oom"); return EXECUTION_FAILURE; }
        for (i = 0; i < (size_t) n; i++)
          if (strcmp (bans[i].jail, jail) == 0)
            ips[cnt++] = bans[i].ip;
      }
    printf ("Status for the jail: %s\n", jail);
    printf ("|- Currently banned:\t%zu\n", cnt);
    printf ("`- Banned IP list:\t");
    f2b_print_joined (ips, cnt);
    free (ips);
  }
  f2b_free_bans (bans, (size_t) n);
  return EXECUTION_SUCCESS;
}

/* ---- self-test ---- */

static int
f2b_selftest (void)
{
  int fails = 0;
#define CK(cond, msg) do { if (!(cond)) { printf ("FAIL: %s\n", msg); fails++; } } while (0)
  CK (f2b_valid_ip ("1.2.3.4") == 1, "ipv4 1.2.3.4 valid");
  CK (f2b_valid_ip ("203.0.113.7") == 1, "ipv4 203.0.113.7 valid");
  CK (f2b_valid_ip ("1.2.3") == 0, "ipv4 1.2.3 invalid (3 groups)");
  CK (f2b_valid_ip ("1.2.3.4.5") == 0, "ipv4 5 groups invalid");
  CK (f2b_valid_ip ("12.34.56.789") == 1, "ipv4 1-3 digit groups (loose, matches shell)");
  CK (f2b_valid_ip ("1.2.3.4567") == 0, "ipv4 4-digit group invalid");
  CK (f2b_valid_ip ("fe80::1") == 1, "ipv6 fe80::1 valid");
  CK (f2b_valid_ip ("2001:db8::dead:beef") == 1, "ipv6 valid");
  CK (f2b_valid_ip ("not.an.ip.x") == 0, "alpha octet invalid");
  CK (f2b_valid_ip ("g::1") == 0, "ipv6 non-hex invalid");
  CK (f2b_valid_ip ("") == 0, "empty invalid");
  CK (f2b_valid_jail ("sshd") == 1, "jail sshd valid");
  CK (f2b_valid_jail ("nginx-http-auth") == 1, "jail with dash valid");
  CK (f2b_valid_jail ("bad jail") == 0, "jail with space invalid");
  CK (f2b_valid_jail ("") == 0, "empty jail invalid");
  CK (f2b_in_subset ("status") && f2b_in_subset ("banip")
      && f2b_in_subset ("unbanip") && f2b_in_subset ("reload"), "accepted subset");
  CK (!f2b_in_subset ("set") && f2b_known_unsupported ("set"), "set rejected/known");
  CK (!f2b_in_subset ("bogus") && !f2b_known_unsupported ("bogus"), "unknown verb");
#undef CK
  if (fails == 0)
    { printf ("fail2ban selftest: OK\n"); return EXECUTION_SUCCESS; }
  printf ("fail2ban selftest: %d failure(s)\n", fails);
  return EXECUTION_FAILURE;
}

/* ---- verb dispatch ---- */

static int
f2b_parse_command (WORD_LIST *args)
{
  const char *verb;
  if (args == NULL)
    { builtin_error ("parse-command: need VERB"); return EX_USAGE; }
  verb = args->word->word;
  if (f2b_in_subset (verb))
    { printf ("%s\n", verb); return EXECUTION_SUCCESS; }
  if (f2b_known_unsupported (verb))
    { builtin_error ("%s: not in accepted subset (status banip unbanip reload)", verb); return EX_USAGE; }
  builtin_error ("%s: unknown command (accepted: status banip unbanip reload)", verb);
  return EX_USAGE;
}

int
fail2ban_builtin (WORD_LIST *list)
{
  const char *cmd;
  WORD_LIST *args;

  if (list == NULL)
    { builtin_usage (); return EX_USAGE; }
  cmd = list->word->word;
  args = list->next;

  if (!strcmp (cmd, "selftest"))
    {
      if (args) { builtin_error ("selftest takes no args"); return EX_USAGE; }
      return f2b_selftest ();
    }
  if (!strcmp (cmd, "parse-command"))
    return f2b_parse_command (args);
  if (!strcmp (cmd, "validate-ip"))
    {
      if (args == NULL || args->next) { builtin_error ("validate-ip: need exactly one IP"); return EX_USAGE; }
      return f2b_valid_ip (args->word->word) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (!strcmp (cmd, "validate-jail"))
    {
      if (args == NULL || args->next) { builtin_error ("validate-jail: need exactly one JAIL"); return EX_USAGE; }
      return f2b_valid_jail (args->word->word) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
    }
  if (!strcmp (cmd, "format-status"))
    {
      const char *db, *jail = NULL;
      if (args == NULL) { builtin_error ("format-status: need DB [JAIL]"); return EX_USAGE; }
      db = args->word->word;
      if (args->next)
        {
          jail = args->next->word->word;
          if (args->next->next) { builtin_error ("format-status: too many arguments"); return EX_USAGE; }
        }
      return f2b_format_status (db, jail);
    }

  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *fail2ban_doc[] = {
  "Native control-plane parser/helper for the fail2ban-class engine.",
  "",
  "    fail2ban selftest",
  "    fail2ban parse-command VERB [ARG...]",
  "    fail2ban validate-ip   IP",
  "    fail2ban validate-jail JAIL",
  "    fail2ban format-status DB [JAIL]",
  "",
  "Control-plane only: validates the accepted fail2ban-client subset",
  "(status/banip/unbanip/reload), validates IP/jail tokens, and formats the",
  "TAB-separated ban.db into fail2ban-client status output. Owns no firewall",
  "logic (fw remains the firewall actor) and never mutates the db.",
  "Exit: 0 ok, 1 failure, 2 usage / out-of-subset / invalid token.",
  (char *) NULL
};

struct builtin fail2ban_struct = {
  "fail2ban",
  fail2ban_builtin,
  BUILTIN_ENABLED,
  fail2ban_doc,
  "fail2ban selftest|parse-command|validate-ip|validate-jail|format-status ...",
  0
};
