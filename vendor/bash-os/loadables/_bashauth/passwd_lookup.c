/* SPDX-License-Identifier: MIT */
#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "_bashauth_passwd_lookup.h"

static const char *
bashos_passwd_path (void)
{
  const char *path = getenv ("PHCLIB_PASSWD");
  if (!path || !*path)
    path = getenv ("PASSWD_FILE");
  return (path && *path) ? path : "/etc/passwd";
}

static const char *
bashos_shadow_path (void)
{
  const char *path = getenv ("PHCLIB_SHADOW");
  if (!path || !*path)
    path = getenv ("SHADOW_FILE");
  return (path && *path) ? path : "/etc/shadow";
}

static int
bashos_parse_id (const char *s, uintmax_t *value)
{
  if (!s || !*s) return -1;
  uintmax_t v = 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9' || v > (UINTMAX_MAX - (*s - '0')) / 10) return -1;
    v = v * 10 + (*s - '0');
  }
  *value = v;
  return 0;
}

int
bashos_valid_user_name (const char *user)
{
  if (!user || !user[0])
    return 0;
  if (!((user[0] >= 'a' && user[0] <= 'z') || user[0] == '_'))
    return 0;

  for (size_t i = 1; user[i]; i++)
    {
      unsigned char c = (unsigned char) user[i];
      if (i >= 32)
        return 0;
      if (!((c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-'))
        return 0;
    }
  return 1;
}

int
bashos_lookup_user (const char *name, bashos_auth_user *out)
{
  if (!bashos_valid_user_name (name) || !out)
    {
      errno = EINVAL;
      return -1;
    }

  FILE *f = fopen (bashos_passwd_path (), "r");
  if (!f)
    return -2;

  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int found = 0;

  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (line[n - 1] == '\n')
        line[n - 1] = '\0';
      if (line[0] == '#' || line[0] == '\0')
        continue;

      char *fields[7] = { 0 };
      int nf = 0;
      char *p = line, *start = line;
      while (*p && nf < 7)
        {
          if (*p == ':')
            {
              *p = '\0';
              fields[nf++] = start;
              start = p + 1;
            }
          p++;
        }
      if (nf < 6)
        continue;
      fields[nf++] = start;

      if (strcmp (fields[0], name) != 0)
        continue;

      uintmax_t uid, gid;
      if (bashos_parse_id (fields[2], &uid) < 0 || bashos_parse_id (fields[3], &gid) < 0 ||
          uid >= (uintmax_t) (uid_t) -1 || gid >= (uintmax_t) (gid_t) -1 ||
          strchr (fields[6], ':') || strlen (fields[4]) >= sizeof out->gecos ||
          strlen (fields[5]) >= sizeof out->home || strlen (fields[6]) >= sizeof out->shell) {
        errno = EINVAL; break;
      }

      memset (out, 0, sizeof *out);
      strncpy (out->name, fields[0], sizeof out->name - 1);
      out->uid = (uid_t) uid;
      out->gid = (gid_t) gid;
      strncpy (out->gecos, fields[4], sizeof out->gecos - 1);
      strncpy (out->home, fields[5], sizeof out->home - 1);
      strncpy (out->shell, fields[6], sizeof out->shell - 1);
      if (out->shell[0] == '\0')
        strncpy (out->shell, "/bin/bash", sizeof out->shell - 1);
      found = 1;
      break;
    }

  free (line);
  fclose (f);
  return found ? 0 : -1;
}

int
bashos_read_shadow_entry (const char *name, bashos_shadow_entry *out)
{
  if (!bashos_valid_user_name (name) || !out)
    {
      errno = EINVAL;
      return -1;
    }

  FILE *f = fopen (bashos_shadow_path (), "r");
  if (!f)
    return -1;

  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int rc = -1;

  while ((n = getline (&line, &cap, f)) > 0)
    {
      if (n && line[n - 1] == '\n')
        line[n - 1] = '\0';
      char *c1 = strchr (line, ':');
      if (!c1)
        continue;
      *c1 = '\0';
      if (strcmp (line, name) != 0)
        continue;

      char *phc = c1 + 1;
      char *c2 = strchr (phc, ':');
      if (c2)
        *c2 = '\0';
      char *fields[8] = { 0 };
      int nf = 0;
      if (phc[0] == '\0' || phc[0] == '!' || phc[0] == '*')
        {
          rc = -2;
          break;
        }
      if (strlen (phc) >= sizeof out->phc)
        {
          errno = ENAMETOOLONG;
          rc = -1;
          break;
        }
      memset (out, 0, sizeof *out);
      out->last_change = out->min_days = out->max_days = out->warn_days = -1;
      out->inactive_days = out->expire_days = -1;
      strcpy (out->phc, phc);
      char *rest = c2 ? c2 + 1 : NULL;
      while (rest && nf < 8)
        {
          fields[nf++] = rest;
          char *colon = strchr (rest, ':');
          if (!colon)
            break;
          *colon = '\0';
          rest = colon + 1;
        }
      if (nf > 0 && fields[0] && *fields[0]) out->last_change = strtol (fields[0], NULL, 10);
      if (nf > 1 && fields[1] && *fields[1]) out->min_days = strtol (fields[1], NULL, 10);
      if (nf > 2 && fields[2] && *fields[2]) out->max_days = strtol (fields[2], NULL, 10);
      if (nf > 3 && fields[3] && *fields[3]) out->warn_days = strtol (fields[3], NULL, 10);
      if (nf > 4 && fields[4] && *fields[4]) out->inactive_days = strtol (fields[4], NULL, 10);
      if (nf > 5 && fields[5] && *fields[5]) out->expire_days = strtol (fields[5], NULL, 10);
      rc = 0;
      break;
    }

  free (line);
  fclose (f);
  return rc;
}

int
bashos_read_shadow_phc (const char *name, char *out, size_t outsz)
{
  if (!out || outsz == 0)
    {
      errno = EINVAL;
      return -1;
    }
  bashos_shadow_entry ent;
  int rc = bashos_read_shadow_entry (name, &ent);
  if (rc != 0)
    return rc;
  if (strlen (ent.phc) >= outsz)
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  strcpy (out, ent.phc);
  return 0;
}
