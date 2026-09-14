/* SPDX-License-Identifier: MIT */
#include <config.h>

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "_bashauth_pwverify.h"
#include "_bashos_authcrypto_argon2id.h"

typedef struct {
  unsigned int m, t, p;
  char salt_hex[129];
  char hash_hex[257];
} bashos_phc_argon2id;

static void
bashos_pw_wipe (void *p, size_t n)
{
  volatile unsigned char *q = (volatile unsigned char *) p;
  while (q && n--)
    *q++ = 0;
}

static int
bashos_pw_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
bashos_pw_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;

  for (const char *p = hex; *p; p++)
    {
      int v = bashos_pw_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  return hi < 0 ? (int) o : -1;
}

static void
bashos_pw_hex_encode (const unsigned char *buf, size_t n, char *out)
{
  static const char d[] = "0123456789abcdef";

  for (size_t i = 0; i < n; i++)
    {
      out[i * 2] = d[(buf[i] >> 4) & 0xf];
      out[i * 2 + 1] = d[buf[i] & 0xf];
    }
  out[n * 2] = '\0';
}

static int
bashos_pw_parse_uint (const char *s, unsigned int *out)
{
  char *end = NULL;
  unsigned long v;

  if (!s || !*s)
    return -1;
  v = strtoul (s, &end, 10);
  if (!end || end == s || *end || v > 0xfffffffful)
    return -1;
  *out = (unsigned int) v;
  return 0;
}

static int
bashos_pw_parse_phc (const char *phc, bashos_phc_argon2id *out)
{
  if (!phc || strncmp (phc, "$argon2id$", 10) != 0)
    return -1;

  char *copy = strdup (phc);
  if (!copy)
    return -1;

  char *save = NULL;
  char *parts[6] = { 0 };
  int n = 0;
  for (char *tok = strtok_r (copy, "$", &save); tok && n < 6;
       tok = strtok_r (NULL, "$", &save))
    parts[n++] = tok;

  if (n != 5 || strcmp (parts[0], "argon2id") != 0 ||
      strcmp (parts[1], "v=19") != 0)
    goto fail;

  memset (out, 0, sizeof *out);
  char *psave = NULL;
  for (char *kv = strtok_r (parts[2], ",", &psave); kv;
       kv = strtok_r (NULL, ",", &psave))
    {
      if (strncmp (kv, "m=", 2) == 0)
        {
          if (bashos_pw_parse_uint (kv + 2, &out->m) < 0) goto fail;
        }
      else if (strncmp (kv, "t=", 2) == 0)
        {
          if (bashos_pw_parse_uint (kv + 2, &out->t) < 0) goto fail;
        }
      else if (strncmp (kv, "p=", 2) == 0)
        {
          if (bashos_pw_parse_uint (kv + 2, &out->p) < 0) goto fail;
        }
    }

  size_t sl = strlen (parts[3]), hl = strlen (parts[4]);
  if (out->m < 1024 || out->m > 262144 ||
      out->t < 1 || out->t > 10 ||
      out->p < 1 || out->p > 8 ||
      sl < 16 || sl > 128 || (sl & 1) ||
      hl < 32 || hl > 256 || (hl & 1))
    goto fail;

  strncpy (out->salt_hex, parts[3], sizeof out->salt_hex - 1);
  strncpy (out->hash_hex, parts[4], sizeof out->hash_hex - 1);
  free (copy);
  return 0;

fail:
  free (copy);
  return -1;
}

int
bashos_verify_phc_secret (const unsigned char *pw, size_t pw_len,
                          const char *phc)
{
  bashos_phc_argon2id parsed;
  unsigned char salt[64];
  unsigned char got[128];
  char derived[257];
  int salt_len;
  size_t out_len;

  memset (&parsed, 0, sizeof parsed);
  memset (salt, 0, sizeof salt);
  memset (got, 0, sizeof got);
  memset (derived, 0, sizeof derived);

  if (bashos_pw_parse_phc (phc, &parsed) < 0)
    return -1;

  salt_len = bashos_pw_unhex (parsed.salt_hex, salt, sizeof salt);
  if (salt_len < 8)
    {
      bashos_pw_wipe (&parsed, sizeof parsed);
      return -1;
    }

  out_len = strlen (parsed.hash_hex) / 2;
  if (bashos_auth_argon2id_raw (pw, pw_len, salt, (size_t) salt_len,
                                parsed.t, parsed.m, parsed.p,
                                got, out_len, 1, NULL) < 0)
    {
      bashos_pw_wipe (&parsed, sizeof parsed);
      bashos_pw_wipe (salt, sizeof salt);
      bashos_pw_wipe (got, sizeof got);
      return -1;
    }

  bashos_pw_hex_encode (got, out_len, derived);
  bashos_pw_wipe (got, sizeof got);
  bashos_pw_wipe (salt, sizeof salt);

  volatile unsigned char acc = 0;
  size_t dl = strlen (derived), hl = strlen (parsed.hash_hex);
  if (dl != hl)
    {
      bashos_pw_wipe (derived, sizeof derived);
      bashos_pw_wipe (&parsed, sizeof parsed);
      return 1;
    }
  for (size_t i = 0; i < dl; i++)
    acc |= (unsigned char) (derived[i] ^ parsed.hash_hex[i]);

  bashos_pw_wipe (derived, sizeof derived);
  bashos_pw_wipe (&parsed, sizeof parsed);
  return acc == 0 ? 0 : 1;
}
