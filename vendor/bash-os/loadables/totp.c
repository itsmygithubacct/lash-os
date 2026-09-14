/* SPDX-License-Identifier: MIT */
/* totp.c - RFC 6238 TOTP generate/verify helpers.
 *
 *   totp generate -k SECRET_B32 [-t TIME] [-d DIGITS] [-s STEP] [-a ALG]
 *   totp verify   -k SECRET_B32 -c CODE [-w WINDOW] [-t TIME] [-d DIGITS] [-s STEP] [-a ALG]
 *   totp uri      -k SECRET_B32 -l LABEL -i ISSUER [-d DIGITS] [-s STEP] [-a ALG]
 *   totp keygen
 *
 * HMAC is deliberately delegated to crypto (`hmac-sha1`,
 * `hmac-sha256`, `hmac-sha512`) so this loadable owns only RFC 3548
 * base32 handling, HOTP dynamic truncation, and CLI policy.
 *
 * Verify path uses a byte-wise constant-time compare against each
 * candidate window step so a timing attacker cannot distinguish the
 * first differing byte of the OTP. Base32 decode enforces RFC 4648
 * §6: any trailing 5-bit group that does not align to a byte boundary
 * must have all leftover bits equal to zero; otherwise the secret is
 * rejected as malformed before any HMAC work runs.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

#include "loadables.h"

/* Genuine RFC 6238 secrets are small (keygen emits 20 bytes). Keep a
 * generous decoded-key ceiling so pathological argv input is rejected before
 * decoder/HMAC allocations grow without bound. */
#define BT_MAX_SECRET_BYTES 8192U

static int
bt_hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void
bt_to_hex (const unsigned char *buf, size_t n, char *out)
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
bt_unhex (const char *hex, unsigned char *out, size_t outsz)
{
  size_t o = 0;
  int hi = -1;
  for (const char *p = hex; *p; p++)
    {
      if (isspace ((unsigned char) *p)) continue;
      int v = bt_hexval ((unsigned char) *p);
      if (v < 0) return -1;
      if (hi < 0) { hi = v; continue; }
      if (o >= outsz) return -1;
      out[o++] = (unsigned char) ((hi << 4) | v);
      hi = -1;
    }
  if (hi >= 0) return -1;
  return (int) o;
}

static int
bt_b32val (int c)
{
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return c - '2' + 26;
  return -1;
}

static int
bt_base32_decode (const char *s, unsigned char **out, size_t *out_len)
{
  size_t cap = strlen (s) * 5 / 8 + 8;
  unsigned char *buf = malloc (cap);
  if (!buf) { builtin_error ("base32: oom"); return -1; }
  unsigned int acc = 0;
  int bits = 0;
  size_t n = 0;
  for (const char *p = s; *p; p++)
    {
      if (*p == '=' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '-') continue;
      int v = bt_b32val ((unsigned char) *p);
      if (v < 0)
        {
          free (buf);
          builtin_error ("base32: invalid character 0x%02x", (unsigned char) *p);
          return -1;
        }
      acc = (acc << 5) | (unsigned int) v;
      bits += 5;
      if (bits >= 8)
        {
          bits -= 8;
          if (n >= cap)
            {
              unsigned char *nb = realloc (buf, cap * 2);
              if (!nb) { free (buf); builtin_error ("base32: oom"); return -1; }
              buf = nb;
              cap *= 2;
            }
          buf[n++] = (unsigned char) ((acc >> bits) & 0xff);
        }
    }
  /* RFC 4648 §6: any leftover bits that do not form a complete byte
   * must be zero. Allowing non-zero leftover bits would mean two
   * distinct base32 strings decode to the same secret, breaking
   * authenticator-import canonicalization. */
  if (bits > 0 && (acc & (unsigned int) ((1u << bits) - 1u)) != 0)
    {
      free (buf);
      builtin_error ("base32: non-zero trailing bits (RFC 4648 §6)");
      return -1;
    }
  *out = buf;
  *out_len = n;
  return 0;
}

static int
bt_base32_decoded_bound_exceeds (const char *s)
{
  size_t chars = strlen (s);
  size_t decoded_bound = (chars / 8) * 5 + ((chars % 8) * 5) / 8;
  return decoded_bound > BT_MAX_SECRET_BYTES;
}

static char *
bt_base32_encode (const unsigned char *buf, size_t n)
{
  static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  size_t cap = ((n + 4) / 5) * 8 + 1;
  char *out = malloc (cap);
  if (!out) return NULL;
  unsigned int acc = 0;
  int bits = 0;
  size_t o = 0;
  for (size_t i = 0; i < n; i++)
    {
      acc = (acc << 8) | buf[i];
      bits += 8;
      while (bits >= 5)
        {
          bits -= 5;
          out[o++] = alpha[(acc >> bits) & 31];
        }
    }
  if (bits > 0)
    out[o++] = alpha[(acc << (5 - bits)) & 31];
  out[o] = '\0';
  return out;
}

static const char *
bt_alg_norm (const char *alg)
{
  if (!alg || !*alg) return "sha1";
  if (!strcasecmp (alg, "sha1") || !strcasecmp (alg, "hmac-sha1")) return "sha1";
  if (!strcasecmp (alg, "sha256") || !strcasecmp (alg, "hmac-sha256")) return "sha256";
  if (!strcasecmp (alg, "sha512") || !strcasecmp (alg, "hmac-sha512")) return "sha512";
  return NULL;
}

static const char *
bt_alg_uri (const char *alg)
{
  if (!strcmp (alg, "sha1")) return "SHA1";
  if (!strcmp (alg, "sha256")) return "SHA256";
  if (!strcmp (alg, "sha512")) return "SHA512";
  return "SHA1";
}

struct bt_child_guard {
  struct sigaction old_chld;
  sigset_t oldmask;
};

static int
bt_child_guard_begin (struct bt_child_guard *g)
{
  struct sigaction dfl;
  sigset_t block;
  memset (&dfl, 0, sizeof dfl);
  dfl.sa_handler = SIG_DFL;
  sigemptyset (&dfl.sa_mask);
  if (sigaction (SIGCHLD, &dfl, &g->old_chld) < 0)
    return -1;
  sigemptyset (&block);
  sigaddset (&block, SIGCHLD);
  if (sigprocmask (SIG_BLOCK, &block, &g->oldmask) < 0)
    {
      sigaction (SIGCHLD, &g->old_chld, NULL);
      return -1;
    }
  return 0;
}

static void
bt_child_guard_parent_end (struct bt_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
  sigaction (SIGCHLD, &g->old_chld, NULL);
}

static void
bt_child_guard_child_end (struct bt_child_guard *g)
{
  sigprocmask (SIG_SETMASK, &g->oldmask, NULL);
}

static int
bt_hmac_hex_via_bashcrypto (const char *alg, const unsigned char *key,
                            size_t key_len, uint64_t counter,
                            unsigned char *digest, size_t *digest_len)
{
  char key_hex_stack[512];
  char *key_hex = key_hex_stack;
  if (key_len * 2 + 1 > sizeof key_hex_stack)
    {
      key_hex = malloc (key_len * 2 + 1);
      if (!key_hex) { builtin_error ("hmac: oom"); return -1; }
    }
  bt_to_hex (key, key_len, key_hex);

  unsigned char msg[8];
  for (int i = 7; i >= 0; i--)
    {
      msg[i] = (unsigned char) (counter & 0xff);
      counter >>= 8;
    }

  char path[] = "/tmp/totp-counter.XXXXXX";
  int fd = mkstemp (path);
  if (fd < 0)
    {
      builtin_error ("mkstemp: %s", strerror (errno));
      if (key_hex != key_hex_stack) free (key_hex);
      return -1;
    }
  if (write (fd, msg, sizeof msg) != (ssize_t) sizeof msg)
    {
      builtin_error ("write counter: %s", strerror (errno));
      close (fd);
      unlink (path);
      if (key_hex != key_hex_stack) free (key_hex);
      return -1;
    }
  close (fd);

  /* Build only the verb name (closed enum sha1/sha256/sha512 via
   * bt_alg_norm). All other dynamic data (key_hex, path) is passed to
   * bash as positional parameters so the inline `-c` script body
   * remains a constant string literal — bash never re-parses the
   * dynamic values for metacharacters. See execlp call site below. */
  char alg_verb[32];
  if ((size_t) snprintf (alg_verb, sizeof alg_verb, "hmac-%s", alg) >= sizeof alg_verb)
    {
      builtin_error ("hmac alg name too long");
      unlink (path);
      if (key_hex != key_hex_stack) free (key_hex);
      return -1;
    }

  int p[2];
  if (pipe (p) < 0)
    {
      builtin_error ("pipe crypto: %s", strerror (errno));
      unlink (path);
      if (key_hex != key_hex_stack) free (key_hex);
      return -1;
    }

  struct bt_child_guard guard;
  if (bt_child_guard_begin (&guard) < 0)
    {
      builtin_error ("SIGCHLD guard: %s", strerror (errno));
      close (p[0]);
      close (p[1]);
      unlink (path);
      if (key_hex != key_hex_stack) free (key_hex);
      return -1;
    }

  pid_t pid = fork ();
  if (pid < 0)
    {
      builtin_error ("fork crypto: %s", strerror (errno));
      bt_child_guard_parent_end (&guard);
      close (p[0]);
      close (p[1]);
      unlink (path);
      if (key_hex != key_hex_stack) free (key_hex);
      return -1;
    }
  if (pid == 0)
    {
      bt_child_guard_child_end (&guard);
      close (p[0]);
      if (dup2 (p[1], STDOUT_FILENO) < 0)
        _exit (127);
      close (p[1]);
      /* crypto is a builtin baked into the running bash-os bash.
       * Re-exec this same binary first; falling back to PATH "bash" is
       * only for non-/proc hosts and may not carry the compiled-in builtin.
       * The script body stays literal; dynamic values arrive via "$@". */
      execl ("/proc/self/exe", "bash", "-c", "builtin crypto \"$@\"",
             "_", alg_verb, "-k", key_hex, "-x", path, (char *) NULL);
      execlp ("bash", "bash", "-c", "builtin crypto \"$@\"", "_", alg_verb, "-k", key_hex, "-x", path, (char *) NULL);
      _exit (127);
    }

  close (p[1]);
  char hex[257];
  size_t n = 0;
  while (n < sizeof hex - 1)
    {
      ssize_t r = read (p[0], hex + n, sizeof hex - 1 - n);
      if (r < 0)
        {
          if (errno == EINTR) continue;
          break;
        }
      if (r == 0) break;
      n += (size_t) r;
    }
  hex[n] = '\0';
  close (p[0]);
  int status = 0;
  pid_t w;
  while ((w = waitpid (pid, &status, 0)) < 0 && errno == EINTR)
    ;
  bt_child_guard_parent_end (&guard);
  unlink (path);
  if (key_hex != key_hex_stack) free (key_hex);
  if (w < 0)
    {
      builtin_error ("waitpid crypto: %s", strerror (errno));
      return -1;
    }
  if (!WIFEXITED (status) || WEXITSTATUS (status) != 0)
    {
      builtin_error ("crypto hmac-%s failed", alg);
      return -1;
    }

  char compact[257];
  size_t j = 0;
  for (size_t i = 0; i < n && j + 1 < sizeof compact; i++)
    if (!isspace ((unsigned char) hex[i])) compact[j++] = hex[i];
  compact[j] = '\0';
  int dn = bt_unhex (compact, digest, 64);
  if (dn <= 0)
    {
      builtin_error ("crypto hmac-%s emitted invalid hex", alg);
      return -1;
    }
  *digest_len = (size_t) dn;
  return 0;
}

static uint32_t
bt_mod10 (int digits)
{
  uint32_t m = 1;
  for (int i = 0; i < digits; i++) m *= 10U;
  return m;
}

static int
bt_totp_code (const char *secret_b32, int64_t when, int digits,
              int step, const char *alg, char *out, size_t outsz)
{
  unsigned char *key = NULL;
  size_t key_len = 0;
  if (bt_base32_decoded_bound_exceeds (secret_b32))
    {
      builtin_error ("secret too long (decoded > %u bytes)", BT_MAX_SECRET_BYTES);
      return -1;
    }
  if (bt_base32_decode (secret_b32, &key, &key_len) < 0) return -1;
  if (key_len == 0)
    {
      free (key);
      builtin_error ("secret decodes to zero bytes");
      return -1;
    }
  if (key_len > BT_MAX_SECRET_BYTES)
    {
      free (key);
      builtin_error ("secret too long (decoded %zu > %u bytes)", key_len, BT_MAX_SECRET_BYTES);
      return -1;
    }
  if (when < 0 || step <= 0)
    {
      free (key);
      builtin_error ("invalid time/step");
      return -1;
    }

  unsigned char digest[64];
  size_t dlen = 0;
  uint64_t counter = (uint64_t) (when / step);
  if (bt_hmac_hex_via_bashcrypto (alg, key, key_len, counter, digest, &dlen) < 0)
    {
      free (key);
      return -1;
    }
  free (key);
  if (dlen < 20)
    {
      builtin_error ("hmac digest too short");
      return -1;
    }
  unsigned int off = digest[dlen - 1] & 0x0f;
  if (off + 4 > dlen)
    {
      builtin_error ("hmac digest truncation offset out of range");
      return -1;
    }
  uint32_t bin = ((uint32_t) (digest[off] & 0x7f) << 24)
               | ((uint32_t) digest[off + 1] << 16)
               | ((uint32_t) digest[off + 2] << 8)
               | ((uint32_t) digest[off + 3]);
  uint32_t code = bin % bt_mod10 (digits);
  snprintf (out, outsz, "%0*u", digits, code);
  return 0;
}

static int
bt_parse_ll (const char *s, long long *out)
{
  char *e;
  errno = 0;
  long long v = strtoll (s, &e, 10);
  if (errno || e == s || *e != '\0') return -1;
  *out = v;
  return 0;
}

static int
bt_valid_code (const char *code, int digits)
{
  if ((int) strlen (code) != digits) return 0;
  for (const char *p = code; *p; p++)
    if (!isdigit ((unsigned char) *p)) return 0;
  return 1;
}

/* Byte-wise constant-time compare for two equal-length NUL-terminated
 * ASCII OTP strings. Caller has already verified both sides are
 * `digits` bytes long via bt_valid_code (verified side) and the
 * snprintf in bt_totp_code (candidate side); we compare exactly
 * `digits` bytes without short-circuiting so a timing attacker
 * cannot distinguish which byte first diverged. */
static int
bt_ct_str_equal (const char *a, const char *b, size_t n)
{
  /* volatile so -Os/-O2 cannot elide or short-circuit the accumulation. */
  volatile unsigned int diff = 0;
  for (size_t i = 0; i < n; i++)
    diff |= (unsigned int) ((unsigned char) a[i] ^ (unsigned char) b[i]);
  return diff == 0;
}

static int
bt_parse_common (WORD_LIST *args, const char **key, long long *when,
                 int *digits, int *step, const char **alg,
                 const char **code, int *window,
                 const char **label, const char **issuer)
{
  *key = NULL;
  *when = (long long) time (NULL);
  *digits = 6;
  *step = 30;
  *alg = "sha1";
  if (code) *code = NULL;
  if (window) *window = 1;
  if (label) *label = NULL;
  if (issuer) *issuer = NULL;

  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-k"))
        { if (!p->next) { builtin_error ("-k needs SECRET_B32"); return -1; }
          p = p->next; *key = p->word->word; }
      else if (!strcmp (w, "-t"))
        { long long v; if (!p->next || bt_parse_ll (p->next->word->word, &v) < 0) { builtin_error ("-t needs integer TIME"); return -1; }
          p = p->next; *when = v; }
      else if (!strcmp (w, "-d"))
        { long long v; if (!p->next || bt_parse_ll (p->next->word->word, &v) < 0 || v < 6 || v > 8) { builtin_error ("-d needs DIGITS 6..8"); return -1; }
          p = p->next; *digits = (int) v; }
      else if (!strcmp (w, "-s"))
        { long long v; if (!p->next || bt_parse_ll (p->next->word->word, &v) < 0 || v <= 0 || v > 3600) { builtin_error ("-s needs positive STEP"); return -1; }
          p = p->next; *step = (int) v; }
      else if (!strcmp (w, "-a"))
        { if (!p->next) { builtin_error ("-a needs HMAC_ALG"); return -1; }
          p = p->next; *alg = bt_alg_norm (p->word->word); if (!*alg) { builtin_error ("unsupported HMAC_ALG: %s", p->word->word); return -1; } }
      else if (code && !strcmp (w, "-c"))
        { if (!p->next) { builtin_error ("-c needs CODE"); return -1; }
          p = p->next; *code = p->word->word; }
      else if (window && !strcmp (w, "-w"))
        { long long v; if (!p->next || bt_parse_ll (p->next->word->word, &v) < 0 || v < 0 || v > 10) { builtin_error ("-w needs WINDOW 0..10"); return -1; }
          p = p->next; *window = (int) v; }
      else if (label && !strcmp (w, "-l"))
        { if (!p->next) { builtin_error ("-l needs LABEL"); return -1; }
          p = p->next; *label = p->word->word; }
      else if (issuer && !strcmp (w, "-i"))
        { if (!p->next) { builtin_error ("-i needs ISSUER"); return -1; }
          p = p->next; *issuer = p->word->word; }
      else
        {
          builtin_error ("unexpected arg: %s", w);
          return -1;
        }
    }
  return 0;
}

static int
bt_generate_cmd (WORD_LIST *args)
{
  const char *key, *alg, *code = NULL, *label = NULL, *issuer = NULL;
  long long when;
  int digits, step, window;
  char out[16];
  if (bt_parse_common (args, &key, &when, &digits, &step, &alg, &code, &window, &label, &issuer) < 0)
    return EX_USAGE;
  if (!key) { builtin_error ("generate needs -k SECRET_B32"); return EX_USAGE; }
  if (bt_totp_code (key, when, digits, step, alg, out, sizeof out) < 0)
    return EXECUTION_FAILURE;
  puts (out);
  return EXECUTION_SUCCESS;
}

static int
bt_verify_cmd (WORD_LIST *args)
{
  const char *key, *alg, *code, *label = NULL, *issuer = NULL;
  long long when;
  int digits, step, window;
  char out[16];
  if (bt_parse_common (args, &key, &when, &digits, &step, &alg, &code, &window, &label, &issuer) < 0)
    return EX_USAGE;
  if (!key || !code) { builtin_error ("verify needs -k SECRET_B32 -c CODE"); return EX_USAGE; }
  if (!bt_valid_code (code, digits)) return EXECUTION_FAILURE;
  for (int off = -window; off <= window; off++)
    {
      long long t = when + (long long) off * step;
      if (t < 0) continue;
      if (bt_totp_code (key, t, digits, step, alg, out, sizeof out) == 0
          && bt_ct_str_equal (out, code, (size_t) digits))
        return EXECUTION_SUCCESS;
    }
  return EXECUTION_FAILURE;
}

static int
bt_keygen_cmd (WORD_LIST *args)
{
  if (args) { builtin_error ("keygen takes no args"); return EX_USAGE; }
  unsigned char key[20];
  int fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0) { builtin_error ("open /dev/urandom: %s", strerror (errno)); return EXECUTION_FAILURE; }
  size_t got = 0;
  while (got < sizeof key)
    {
      ssize_t n = read (fd, key + got, sizeof key - got);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          builtin_error ("read /dev/urandom: %s", strerror (errno));
          close (fd);
          return EXECUTION_FAILURE;
        }
      if (n == 0) { builtin_error ("short read from /dev/urandom"); close (fd); return EXECUTION_FAILURE; }
      got += (size_t) n;
    }
  close (fd);
  char *b32 = bt_base32_encode (key, sizeof key);
  if (!b32) { builtin_error ("keygen: oom"); return EXECUTION_FAILURE; }
  puts (b32);
  free (b32);
  return EXECUTION_SUCCESS;
}

static int
bt_uri_put_component (const char *s)
{
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *) s; *p; p++)
    {
      if (isalnum (*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~')
        putchar (*p);
      else
        {
          putchar ('%');
          putchar (hex[*p >> 4]);
          putchar (hex[*p & 15]);
        }
    }
  return 0;
}

static int
bt_uri_cmd (WORD_LIST *args)
{
  const char *key, *alg, *code = NULL, *label, *issuer;
  long long when;
  int digits, step, window;
  if (bt_parse_common (args, &key, &when, &digits, &step, &alg, &code, &window, &label, &issuer) < 0)
    return EX_USAGE;
  if (!key || !label || !issuer)
    { builtin_error ("uri needs -k SECRET_B32 -l LABEL -i ISSUER"); return EX_USAGE; }
  printf ("otpauth://totp/");
  bt_uri_put_component (issuer);
  putchar (':');
  bt_uri_put_component (label);
  printf ("?secret=%s&issuer=", key);
  bt_uri_put_component (issuer);
  printf ("&algorithm=%s&digits=%d&period=%d\n", bt_alg_uri (alg), digits, step);
  return EXECUTION_SUCCESS;
}

/* Percent-decode a NUL-terminated string in-place.  Returns the string. */
static char *
bt_uri_pct_decode (char *s)
{
  char *w = s;
  for (const char *r = s; *r; )
    {
      if (*r == '%' && r[1] && r[2])
        {
          int hi = bt_hexval ((unsigned char) r[1]);
          int lo = bt_hexval ((unsigned char) r[2]);
          if (hi >= 0 && lo >= 0)
            { *w++ = (char) ((hi << 4) | lo); r += 3; continue; }
        }
      *w++ = *r++;
    }
  *w = '\0';
  return s;
}

/* Extract a single key=value pair from a query string.  Returns 1 if
   found, 0 if not, 2 if the raw value will not fit.  The value is
   percent-decoded in-place into val. */
static int
bt_qval (const char *qs, size_t qlen, const char *key,
         char *val, size_t valsz)
{
  size_t klen = strlen (key);
  const char *end = qs + qlen;
  while (qs < end)
    {
      const char *amp = memchr (qs, '&', (size_t) (end - qs));
      if (!amp) amp = end;
      const char *eq = memchr (qs, '=', (size_t) (amp - qs));
      if (eq)
        {
          size_t nk = (size_t) (eq - qs);
          if (nk == klen && memcmp (qs, key, klen) == 0)
            {
              size_t nv = (size_t) (amp - eq - 1);
              if (nv >= valsz) return 2;
              memcpy (val, eq + 1, nv);
              val[nv] = '\0';
              bt_uri_pct_decode (val);
              return 1;
            }
        }
      qs = amp + 1;
    }
  return 0;
}

/*
 * totp parse-uri <otpauth://totp/...>
 *
 * Parse an otpauth://totp/ URI and print its components as
 * key=value lines (secret, issuer, label, algorithm, digits, period).
 * Machine-parseable: one field per line, no escaping beyond the
 * percent-decoding already applied.
 */
static int
bt_parse_uri_cmd (WORD_LIST *args)
{
  if (!args || !args->word || args->next)
    { builtin_error ("usage: totp parse-uri <otpauth://totp/...>"); return EX_USAGE; }

  const char *uri = args->word->word;
  size_t ulen = strlen (uri);

  /* Scheme: "otpauth://" (10 chars) */
  if (ulen < 11 || strncmp (uri, "otpauth://", 10) != 0)
    { builtin_error ("not an otpauth URI"); return EXECUTION_FAILURE; }

  /* Reject any literal '#' (RFC 3986 §3.5 fragment delimiter). The
   * otpauth URI scheme defines no fragment semantics, so a literal '#'
   * indicates a malformed or forged URI — without this guard the query
   * walker treats '?secret=Y#frag' as a single secret value of
   * 'Y#frag' (which then gets uppercased to 'Y#FRAG'), accepting the
   * URI silently. Percent-encoded '%23' is data, not a fragment
   * delimiter, and is left alone. */
  if (strchr (uri, '#') != NULL)
    { builtin_error ("otpauth URI must not contain a fragment");
      return EXECUTION_FAILURE; }

  const char *p = uri + 10;

  /* Type: must be "totp" */
  if (strncmp (p, "totp", 4) != 0)
    {
      const char *tend = p;
      while (*tend && *tend != '/' && *tend != '?') tend++;
      builtin_error ("unsupported otpauth type '%.*s'", (int) (tend - p), p);
      return EXECUTION_FAILURE;
    }
  p += 4;

  /* Skip '/' after type */
  if (*p == '/') p++;

  /* Path: [ISSUER:]LABEL (up to '?' or end) */
  const char *qmark = strchr (p, '?');
  if (!qmark) qmark = uri + ulen;

  char label[256];
  char issuer[256];
  const char *issuer_out = NULL;
  int has_label = 0;

  if (qmark > p)
    {
      size_t plen = (size_t) (qmark - p);
      if (plen >= sizeof label)
        { builtin_error ("otpauth URI label too long"); return EXECUTION_FAILURE; }
      memcpy (label, p, plen);
      label[plen] = '\0';
      has_label = 1;

      /* Split issuer/label on the FIRST LITERAL ':' (before percent-
       * decoding) so a percent-encoded ':' (RFC 3986 §2.4 reserved)
       * embedded in the issuer or label survives the split.  Each
       * half is then percent-decoded independently. */
      char *colon = strchr (label, ':');
      if (colon)
        {
          *colon = '\0';
          strcpy (issuer, label);
          bt_uri_pct_decode (issuer);
          issuer_out = issuer;
          memmove (label, colon + 1, strlen (colon + 1) + 1);
        }
      bt_uri_pct_decode (label);
    }

  /* Query parameters */
  char secret[1024] = "";
  char q_alg[32] = "", q_issuer_decoded[256] = "";
  char q_digits[16] = "", q_period[16] = "";
  int has_secret = 0, has_issuer_param = 0;

  if (*qmark == '?')
    {
      const char *qs = qmark + 1;
      size_t qlen = (size_t) (uri + ulen - qs);
      int qrc;

      qrc = bt_qval (qs, qlen, "secret", secret, sizeof secret);
      if (qrc == 2)
        { builtin_error ("otpauth URI secret too long"); return EXECUTION_FAILURE; }
      has_secret = qrc;
      qrc = bt_qval (qs, qlen, "issuer", q_issuer_decoded, sizeof q_issuer_decoded);
      if (qrc == 2)
        { builtin_error ("otpauth URI issuer too long"); return EXECUTION_FAILURE; }
      has_issuer_param = qrc;
      qrc = bt_qval (qs, qlen, "algorithm", q_alg, sizeof q_alg);
      if (qrc == 2)
        { builtin_error ("otpauth URI algorithm too long"); return EXECUTION_FAILURE; }
      qrc = bt_qval (qs, qlen, "digits", q_digits, sizeof q_digits);
      if (qrc == 2)
        { builtin_error ("otpauth URI digits too long"); return EXECUTION_FAILURE; }
      qrc = bt_qval (qs, qlen, "period", q_period, sizeof q_period);
      if (qrc == 2)
        { builtin_error ("otpauth URI period too long"); return EXECUTION_FAILURE; }
    }

  /* Must have a secret */
  if (!has_secret || secret[0] == '\0')
    { builtin_error ("URI missing required 'secret' parameter"); return EXECUTION_FAILURE; }

  /* Canonicalize secret to uppercase */
  for (char *s = secret; *s; s++) *s = toupper ((unsigned char) *s);

  /* Normalize algorithm */
  const char *alg = q_alg[0] ? bt_alg_norm (q_alg) : "sha1";
  if (!alg)
    { builtin_error ("unsupported algorithm in URI: %s", q_alg); return EXECUTION_FAILURE; }

  /* Parse digits */
  int digits = 6;
  if (q_digits[0])
    {
      long long v;
      if (bt_parse_ll (q_digits, &v) < 0 || v < 6 || v > 8)
        { builtin_error ("invalid digits in URI: %s", q_digits); return EXECUTION_FAILURE; }
      digits = (int) v;
    }

  /* Parse period */
  int period = 30;
  if (q_period[0])
    {
      long long v;
      if (bt_parse_ll (q_period, &v) < 0 || v <= 0 || v > 86400)
        { builtin_error ("invalid period in URI: %s", q_period); return EXECUTION_FAILURE; }
      period = (int) v;
    }

  /* If query-param issuer is present, it takes precedence over path issuer */
  if (has_issuer_param && q_issuer_decoded[0])
    issuer_out = q_issuer_decoded;

  /* Output */
  printf ("secret=%s\n", secret);
  if (issuer_out && issuer_out[0]) printf ("issuer=%s\n", issuer_out);
  if (has_label) printf ("label=%s\n", label);
  printf ("algorithm=%s\n", alg);
  printf ("digits=%d\n", digits);
  printf ("period=%d\n", period);

  return EXECUTION_SUCCESS;
}

int
totp_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  WORD_LIST *args = list->next;
  if (!strcmp (cmd, "generate"))  return bt_generate_cmd (args);
  if (!strcmp (cmd, "verify"))    return bt_verify_cmd (args);
  if (!strcmp (cmd, "uri"))       return bt_uri_cmd (args);
  if (!strcmp (cmd, "keygen"))    return bt_keygen_cmd (args);
  if (!strcmp (cmd, "parse-uri")) return bt_parse_uri_cmd (args);
  builtin_error ("unknown subcommand: %s", cmd);
  return EX_USAGE;
}

char *totp_doc[] = {
  "RFC 6238 TOTP generate/verify helpers.",
  "",
  "    totp generate -k SECRET_B32 [-t TIME] [-d DIGITS] [-s STEP] [-a sha1|sha256|sha512]",
  "    totp verify   -k SECRET_B32 -c CODE [-w WINDOW] [-t TIME] [-d DIGITS] [-s STEP] [-a ALG]",
  "    totp uri      -k SECRET_B32 -l LABEL -i ISSUER [-d DIGITS] [-s STEP] [-a ALG]",
  "    totp parse-uri <otpauth://totp/...>",
  "    totp keygen",
  "",
  "SECRET_B32 is RFC 3548/RFC 4648 base32. HMAC is delegated to crypto.",
  "Verify uses byte-wise constant-time compare on the OTP. Base32 decode",
  "enforces RFC 4648 §6: trailing bits that don't form a byte must be zero.",
  "parse-uri rejects over-long URI fields instead of truncating them.",
  (char *)NULL
};

struct builtin totp_struct = {
  "totp",
  totp_builtin,
  BUILTIN_ENABLED,
  totp_doc,
  "totp generate|verify|uri|parse-uri|keygen ...",
  0
};
