/* SPDX-License-Identifier: MIT */
/* pkt.c - Git pkt-line helpers for bash-os network git stages. */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "loadables.h"

static int
bind_or_print (const char *var, const char *s, size_t n)
{
  if (var)
    {
      char *buf = malloc (n + 1);
      if (!buf) return EXECUTION_FAILURE;
      memcpy (buf, s, n);
      buf[n] = '\0';
      builtin_bind_variable ((char *) var, buf, 0);
      free (buf);
    }
  else
    fwrite (s, 1, n, stdout);
  return EXECUTION_SUCCESS;
}

static int
hexval (int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int
encode_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("encode TEXT [-V VAR]"); return EX_USAGE; }
  const char *text = args->word->word;
  const char *var = NULL;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      if (!strcmp (p->word->word, "-V") && p->next)
        { p = p->next; var = p->word->word; }
      else { builtin_error ("encode: unexpected arg: %s", p->word->word); return EX_USAGE; }
    }
  size_t tlen = strlen (text);
  size_t len = tlen + 4;
  if (len > 0xffff) { builtin_error ("encode: pkt-line too long"); return EX_USAGE; }
  char *out = malloc (len + 1);
  if (!out) return EXECUTION_FAILURE;
  snprintf (out, 5, "%04zx", len);
  memcpy (out + 4, text, tlen);
  out[len] = '\0';
  int rc = bind_or_print (var, out, len);
  free (out);
  return rc;
}

static int
decode_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("decode INPUT [-L LEN_VAR] [-V PAYLOAD_VAR]"); return EX_USAGE; }
  const char *in = args->word->word;
  const char *len_var = NULL, *payload_var = NULL;
  for (WORD_LIST *p = args->next; p; p = p->next)
    {
      if (!strcmp (p->word->word, "-L") && p->next)
        { p = p->next; len_var = p->word->word; }
      else if (!strcmp (p->word->word, "-V") && p->next)
        { p = p->next; payload_var = p->word->word; }
      else { builtin_error ("decode: unexpected arg: %s", p->word->word); return EX_USAGE; }
    }
  if (strlen (in) < 4) { builtin_error ("decode: short input"); return EX_USAGE; }
  int n0 = hexval ((unsigned char) in[0]);
  int n1 = hexval ((unsigned char) in[1]);
  int n2 = hexval ((unsigned char) in[2]);
  int n3 = hexval ((unsigned char) in[3]);
  if (n0 < 0 || n1 < 0 || n2 < 0 || n3 < 0)
    { builtin_error ("decode: invalid length header"); return EX_USAGE; }
  int len = (n0 << 12) | (n1 << 8) | (n2 << 4) | n3;
  char lbuf[16];
  snprintf (lbuf, sizeof lbuf, "%d", len);
  if (len_var) builtin_bind_variable ((char *) len_var, lbuf, 0);
  if (len == 0 || len == 1 || len == 2)
    {
      if (payload_var) builtin_bind_variable ((char *) payload_var, "", 0);
      return EXECUTION_SUCCESS;
    }
  if (len < 4 || (size_t) len > strlen (in))
    { builtin_error ("decode: declared length exceeds input"); return EXECUTION_FAILURE; }
  return bind_or_print (payload_var, in + 4, (size_t) len - 4);
}

static int
sideband_cmd (WORD_LIST *args)
{
  const char *in = NULL, *out = NULL;
  for (WORD_LIST *p = args; p; p = p->next)
    {
      const char *w = p->word->word;
      if (!strcmp (w, "-o") && p->next) { p = p->next; out = p->word->word; }
      else if (!in) in = w;
      else { builtin_error ("sideband: unexpected arg: %s", w); return EX_USAGE; }
    }
  if (!in || !out) { builtin_error ("sideband BODY_FILE -o PACK_FILE"); return EX_USAGE; }

  FILE *f = fopen (in, "rb");
  if (!f) { builtin_error ("sideband: %s: %s", in, strerror (errno)); return EXECUTION_FAILURE; }
  FILE *o = fopen (out, "wb");
  if (!o) { builtin_error ("sideband: %s: %s", out, strerror (errno)); fclose (f); return EXECUTION_FAILURE; }

  int rc = EXECUTION_SUCCESS;
  for (;;)
    {
      unsigned char hdr[4];
      size_t h = fread (hdr, 1, 4, f);
      if (h == 0) break;
      if (h != 4) { builtin_error ("sideband: short pkt header"); rc = EXECUTION_FAILURE; break; }
      int n0 = hexval (hdr[0]), n1 = hexval (hdr[1]), n2 = hexval (hdr[2]), n3 = hexval (hdr[3]);
      if (n0 < 0 || n1 < 0 || n2 < 0 || n3 < 0)
        { builtin_error ("sideband: invalid pkt header"); rc = EXECUTION_FAILURE; break; }
      int len = (n0 << 12) | (n1 << 8) | (n2 << 4) | n3;
      if (len == 0 || len == 1 || len == 2) continue;
      if (len < 5) { builtin_error ("sideband: bad pkt length"); rc = EXECUTION_FAILURE; break; }
      int payload = len - 4;
      unsigned char *buf = malloc ((size_t) payload);
      if (!buf) { rc = EXECUTION_FAILURE; break; }
      if (fread (buf, 1, (size_t) payload, f) != (size_t) payload)
        { free (buf); builtin_error ("sideband: truncated payload"); rc = EXECUTION_FAILURE; break; }
      if (payload == 4 && !memcmp (buf, "NAK\n", 4)) { free (buf); continue; }
      unsigned char chan = buf[0];
      if (chan == 1)
        {
          if (fwrite (buf + 1, 1, (size_t) payload - 1, o) != (size_t) payload - 1)
            { free (buf); rc = EXECUTION_FAILURE; break; }
        }
      else if (chan == 2)
        fwrite (buf + 1, 1, (size_t) payload - 1, stderr);
      else if (chan == 3)
        {
          fwrite (buf + 1, 1, (size_t) payload - 1, stderr);
          free (buf);
          rc = EXECUTION_FAILURE;
          break;
        }
      else if (payload > 45 && isxdigit (buf[0]) && isxdigit (buf[39]) && buf[40] == ' ')
        {
          /* Smart-SSH transcripts start with ref advertisement pkt-lines
             before the client request is processed. They are not side-band
             frames; skip them until NAK/channel packets begin. */
        }
      else if (payload > 10 && !memcmp (buf, "# service=", 10))
        {
        }
      else
        {
          builtin_error ("sideband: unknown channel %u", (unsigned) chan);
          free (buf);
          rc = EXECUTION_FAILURE;
          break;
        }
      free (buf);
    }
  fclose (o);
  fclose (f);
  return rc;
}

static int
refs_cmd (WORD_LIST *args)
{
  if (!args) { builtin_error ("refs BODY_FILE"); return EX_USAGE; }
  const char *in = args->word->word;
  FILE *f = fopen (in, "rb");
  if (!f) { builtin_error ("refs: %s: %s", in, strerror (errno)); return EXECUTION_FAILURE; }
  int rc = EXECUTION_SUCCESS;
  for (;;)
    {
      unsigned char hdr[4];
      size_t h = fread (hdr, 1, 4, f);
      if (h == 0) break;
      if (h != 4) { builtin_error ("refs: short pkt header"); rc = EXECUTION_FAILURE; break; }
      int n0 = hexval (hdr[0]), n1 = hexval (hdr[1]), n2 = hexval (hdr[2]), n3 = hexval (hdr[3]);
      if (n0 < 0 || n1 < 0 || n2 < 0 || n3 < 0)
        { builtin_error ("refs: invalid pkt header"); rc = EXECUTION_FAILURE; break; }
      int len = (n0 << 12) | (n1 << 8) | (n2 << 4) | n3;
      if (len == 0 || len == 1 || len == 2) continue;
      if (len < 4) { rc = EXECUTION_FAILURE; break; }
      int payload = len - 4;
      char *buf = malloc ((size_t) payload + 1);
      if (!buf) { rc = EXECUTION_FAILURE; break; }
      if (fread (buf, 1, (size_t) payload, f) != (size_t) payload)
        { free (buf); rc = EXECUTION_FAILURE; break; }
      buf[payload] = '\0';
      for (int i = 0; i < payload; i++)
        if (buf[i] == '\0' || buf[i] == '\n' || buf[i] == '\r')
          { buf[i] = '\0'; break; }
      if (strlen (buf) >= 45)
        {
          int hex = 1;
          for (int i = 0; i < 40; i++)
            if (!isxdigit ((unsigned char) buf[i])) { hex = 0; break; }
          if (hex && buf[40] == ' ' && !strncmp (buf + 41, "refs/", 5)
              && !strstr (buf + 41, "^{}"))
            printf ("%s\n", buf);
          else if (hex && buf[40] == ' ' && !strcmp (buf + 41, "HEAD"))
            printf ("%s\n", buf);
        }
      free (buf);
    }
  fclose (f);
  return rc;
}

int
pkt_builtin (WORD_LIST *list)
{
  if (!list) { builtin_usage (); return EX_USAGE; }
  const char *cmd = list->word->word;
  if (!strcmp (cmd, "encode")) return encode_cmd (list->next);
  if (!strcmp (cmd, "decode")) return decode_cmd (list->next);
  if (!strcmp (cmd, "sideband")) return sideband_cmd (list->next);
  if (!strcmp (cmd, "refs")) return refs_cmd (list->next);
  if (!strcmp (cmd, "flush")) { fputs ("0000", stdout); return EXECUTION_SUCCESS; }
  if (!strcmp (cmd, "delim")) { fputs ("0001", stdout); return EXECUTION_SUCCESS; }
  if (!strcmp (cmd, "response-end")) { fputs ("0002", stdout); return EXECUTION_SUCCESS; }
  builtin_error ("unknown verb: %s", cmd);
  return EX_USAGE;
}

char *pkt_doc[] = {
  "Git pkt-line helpers.",
  "  pkt encode TEXT [-V VAR]",
  "  pkt decode INPUT [-L LEN_VAR] [-V PAYLOAD_VAR]",
  "  pkt sideband BODY_FILE -o PACK_FILE",
  "  pkt refs BODY_FILE",
  "  pkt flush | delim | response-end",
  (char *) NULL
};

struct builtin pkt_struct = {
  "pkt",
  pkt_builtin,
  BUILTIN_ENABLED,
  pkt_doc,
  "pkt encode|decode|sideband|refs|flush|delim|response-end",
  0
};
