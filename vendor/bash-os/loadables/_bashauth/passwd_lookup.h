/* SPDX-License-Identifier: MIT */
#ifndef BASHAUTH_PASSWD_LOOKUP_H
#define BASHAUTH_PASSWD_LOOKUP_H

#include <stddef.h>
#include <sys/types.h>

typedef struct bashos_auth_user {
  char name[64];
  uid_t uid;
  gid_t gid;
  char gecos[256];
  char home[256];
  char shell[256];
} bashos_auth_user;

typedef struct bashos_shadow_entry {
  char phc[512];
  long last_change;
  long min_days;
  long max_days;
  long warn_days;
  long inactive_days;
  long expire_days;
} bashos_shadow_entry;

int bashos_valid_user_name (const char *user);
int bashos_lookup_user (const char *name, bashos_auth_user *out);
int bashos_read_shadow_entry (const char *name, bashos_shadow_entry *out);
int bashos_read_shadow_phc (const char *name, char *phc, size_t phc_len);

#endif /* BASHAUTH_PASSWD_LOOKUP_H */
