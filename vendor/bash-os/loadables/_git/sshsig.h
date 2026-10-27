/* SPDX-License-Identifier: MIT */
/* _git/sshsig.h — signing with an ssh key, the way OpenSSH does it.
 *
 * git can sign a commit or a tag with an ssh key rather than a PGP one:
 * `gpg.format = ssh`, `user.signingKey` naming the private key, and the
 * signature written into the object in OpenSSH's SSHSIG armour. This is
 * that format — the blob that is signed, the blob that carries the
 * signature, and the files the keys are read out of.
 *
 * Only ed25519 keys are handled, and only unencrypted private ones: a
 * key that needs a passphrase has nowhere to ask for it here.
 *
 * --- LICENSE ---
 * MIT License — same boilerplate as binhex.c.
 */

#ifndef BASH_OS_GIT_SSHSIG_H
#define BASH_OS_GIT_SSHSIG_H

#include <stddef.h>

/* An ed25519 key as OpenSSH keeps one. */
typedef struct {
    unsigned char secret[64];      /* seed and public key, which signing wants */
    unsigned char public_key[32];
    int have_secret;
} bgit_ssh_key;

/* Read a private key out of an OpenSSH key file. Returns 0, or -1 with a
   message saying why not. */
int bgit_ssh_key_private (const char *path, bgit_ssh_key *key);

/* Read a public key from "ssh-ed25519 <base64> [comment]", which is the
   line that stands in an authorized_keys or allowed_signers file.
   Returns 0, or -1. Silent. */
int bgit_ssh_key_public (const char *text, bgit_ssh_key *key);

/* The public key as that same line, without a comment. */
int bgit_ssh_key_line (const bgit_ssh_key *key, char *out, size_t outsz);

/* The name ssh-keygen calls this key by: "SHA256:" and the digest of the
   key's blob in base64, with the padding left off. Returns 0, or -1. */
int bgit_ssh_key_fingerprint (const bgit_ssh_key *key, char *out, size_t outsz);

/* Sign LEN bytes at PAYLOAD under NAMESPACE, and give back the armoured
   signature for the caller to free. Returns 0, or -1. */
int bgit_sshsig_sign (const bgit_ssh_key *key, const char *name_space,
                      const unsigned char *payload, size_t len, char **out);

/* Check an armoured signature over the same. Returns 0 when it is good,
   1 when it is not, and -1 when it cannot be read at all. The key that
   made it is left in KEY, for the caller to decide whether that is
   somebody it believes. */
int bgit_sshsig_check (const char *armoured, const char *name_space,
                       const unsigned char *payload, size_t len,
                       bgit_ssh_key *key);

/* Look for KEY in a file of "<principal> <keytype> <key>" lines, which is
   what gpg.ssh.allowedSignersFile names. Returns 1 with the principal in
   OUT when it is there, 0 when it is not, -1 when the file cannot be
   read. */
int bgit_ssh_allowed_signer (const char *path, const bgit_ssh_key *key,
                             char *out, size_t outsz);

#endif /* BASH_OS_GIT_SSHSIG_H */
