/* SPDX-License-Identifier: MIT */
/* auth.c — bash builtin for /dev/bashos-auth.
 *
 * Milestone 2 surface:
 *
 *   auth probe
 *       Open /dev/bashos-auth, issue BASHOS_AUTH_IOC_VERSION, print
 *       "abi=MAJOR.MINOR features=0xHEX". Closes the fd before
 *       returning. Used by tests/bash-os/130-auth-probe.sh.
 *
 *   auth open FDVAR
 *       Open /dev/bashos-auth O_RDWR|O_CLOEXEC, set FD_CLOEXEC
 *       defensively, bind the integer fd into shell variable FDVAR.
 *       Holding the fd open is what later milestones use to associate
 *       a kernel-side session with the caller. The Bash script is
 *       responsible for closing it via `exec {FDVAR}<&-` when done.
 *
 *   auth read-secret FD [-p PROMPT] HANDLEVAR
 *       Prompt with echo disabled, store the secret in a kernel slot
 *       bound to FD, seal it, and bind only the opaque handle id into
 *       HANDLEVAR.
 *
 *   auth clear FD HANDLE
 *       Clear a kernel secret slot early. Closing FD clears all slots
 *       associated with that open file description.
 *
 *   auth same-secret FD HANDLE_A HANDLE_B
 *       Ask the kernel to compare two sealed handles without exporting
 *       either secret to userspace.
 *
 *   auth stats FD
 *       Print per-fd kernel counters for secret and token lifecycle events.
 *
 *   auth hash-secret FD HANDLE SALT_HEX T M P HASHLEN OUTVAR
 *       Export a sealed handle once into a C-owned buffer, derive an
 *       Argon2id PHC string, bind it into OUTVAR, and wipe the buffer.
 *
 *   auth verify-login FD HANDLE USER PHC TOKENVAR
 *       Export a sealed handle once into a C-owned buffer, verify the PHC,
 *       mint a short-lived kernel authority token, and bind only the token
 *       reference into TOKENVAR.
 *
 * License: MIT — same boilerplate as mlock.c.
 *
 * See research/bash-os2/KERNEL-MEDIATED-SECRETS-AUTHORITY-IMPLEMENTATION-PLAN.md.
 */

#include <config.h>

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>		/* fork / _exit — interactive in-context handoff child */
#include <sys/wait.h>		/* waitpid / WIFEXITED — reap the elevated child */
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <pwd.h>
#include <grp.h>

#include "_monocypher_monocypher-ed25519.h"
#include "_bashos_authcrypto_argon2id.h"
#include "_bashauth_pwverify.h"
#include "_mbedtls_sha256.h"
#include "_bashos_auth_uapi.h"
#include "loadables.h"

/* The UAPI struct, ioctl, and constant definitions live in
 * _bashos_auth_uapi.h, a flattened userspace mirror of
 * kernel/bashos-auth/uapi/linux/bashos_auth.h. The runtime guest headers
 * may not have <linux/bashos_auth.h> yet during early bring-up, so the
 * flattened mirror lets the loadable compile without depending on the
 * installed kernel headers. The kernel side returns the layout described
 * in the mirror regardless of the installed-header generation. */

/* Userspace-only constants (not part of the kernel UAPI). */
#define BASHOS_AUTH_DEV          "/dev/bashos-auth"
#define BASHOS_AUTH_MAX_SECRET   4096

typedef struct {
	unsigned int m, t, p;
	char salt_hex[129];
	char hash_hex[257];
} ba_phc;

static int ba_argon2id_raw (const unsigned char *pass, size_t pass_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned int passes, unsigned int mem_kib,
                            unsigned int lanes, unsigned char *out,
                            size_t out_len);
static int ba_parse_fd (const char *s, int *fdp);
static void ba_hex_encode (const unsigned char *buf, size_t n, char *out);
static const char *ba_policy_status_name (unsigned int status);

static void
ba_wipe (void *p, size_t n)
{
	volatile unsigned char *q = (volatile unsigned char *) p;
	while (q && n--)
		*q++ = 0;
}

static int
ba_version_reserved_zero (const struct bashos_auth_version *v)
{
	for (size_t i = 0; i < sizeof v->reserved; i++)
		if (v->reserved[i] != 0)
			return 0;
	return 1;
}

static int
ba_privcmd_version_ok (int fd, struct bashos_auth_version *v)
{
	memset (v, 0, sizeof *v);
	if (ioctl (fd, BASHOS_AUTH_IOC_VERSION, v) < 0) {
		builtin_error ("ioctl VERSION: %s", strerror (errno));
		return -1;
	}
	if (v->abi_major != BASHOS_AUTH_ABI_MAJOR ||
	    v->abi_minor < BASHOS_AUTH_ABI_MINOR ||
	    !ba_version_reserved_zero (v)) {
		builtin_error ("privcmd authority not available (abi=%u.%u features=0x%llx reason=unsupported privcmd authority ABI)",
		               v->abi_major, v->abi_minor, v->features);
		return -1;
	}
	if ((v->features & BASHOS_AUTH_FEAT_PRIVCMD) == 0) {
		builtin_error ("privcmd authority not available (abi=%u.%u features=0x%llx)",
		               v->abi_major, v->abi_minor, v->features);
		return -1;
	}
	return 0;
}

static int
ba_open_dev (void)
{
	int fd = open (BASHOS_AUTH_DEV, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		builtin_error ("%s: %s", BASHOS_AUTH_DEV, strerror (errno));
		return -1;
	}
	/* Defensive: re-assert FD_CLOEXEC even though O_CLOEXEC was passed. */
	int fl = fcntl (fd, F_GETFD, 0);
	if (fl >= 0)
		(void) fcntl (fd, F_SETFD, fl | FD_CLOEXEC);
	return fd;
}

static int
ba_probe_cmd (WORD_LIST *args)
{
	(void) args;
	int fd = ba_open_dev ();
	if (fd < 0) return EXECUTION_FAILURE;

	struct bashos_auth_version v;
	memset (&v, 0, sizeof v);
	if (ioctl (fd, BASHOS_AUTH_IOC_VERSION, &v) < 0) {
		builtin_error ("ioctl VERSION: %s", strerror (errno));
		close (fd);
		return EXECUTION_FAILURE;
	}
	close (fd);

	printf ("abi=%u.%u features=0x%llx\n",
		v.abi_major, v.abi_minor, v.features);
	return EXECUTION_SUCCESS;
}

static int
ba_privcmd_probe_cmd (WORD_LIST *args)
{
	if (args) {
		builtin_error ("privcmd-probe: unexpected arguments");
		return EX_USAGE;
	}

	int fd = ba_open_dev ();
	if (fd < 0) return EXECUTION_FAILURE;

	struct bashos_auth_version v;
	if (ba_privcmd_version_ok (fd, &v) < 0) {
		close (fd);
		return EXECUTION_FAILURE;
	}
	close (fd);

	printf ("privcmd=1 abi=%u.%u features=0x%llx\n",
	        v.abi_major, v.abi_minor, v.features);
	return EXECUTION_SUCCESS;
}

static int
ba_privcmd_mode (const char *s)
{
	if (!s) return 0;
	if (strcmp (s, "exec") == 0) return BASHOS_AUTH_PRIVCMD_MODE_EXEC;
	if (strcmp (s, "shell") == 0) return BASHOS_AUTH_PRIVCMD_MODE_SHELL;
	if (strcmp (s, "login") == 0) return BASHOS_AUTH_PRIVCMD_MODE_LOGIN;
	if (strcmp (s, "validate") == 0) return BASHOS_AUTH_PRIVCMD_MODE_VALIDATE;
	if (strcmp (s, "reset") == 0 || strcmp (s, "reset-timestamp") == 0)
		return BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP;
	if (strcmp (s, "sudoedit") == 0 || strcmp (s, "edit") == 0)
		return BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT;
	return 0;
}

static int
ba_word_count (WORD_LIST *p)
{
	int n = 0;
	for (; p; p = p->next) n++;
	return n;
}

static char *
ba_words_blob (WORD_LIST *p, int *countp, unsigned int *bytesp)
{
	int count = ba_word_count (p);
	size_t bytes = 0;
	for (WORD_LIST *q = p; q; q = q->next)
		bytes += strlen (q->word->word) + 1;
	if (bytes > 1024 * 1024) {
		errno = E2BIG;
		return NULL;
	}
	char *blob = calloc (bytes ? bytes : 1, 1);
	if (!blob)
		return NULL;
	size_t off = 0;
	for (WORD_LIST *q = p; q; q = q->next) {
		size_t n = strlen (q->word->word) + 1;
		memcpy (blob + off, q->word->word, n);
		off += n;
	}
	*countp = count;
	*bytesp = (unsigned int) bytes;
	return blob;
}

static int
ba_privcmd_digest_update_u32 (mbedtls_sha256_context *sha, unsigned int v)
{
	unsigned char b[4];
	b[0] = (unsigned char) (v & 0xff);
	b[1] = (unsigned char) ((v >> 8) & 0xff);
	b[2] = (unsigned char) ((v >> 16) & 0xff);
	b[3] = (unsigned char) ((v >> 24) & 0xff);
	return mbedtls_sha256_update (sha, b, sizeof b);
}

static int
ba_privcmd_digest_update_str (mbedtls_sha256_context *sha, const char *s)
{
	size_t n = s ? strlen (s) : 0;
	if (ba_privcmd_digest_update_u32 (sha, (unsigned int) n) != 0)
		return -1;
	return n ? mbedtls_sha256_update (sha, (const unsigned char *) s, n) : 0;
}

static int
ba_privcmd_fill_digest (struct bashos_auth_privcmd *r,
                        const char *argv_blob)
{
	mbedtls_sha256_context sha;
	mbedtls_sha256_init (&sha);
	int rc = mbedtls_sha256_starts (&sha, 0);
	if (rc == 0)
		rc = mbedtls_sha256_update (&sha,
		                            (const unsigned char *) "bashos-privcmd-v1",
		                            16);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->mode);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->flags);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->non_interactive);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->caller_uid);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->caller_gid);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->target_uid);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->target_gid);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->argc);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->envc);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->argv_bytes);
	if (rc == 0) rc = ba_privcmd_digest_update_u32 (&sha, r->env_bytes);
	if (rc == 0) rc = ba_privcmd_digest_update_str (&sha, r->caller_user);
	if (rc == 0) rc = ba_privcmd_digest_update_str (&sha, r->target_user);
	if (rc == 0) rc = ba_privcmd_digest_update_str (&sha, r->cwd);
	if (rc == 0 && r->argv_bytes)
		rc = mbedtls_sha256_update (&sha, (const unsigned char *) argv_blob,
		                            r->argv_bytes);
	if (rc == 0)
		rc = mbedtls_sha256_finish (&sha, r->request_digest);
	mbedtls_sha256_free (&sha);
	return rc == 0 ? 0 : -1;
}

static int
ba_privcmd_response_is_allowish (unsigned int decision)
{
	return decision == BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC ||
	       decision == BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT ||
	       decision == BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK ||
	       decision == BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK;
}

static const char *
ba_privcmd_decision_name (unsigned int decision)
{
	switch (decision) {
	case BASHOS_AUTH_PRIVCMD_DECISION_DENY: return "deny";
	case BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC: return "allow_exec";
	case BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT: return "allow_edit";
	case BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK: return "reset_ok";
	case BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK: return "validate_ok";
	case BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED: return "auth_required";
	default: return "unknown";
	}
}

static void
ba_privcmd_exec_verify_child (int fd, const struct bashos_auth_privcmd *r)
{
	struct bashos_auth_exec_verify_req vr;

	memset (&vr, 0, sizeof vr);
	vr.size = sizeof vr;
	vr.mode = r->mode;
	vr.caller_uid = r->caller_uid;
	vr.caller_gid = r->caller_gid;
	vr.target_uid = r->target_uid;
	vr.target_gid = r->target_gid;
	vr.policy_generation = r->policy_generation;
	vr.timeout_sec = r->timestamp_timeout;
	vr.policy_status = r->policy_status;
	memcpy (vr.request_digest, r->request_digest, sizeof vr.request_digest);
	memcpy (vr.normalized_policy_digest, r->normalized_policy_digest,
	        sizeof vr.normalized_policy_digest);
	if (ioctl (fd, BASHOS_AUTH_IOC_EXEC_VERIFY, &vr) < 0) {
		fprintf (stderr, "privcmd-exec: verifier launch failed: %s\n",
		         strerror (errno));
		_exit (126);
	}
	_exit (0);
}

static int
ba_privcmd_run_verify_once (int fd, const struct bashos_auth_privcmd *r)
{
	pid_t pid = fork ();
	int status = 0;

	if (pid < 0) {
		builtin_error ("privcmd-exec: verifier fork: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}
	if (pid == 0)
		ba_privcmd_exec_verify_child (fd, r);
	while (waitpid (pid, &status, 0) < 0 && errno == EINTR)
		;
	return WIFEXITED (status) ? WEXITSTATUS (status)
	     : WIFSIGNALED (status) ? 128 + WTERMSIG (status) : EXECUTION_FAILURE;
}

static void
ba_privcmd_reset_response (struct bashos_auth_privcmd *r)
{
	r->decision = 0;
	r->env_policy = 0;
	r->timestamp_timeout = 0;
	r->policy_generation = 0;
	r->policy_status = 0;
	r->reserved0 = 0;
	r->audit_id = 0;
	memset (r->exec_token, 0, sizeof r->exec_token);
	memset (r->policy_digest, 0, sizeof r->policy_digest);
	memset (r->normalized_policy_digest, 0, sizeof r->normalized_policy_digest);
	memset (r->reason, 0, sizeof r->reason);
	r->handle_id = 0;
	r->handle_expires_sec = 0;
	memset (r->reserved, 0, sizeof r->reserved);
}

static int
ba_parse_uint_arg (const char *s, unsigned int *out)
{
	char *end = NULL;
	unsigned long v;
	if (!s || !*s) return -1;
	errno = 0;
	v = strtoul (s, &end, 10);
	if (errno || !end || *end || v > 0xfffffffful)
		return -1;
	*out = (unsigned int) v;
	return 0;
}

static int
ba_privcmd_authz_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->next || !args->next->next ||
	    !args->next->next->next) {
		builtin_error ("privcmd-authz: usage: privcmd-authz FD MODE TARGET_UID TARGET_GID [--] command [args...]");
		return EX_USAGE;
	}

	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("privcmd-authz: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	unsigned int mode = (unsigned int) ba_privcmd_mode (args->next->word->word);
	if (!mode) {
		builtin_error ("privcmd-authz: invalid mode: %s", args->next->word->word);
		return EX_USAGE;
	}

	unsigned int target_uid, target_gid;
	if (ba_parse_uint_arg (args->next->next->word->word, &target_uid) < 0 ||
	    ba_parse_uint_arg (args->next->next->next->word->word, &target_gid) < 0) {
		builtin_error ("privcmd-authz: invalid target uid/gid");
		return EX_USAGE;
	}
	struct bashos_auth_version v;
	if (ba_privcmd_version_ok (fd, &v) < 0)
		return EXECUTION_FAILURE;

	WORD_LIST *cmd = args->next->next->next->next;
	if (cmd && cmd->word && cmd->word->word && strcmp (cmd->word->word, "--") == 0)
		cmd = cmd->next;
	if (!cmd && mode != BASHOS_AUTH_PRIVCMD_MODE_VALIDATE &&
	    mode != BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP) {
		builtin_error ("privcmd-authz: command required for mode");
		return EX_USAGE;
	}

	int argc = 0;
	unsigned int argv_bytes = 0;
	char *argv_blob = ba_words_blob (cmd, &argc, &argv_bytes);
	if (!argv_blob && cmd) {
		builtin_error ("privcmd-authz: argv build: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	struct bashos_auth_privcmd r;
	memset (&r, 0, sizeof r);
	r.size = sizeof r;
	r.mode = mode;
	r.caller_uid = (unsigned int) getuid ();
	r.caller_gid = (unsigned int) getgid ();
	r.target_uid = target_uid;
	r.target_gid = target_gid;
	r.argc = (unsigned int) argc;
	r.argv_bytes = argv_bytes;
	r.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
	snprintf (r.caller_user, sizeof r.caller_user, "%u", r.caller_uid);
	snprintf (r.target_user, sizeof r.target_user, "%u", target_uid);
	if (!getcwd (r.cwd, sizeof r.cwd))
		strncpy (r.cwd, "/", sizeof r.cwd - 1);
	if (ba_privcmd_fill_digest (&r, argv_blob) < 0) {
		free (argv_blob);
		builtin_error ("privcmd-authz: request digest failed");
		return EXECUTION_FAILURE;
	}

	if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0) {
		int saved = errno;
		free (argv_blob);
		builtin_error ("ioctl PRIVCMD_AUTHZ: %s", strerror (saved));
		errno = saved;
		return EXECUTION_FAILURE;
	}
	free (argv_blob);

	char digest_hex[65];
	char normalized_digest_hex[65];
	ba_hex_encode (r.policy_digest, sizeof r.policy_digest, digest_hex);
	ba_hex_encode (r.normalized_policy_digest,
	               sizeof r.normalized_policy_digest, normalized_digest_hex);
	printf ("decision=%s audit_id=%llu policy_generation=%u policy_status=%s policy_sha256=%s normalized_policy_sha256=%s reason=%s\n",
	        ba_privcmd_decision_name (r.decision),
	        r.audit_id, r.policy_generation, ba_policy_status_name (r.policy_status),
	        digest_hex, normalized_digest_hex, r.reason);
	if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_DENY)
		return EXECUTION_FAILURE;
	if (ba_privcmd_response_is_allowish (r.decision))
		builtin_error ("privcmd-authz: v2 authority response is not executable yet");
	else
		builtin_error ("privcmd-authz: malformed v2 authority decision: %u",
		               r.decision);
	return EXECUTION_FAILURE;
}

/*
 * privcmd-exec FD MODE TARGET_UID TARGET_GID [--] command [args...]
 *
 * The full client flow: PRIVCMD_AUTHZ to obtain an opaque handle, then
 * EXEC_HANDOFF presenting that handle_id + the SAME re-presented argv (the
 * kernel re-verifies argv against the bound argv_digest). The raw token bytes
 * never cross to the client; only the non-secret handle_id does. Inert until the
 * joint flip: EXEC_HANDOFF returns -ENOSYS while the backend is unready, and
 * AUTHZ returns DENY (no handle) so this verb reports the denial and stops.
 * Prints a stable, parseable line for the QEMU matrix.
 */
static int
ba_privcmd_exec_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->next || !args->next->next ||
	    !args->next->next->next) {
		builtin_error ("privcmd-exec: usage: privcmd-exec FD MODE TARGET_UID TARGET_GID [--] command [args...]");
		return EX_USAGE;
	}

	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("privcmd-exec: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	unsigned int mode = (unsigned int) ba_privcmd_mode (args->next->word->word);
	if (!mode) {
		builtin_error ("privcmd-exec: invalid mode: %s", args->next->word->word);
		return EX_USAGE;
	}
	unsigned int target_uid, target_gid;
	if (ba_parse_uint_arg (args->next->next->word->word, &target_uid) < 0 ||
	    ba_parse_uint_arg (args->next->next->next->word->word, &target_gid) < 0) {
		builtin_error ("privcmd-exec: invalid target uid/gid");
		return EX_USAGE;
	}
	struct bashos_auth_version v;
	if (ba_privcmd_version_ok (fd, &v) < 0)
		return EXECUTION_FAILURE;

	WORD_LIST *cmd = args->next->next->next->next;
	if (cmd && cmd->word && cmd->word->word && strcmp (cmd->word->word, "--") == 0)
		cmd = cmd->next;

	int argc = 0;
	unsigned int argv_bytes = 0;
	char *argv_blob = ba_words_blob (cmd, &argc, &argv_bytes);
	if (!argv_blob && cmd) {
		builtin_error ("privcmd-exec: argv build: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	struct bashos_auth_privcmd r;
	memset (&r, 0, sizeof r);
	r.size = sizeof r;
	r.mode = mode;
	r.caller_uid = (unsigned int) getuid ();
	r.caller_gid = (unsigned int) getgid ();
	r.target_uid = target_uid;
	r.target_gid = target_gid;
	r.argc = (unsigned int) argc;
	r.argv_bytes = argv_bytes;
	r.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
	snprintf (r.caller_user, sizeof r.caller_user, "%u", r.caller_uid);
	snprintf (r.target_user, sizeof r.target_user, "%u", target_uid);
	if (!getcwd (r.cwd, sizeof r.cwd))
		strncpy (r.cwd, "/", sizeof r.cwd - 1);
	if (ba_privcmd_fill_digest (&r, argv_blob) < 0) {
		free (argv_blob);
		builtin_error ("privcmd-exec: request digest failed");
		return EXECUTION_FAILURE;
	}

	if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0) {
		int saved = errno;
		free (argv_blob);
		builtin_error ("ioctl PRIVCMD_AUTHZ: %s", strerror (saved));
		return EXECUTION_FAILURE;
	}
	if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED) {
		int vrc = ba_privcmd_run_verify_once (fd, &r);

		if (vrc != 0) {
			printf ("decision=%s handle_id=0 approval=denied exit_code=0 reject_stage=0\n",
			        ba_privcmd_decision_name (r.decision));
			free (argv_blob);
			return EXECUTION_FAILURE;
		}
		ba_privcmd_reset_response (&r);
		if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0) {
			int saved = errno;
			free (argv_blob);
			builtin_error ("ioctl PRIVCMD_AUTHZ after verification: %s",
				       strerror (saved));
			return EXECUTION_FAILURE;
		}
	}

	if (!ba_privcmd_response_is_allowish (r.decision) || r.handle_id == 0) {
		/* Denied (or backend not ready -> deny + no handle): report + stop. */
		printf ("decision=%s handle_id=0 approval=denied exit_code=0 reject_stage=0\n",
		        ba_privcmd_decision_name (r.decision));
		free (argv_blob);
		return EXECUTION_FAILURE;
	}

	/* Present the opaque handle_id + the SAME argv to the trusted handoff. */
	struct bashos_auth_exec_handoff_req hr;
	memset (&hr, 0, sizeof hr);
	hr.size = sizeof hr;
	hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_NONINTERACTIVE;
	hr.argc = (unsigned int) argc;
	hr.argv_bytes = argv_bytes;
	hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
	hr.handle.handle_id = r.handle_id;
	int hrc = ioctl (fd, BASHOS_AUTH_IOC_EXEC_HANDOFF, &hr);
	int saved = errno;
	free (argv_blob);
	if (hrc < 0) {
		printf ("decision=%s handle_id=%llu approval=ioctl-error exit_code=0 reject_stage=0 errno=%d\n",
		        ba_privcmd_decision_name (r.decision), r.handle_id, saved);
		builtin_error ("ioctl EXEC_HANDOFF: %s", strerror (saved));
		return EXECUTION_FAILURE;
	}

	const char *appr = hr.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED ? "allowed"
		: hr.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_FORCED_UMH ? "umh"
		: "denied";
	printf ("decision=%s handle_id=%llu approval=%s exit_code=%u reject_stage=%u\n",
	        ba_privcmd_decision_name (r.decision), r.handle_id, appr,
	        hr.exit_code, hr.reject_stage);
	return (hr.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED)
	       ? EXECUTION_FAILURE : EXECUTION_SUCCESS;
	}

static const char *
ba_handoff_approval_name (unsigned int approval)
{
	switch (approval) {
	case BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED: return "allowed";
	case BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED: return "denied";
	case BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_FORCED_UMH: return "umh";
	default: return "unknown";
	}
}

static unsigned int
ba_privcmd_handoff_test_expected_stage (const char *which)
{
	/* Stable frozen reject-stage numbers, kept numeric here so this fixture never
	 * imports the kernel-private EXEC_REJECT names into normal client logic. */
	if (strcmp (which, "bad-handle") == 0) return 3;
	if (strcmp (which, "argv-mismatch") == 0) return 4;
	if (strcmp (which, "mode-mismatch") == 0) return 7;
	if (strcmp (which, "replay") == 0) return 1;
	return 0;
}

static int
ba_privcmd_handoff_once (int fd, unsigned long long handle_id,
                         unsigned int argc, unsigned int argv_bytes,
                         char *argv_blob, unsigned int flags,
                         struct bashos_auth_exec_handoff_req *out)
{
	struct bashos_auth_exec_handoff_req hr;
	memset (&hr, 0, sizeof hr);
	hr.size = sizeof hr;
	hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_NONINTERACTIVE;
	hr.flags = flags;
	hr.argc = argc;
	hr.argv_bytes = argv_bytes;
	hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
	hr.handle.handle_id = handle_id;
	int rc = ioctl (fd, BASHOS_AUTH_IOC_EXEC_HANDOFF, &hr);
	if (out)
		*out = hr;
	return rc;
}

/*
 * privcmd-handoff-test FD CASE MODE TARGET_UID TARGET_GID [--] command [args...]
 *
 * Test-only, fail-closed fixture for QEMU token-lifecycle matrices. It is inert
 * unless BASHOS_AUTH_TEST_HOOKS=1 is present. The fixture mints a normal
 * handle-only PRIVCMD grant, then redeems it with one controlled mutation:
 *   ok | bad-handle | argv-mismatch | mode-mismatch | replay
 *
 * It never reads or prints r.exec_token; the only client-visible grant reference
 * is the opaque handle_id.
 */
static int
ba_privcmd_handoff_test_cmd (WORD_LIST *args)
{
	const char *hooks = getenv ("BASHOS_AUTH_TEST_HOOKS");
	if (!hooks || strcmp (hooks, "1") != 0) {
		builtin_error ("privcmd-handoff-test: disabled (set BASHOS_AUTH_TEST_HOOKS=1)");
		return EXECUTION_FAILURE;
	}
	if (!args || !args->word || !args->next || !args->next->next ||
	    !args->next->next->next || !args->next->next->next->next) {
		builtin_error ("privcmd-handoff-test: usage: privcmd-handoff-test FD CASE MODE TARGET_UID TARGET_GID [--] command [args...]");
		return EX_USAGE;
	}

	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("privcmd-handoff-test: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	const char *which = args->next->word->word;
	unsigned int want_stage = ba_privcmd_handoff_test_expected_stage (which);
	if (strcmp (which, "ok") != 0 && want_stage == 0) {
		builtin_error ("privcmd-handoff-test: invalid case: %s", which);
		return EX_USAGE;
	}
	unsigned int mode = (unsigned int) ba_privcmd_mode (args->next->next->word->word);
	if (!mode) {
		builtin_error ("privcmd-handoff-test: invalid mode: %s",
		               args->next->next->word->word);
		return EX_USAGE;
	}
	unsigned int target_uid, target_gid;
	if (ba_parse_uint_arg (args->next->next->next->word->word, &target_uid) < 0 ||
	    ba_parse_uint_arg (args->next->next->next->next->word->word, &target_gid) < 0) {
		builtin_error ("privcmd-handoff-test: invalid target uid/gid");
		return EX_USAGE;
	}
	struct bashos_auth_version v;
	if (ba_privcmd_version_ok (fd, &v) < 0)
		return EXECUTION_FAILURE;

	WORD_LIST *cmd = args->next->next->next->next->next;
	if (cmd && cmd->word && cmd->word->word && strcmp (cmd->word->word, "--") == 0)
		cmd = cmd->next;
	if (!cmd) {
		builtin_error ("privcmd-handoff-test: command required");
		return EX_USAGE;
	}

	int argc = 0;
	unsigned int argv_bytes = 0;
	char *argv_blob = ba_words_blob (cmd, &argc, &argv_bytes);
	if (!argv_blob) {
		builtin_error ("privcmd-handoff-test: argv build: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	struct bashos_auth_privcmd r;
	memset (&r, 0, sizeof r);
	r.size = sizeof r;
	r.mode = mode;
	r.caller_uid = (unsigned int) getuid ();
	r.caller_gid = (unsigned int) getgid ();
	r.target_uid = target_uid;
	r.target_gid = target_gid;
	r.argc = (unsigned int) argc;
	r.argv_bytes = argv_bytes;
	r.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
	snprintf (r.caller_user, sizeof r.caller_user, "%u", r.caller_uid);
	snprintf (r.target_user, sizeof r.target_user, "%u", target_uid);
	if (!getcwd (r.cwd, sizeof r.cwd))
		strncpy (r.cwd, "/", sizeof r.cwd - 1);
	if (ba_privcmd_fill_digest (&r, argv_blob) < 0) {
		free (argv_blob);
		builtin_error ("privcmd-handoff-test: request digest failed");
		return EXECUTION_FAILURE;
	}

	if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0) {
		int saved = errno;
		free (argv_blob);
		builtin_error ("ioctl PRIVCMD_AUTHZ: %s", strerror (saved));
		errno = saved;
		return EXECUTION_FAILURE;
	}
	if (r.decision == BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED) {
		int vrc = ba_privcmd_run_verify_once (fd, &r);
		if (vrc != 0) {
			printf ("case=%s decision=%s handle_id=0 approval=denied reject_stage=0\n",
			        which, ba_privcmd_decision_name (r.decision));
			free (argv_blob);
			return EXECUTION_FAILURE;
		}
		ba_privcmd_reset_response (&r);
		if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0) {
			int saved = errno;
			free (argv_blob);
			builtin_error ("ioctl PRIVCMD_AUTHZ after verification: %s",
			               strerror (saved));
			errno = saved;
			return EXECUTION_FAILURE;
		}
	}
	if (!ba_privcmd_response_is_allowish (r.decision) || r.handle_id == 0) {
		printf ("case=%s decision=%s handle_id=0 approval=denied reject_stage=0\n",
		        which, ba_privcmd_decision_name (r.decision));
		free (argv_blob);
		return EXECUTION_FAILURE;
	}

	char *handoff_blob = malloc (argv_bytes);
	if (!handoff_blob) {
		free (argv_blob);
		builtin_error ("privcmd-handoff-test: handoff argv copy: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}
	memcpy (handoff_blob, argv_blob, argv_bytes);

	unsigned long long handle_id = r.handle_id;
	unsigned int flags = 0;
	if (strcmp (which, "bad-handle") == 0)
		handle_id ^= 0x0101010101010101ULL;
	else if (strcmp (which, "argv-mismatch") == 0)
		handoff_blob[0] = handoff_blob[0] == 'X' ? 'Y' : 'X';
	else if (strcmp (which, "mode-mismatch") == 0)
		flags = BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_OPEN;

	struct bashos_auth_exec_handoff_req hr;
	int rc = ba_privcmd_handoff_once (fd, handle_id, (unsigned int) argc,
	                                  argv_bytes, handoff_blob, flags, &hr);
	int saved = errno;
	printf ("case=%s phase=first decision=%s handle_id=%llu approval=%s exit_code=%u reject_stage=%u errno=%d\n",
	        which, ba_privcmd_decision_name (r.decision), r.handle_id,
	        ba_handoff_approval_name (hr.approval_status), hr.exit_code,
	        hr.reject_stage, rc < 0 ? saved : 0);

	int ok = 0;
	if (strcmp (which, "replay") == 0) {
		if (rc < 0 || hr.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED) {
			free (handoff_blob);
			free (argv_blob);
			return EXECUTION_FAILURE;
		}
		struct bashos_auth_exec_handoff_req hr2;
		int rc2 = ba_privcmd_handoff_once (fd, r.handle_id, (unsigned int) argc,
		                                   argv_bytes, argv_blob, 0, &hr2);
		int saved2 = errno;
		printf ("case=%s phase=second decision=%s handle_id=%llu approval=%s exit_code=%u reject_stage=%u errno=%d\n",
		        which, ba_privcmd_decision_name (r.decision), r.handle_id,
		        ba_handoff_approval_name (hr2.approval_status), hr2.exit_code,
		        hr2.reject_stage, rc2 < 0 ? saved2 : 0);
		ok = (rc2 == 0 &&
		      hr2.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED &&
		      hr2.reject_stage == want_stage);
	} else if (strcmp (which, "ok") == 0) {
		ok = (rc == 0 && hr.approval_status != BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED &&
		      hr.reject_stage == 0);
	} else {
		ok = (rc == 0 &&
		      hr.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED &&
		      hr.reject_stage == want_stage);
	}

	free (handoff_blob);
	free (argv_blob);
	return ok ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/* privcmd-exec-interactive FD MODE TARGET_UID TARGET_GID [--] cmd...
 *
 * Drive the INTERACTIVE in-context elevation: AUTHZ to get the opaque handle,
 * then FORK and have the child redeem it via BASHOS_AUTH_IOC_EXEC_INTERACTIVE.
 * The kernel's in-context kernel_execve REPLACES the calling task with the
 * target program, so it MUST run in a dedicated child — otherwise this
 * interactive shell would be overwritten. The child inherits the controlling
 * tty + the authority fd; on a successful elevation the ioctl never returns (the
 * child becomes the target program on the tty) and the parent reaps its exit.
 * On ANY return from the ioctl the elevation FAILED — the child may be
 * mid-elevated, so it _exit()s immediately without running anything as target. */
static int
ba_privcmd_exec_interactive_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->next || !args->next->next ||
	    !args->next->next->next) {
		builtin_error ("privcmd-exec-interactive: usage: privcmd-exec-interactive FD MODE TARGET_UID TARGET_GID [--] command [args...]");
		return EX_USAGE;
	}

	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("privcmd-exec-interactive: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	unsigned int mode = (unsigned int) ba_privcmd_mode (args->next->word->word);
	if (!mode) {
		builtin_error ("privcmd-exec-interactive: invalid mode: %s", args->next->word->word);
		return EX_USAGE;
	}
	unsigned int target_uid, target_gid;
	if (ba_parse_uint_arg (args->next->next->word->word, &target_uid) < 0 ||
	    ba_parse_uint_arg (args->next->next->next->word->word, &target_gid) < 0) {
		builtin_error ("privcmd-exec-interactive: invalid target uid/gid");
		return EX_USAGE;
	}
	struct bashos_auth_version v;
	if (ba_privcmd_version_ok (fd, &v) < 0)
		return EXECUTION_FAILURE;

	WORD_LIST *cmd = args->next->next->next->next;
	if (cmd && cmd->word && cmd->word->word && strcmp (cmd->word->word, "--") == 0)
		cmd = cmd->next;

	int argc = 0;
	unsigned int argv_bytes = 0;
	char *argv_blob = ba_words_blob (cmd, &argc, &argv_bytes);
	if (!argv_blob && cmd) {
		builtin_error ("privcmd-exec-interactive: argv build: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	struct bashos_auth_privcmd r;
	memset (&r, 0, sizeof r);
	r.size = sizeof r;
	r.mode = mode;
	r.caller_uid = (unsigned int) getuid ();
	r.caller_gid = (unsigned int) getgid ();
	r.target_uid = target_uid;
	r.target_gid = target_gid;
	r.argc = (unsigned int) argc;
	r.argv_bytes = argv_bytes;
	r.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
	snprintf (r.caller_user, sizeof r.caller_user, "%u", r.caller_uid);
	snprintf (r.target_user, sizeof r.target_user, "%u", target_uid);
	if (!getcwd (r.cwd, sizeof r.cwd))
		strncpy (r.cwd, "/", sizeof r.cwd - 1);
	if (ba_privcmd_fill_digest (&r, argv_blob) < 0) {
		free (argv_blob);
		builtin_error ("privcmd-exec-interactive: request digest failed");
		return EXECUTION_FAILURE;
	}

	/* MINT + REDEEM in the SAME task (kernel binds the grant to the minting
	 * task's struct pid, and the in-context execve REPLACES this task): fork
	 * FIRST and have the CHILD do BOTH the AUTHZ (mint) and EXEC_INTERACTIVE
	 * (redeem). A dedicated child is mandatory — the interactive shell must not be
	 * the one replaced — and minter==redeemer is what the kernel lineage check
	 * requires. The parent only reaps + reports. */
	fflush (NULL);
	pid_t pid = fork ();
	if (pid < 0) {
		int saved = errno;
		free (argv_blob);
		builtin_error ("privcmd-exec-interactive: fork: %s", strerror (saved));
		return EXECUTION_FAILURE;
	}
	if (pid == 0) {
		/* CHILD — single-threaded, inherits the tty + the authority fd. */
		if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0) {
			fprintf (stderr, "privcmd-exec-interactive: AUTHZ: %s\n", strerror (errno));
			_exit (125);
		}
		if (!ba_privcmd_response_is_allowish (r.decision) || r.handle_id == 0) {
			fprintf (stderr, "privcmd-exec-interactive: denied (decision=%s)\n",
			         ba_privcmd_decision_name (r.decision));
			_exit (125);
		}
		struct bashos_auth_exec_handoff_req hr;
		memset (&hr, 0, sizeof hr);
		hr.size = sizeof hr;
		hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_INTERACTIVE;
		hr.argc = (unsigned int) argc;
		hr.argv_bytes = argv_bytes;
		hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
		hr.handle.handle_id = r.handle_id;
		/* On success the kernel commit_creds + kernel_execve REPLACES this child
		 * with the target program on the tty (never returns). On ANY return the
		 * elevation failed (and the kernel force-killed us if we were already
		 * elevated) — report + die without ever running as the target. */
		ioctl (fd, BASHOS_AUTH_IOC_EXEC_INTERACTIVE, &hr);
		fprintf (stderr, "privcmd-exec-interactive: child elevation failed: errno=%d reject_stage=%u\n",
		         errno, hr.reject_stage);
		_exit (126);
	}

	/* PARENT — reap the child (the elevated program, on success) + report. */
	int status = 0;
	while (waitpid (pid, &status, 0) < 0 && errno == EINTR)
		;
	free (argv_blob);
	int childrc = WIFEXITED (status) ? WEXITSTATUS (status)
		    : WIFSIGNALED (status) ? 128 + WTERMSIG (status) : -1;
	printf ("approval=interactive child_exit=%d\n", childrc);
	return (childrc == 0) ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/*
 * privcmd-interactive-lineage-test FD MODE TARGET_UID TARGET_GID [--] cmd...
 *
 * Test-only adversarial fixture. It mints an interactive grant in the current
 * process, then forks a child to redeem the inherited fd + handle. The child has
 * the same uid/gid, session, tty, and fd, but not the same struct pid. The kernel
 * must reject before consume with BASHOS_AUTH_EXEC_REJECT_LINEAGE.
 */
static int
ba_privcmd_interactive_lineage_test_cmd (WORD_LIST *args)
{
	const char *hooks = getenv ("BASHOS_AUTH_TEST_HOOKS");
	if (!hooks || strcmp (hooks, "1") != 0) {
		builtin_error ("privcmd-interactive-lineage-test: disabled (set BASHOS_AUTH_TEST_HOOKS=1)");
		return EXECUTION_FAILURE;
	}
	if (!args || !args->word || !args->next || !args->next->next ||
	    !args->next->next->next) {
		builtin_error ("privcmd-interactive-lineage-test: usage: privcmd-interactive-lineage-test FD MODE TARGET_UID TARGET_GID [--] command [args...]");
		return EX_USAGE;
	}

	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("privcmd-interactive-lineage-test: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	unsigned int mode = (unsigned int) ba_privcmd_mode (args->next->word->word);
	if (!mode) {
		builtin_error ("privcmd-interactive-lineage-test: invalid mode: %s",
		               args->next->word->word);
		return EX_USAGE;
	}
	unsigned int target_uid, target_gid;
	if (ba_parse_uint_arg (args->next->next->word->word, &target_uid) < 0 ||
	    ba_parse_uint_arg (args->next->next->next->word->word, &target_gid) < 0) {
		builtin_error ("privcmd-interactive-lineage-test: invalid target uid/gid");
		return EX_USAGE;
	}
	struct bashos_auth_version v;
	if (ba_privcmd_version_ok (fd, &v) < 0)
		return EXECUTION_FAILURE;

	WORD_LIST *cmd = args->next->next->next->next;
	if (cmd && cmd->word && cmd->word->word && strcmp (cmd->word->word, "--") == 0)
		cmd = cmd->next;
	if (!cmd) {
		builtin_error ("privcmd-interactive-lineage-test: command required");
		return EX_USAGE;
	}

	int argc = 0;
	unsigned int argv_bytes = 0;
	char *argv_blob = ba_words_blob (cmd, &argc, &argv_bytes);
	if (!argv_blob) {
		builtin_error ("privcmd-interactive-lineage-test: argv build: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	struct bashos_auth_privcmd r;
	memset (&r, 0, sizeof r);
	r.size = sizeof r;
	r.mode = mode;
	r.caller_uid = (unsigned int) getuid ();
	r.caller_gid = (unsigned int) getgid ();
	r.target_uid = target_uid;
	r.target_gid = target_gid;
	r.argc = (unsigned int) argc;
	r.argv_bytes = argv_bytes;
	r.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
	snprintf (r.caller_user, sizeof r.caller_user, "%u", r.caller_uid);
	snprintf (r.target_user, sizeof r.target_user, "%u", target_uid);
	if (!getcwd (r.cwd, sizeof r.cwd))
		strncpy (r.cwd, "/", sizeof r.cwd - 1);
	if (ba_privcmd_fill_digest (&r, argv_blob) < 0) {
		free (argv_blob);
		builtin_error ("privcmd-interactive-lineage-test: request digest failed");
		return EXECUTION_FAILURE;
	}
	if (ioctl (fd, BASHOS_AUTH_IOC_PRIVCMD_AUTHZ, &r) < 0) {
		int saved = errno;
		free (argv_blob);
		builtin_error ("ioctl PRIVCMD_AUTHZ: %s", strerror (saved));
		errno = saved;
		return EXECUTION_FAILURE;
	}
	if (!ba_privcmd_response_is_allowish (r.decision) || r.handle_id == 0) {
		printf ("decision=%s handle_id=0 approval=denied reject_stage=0\n",
		        ba_privcmd_decision_name (r.decision));
		free (argv_blob);
		return EXECUTION_FAILURE;
	}

	fflush (NULL);
	pid_t pid = fork ();
	if (pid < 0) {
		int saved = errno;
		free (argv_blob);
		builtin_error ("privcmd-interactive-lineage-test: fork: %s", strerror (saved));
		return EXECUTION_FAILURE;
	}
	if (pid == 0) {
		struct bashos_auth_exec_handoff_req hr;
		memset (&hr, 0, sizeof hr);
		hr.size = sizeof hr;
		hr.mode = BASHOS_AUTH_EXEC_HANDOFF_MODE_INTERACTIVE;
		hr.argc = (unsigned int) argc;
		hr.argv_bytes = argv_bytes;
		hr.argv_user_ptr = (unsigned long long) (uintptr_t) argv_blob;
		hr.handle.handle_id = r.handle_id;
		int rc = ioctl (fd, BASHOS_AUTH_IOC_EXEC_INTERACTIVE, &hr);
		int saved = errno;
		printf ("phase=child decision=%s handle_id=%llu ioctl_rc=%d errno=%d approval=%s reject_stage=%u\n",
		        ba_privcmd_decision_name (r.decision), r.handle_id, rc,
		        rc < 0 ? saved : 0, ba_handoff_approval_name (hr.approval_status),
		        hr.reject_stage);
		_exit (rc == 0 &&
		       hr.approval_status == BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED &&
		       hr.reject_stage == BASHOS_AUTH_EXEC_REJECT_LINEAGE ? 0 : 126);
	}

	int status = 0;
	while (waitpid (pid, &status, 0) < 0 && errno == EINTR)
		;
	free (argv_blob);
	int childrc = WIFEXITED (status) ? WEXITSTATUS (status)
		    : WIFSIGNALED (status) ? 128 + WTERMSIG (status) : -1;
	printf ("phase=parent child_exit=%d expected_reject_stage=%u\n",
	        childrc, BASHOS_AUTH_EXEC_REJECT_LINEAGE);
	return childrc == 0 ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static const char *
ba_policy_status_name (unsigned int status)
{
	switch (status) {
	case BASHOS_AUTH_POLICY_STATUS_OK: return "ok";
	case BASHOS_AUTH_POLICY_STATUS_MISSING: return "missing";
	case BASHOS_AUTH_POLICY_STATUS_UNSAFE: return "unsafe";
	case BASHOS_AUTH_POLICY_STATUS_ERROR: return "error";
	default: return "unknown";
	}
}

static int
ba_policy_info_cmd (WORD_LIST *args)
{
	if (!args || !args->word || args->next) {
		builtin_error ("policy-info: usage: policy-info FD");
		return EX_USAGE;
	}

	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("policy-info: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}

	struct bashos_auth_policy_info p;
	memset (&p, 0, sizeof p);
	p.size = sizeof p;
	if (ioctl (fd, BASHOS_AUTH_IOC_POLICY_INFO, &p) < 0) {
		builtin_error ("ioctl POLICY_INFO: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	char digest_hex[65];
	char normalized_digest_hex[65];
	ba_hex_encode (p.policy_digest, sizeof p.policy_digest, digest_hex);
	ba_hex_encode (p.normalized_policy_digest,
	               sizeof p.normalized_policy_digest, normalized_digest_hex);
	printf ("status=%s generation=%u policy_sha256=%s normalized_policy_sha256=%s uid=%u gid=%u mode=%04o size=%llu path=%s reason=%s\n",
	        ba_policy_status_name (p.status), p.generation, digest_hex,
	        normalized_digest_hex,
	        p.uid, p.gid, p.mode & 07777u, p.size_bytes, p.path, p.reason);
	return p.status == BASHOS_AUTH_POLICY_STATUS_OK
	       ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/*
 * audit-read FD — operator drain of the authority's durable audit ring
 * (BASHOS_AUTH_IOC_AUDIT_READ, CAP_SYS_ADMIN-gated in the kernel). Reports the
 * PUBLISHED counters (returned/total_written/dropped/next_cursor) that prove an
 * operator can read the durable audit trail; it deliberately does NOT decode the
 * per-record payload — the kernel keeps that layout unpublished so it can evolve,
 * and a decoder would couple userspace to it. This is the "first root-readable
 * proof path" of sudo-audit-persistence.md (the full drainer-to-/var/log
 * service stays deferred). Exit 0 with the counters; non-root callers get EPERM
 * from the ioctl (the audit trail is privileged diagnostic data).
 */
static int
ba_audit_read_cmd (WORD_LIST *args)
{
	int fd;
	struct bashos_auth_audit_read_req req;
	/* Up to 64 records (the kernel cap); size each generously (the in-kernel
	 * record is ~176B) so the kernel's copy_to_user always fits. Static to keep
	 * the 16K buffer off the stack. We never parse it — counters only. */
	static unsigned char ba_audit_recbuf[64 * 256];

	if (!args || !args->word || args->next) {
		builtin_error ("audit-read: usage: audit-read FD");
		return EX_USAGE;
	}
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("audit-read: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	memset (&req, 0, sizeof req);
	req.size = sizeof req;
	req.max_count = 64;
	req.records_ptr = (unsigned long long) (unsigned long) ba_audit_recbuf;
	if (ioctl (fd, BASHOS_AUTH_IOC_AUDIT_READ, &req) < 0) {
		builtin_error ("ioctl AUDIT_READ: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}
	printf ("returned=%u total_written=%llu dropped=%llu next_cursor=%llu\n",
	        req.returned_count,
	        (unsigned long long) req.total_written,
	        (unsigned long long) req.dropped,
	        (unsigned long long) req.next_cursor);
	return EXECUTION_SUCCESS;
}

/*
 * audit-read-text FD [CURSOR] [MAX] — drain the audit ring as published fmt=v1
 * kind=event TEXT (the kernel projects each record; this verb relays the ASCII
 * VERBATIM and never parses it — single-decoder invariant). Root-only (the
 * ioctl returns EPERM otherwise). Prints the kernel text, then one '#'-prefixed
 * control line the drainer reads for paging.
 */
static int
ba_audit_read_text_cmd (WORD_LIST *args)
{
	int fd;
	unsigned long long cursor = 0;
	unsigned long max = 64;
	char *end = NULL;
	struct bashos_auth_audit_read_text_req req;
	/* Off-stack; sized to max_count*line_cap so the kernel never truncates and
	 * the buf_cap >= LINE_MAX invariant always holds. Relayed, never parsed. */
	static char ba_audit_textbuf[BASHOS_AUTH_AUDIT_TEXT_BUF_MAX];

	if (!args || !args->word) {
		builtin_error ("audit-read-text: usage: audit-read-text FD [CURSOR] [MAX]");
		return EX_USAGE;
	}
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("audit-read-text: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	if (args->next && args->next->word) {
		cursor = strtoull (args->next->word->word, &end, 10);
		if (!end || *end) {
			builtin_error ("audit-read-text: invalid CURSOR");
			return EX_USAGE;
		}
		if (args->next->next && args->next->next->word) {
			max = strtoul (args->next->next->word->word, &end, 10);
			if (!end || *end || max < 1 || max > 64) {
				builtin_error ("audit-read-text: MAX must be 1..64");
				return EX_USAGE;
			}
			if (args->next->next->next) {
				builtin_error ("audit-read-text: too many arguments");
				return EX_USAGE;
			}
		}
	}
	memset (&req, 0, sizeof req);
	req.size = sizeof req;
	req.max_count = (unsigned int) max;
	req.line_cap = BASHOS_AUTH_AUDIT_TEXT_LINE_MAX;
	req.cursor = cursor;
	req.buf_ptr = (unsigned long long) (unsigned long) ba_audit_textbuf;
	req.buf_cap = sizeof ba_audit_textbuf;
	if (ioctl (fd, BASHOS_AUTH_IOC_AUDIT_READ_TEXT, &req) < 0) {
		builtin_error ("ioctl AUDIT_READ_TEXT: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}
	if (req.bytes_written)
		fwrite (ba_audit_textbuf, 1, (size_t) req.bytes_written, stdout);
	printf ("# returned=%u bytes=%llu next_cursor=%llu dropped=%llu total_written=%llu\n",
	        req.returned_count,
	        (unsigned long long) req.bytes_written,
	        (unsigned long long) req.next_cursor,
	        (unsigned long long) req.dropped,
	        (unsigned long long) req.total_written);
	return EXECUTION_SUCCESS;
}

static int
ba_open_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->word->word || !*args->word->word) {
		builtin_error ("open: missing FDVAR");
		return EX_USAGE;
	}
	const char *fdvar = args->word->word;

	/* This shell process may soon own kernel secret handles and C-only
	 * password buffers. Disable core dumps before exposing the auth fd. */
	if (prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
		builtin_warning ("prctl(PR_SET_DUMPABLE,0): %s", strerror (errno));

	int fd = ba_open_dev ();
	if (fd < 0) return EXECUTION_FAILURE;

	char buf[32];
	snprintf (buf, sizeof buf, "%d", fd);
	if (!builtin_bind_variable ((char *) fdvar, buf, 0)) {
		builtin_error ("could not bind: %s", fdvar);
		close (fd);
		return EXECUTION_FAILURE;
	}
	return EXECUTION_SUCCESS;
}

static int
ba_hexval (int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int
ba_unhex (const char *hex, unsigned char *out, size_t outsz)
{
	size_t o = 0;
	int hi = -1;
	for (const char *p = hex; *p; p++) {
		int v = ba_hexval ((unsigned char) *p);
		if (v < 0) return -1;
		if (hi < 0) { hi = v; continue; }
		if (o >= outsz) return -1;
		out[o++] = (unsigned char) ((hi << 4) | v);
		hi = -1;
	}
	return hi < 0 ? (int) o : -1;
}

static void
ba_hex_encode (const unsigned char *buf, size_t n, char *out)
{
	static const char d[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		out[i * 2] = d[(buf[i] >> 4) & 0xf];
		out[i * 2 + 1] = d[buf[i] & 0xf];
	}
	out[n * 2] = '\0';
}

static int
ba_parse_fd (const char *s, int *fdp)
{
	char *end = NULL;
	long v;

	if (!s || !*s) return -1;
	errno = 0;
	v = strtol (s, &end, 10);
	if (errno || !end || *end || v < 0 || v > 1048576)
		return -1;
	*fdp = (int) v;
	return 0;
}

static int
ba_parse_handle (const char *s, unsigned int *hp)
{
	char *end = NULL;
	unsigned long v;

	if (!s || !*s) return -1;
	errno = 0;
	v = strtoul (s, &end, 10);
	if (errno || !end || *end || v == 0 || v > 0xfffffffful)
		return -1;
	*hp = (unsigned int) v;
	return 0;
}

static int
ba_parse_phc (const char *phc, ba_phc *out)
{
	if (!phc || strncmp (phc, "$argon2id$", 10) != 0)
		return -1;
	char *copy = strdup (phc);
	if (!copy)
		return -1;
	char *save = NULL, *parts[6] = { 0 };
	int n = 0;
	for (char *tok = strtok_r (copy, "$", &save); tok && n < 6;
	     tok = strtok_r (NULL, "$", &save))
		parts[n++] = tok;
	if (n != 5 || strcmp (parts[0], "argon2id") != 0 ||
	    strcmp (parts[1], "v=19") != 0) {
		free (copy);
		return -1;
	}

	memset (out, 0, sizeof *out);
	char *psave = NULL;
	/* Strict m=/t=/p= parse: reject trailing garbage (e.g. "m=12345xxx"
	 * silently became 12345 with the previous NULL-endptr strtoul; an
	 * attacker-controlled PHC field should fail parse at the syntactic
	 * level, not coerce into a numeric prefix). */
	for (char *kv = strtok_r (parts[2], ",", &psave); kv;
	     kv = strtok_r (NULL, ",", &psave)) {
		const char *digits = NULL;
		unsigned int *slot = NULL;
		if      (strncmp (kv, "m=", 2) == 0) { digits = kv + 2; slot = &out->m; }
		else if (strncmp (kv, "t=", 2) == 0) { digits = kv + 2; slot = &out->t; }
		else if (strncmp (kv, "p=", 2) == 0) { digits = kv + 2; slot = &out->p; }
		else continue;
		char *kend = NULL;
		unsigned long v = strtoul (digits, &kend, 10);
		if (!kend || kend == digits || *kend) {
			free (copy);
			return -1;
		}
		*slot = (unsigned int) v;
	}

	size_t sl = strlen (parts[3]), hl = strlen (parts[4]);
	if (out->m < 1024 || out->m > 262144 ||
	    out->t < 1 || out->t > 10 ||
	    out->p < 1 || out->p > 8 ||
	    sl < 16 || sl > 128 || (sl & 1) ||
	    hl < 32 || hl > 256 || (hl & 1)) {
		free (copy);
		return -1;
	}
	strncpy (out->salt_hex, parts[3], sizeof out->salt_hex - 1);
	strncpy (out->hash_hex, parts[4], sizeof out->hash_hex - 1);
	free (copy);
	return 0;
}

static int
ba_verify_phc_secret (const unsigned char *secret, size_t secret_len,
                      const char *phc)
{
	int rc = bashos_verify_phc_secret (secret, secret_len, phc);
	if (rc < 0)
		builtin_error ("verify-login: unsupported or malformed PHC string");
	return rc;
}

static void
ba_free_secret_buf (unsigned char *buf)
{
	if (!buf) return;
	ba_wipe (buf, BASHOS_AUTH_MAX_SECRET);
	munlock (buf, BASHOS_AUTH_MAX_SECRET);
	munmap (buf, BASHOS_AUTH_MAX_SECRET);
}

static int
ba_export_secret_once (int fd, unsigned int handle, unsigned char **out, size_t *out_len)
{
	*out = NULL;
	*out_len = 0;
	unsigned char *buf = mmap (NULL, BASHOS_AUTH_MAX_SECRET,
	                           PROT_READ | PROT_WRITE,
	                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED)
		return -1;
	(void) mlock (buf, BASHOS_AUTH_MAX_SECRET);

	struct bashos_auth_secret_export e;
	memset (&e, 0, sizeof e);
	e.id = handle;
	e.len = BASHOS_AUTH_MAX_SECRET;
	e.user_ptr = (unsigned long long) (uintptr_t) buf;
	if (ioctl (fd, BASHOS_AUTH_IOC_EXPORT_ONCE, &e) < 0) {
		int saved = errno;
		ba_free_secret_buf (buf);
		errno = saved;
		return -1;
	}
	if (e.len > BASHOS_AUTH_MAX_SECRET) {
		ba_free_secret_buf (buf);
		errno = EOVERFLOW;
		return -1;
	}
	*out = buf;
	*out_len = e.len;
	return 0;
}

static int
ba_argon2id_raw (const unsigned char *pass, size_t pass_len,
                 const unsigned char *salt, size_t salt_len,
                 unsigned int passes, unsigned int mem_kib,
                 unsigned int lanes, unsigned char *out, size_t out_len)
{
	if (mem_kib < 1024 || mem_kib > 262144 ||
	    passes < 1 || passes > 10 ||
	    lanes < 1 || lanes > 8 ||
	    salt_len < 8 || salt_len > 64 ||
	    out_len < 16 || out_len > 128) {
		builtin_error ("argon2id parameters out of range");
		return -1;
	}

	return bashos_auth_argon2id_raw (pass, pass_len, salt, salt_len,
	                                 passes, mem_kib, lanes, out, out_len,
	                                 1, NULL);
}

/* Signal-caught state for ba_read_password.  When SIGINT / SIGTERM /
 * SIGHUP arrives during the password prompt, the handler only sets a
 * flag; the read loop (interrupted with EINTR) checks the flag and
 * exits.  The caller then restores termios + signal handlers BEFORE
 * raising the original signal, so the terminal is never left in an
 * echo-off state.  Single-threaded only — bash builtins run serially. */
static volatile sig_atomic_t ba_sig_caught = 0;
static volatile sig_atomic_t ba_sig_signo  = 0;

static void
ba_sig_handler (int signo)
{
	ba_sig_caught = 1;
	ba_sig_signo  = signo;
}

static int
ba_read_password (const char *prompt, unsigned char **out, size_t *out_len)
{
	*out = NULL;
	*out_len = 0;
	int fd = open ("/dev/tty", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		if (!isatty (STDIN_FILENO)) {
			errno = ENOTTY;
			return -1;
		}
		fd = STDIN_FILENO;
	}

	struct termios oldt, newt;
	int have_termios = (tcgetattr (fd, &oldt) == 0);
	if (have_termios) {
		newt = oldt;
		newt.c_lflag &= ~(ECHO | ICANON);
		newt.c_cc[VMIN] = 1;
		newt.c_cc[VTIME] = 0;
		if (tcsetattr (fd, TCSAFLUSH, &newt) < 0)
			have_termios = 0;
	}

	int prompt_fd = (fd == STDIN_FILENO) ? STDERR_FILENO : fd;
	int prompted = 0;
	if (prompt && *prompt) {
		(void) write (prompt_fd, prompt, strlen (prompt));
		prompted = 1;
	}

	/* Install handlers for SIGINT / SIGTERM / SIGHUP for the duration
	 * of the password read.  SA_RESTART is intentionally NOT set —
	 * read() must EINTR-exit on signal so we can restore termios.
	 * Handlers themselves are minimal: set a flag, nothing more. */
	struct sigaction sa, old_int, old_term, old_hup;
	memset (&sa, 0, sizeof sa);
	sa.sa_handler = ba_sig_handler;
	sigemptyset (&sa.sa_mask);
	sa.sa_flags = 0;
	ba_sig_caught = 0;
	ba_sig_signo  = 0;
	sigaction (SIGINT,  &sa, &old_int);
	sigaction (SIGTERM, &sa, &old_term);
	sigaction (SIGHUP,  &sa, &old_hup);

	unsigned char *buf = mmap (NULL, BASHOS_AUTH_MAX_SECRET,
	                           PROT_READ | PROT_WRITE,
	                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		int saved = errno;
		if (have_termios) tcsetattr (fd, TCSANOW, &oldt);
		if (prompted) (void) write (prompt_fd, "\n", 1);
		sigaction (SIGINT,  &old_int,  NULL);
		sigaction (SIGTERM, &old_term, NULL);
		sigaction (SIGHUP,  &old_hup,  NULL);
		if (fd != STDIN_FILENO) close (fd);
		errno = saved;
		return -1;
	}
	(void) mlock (buf, BASHOS_AUTH_MAX_SECRET);

	size_t len = 0;
	int saved = 0;
	for (;;) {
		unsigned char c;
		ssize_t r;
		/* EINTR retry — but break out if our own handler caught the
		 * signal (the user-visible Ctrl-C / SIGTERM / SIGHUP). */
		do { r = read (fd, &c, 1); } while (r < 0 && errno == EINTR && !ba_sig_caught);
		if (ba_sig_caught) { saved = EINTR; break; }
		if (r < 0) { saved = errno; break; }
		if (r == 0 || c == '\n' || c == '\r') break;
		/* Backspace (BS / DEL) erases the most recent byte if any.
		 * Standard readpassphrase(3) behavior; the terminal is in
		 * no-echo so there is no on-screen artifact to undo. */
		if (c == 0x08 || c == 0x7f) {
			if (len > 0) len--;
			continue;
		}
		if (len >= BASHOS_AUTH_MAX_SECRET) { saved = E2BIG; break; }
		buf[len++] = c;
	}

	if (have_termios) tcsetattr (fd, TCSANOW, &oldt);
	if (prompted) (void) write (prompt_fd, "\n", 1);
	sigaction (SIGINT,  &old_int,  NULL);
	sigaction (SIGTERM, &old_term, NULL);
	sigaction (SIGHUP,  &old_hup,  NULL);
	if (fd != STDIN_FILENO) close (fd);

	/* If a signal was caught, terminal + handlers are restored;
	 * re-raise the original signal so the shell sees the cancellation
	 * it would have seen with the default handler.  buf is wiped
	 * below via the `saved` cleanup path. */
	int caught_signo = 0;
	if (ba_sig_caught) {
		caught_signo = (int) ba_sig_signo;
		ba_sig_caught = 0;
		ba_sig_signo  = 0;
	}

	if (saved) {
		ba_free_secret_buf (buf);
		if (caught_signo) {
			/* Re-raise the cancellation signal. With the original
			 * disposition restored above, this will invoke the
			 * shell's handler (typically SIG_DFL → process exit
			 * for SIGTERM/SIGHUP, longjmp out of read-line for
			 * SIGINT in interactive bash).  If raise() returns
			 * (signal blocked, etc.), fall through with EINTR. */
			(void) raise (caught_signo);
		}
		errno = saved;
		return -1;
	}

	*out = buf;
	*out_len = len;
	return 0;
}

static int
ba_read_secret_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->next) {
		builtin_error ("read-secret: usage: read-secret FD [-p PROMPT] HANDLEVAR");
		return EX_USAGE;
	}
	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("read-secret: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}

	const char *prompt = "Password: ";
	WORD_LIST *p = args->next;
	if (p && p->word && p->word->word && strcmp (p->word->word, "-p") == 0) {
		if (!p->next || !p->next->word || !p->next->next) {
			builtin_error ("read-secret: -p needs PROMPT and HANDLEVAR");
			return EX_USAGE;
		}
		prompt = p->next->word->word;
		p = p->next->next;
	}
	if (!p || !p->word || !p->word->word || !*p->word->word || p->next) {
		builtin_error ("read-secret: missing or extra HANDLEVAR");
		return EX_USAGE;
	}
	const char *handle_var = p->word->word;

	struct bashos_auth_handle h;
	memset (&h, 0, sizeof h);
	if (ioctl (fd, BASHOS_AUTH_IOC_NEW_SECRET, &h) < 0) {
		builtin_error ("ioctl NEW_SECRET: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	unsigned char *secret = NULL;
	size_t secret_len = 0;
	if (ba_read_password (prompt, &secret, &secret_len) < 0) {
		int saved = errno;
		(void) ioctl (fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &h);
		builtin_error ("read-secret: %s", strerror (saved));
		errno = saved;
		return EXECUTION_FAILURE;
	}

	struct bashos_auth_secret_write w;
	memset (&w, 0, sizeof w);
	w.id = h.id;
	w.len = (unsigned int) secret_len;
	w.user_ptr = (unsigned long long) (uintptr_t) secret;
	if (ioctl (fd, BASHOS_AUTH_IOC_WRITE_SECRET, &w) < 0) {
		int saved = errno;
		ba_free_secret_buf (secret);
		(void) ioctl (fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &h);
		builtin_error ("ioctl WRITE_SECRET: %s", strerror (saved));
		errno = saved;
		return EXECUTION_FAILURE;
	}
	ba_free_secret_buf (secret);

	if (ioctl (fd, BASHOS_AUTH_IOC_SEAL_SECRET, &h) < 0) {
		int saved = errno;
		(void) ioctl (fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &h);
		builtin_error ("ioctl SEAL_SECRET: %s", strerror (saved));
		errno = saved;
		return EXECUTION_FAILURE;
	}

	char buf[32];
	snprintf (buf, sizeof buf, "%u", h.id);
	if (!builtin_bind_variable ((char *) handle_var, buf, 0)) {
		(void) ioctl (fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &h);
		builtin_error ("could not bind: %s", handle_var);
		return EXECUTION_FAILURE;
	}
	return EXECUTION_SUCCESS;
}

static int
ba_clear_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->next || args->next->next) {
		builtin_error ("clear: usage: clear FD HANDLE");
		return EX_USAGE;
	}
	int fd;
	unsigned int handle;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("clear: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	if (ba_parse_handle (args->next->word->word, &handle) < 0) {
		builtin_error ("clear: invalid handle: %s", args->next->word->word);
		return EX_USAGE;
	}

	struct bashos_auth_handle h;
	memset (&h, 0, sizeof h);
	h.id = handle;
	if (ioctl (fd, BASHOS_AUTH_IOC_CLEAR_SECRET, &h) < 0) {
		builtin_error ("ioctl CLEAR_SECRET: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}
	return EXECUTION_SUCCESS;
}

static int
ba_same_secret_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->next || !args->next->next ||
	    args->next->next->next) {
		builtin_error ("same-secret: usage: same-secret FD HANDLE_A HANDLE_B");
		return EX_USAGE;
	}
	int fd;
	unsigned int a, b;
	if (ba_parse_fd (args->word->word, &fd) < 0 ||
	    ba_parse_handle (args->next->word->word, &a) < 0 ||
	    ba_parse_handle (args->next->next->word->word, &b) < 0) {
		builtin_error ("same-secret: invalid fd or handle");
		return EX_USAGE;
	}

	struct bashos_auth_secret_compare c;
	memset (&c, 0, sizeof c);
	c.id_a = a;
	c.id_b = b;
	if (ioctl (fd, BASHOS_AUTH_IOC_SAME_SECRET, &c) < 0) {
		builtin_error ("ioctl SAME_SECRET: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}
	return c.result ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

static int
ba_stats_cmd (WORD_LIST *args)
{
	if (!args || !args->word || args->next) {
		builtin_error ("stats: usage: stats FD");
		return EX_USAGE;
	}
	int fd;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("stats: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}

	struct bashos_auth_stats s;
	memset (&s, 0, sizeof s);
	if (ioctl (fd, BASHOS_AUTH_IOC_STATS, &s) < 0) {
		builtin_error ("ioctl STATS: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	printf ("created_secrets=%llu cleared_secrets=%llu refused_exports=%llu "
	        "minted_tokens=%llu consumed_tokens=%llu expired_tokens=%llu\n",
	        s.created_secrets, s.cleared_secrets, s.refused_exports,
	        s.minted_tokens, s.consumed_tokens, s.expired_tokens);
	return EXECUTION_SUCCESS;
}

static int
ba_hash_secret_cmd (WORD_LIST *args)
{
	const char *vals[8];
	WORD_LIST *p = args;
	for (int i = 0; i < 8; i++) {
		if (!p || !p->word || !p->word->word) {
			builtin_error ("hash-secret: usage: hash-secret FD HANDLE SALT_HEX T M P HASHLEN OUTVAR");
			return EX_USAGE;
		}
		vals[i] = p->word->word;
		p = p->next;
	}
	if (p) {
		builtin_error ("hash-secret: extra arguments");
		return EX_USAGE;
	}

	int fd;
	unsigned int handle;
	if (ba_parse_fd (vals[0], &fd) < 0 || ba_parse_handle (vals[1], &handle) < 0) {
		builtin_error ("hash-secret: invalid fd or handle");
		return EX_USAGE;
	}
	char *end = NULL;
	unsigned long t = strtoul (vals[3], &end, 10);
	if (!end || *end) { builtin_error ("hash-secret: bad T"); return EX_USAGE; }
	unsigned long m = strtoul (vals[4], &end, 10);
	if (!end || *end) { builtin_error ("hash-secret: bad M"); return EX_USAGE; }
	unsigned long lanes = strtoul (vals[5], &end, 10);
	if (!end || *end) { builtin_error ("hash-secret: bad P"); return EX_USAGE; }
	unsigned long hash_len = strtoul (vals[6], &end, 10);
	if (!end || *end || hash_len > 128) { builtin_error ("hash-secret: bad HASHLEN"); return EX_USAGE; }
	const char *outvar = vals[7];
	if (!*outvar) { builtin_error ("hash-secret: empty OUTVAR"); return EX_USAGE; }

	unsigned char salt[64];
	int salt_len = ba_unhex (vals[2], salt, sizeof salt);
	if (salt_len < 8) {
		builtin_error ("hash-secret: bad SALT_HEX");
		return EX_USAGE;
	}

	unsigned char *secret = NULL;
	size_t secret_len = 0;
	if (ba_export_secret_once (fd, handle, &secret, &secret_len) < 0) {
		builtin_error ("ioctl EXPORT_ONCE: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	unsigned char hash[128];
	memset (hash, 0, sizeof hash);
	int rc = ba_argon2id_raw (secret, secret_len, salt, (size_t) salt_len,
	                          (unsigned int) t, (unsigned int) m,
	                          (unsigned int) lanes, hash, (size_t) hash_len);
	ba_free_secret_buf (secret);
	if (rc < 0) {
		ba_wipe (hash, sizeof hash);
		return EXECUTION_FAILURE;
	}

	char salt_hex[sizeof salt * 2 + 1];
	char hash_hex[sizeof hash * 2 + 1];
	ba_hex_encode (salt, (size_t) salt_len, salt_hex);
	ba_hex_encode (hash, (size_t) hash_len, hash_hex);
	ba_wipe (hash, sizeof hash);

	char *phc = NULL;
	if (asprintf (&phc, "$argon2id$v=19$m=%lu,t=%lu,p=%lu$%s$%s",
	              m, t, lanes, salt_hex, hash_hex) < 0) {
		ba_wipe (salt_hex, sizeof salt_hex);
		ba_wipe (hash_hex, sizeof hash_hex);
		builtin_error ("hash-secret: out of memory");
		return EXECUTION_FAILURE;
	}
	ba_wipe (salt_hex, sizeof salt_hex);
	ba_wipe (hash_hex, sizeof hash_hex);
	if (!builtin_bind_variable ((char *) outvar, phc, 0)) {
		free (phc);
		builtin_error ("could not bind: %s", outvar);
		return EXECUTION_FAILURE;
	}
	free (phc);
	return EXECUTION_SUCCESS;
}

static int
ba_verify_login_cmd (WORD_LIST *args)
{
	const char *vals[5];
	WORD_LIST *p = args;
	for (int i = 0; i < 5; i++) {
		if (!p || !p->word || !p->word->word) {
			builtin_error ("verify-login: usage: verify-login FD HANDLE USER PHC TOKENVAR");
			return EX_USAGE;
		}
		vals[i] = p->word->word;
		p = p->next;
	}
	if (p) {
		builtin_error ("verify-login: extra arguments");
		return EX_USAGE;
	}

	int fd;
	unsigned int handle;
	if (ba_parse_fd (vals[0], &fd) < 0 || ba_parse_handle (vals[1], &handle) < 0) {
		builtin_error ("verify-login: invalid fd or handle");
		return EX_USAGE;
	}
	const char *user = vals[2];
	const char *phc = vals[3];
	const char *token_var = vals[4];
	if (!*user || strlen (user) >= BASHOS_AUTH_USER_BYTES) {
		builtin_error ("verify-login: invalid USER");
		return EX_USAGE;
	}
	if (!*token_var) {
		builtin_error ("verify-login: empty TOKENVAR");
		return EX_USAGE;
	}
	ba_phc parsed;
	if (ba_parse_phc (phc, &parsed) < 0) {
		builtin_error ("verify-login: unsupported or malformed PHC string");
		return EXECUTION_FAILURE;
	}

	struct passwd *pw = getpwnam (user);
	if (!pw) {
		builtin_error ("verify-login: no such user: %s", user);
		return EXECUTION_FAILURE;
	}

	unsigned char *secret = NULL;
	size_t secret_len = 0;
	if (ba_export_secret_once (fd, handle, &secret, &secret_len) < 0) {
		builtin_error ("ioctl EXPORT_ONCE: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	int vr = ba_verify_phc_secret (secret, secret_len, phc);
	ba_free_secret_buf (secret);
	if (vr != 0)
		return EXECUTION_FAILURE;

	struct bashos_auth_token_req req;
	memset (&req, 0, sizeof req);
	req.uid = (unsigned int) pw->pw_uid;
	req.gid = (unsigned int) pw->pw_gid;
	req.purpose = BASHOS_AUTH_TOKEN_LOGIN;
	req.expires_sec = 5;
	strncpy (req.user, user, sizeof req.user - 1);
	if (ioctl (fd, BASHOS_AUTH_IOC_MINT_TOKEN, &req) < 0) {
		builtin_error ("ioctl MINT_TOKEN: %s", strerror (errno));
		return EXECUTION_FAILURE;
	}

	char hex[BASHOS_AUTH_TOKEN_BYTES * 2 + 1];
	ba_hex_encode (req.token, sizeof req.token, hex);
	ba_wipe (&req, sizeof req);
	if (!builtin_bind_variable ((char *) token_var, hex, 0)) {
		ba_wipe (hex, sizeof hex);
		builtin_error ("could not bind: %s", token_var);
		return EXECUTION_FAILURE;
	}
	ba_wipe (hex, sizeof hex);
	return EXECUTION_SUCCESS;
}

/* ── per-user failed-attempt cap ──────────────────────────────────────
 *
 * Stage-32 login rate-limit pins a *global* throttle (token bucket
 * shared across all callers). That closes burst floods but not the
 * slow-distributed-attack hole: an attacker who paces probes under the
 * global threshold can grind one user's password indefinitely. The
 * per-user counter here is the targeted complement:
 *
 *   auth peruser bump  USER   → fails++; arm lock if cap reached
 *   auth peruser check USER   → exit 0 if under cap, 1 if locked
 *   auth peruser reset USER   → clear (call on successful auth)
 *   auth peruser status USER  → print fails=N locked=0|1 remaining=Ns
 *
 * State is process-local: the table lives in the bash process that
 * has auth enabled. Cooldown elapses naturally (lock_until <= now
 * on check → entry is reset and the caller may try again).
 *
 * Bounded LRU: BA_PERUSER_SLOTS entries; on overflow the oldest
 * last_seen wins eviction. Keeps memory deterministic against a
 * username-flood probe.
 *
 * Env hooks (read on every call so tests can flip mid-run):
 *   BASHAUTH_PERUSER_MAX       attempt cap before lockout       (default 10)
 *   BASHAUTH_PERUSER_COOLDOWN  lock duration in seconds         (default 60)
 */

#define BA_PERUSER_SLOTS     64
#define BA_PERUSER_NAME_LEN  64

struct ba_peruser_entry {
	char         user[BA_PERUSER_NAME_LEN];
	unsigned int fails;
	time_t       lock_until;
	time_t       last_seen;
};

static struct ba_peruser_entry ba_peruser_tab[BA_PERUSER_SLOTS];

static unsigned int
ba_peruser_max (void)
{
	const char *s = getenv ("BASHAUTH_PERUSER_MAX");
	if (s && *s) {
		long v = strtol (s, NULL, 10);
		if (v > 0 && v < 1000000) return (unsigned int) v;
	}
	return 10;
}

static long
ba_peruser_cooldown (void)
{
	const char *s = getenv ("BASHAUTH_PERUSER_COOLDOWN");
	if (s && *s) {
		long v = strtol (s, NULL, 10);
		if (v >= 0 && v < 365L * 86400L) return v;
	}
	return 60;
}

/* Find existing entry for USER, or NULL. */
static struct ba_peruser_entry *
ba_peruser_find (const char *user)
{
	for (int i = 0; i < BA_PERUSER_SLOTS; i++)
		if (ba_peruser_tab[i].user[0] && !strcmp (ba_peruser_tab[i].user, user))
			return &ba_peruser_tab[i];
	return NULL;
}

/* Find existing entry, or allocate one (LRU-evicting if full).
 * Always returns a slot; updates last_seen. */
static struct ba_peruser_entry *
ba_peruser_get_or_alloc (const char *user)
{
	struct ba_peruser_entry *hit = ba_peruser_find (user);
	if (hit) {
		hit->last_seen = time (NULL);
		return hit;
	}
	struct ba_peruser_entry *victim = &ba_peruser_tab[0];
	for (int i = 0; i < BA_PERUSER_SLOTS; i++) {
		if (!ba_peruser_tab[i].user[0]) { victim = &ba_peruser_tab[i]; break; }
		if (ba_peruser_tab[i].last_seen < victim->last_seen) victim = &ba_peruser_tab[i];
	}
	memset (victim, 0, sizeof *victim);
	strncpy (victim->user, user, BA_PERUSER_NAME_LEN - 1);
	victim->last_seen = time (NULL);
	return victim;
}

static int
ba_peruser_cmd (WORD_LIST *args)
{
	if (!args || !args->word || !args->word->word) {
		builtin_error ("peruser: missing ACTION (bump|check|reset|status)");
		return EX_USAGE;
	}
	const char *action = args->word->word;
	WORD_LIST *rest = args->next;
	if (!rest || !rest->word || !rest->word->word || !*rest->word->word) {
		builtin_error ("peruser %s: missing USER", action);
		return EX_USAGE;
	}
	const char *user = rest->word->word;
	if (strlen (user) >= BA_PERUSER_NAME_LEN) {
		builtin_error ("peruser %s: user too long", action);
		return EX_USAGE;
	}
	time_t now = time (NULL);

	if (!strcmp (action, "bump")) {
		struct ba_peruser_entry *e = ba_peruser_get_or_alloc (user);
		/* A stale lock that already expired should not block the
		 * fresh attempt; clear it before counting. */
		if (e->lock_until && now >= e->lock_until) {
			e->fails = 0;
			e->lock_until = 0;
		}
		e->fails++;
		if (e->fails >= ba_peruser_max ())
			e->lock_until = now + ba_peruser_cooldown ();
		return EXECUTION_SUCCESS;
	}
	if (!strcmp (action, "check")) {
		struct ba_peruser_entry *e = ba_peruser_find (user);
		if (!e) return EXECUTION_SUCCESS;             /* no record → ok */
		if (!e->lock_until) return EXECUTION_SUCCESS; /* not locked */
		if (now >= e->lock_until) {
			/* Cooldown elapsed — reset and report ok. */
			e->fails = 0;
			e->lock_until = 0;
			return EXECUTION_SUCCESS;
		}
		return EXECUTION_FAILURE;                     /* still locked */
	}
	if (!strcmp (action, "reset")) {
		struct ba_peruser_entry *e = ba_peruser_find (user);
		if (e) memset (e, 0, sizeof *e);
		return EXECUTION_SUCCESS;
	}
	if (!strcmp (action, "status")) {
		struct ba_peruser_entry *e = ba_peruser_find (user);
		unsigned int fails = e ? e->fails : 0;
		int locked = (e && e->lock_until && now < e->lock_until) ? 1 : 0;
		long remaining = (e && locked) ? (long)(e->lock_until - now) : 0;
		printf ("fails=%u locked=%d remaining=%lds\n", fails, locked, remaining);
		return EXECUTION_SUCCESS;
	}
	builtin_error ("peruser: unknown action %s (try bump|check|reset|status)", action);
	return EX_USAGE;
}

static char *
ba_policy_trim (char *s)
{
	while (*s && isspace ((unsigned char) *s)) s++;
	char *e = s + strlen (s);
	while (e > s && isspace ((unsigned char) e[-1])) *--e = '\0';
	return s;
}

static int
ba_policy_has_glob_or_negation (const char *s)
{
	for (; *s; s++)
		if (*s == '*' || *s == '?' || *s == '[' || *s == ']' || *s == '!')
			return 1;
	return 0;
}

static int
ba_policy_has_negation (const char *s)
{
	for (; *s; s++)
		if (*s == '!')
			return 1;
	return 0;
}

static int
ba_policy_path_has_glob (const char *s)
{
	int esc = 0;

	for (; *s; s++) {
		if (esc) {
			if (*s == '*' || *s == '?' || *s == '[' ||
			    *s == ']' || *s == '\\')
				return 1;
			esc = 0;
			continue;
		}
		if (*s == '\\') {
			esc = 1;
			continue;
		}
		if (*s == '*' || *s == '?' || *s == '[' || *s == ']')
			return 1;
	}
	return 0;
}

static int
ba_policy_glob_syntax_ok (const char *s)
{
	int esc = 0, in_class = 0, class_has_char = 0;

	for (; *s; s++) {
		if (esc) {
			esc = 0;
			if (in_class)
				class_has_char = 1;
			continue;
		}
		if (*s == '\\') {
			esc = 1;
			continue;
		}
		if (*s == '!')
			return 0;
		if (*s == '[' && !in_class) {
			in_class = 1;
			class_has_char = 0;
			continue;
		}
		if (*s == ']' && in_class) {
			if (!class_has_char)
				return 0;
			in_class = 0;
			continue;
		}
		if (in_class)
			class_has_char = 1;
	}
	return !in_class;
}

static int
ba_policy_path_has_dot_component (const char *s, size_t len)
{
	size_t start = 0;

	while (start < len) {
		size_t end = start;

		while (start < len && s[start] == '/')
			start++;
		end = start;
		while (end < len && s[end] != '/')
			end++;
		if (end > start &&
		    ((end - start == 1 && s[start] == '.') ||
		     (end - start == 2 && s[start] == '.' && s[start + 1] == '.')))
			return 1;
		start = end;
	}
	return 0;
}

static int
ba_policy_normalize_cmd_path (const char *in, char *out, size_t cap)
{
	size_t i, pos = 0, len;

	if (!in || !out || cap < 2 || in[0] != '/')
		return -1;
	len = strnlen (in, 256);
	if (len == 0 || len >= 256)
		return -1;
	if (ba_policy_path_has_dot_component (in, len))
		return -1;
	for (i = 0; in[i]; i++) {
		if (in[i] == '/' && pos > 0 && out[pos - 1] == '/')
			continue;
		if (pos + 1 >= cap)
			return -1;
		out[pos++] = in[i];
	}
	while (pos > 1 && out[pos - 1] == '/')
		pos--;
	out[pos] = '\0';
	return pos ? 0 : -1;
}

static int
ba_policy_class_match (const char **patp, char c)
{
	const char *p = *patp;
	int matched = 0, any = 0;

	if (!c || c == '/')
		return 0;
	if (*p == ']') {
		matched = c == ']';
		any = 1;
		p++;
	}
	while (*p && *p != ']') {
		char first, last;

		if (*p == '\\' && p[1])
			p++;
		first = *p++;
		any = 1;
		if (*p == '-' && p[1] && p[1] != ']') {
			p++;
			if (*p == '\\' && p[1])
				p++;
			last = *p++;
			if ((first <= last && c >= first && c <= last) ||
			    (last < first && c >= last && c <= first))
				matched = 1;
		} else if (c == first) {
			matched = 1;
		}
	}
	if (*p != ']' || !any)
		return 0;
	*patp = p + 1;
	return matched;
}

static int
ba_policy_fnmatch_inner (const char *pat, const char *str, unsigned int depth)
{
	if (depth > 512)
		return 0;
	while (*pat) {
		char pc = *pat++;

		if (pc == '\\' && *pat) {
			pc = *pat++;
			if (*str++ != pc)
				return 0;
			continue;
		}
		if (pc == '?') {
			if (!*str || *str == '/')
				return 0;
			str++;
			continue;
		}
		if (pc == '*') {
			const char *scan = str;

			while (*pat == '*')
				pat++;
			do {
				if (ba_policy_fnmatch_inner (pat, scan, depth + 1))
					return 1;
				if (!*scan || *scan == '/')
					break;
				scan++;
			} while (1);
			return 0;
		}
		if (pc == '[') {
			if (!ba_policy_class_match (&pat, *str))
				return 0;
			str++;
			continue;
		}
		if (*str++ != pc)
			return 0;
	}
	return *str == '\0';
}

static int
ba_policy_fnmatch (const char *pat, const char *str)
{
	if (!pat || !str)
		return 0;
	return ba_policy_fnmatch_inner (pat, str, 0);
}

static int
ba_policy_name_ok (const char *s, int alias)
{
	if (!s || !*s) return 0;
	if (alias && !isupper ((unsigned char) *s)) return 0;
	if (!alias && !(isalnum ((unsigned char) *s) || *s == '_' || *s == '%' || *s == '.'))
		return 0;
	for (const char *p = s + 1; *p; p++) {
		if (isalnum ((unsigned char) *p) || *p == '_' || *p == '-' || *p == '.')
			continue;
		return 0;
	}
	return 1;
}

static int
ba_policy_ident_ok (const char *s)
{
	if (!s || !((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '_'))
		return 0;
	for (const char *p = s + 1; *p; p++)
		if (!(isalnum ((unsigned char) *p) || *p == '_'))
			return 0;
	return 1;
}

static int
ba_policy_uint_ok (const char *s)
{
	if (!s || !*s)
		return 0;
	for (const char *p = s; *p; p++)
		if (!isdigit ((unsigned char) *p))
			return 0;
	return 1;
}

static int
ba_policy_bool_value (const char *s, const char **normalized)
{
	if (!s || !*s)
		return 0;
	if (strcmp (s, "true") == 0 || strcmp (s, "on") == 0) {
		if (normalized) *normalized = "true";
		return 1;
	}
	if (strcmp (s, "false") == 0 || strcmp (s, "off") == 0) {
		if (normalized) *normalized = "false";
		return 1;
	}
	return 0;
}

static int
ba_policy_secure_path_ok (const char *s)
{
	if (!s || s[0] != '/')
		return 0;
	if (ba_policy_has_glob_or_negation (s))
		return 0;
	for (const char *p = s; *p; p++)
		if (isspace ((unsigned char) *p))
			return 0;
	return 1;
}

static int
ba_policy_env_name_dangerous (const char *s)
{
	/* Keep in sync with bashos_ce_env_name_is_dangerous
	   (_bashauth/cred_exec.c), the canonical runtime scrub. */
	static const char *const exact[] = {
		"BASH_ENV", "CDPATH", "ENV", "GETCONF_DIR", "GLOBIGNORE",
		"GCONV_PATH", "HOSTALIASES", "IFS", "LOCPATH", "NLSPATH",
		"NODE_OPTIONS", "NODE_PATH", "PERL5LIB", "PERL5OPT",
		"PROMPT_COMMAND", "PYTHONHOME", "PYTHONINSPECT", "PYTHONPATH",
		"PYTHONSTARTUP", "RES_OPTIONS", "RUBYLIB", "RUBYOPT",
		"TERMCAP", "TZDIR",
		/* Bash startup-influencing family + interpreter extras (added
		   2026-06-28 to match the canonical cred_exec.c list). */
		"SHELLOPTS", "BASHOPTS", "PS4", "BASH_XTRACEFD",
		"PERLLIB", "PERL5DB", "PYTHONUSERBASE", "PYTHONNOUSERSITE",
		"PYTHONOPTIMIZE", "RUBYPATH",
	};
	static const char *const prefix[] = {
		"BASH_FUNC_", "DYLD_", "LD_",
	};

	for (size_t i = 0; i < sizeof (exact) / sizeof (exact[0]); i++)
		if (strcmp (s, exact[i]) == 0)
			return 1;
	for (size_t i = 0; i < sizeof (prefix) / sizeof (prefix[0]); i++)
		if (strncmp (s, prefix[i], strlen (prefix[i])) == 0)
			return 1;
	return 0;
}

static int
ba_policy_env_list_ok (const char *value)
{
	char *copy = strdup (value);
	if (!copy)
		return 0;
	char *v = ba_policy_trim (copy);
	size_t len = strlen (v);
	if (len >= 2 && ((v[0] == '"' && v[len - 1] == '"') ||
	                 (v[0] == '\'' && v[len - 1] == '\''))) {
		v[len - 1] = '\0';
		v++;
	}
	int n = 0;
	char *save = NULL;
	for (char *tok = strtok_r (v, " \t,", &save); tok; tok = strtok_r (NULL, " \t,", &save)) {
		if (!ba_policy_ident_ok (tok) || ba_policy_has_glob_or_negation (tok) ||
		    ba_policy_env_name_dangerous (tok)) {
			free (copy);
			return 0;
		}
		n++;
	}
	free (copy);
	return n > 0;
}

static int
ba_policy_sha256_cmd_ok (const char *s)
{
	if (strncmp (s, "sha256:", 7) != 0) return 0;
	const char *hex = s + 7;
	for (int i = 0; i < 64; i++)
		if (!isxdigit ((unsigned char) hex[i]))
			return 0;
	return hex[64] == ':' && hex[65] == '/';
}

enum ba_policy_command_args_mode {
	BA_POLICY_COMMAND_ANY_ARGS = 0,
	BA_POLICY_COMMAND_NO_ARGS,
	BA_POLICY_COMMAND_EXACT_ARGS
};

enum ba_policy_token_type {
	BA_POLICY_TOKEN_ALL = 1,
	BA_POLICY_TOKEN_ALIAS_REF = 2,
	BA_POLICY_TOKEN_SHA256_PATH = 3,
	BA_POLICY_TOKEN_ABSOLUTE_PATH = 4,
	BA_POLICY_TOKEN_SUDOEDIT_EDIT = 5,
	BA_POLICY_TOKEN_GLOB_PATH = 6
};

struct ba_policy_command_spec {
	int type;
	enum ba_policy_command_args_mode args_mode;
	char cmd[256];
	char args[256];
};

static int
ba_policy_arg_text_ok (const char *s)
{
	if (!s || !*s)
		return 0;
	if (strcmp (s, "\"\"") == 0)
		return 1;
	for (const char *p = s; *p; p++) {
		unsigned char c = (unsigned char) *p;
		if (c == '"' || c == '\'' || c == '\\' || c == ',' ||
		    c == ';' || c == '&' || c == '|' || c == '`' ||
		    c == '$' || c == '<' || c == '>' || c == '(' || c == ')' ||
		    c == '*' || c == '?' || c == '[' || c == ']' || c == '!')
			return 0;
		if (c < 0x20 && !isspace (c))
			return 0;
	}
	return 1;
}

static int
ba_policy_parse_command_spec (const char *tok, struct ba_policy_command_spec *spec)
{
	char buf[256];
	char norm[256];
	char *p, *args = NULL, *scan;
	size_t cmd_len;
	int ret;

	if (!tok || !spec)
		return -1;
	memset (spec, 0, sizeof *spec);
	snprintf (buf, sizeof buf, "%s", tok);
	p = ba_policy_trim (buf);
	if (!*p)
		return -1;
	if (strcmp (p, "ALL") == 0) {
		spec->type = BA_POLICY_TOKEN_ALL;
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		snprintf (spec->cmd, sizeof spec->cmd, "%s", p);
		return 0;
	}
	if (ba_policy_name_ok (p, 1)) {
		spec->type = BA_POLICY_TOKEN_ALIAS_REF;
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		snprintf (spec->cmd, sizeof spec->cmd, "%s", p);
		return 0;
	}
	/* `sudoedit <abs-path>`: an EDIT-ONLY command spec. Must mirror the kernel
	 * parser in kernel/bashos-auth/bashos_auth.c exactly (the kernel re-parses
	 * the raw policy text; this validator + the kernel must agree). Single
	 * absolute target per spec, no command args. type 5 = SUDOEDIT_EDIT. */
	if (strncmp (p, "sudoedit", 8) == 0 && (p[8] == ' ' || p[8] == '\t')) {
		char *t = ba_policy_trim (p + 8);
		if (t[0] != '/')
			return -1;
		if (ba_policy_has_glob_or_negation (t))
			return -1;
		for (const char *q = t; *q; q++)
			if (isspace ((unsigned char) *q))
				return -1;
		if (ba_policy_normalize_cmd_path (t, norm, sizeof norm) < 0)
			return -1;
		if (!norm[0] || strlen (norm) >= sizeof spec->cmd)
			return -1;
		spec->type = BA_POLICY_TOKEN_SUDOEDIT_EDIT;
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		snprintf (spec->cmd, sizeof spec->cmd, "%s", norm);
		return 0;
	}

	scan = p;
	if (ba_policy_sha256_cmd_ok (p))
		scan = p + 72;
	else if (p[0] != '/')
		return -1;
	for (; *scan && !isspace ((unsigned char) *scan); scan++)
		;
	if (*scan) {
		*scan++ = '\0';
		args = ba_policy_trim (scan);
	}
	if (ba_policy_sha256_cmd_ok (p)) {
		spec->type = BA_POLICY_TOKEN_SHA256_PATH;
		if (p[72] != '/')
			return -1;
		if (ba_policy_has_glob_or_negation (p))
			return -1;
		if (ba_policy_normalize_cmd_path (p + 72, norm, sizeof norm) < 0)
			return -1;
		ret = snprintf (spec->cmd, sizeof spec->cmd, "%.72s%s", p, norm);
		if (ret < 0 || ret >= (int) sizeof spec->cmd)
			return -1;
	} else {
		if (ba_policy_has_negation (p))
			return -1;
		if (ba_policy_normalize_cmd_path (p, norm, sizeof norm) < 0)
			return -1;
		if (ba_policy_path_has_glob (norm)) {
			if (!ba_policy_glob_syntax_ok (norm))
				return -1;
			spec->type = BA_POLICY_TOKEN_GLOB_PATH;
		} else {
			spec->type = BA_POLICY_TOKEN_ABSOLUTE_PATH;
		}
	}
	if (spec->type != BA_POLICY_TOKEN_SHA256_PATH)
		snprintf (spec->cmd, sizeof spec->cmd, "%s", norm);
	cmd_len = strlen (spec->cmd);
	if (cmd_len == 0 || cmd_len >= sizeof spec->cmd)
		return -1;
	if (!args || !*args) {
		spec->args_mode = BA_POLICY_COMMAND_ANY_ARGS;
		return 0;
	}
	if (!ba_policy_arg_text_ok (args) || strlen (args) >= sizeof spec->args)
		return -1;
	if (strcmp (args, "\"\"") == 0) {
		spec->args_mode = BA_POLICY_COMMAND_NO_ARGS;
		return 0;
	}
	spec->args_mode = BA_POLICY_COMMAND_EXACT_ARGS;
	snprintf (spec->args, sizeof spec->args, "%s", args);
	return 0;
}

static int
ba_policy_append_text (char *out, size_t cap, size_t *pos, const char *s)
{
	size_t len;

	if (!out || !pos || !s)
		return -1;
	len = strlen (s);
	if (*pos + len >= cap)
		return -1;
	memcpy (out + *pos, s, len);
	*pos += len;
	out[*pos] = '\0';
	return 0;
}

static int
ba_policy_normalize_command_spec_text (const char *tok, char *out, size_t cap)
{
	struct ba_policy_command_spec spec;
	size_t pos = 0;
	int ret;

	if (!out || cap == 0)
		return -1;
	out[0] = '\0';
	ret = ba_policy_parse_command_spec (tok, &spec);
	if (ret)
		return ret;
	if (spec.type == BA_POLICY_TOKEN_SUDOEDIT_EDIT) {
		ret = snprintf (out, cap, "sudoedit %s", spec.cmd);
		if (ret < 0 || ret >= (int) cap)
			return -1;
	} else if (ba_policy_append_text (out, cap, &pos, spec.cmd) < 0) {
		return -1;
	}
	if (spec.args_mode == BA_POLICY_COMMAND_NO_ARGS)
		return ba_policy_append_text (out, cap, &pos, " \"\"");
	if (spec.args_mode == BA_POLICY_COMMAND_EXACT_ARGS) {
		if (ba_policy_append_text (out, cap, &pos, " ") < 0)
			return -1;
		return ba_policy_append_text (out, cap, &pos, spec.args);
	}
	return 0;
}

static int
ba_policy_normalize_command_list (const char *list, char *out, size_t cap)
{
	char *copy, *save = NULL;
	size_t pos = 0;
	int n = 0, ret = 0;

	if (!list || !out || cap == 0)
		return -1;
	out[0] = '\0';
	copy = strdup (list);
	if (!copy)
		return -1;
	for (char *tok = strtok_r (copy, ",", &save); tok;
	     tok = strtok_r (NULL, ",", &save)) {
		char one[256];

		tok = ba_policy_trim (tok);
		if (!*tok)
			continue;
		ret = ba_policy_normalize_command_spec_text (tok, one, sizeof one);
		if (ret)
			break;
		if (n++ > 0 && ba_policy_append_text (out, cap, &pos, ",") < 0) {
			ret = -1;
			break;
		}
		if (ba_policy_append_text (out, cap, &pos, one) < 0) {
			ret = -1;
			break;
		}
	}
	free (copy);
	return ret ? ret : (n > 0 ? 0 : -1);
}

static int
ba_policy_value_ok (const char *s, int command)
{
	if (!s || !*s) return 0;
	if (command) {
		struct ba_policy_command_spec spec;
		return ba_policy_parse_command_spec (s, &spec) == 0;
	}
	if (ba_policy_has_glob_or_negation (s)) return 0;
	if (strcmp (s, "ALL") == 0) return 1;
	return ba_policy_name_ok (s, 1) || (!command && ba_policy_name_ok (s, 0));
}

static int
ba_policy_list_ok (char *list, int command)
{
	char *save = NULL;
	int n = 0;
	for (char *tok = strtok_r (list, ",", &save); tok; tok = strtok_r (NULL, ",", &save)) {
		tok = ba_policy_trim (tok);
		if (!ba_policy_value_ok (tok, command))
			return 0;
		n++;
	}
	return n > 0;
}

static int
ba_policy_host_ok (const char *host)
{
	if (strcmp (host, "ALL") == 0) return 1;
	char local[128];
	if (gethostname (local, sizeof local) < 0)
		local[0] = '\0';
	local[sizeof local - 1] = '\0';
	if (local[0] && strcmp (host, local) == 0) return 1;
	if (ba_policy_name_ok (host, 1)) return 1;
	return ba_policy_name_ok (host, 0) && host[0] != '%';
}

typedef int (*ba_policy_record_cb) (void *arg, const char *record);

struct ba_policy_parse_ctx {
	mbedtls_sha256_context sha;
	int sha_ready;
	int suppress_output;
	ba_policy_record_cb record_cb;
	void *record_arg;
};

static void
ba_policy_hex (const unsigned char *in, size_t n, char *out)
{
	static const char hexdigits[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) {
		out[i * 2] = hexdigits[in[i] >> 4];
		out[i * 2 + 1] = hexdigits[in[i] & 0x0f];
	}
	out[n * 2] = '\0';
}

static int
ba_policy_emit (struct ba_policy_parse_ctx *ctx, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	va_list aq;
	va_copy (aq, ap);
	int need = vsnprintf (NULL, 0, fmt, aq);
	va_end (aq);
	if (need < 0) {
		va_end (ap);
		return -1;
	}
	char *buf = malloc ((size_t) need + 1);
	if (!buf) {
		va_end (ap);
		return -1;
	}
	vsnprintf (buf, (size_t) need + 1, fmt, ap);
	va_end (ap);
	if (ctx && ctx->record_cb && ctx->record_cb (ctx->record_arg, buf) < 0) {
		free (buf);
		return -1;
	}
	if (!ctx || !ctx->suppress_output)
		puts (buf);
	if (ctx && ctx->sha_ready) {
		if (mbedtls_sha256_update (&ctx->sha, (const unsigned char *) buf,
		                           (size_t) need) != 0 ||
		    mbedtls_sha256_update (&ctx->sha, (const unsigned char *) "\n", 1) != 0) {
			free (buf);
			return -1;
		}
	}
	free (buf);
	return 0;
}

static int
ba_policy_parse_alias (struct ba_policy_parse_ctx *ctx,
                       const char *kind, char *line, unsigned int lineno)
{
	char *name = line + strlen (kind);
	name = ba_policy_trim (name);
	char *eq = strchr (name, '=');
	if (!eq) {
		builtin_error ("policy-parse:%u: alias missing '='", lineno);
		return -1;
	}
	*eq++ = '\0';
	name = ba_policy_trim (name);
	char *values = ba_policy_trim (eq);
	char normalized_values[256];
	if (!ba_policy_name_ok (name, 1)) {
		builtin_error ("policy-parse:%u: invalid alias name", lineno);
		return -1;
	}
	char *copy = strdup (values);
	if (!copy) return -1;
	int command = strcmp (kind, "Cmnd_Alias") == 0;
	int ok = ba_policy_list_ok (copy, command);
	free (copy);
	if (!ok) {
		builtin_error ("policy-parse:%u: invalid alias list", lineno);
		return -1;
	}
	if (command) {
		if (ba_policy_normalize_command_list (values, normalized_values,
		                                      sizeof normalized_values) < 0) {
			builtin_error ("policy-parse:%u: invalid alias list", lineno);
			return -1;
		}
		values = normalized_values;
	}
	return ba_policy_emit (ctx, "alias type=%s name=%s values=%s",
	                       kind, name, values);
}

enum ba_policy_default_bind_kind {
	BA_POLICY_DEFAULT_BIND_GLOBAL = 0,
	BA_POLICY_DEFAULT_BIND_USER,
	BA_POLICY_DEFAULT_BIND_HOST,
	BA_POLICY_DEFAULT_BIND_RUNAS,
	BA_POLICY_DEFAULT_BIND_CMND
};

static const char *
ba_policy_default_bind_name (enum ba_policy_default_bind_kind bind_kind)
{
	switch (bind_kind) {
	case BA_POLICY_DEFAULT_BIND_USER: return "user";
	case BA_POLICY_DEFAULT_BIND_HOST: return "host";
	case BA_POLICY_DEFAULT_BIND_RUNAS: return "runas";
	case BA_POLICY_DEFAULT_BIND_CMND: return "cmnd";
	default: return "global";
	}
}

static int
ba_policy_default_scope_ok (enum ba_policy_default_bind_kind bind_kind,
                            const char *scope)
{
	if (!scope || !*scope)
		return 0;
	switch (bind_kind) {
	case BA_POLICY_DEFAULT_BIND_USER:
	case BA_POLICY_DEFAULT_BIND_RUNAS:
		return ba_policy_value_ok (scope, 0);
	case BA_POLICY_DEFAULT_BIND_HOST:
		return ba_policy_host_ok (scope);
	case BA_POLICY_DEFAULT_BIND_CMND:
		return ba_policy_name_ok (scope, 1);
	default:
		return strcmp (scope, "global") == 0;
	}
}

static int
ba_policy_default_key_boolean (const char *key)
{
	return strcmp (key, "requiretty") == 0 || strcmp (key, "env_reset") == 0;
}

static int
ba_policy_emit_default (struct ba_policy_parse_ctx *ctx,
                        enum ba_policy_default_bind_kind bind_kind,
                        const char *scope, const char *key, const char *op,
                        const char *value)
{
	if (bind_kind != BA_POLICY_DEFAULT_BIND_GLOBAL) {
		const char *bind = ba_policy_default_bind_name (bind_kind);
		if (strcmp (op, "=") != 0)
			return ba_policy_emit (ctx,
			                       "defaults scope=%s key=%s op=%s value=%s bind=%s bind_scope=%s",
			                       scope, key, op, value, bind, scope);
		return ba_policy_emit (ctx,
		                       "defaults scope=%s key=%s value=%s bind=%s bind_scope=%s",
		                       scope, key, value, bind, scope);
	}
	if (strcmp (op, "=") != 0)
		return ba_policy_emit (ctx, "defaults scope=%s key=%s op=%s value=%s",
		                       scope, key, op, value);
	return ba_policy_emit (ctx, "defaults scope=%s key=%s value=%s",
	                       scope, key, value);
}

static int
ba_policy_parse_defaults (struct ba_policy_parse_ctx *ctx,
                          char *line, unsigned int lineno)
{
	char *p = line + 8;
	enum ba_policy_default_bind_kind bind_kind = BA_POLICY_DEFAULT_BIND_GLOBAL;
	char *scope = "global";
	if (*p == ':' || *p == '@' || *p == '>' || *p == '!') {
		char sigil = *p;

		*p++ = '\0';
		scope = p;
		while (*p && !isspace ((unsigned char) *p)) p++;
		if (*p) *p++ = '\0';
		if (sigil == ':')
			bind_kind = BA_POLICY_DEFAULT_BIND_USER;
		else if (sigil == '@')
			bind_kind = BA_POLICY_DEFAULT_BIND_HOST;
		else if (sigil == '>')
			bind_kind = BA_POLICY_DEFAULT_BIND_RUNAS;
		else
			bind_kind = BA_POLICY_DEFAULT_BIND_CMND;
		if (!ba_policy_default_scope_ok (bind_kind, scope)) {
			builtin_error ("policy-parse:%u: invalid Defaults scope", lineno);
			return -1;
		}
	}
	p = ba_policy_trim (p);
	if (!*p) {
		builtin_error ("policy-parse:%u: Defaults requires assignment", lineno);
		return -1;
	}
	int negated = 0;
	if (*p == '!') {
		negated = 1;
		p = ba_policy_trim (p + 1);
		if (!*p) {
			builtin_error ("policy-parse:%u: Defaults requires assignment", lineno);
			return -1;
		}
	}
	char *eq = strchr (p, '=');
	const char *op = "=";
	char *key;
	char *value;
	char bool_buf[6];
	if (eq) {
		if (negated) {
			builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
		*eq++ = '\0';
		key = ba_policy_trim (p);
		size_t keylen = strlen (key);
		while (keylen > 0 && isspace ((unsigned char) key[keylen - 1]))
			key[--keylen] = '\0';
		if (keylen > 0 && (key[keylen - 1] == '+' || key[keylen - 1] == '-')) {
			op = key[keylen - 1] == '+' ? "+=" : "-=";
			key[--keylen] = '\0';
			while (keylen > 0 && isspace ((unsigned char) key[keylen - 1]))
				key[--keylen] = '\0';
		}
		value = ba_policy_trim (eq);
	} else {
		key = ba_policy_trim (p);
		size_t keylen = strlen (key);
		while (keylen > 0 && isspace ((unsigned char) key[keylen - 1]))
			key[--keylen] = '\0';
		if (!ba_policy_default_key_boolean (key)) {
			builtin_error ("policy-parse:%u: Defaults requires key=value", lineno);
			return -1;
		}
		snprintf (bool_buf, sizeof bool_buf, "%s", negated ? "false" : "true");
		value = bool_buf;
	}
	if (!ba_policy_ident_ok (key) || !*value) {
		builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
		return -1;
	}
	if (strcmp (key, "timestamp_timeout") == 0) {
		if (strcmp (op, "=") != 0 || ba_policy_has_glob_or_negation (value) ||
		    !ba_policy_uint_ok (value)) {
			builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else if (strcmp (key, "passwd_timeout") == 0) {
		if (strcmp (op, "=") != 0 || ba_policy_has_glob_or_negation (value) ||
		    !ba_policy_uint_ok (value)) {
			builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else if (strcmp (key, "env_keep") == 0) {
		if (negated || !eq) {
			builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
		if (!ba_policy_env_list_ok (value)) {
			builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else if (ba_policy_default_key_boolean (key)) {
		const char *normalized = NULL;
		if (strcmp (op, "=") != 0 || !ba_policy_bool_value (value, &normalized)) {
			builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
		value = (char *) normalized;
	} else if (strcmp (key, "secure_path") == 0) {
		if (strcmp (op, "=") != 0 || !eq || !ba_policy_secure_path_ok (value)) {
			builtin_error ("policy-parse:%u: invalid Defaults assignment", lineno);
			return -1;
		}
	} else {
		builtin_error ("policy-parse:%u: unsupported Defaults key", lineno);
		return -1;
	}
	return ba_policy_emit_default (ctx, bind_kind, scope, key, op, value);
}

static int
ba_policy_parse_rule (struct ba_policy_parse_ctx *ctx,
                      char *line, unsigned int lineno)
{
	char *eq = strchr (line, '=');
	if (!eq) {
		builtin_error ("policy-parse:%u: rule missing '='", lineno);
		return -1;
	}
	*eq++ = '\0';
	char *left = ba_policy_trim (line);
	char *right = ba_policy_trim (eq);
	char *save = NULL;
	char *user = strtok_r (left, " \t", &save);
	char *host = strtok_r (NULL, " \t", &save);
	if (!user || !host || strtok_r (NULL, " \t", &save)) {
		builtin_error ("policy-parse:%u: rule left side must be 'user host'", lineno);
		return -1;
	}
	if (!ba_policy_value_ok (user, 0) || !ba_policy_host_ok (host)) {
		builtin_error ("policy-parse:%u: invalid user or host", lineno);
		return -1;
	}
	if (*right != '(') {
		builtin_error ("policy-parse:%u: rule requires '(runas)'", lineno);
		return -1;
	}
	char *closep = strchr (right, ')');
	if (!closep) {
		builtin_error ("policy-parse:%u: unterminated runas list", lineno);
		return -1;
	}
	*closep++ = '\0';
	char *runas = ba_policy_trim (right + 1);
	/* Split the (users:groups) runas spec; a bare (users) has no group half.
	 * Mirrors the kernel parser so offline validation and the normalized
	 * digest agree (the canonical (ALL:ALL) must parse). */
	char *runas_group = strchr (runas, ':');
	if (runas_group) {
		*runas_group++ = '\0';
		runas = ba_policy_trim (runas);
		runas_group = ba_policy_trim (runas_group);
	}
	char *runas_copy = strdup (runas);
	if (!runas_copy) return -1;
	int runas_ok = ba_policy_list_ok (runas_copy, 0);
	free (runas_copy);
	if (!runas_ok) {
		builtin_error ("policy-parse:%u: invalid runas list", lineno);
		return -1;
	}
	if (runas_group) {
		char *group_copy = strdup (runas_group);
		if (!group_copy) return -1;
		int group_ok = ba_policy_list_ok (group_copy, 0);
		free (group_copy);
		if (!group_ok) {
			builtin_error ("policy-parse:%u: invalid runas group list", lineno);
			return -1;
		}
	}
	char *cmds = ba_policy_trim (closep);
	char normalized_cmds[256];
	int nopasswd = 0, setenv = 0;
	for (;;) {
		if (strncmp (cmds, "NOPASSWD:", 9) == 0) { nopasswd = 1; cmds = ba_policy_trim (cmds + 9); continue; }
		if (strncmp (cmds, "SETENV:", 7) == 0) { setenv = 1; cmds = ba_policy_trim (cmds + 7); continue; }
		break;
	}
	char *cmd_copy = strdup (cmds);
	if (!cmd_copy) return -1;
	int cmd_ok = ba_policy_list_ok (cmd_copy, 1);
	free (cmd_copy);
	if (!cmd_ok) {
		builtin_error ("policy-parse:%u: invalid command list", lineno);
		return -1;
	}
	if (ba_policy_normalize_command_list (cmds, normalized_cmds,
	                                      sizeof normalized_cmds) < 0) {
		builtin_error ("policy-parse:%u: invalid command list", lineno);
		return -1;
	}
	/* Emit the group half only when present, matching the kernel parser so a
	 * bare (users) rule keeps its prior normalized digest. */
	if (runas_group)
		return ba_policy_emit (ctx,
		                       "rule user=%s host=%s runas=%s runas_group=%s nopasswd=%d setenv=%d commands=%s",
		                       user, host, runas, runas_group, nopasswd, setenv,
		                       normalized_cmds);
	return ba_policy_emit (ctx,
	                       "rule user=%s host=%s runas=%s nopasswd=%d setenv=%d commands=%s",
	                       user, host, runas, nopasswd, setenv, normalized_cmds);
}

static int
ba_policy_parse_line (struct ba_policy_parse_ctx *ctx,
                      char *line, unsigned int lineno)
{
	char *hash = strchr (line, '#');
	if (hash) *hash = '\0';
	line = ba_policy_trim (line);
	if (!*line) return 0;
	if (line[0] == '@' || strstr (line, "include")) {
		builtin_error ("policy-parse:%u: includes are not supported", lineno);
		return -1;
	}
	if (strncmp (line, "User_Alias", 10) == 0 && isspace ((unsigned char) line[10]))
		return ba_policy_parse_alias (ctx, "User_Alias", line, lineno);
	if (strncmp (line, "Runas_Alias", 11) == 0 && isspace ((unsigned char) line[11]))
		return ba_policy_parse_alias (ctx, "Runas_Alias", line, lineno);
	if (strncmp (line, "Cmnd_Alias", 10) == 0 && isspace ((unsigned char) line[10]))
		return ba_policy_parse_alias (ctx, "Cmnd_Alias", line, lineno);
	if (strncmp (line, "Host_Alias", 10) == 0 && isspace ((unsigned char) line[10]))
		return ba_policy_parse_alias (ctx, "Host_Alias", line, lineno);
	if (strncmp (line, "Defaults", 8) == 0 &&
	    (line[8] == ':' || line[8] == '@' || line[8] == '>' ||
	     line[8] == '!' || isspace ((unsigned char) line[8])))
		return ba_policy_parse_defaults (ctx, line, lineno);
	return ba_policy_parse_rule (ctx, line, lineno);
}

static int
ba_policy_parse_cmd (WORD_LIST *args)
{
	if (!args || !args->word || args->next) {
		builtin_error ("policy-parse: usage: policy-parse FILE");
		return EX_USAGE;
	}
	const char *path = args->word->word;
	FILE *fp = fopen (path, "r");
	if (!fp) {
		builtin_error ("policy-parse: %s: %s", path, strerror (errno));
		return EXECUTION_FAILURE;
	}
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	unsigned int lineno = 0, records = 0;
	int rc = EXECUTION_SUCCESS;
	struct ba_policy_parse_ctx ctx;
	memset (&ctx, 0, sizeof ctx);
	mbedtls_sha256_init (&ctx.sha);
	if (mbedtls_sha256_starts (&ctx.sha, 0) != 0) {
		builtin_error ("policy-parse: sha256 init failed");
		fclose (fp);
		mbedtls_sha256_free (&ctx.sha);
		return EXECUTION_FAILURE;
	}
	ctx.sha_ready = 1;
	while ((n = getline (&line, &cap, fp)) >= 0) {
		(void) n;
		lineno++;
		char *before = line;
		if (ba_policy_parse_line (&ctx, line, lineno) < 0) {
			rc = EXECUTION_FAILURE;
			break;
		}
		if (*ba_policy_trim (before))
			records++;
	}
	free (line);
	if (ferror (fp)) {
		builtin_error ("policy-parse: %s: %s", path, strerror (errno));
		rc = EXECUTION_FAILURE;
	}
	fclose (fp);
	if (rc == EXECUTION_SUCCESS) {
		unsigned char digest[32];
		char hex[65];
		if (mbedtls_sha256_finish (&ctx.sha, digest) != 0) {
			builtin_error ("policy-parse: sha256 finish failed");
			rc = EXECUTION_FAILURE;
		} else {
			ctx.sha_ready = 0;
			ba_policy_hex (digest, sizeof digest, hex);
			printf ("summary records=%u digest_sha256=%s\n", records, hex);
		}
		ba_wipe (digest, sizeof digest);
	}
	mbedtls_sha256_free (&ctx.sha);
	return rc;
}

struct ba_policy_list_alias {
	char *type;
	char *name;
	char *values;
};

struct ba_policy_list_rule {
	char *user;
	char *host;
	char *runas;
	char *runas_group;
	char *commands;
	int nopasswd;
	int setenv;
};

struct ba_policy_list_state {
	struct ba_policy_list_alias *aliases;
	size_t alias_len, alias_cap;
	struct ba_policy_list_rule *rules;
	size_t rule_len, rule_cap;
};

static char *
ba_policy_strndup (const char *s, size_t n)
{
	char *out = malloc (n + 1);
	if (!out) return NULL;
	memcpy (out, s, n);
	out[n] = '\0';
	return out;
}

static char *
ba_policy_record_field_dup (const char *record, const char *key, int rest)
{
	size_t klen = strlen (key);
	const char *p = record;
	while ((p = strstr (p, key)) != NULL) {
		if ((p == record || isspace ((unsigned char) p[-1])) && p[klen] == '=') {
			const char *v = p + klen + 1;
			const char *e = v;
			if (rest) {
				e = record + strlen (record);
			} else {
				while (*e && !isspace ((unsigned char) *e))
					e++;
			}
			return ba_policy_strndup (v, (size_t) (e - v));
		}
		p += klen;
	}
	return NULL;
}

static int
ba_policy_list_add_alias (struct ba_policy_list_state *st,
                          char *type, char *name, char *values)
{
	if (st->alias_len == st->alias_cap) {
		size_t ncap = st->alias_cap ? st->alias_cap * 2 : 8;
		struct ba_policy_list_alias *na =
			realloc (st->aliases, ncap * sizeof *st->aliases);
		if (!na) return -1;
		st->aliases = na;
		st->alias_cap = ncap;
	}
	st->aliases[st->alias_len++] =
		(struct ba_policy_list_alias) { type, name, values };
	return 0;
}

static int
ba_policy_list_add_rule (struct ba_policy_list_state *st,
                         char *user, char *host, char *runas,
                         char *runas_group, char *commands,
                         int nopasswd, int setenv)
{
	if (st->rule_len == st->rule_cap) {
		size_t ncap = st->rule_cap ? st->rule_cap * 2 : 8;
		struct ba_policy_list_rule *nr =
			realloc (st->rules, ncap * sizeof *st->rules);
		if (!nr) return -1;
		st->rules = nr;
		st->rule_cap = ncap;
	}
	st->rules[st->rule_len++] =
		(struct ba_policy_list_rule) { user, host, runas, runas_group,
		                               commands, nopasswd, setenv };
	return 0;
}

static void
ba_policy_list_free (struct ba_policy_list_state *st)
{
	for (size_t i = 0; i < st->alias_len; i++) {
		free (st->aliases[i].type);
		free (st->aliases[i].name);
		free (st->aliases[i].values);
	}
	for (size_t i = 0; i < st->rule_len; i++) {
		free (st->rules[i].user);
		free (st->rules[i].host);
		free (st->rules[i].runas);
		free (st->rules[i].runas_group);
		free (st->rules[i].commands);
	}
	free (st->aliases);
	free (st->rules);
}

static int
ba_policy_list_collect (void *arg, const char *record)
{
	struct ba_policy_list_state *st = arg;
	if (strncmp (record, "alias ", 6) == 0) {
		char *type = ba_policy_record_field_dup (record, "type", 0);
		char *name = ba_policy_record_field_dup (record, "name", 0);
		char *values = ba_policy_record_field_dup (record, "values", 1);
		if (!type || !name || !values ||
		    ba_policy_list_add_alias (st, type, name, values) < 0) {
			free (type); free (name); free (values);
			return -1;
		}
		return 0;
	}
	if (strncmp (record, "rule ", 5) == 0) {
		char *user = ba_policy_record_field_dup (record, "user", 0);
		char *host = ba_policy_record_field_dup (record, "host", 0);
		char *runas = ba_policy_record_field_dup (record, "runas", 0);
		char *runas_group = ba_policy_record_field_dup (record, "runas_group", 0);
		char *nopasswd_s = ba_policy_record_field_dup (record, "nopasswd", 0);
		char *setenv_s = ba_policy_record_field_dup (record, "setenv", 0);
		char *commands = ba_policy_record_field_dup (record, "commands", 1);
		if (!user || !host || !runas || !nopasswd_s || !setenv_s || !commands ||
		    ba_policy_list_add_rule (st, user, host, runas, runas_group,
		                             commands, atoi (nopasswd_s), atoi (setenv_s)) < 0) {
			free (user); free (host); free (runas); free (runas_group);
			free (commands);
			free (nopasswd_s); free (setenv_s);
			return -1;
		}
		free (nopasswd_s);
		free (setenv_s);
		return 0;
	}
	return 0;
}

static const char *
ba_policy_list_alias_values (const struct ba_policy_list_state *st,
                             const char *type, const char *name)
{
	for (size_t i = 0; i < st->alias_len; i++)
		if (strcmp (st->aliases[i].type, type) == 0 &&
		    strcmp (st->aliases[i].name, name) == 0)
			return st->aliases[i].values;
	return NULL;
}

static int
ba_policy_append_piece (char **outp, const char *piece)
{
	if (!piece || !*piece) return 0;
	if (!*outp) {
		*outp = strdup (piece);
		return *outp ? 0 : -1;
	}
	size_t olen = strlen (*outp), plen = strlen (piece);
	char *n = realloc (*outp, olen + 1 + plen + 1);
	if (!n) return -1;
	n[olen] = ',';
	memcpy (n + olen + 1, piece, plen + 1);
	*outp = n;
	return 0;
}

static char *
ba_policy_expand_alias_list (const struct ba_policy_list_state *st,
                             const char *alias_type, const char *list,
                             unsigned int depth)
{
	if (depth > 8)
		return strdup (list ? list : "");
	char *copy = strdup (list ? list : "");
	if (!copy) return NULL;
	char *out = NULL, *save = NULL;
	for (char *tok = strtok_r (copy, ",", &save); tok;
	     tok = strtok_r (NULL, ",", &save)) {
		tok = ba_policy_trim (tok);
		const char *values = ba_policy_list_alias_values (st, alias_type, tok);
		if (values) {
			char *expanded = ba_policy_expand_alias_list (st, alias_type,
			                                             values, depth + 1);
			if (!expanded || ba_policy_append_piece (&out, expanded) < 0) {
				free (expanded);
				free (copy);
				free (out);
				return NULL;
			}
			free (expanded);
		} else if (ba_policy_append_piece (&out, tok) < 0) {
			free (copy);
			free (out);
			return NULL;
		}
	}
	free (copy);
	if (!out)
		out = strdup ("");
	return out;
}

static int
ba_policy_subject_in_group (const char *subject, const char *group)
{
	if (!subject || !group || !*group)
		return 0;
	if (*group == '#')
		group++;
	struct group *gr = getgrnam (group);
	struct passwd *pw = getpwnam (subject);
	if (!gr)
		return 0;
	if (pw && pw->pw_gid == gr->gr_gid)
		return 1;
	for (char **m = gr->gr_mem; m && *m; m++)
		if (strcmp (*m, subject) == 0)
			return 1;
	return 0;
}

static int
ba_policy_user_token_matches (const struct ba_policy_list_state *st,
                              const char *tok, const char *subject,
                              unsigned int depth)
{
	if (!tok || !*tok || depth > 8)
		return 0;
	if (strcmp (tok, "ALL") == 0 || strcmp (tok, subject) == 0)
		return 1;
	if (tok[0] == '+')
		return 0;
	if (tok[0] == '%')
		return ba_policy_subject_in_group (subject, tok + 1);
	const char *values = ba_policy_list_alias_values (st, "User_Alias", tok);
	if (!values)
		return 0;
	char *copy = strdup (values);
	if (!copy) return 0;
	int matched = 0;
	char *save = NULL;
	for (char *v = strtok_r (copy, ",", &save); v; v = strtok_r (NULL, ",", &save)) {
		v = ba_policy_trim (v);
		if (ba_policy_user_token_matches (st, v, subject, depth + 1)) {
			matched = 1;
			break;
		}
	}
	free (copy);
	return matched;
}

static FILE *
ba_policy_open_fd_or_file (const char *target, const char *verb)
{
	int all_digits = target && *target;
	for (const char *p = target; p && *p; p++)
		if (!isdigit ((unsigned char) *p))
			all_digits = 0;
	if (all_digits) {
		errno = 0;
		long fdnum = strtol (target, NULL, 10);
		if (errno || fdnum < 0 || fdnum > INT32_MAX) {
			builtin_error ("%s: invalid fd: %s", verb, target);
			return NULL;
		}
		int d = dup ((int) fdnum);
		if (d < 0) {
			builtin_error ("%s: fd %ld: %s", verb, fdnum, strerror (errno));
			return NULL;
		}
		FILE *fp = fdopen (d, "r");
		if (!fp) {
			builtin_error ("%s: fd %ld: %s", verb, fdnum, strerror (errno));
			close (d);
		}
		return fp;
	}
	FILE *fp = fopen (target, "r");
	if (!fp)
		builtin_error ("%s: %s: %s", verb, target, strerror (errno));
	return fp;
}

static int
ba_policy_list_cmd (WORD_LIST *args)
{
	const char *path = NULL, *want_user = NULL;
	int long_mode = 0;
	for (WORD_LIST *a = args; a; a = a->next) {
		const char *w = a->word->word;
		if (strcmp (w, "--long") == 0) {
			long_mode = 1;
		} else if (strcmp (w, "--user") == 0) {
			if (!a->next) {
				builtin_error ("policy-list: --user needs USER");
				return EX_USAGE;
			}
			a = a->next;
			want_user = a->word->word;
		} else if (strncmp (w, "--user=", 7) == 0) {
			want_user = w + 7;
		} else if (!path) {
			path = w;
		} else {
			builtin_error ("policy-list: usage: policy-list FD-or-FILE [--user U] [--long]");
			return EX_USAGE;
		}
	}
	if (!path) {
		builtin_error ("policy-list: usage: policy-list FD-or-FILE [--user U] [--long]");
		return EX_USAGE;
	}

	struct passwd *self = getpwuid (getuid ());
	const char *self_name = self ? self->pw_name : NULL;
	if (!self_name || !*self_name) {
		builtin_error ("policy-list: cannot resolve caller user");
		return EXECUTION_FAILURE;
	}
	const char *subject = want_user && *want_user ? want_user : self_name;
	if (strcmp (subject, self_name) != 0 && geteuid () != 0) {
		builtin_error ("policy-list: --user other-than-self requires root");
		return EXECUTION_FAILURE;
	}

	FILE *fp = ba_policy_open_fd_or_file (path, "policy-list");
	if (!fp)
		return EXECUTION_FAILURE;

	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	unsigned int lineno = 0, records = 0;
	int rc = EXECUTION_SUCCESS;
	struct ba_policy_list_state st;
	memset (&st, 0, sizeof st);
	struct ba_policy_parse_ctx ctx;
	memset (&ctx, 0, sizeof ctx);
	ctx.suppress_output = 1;
	ctx.record_cb = ba_policy_list_collect;
	ctx.record_arg = &st;
	mbedtls_sha256_init (&ctx.sha);
	if (mbedtls_sha256_starts (&ctx.sha, 0) != 0) {
		builtin_error ("policy-list: sha256 init failed");
		fclose (fp);
		mbedtls_sha256_free (&ctx.sha);
		ba_policy_list_free (&st);
		return EXECUTION_FAILURE;
	}
	ctx.sha_ready = 1;
	while ((n = getline (&line, &cap, fp)) >= 0) {
		(void) n;
		lineno++;
		char *before = line;
		if (ba_policy_parse_line (&ctx, line, lineno) < 0) {
			rc = EXECUTION_FAILURE;
			break;
		}
		if (*ba_policy_trim (before))
			records++;
	}
	free (line);
	if (ferror (fp)) {
		builtin_error ("policy-list: %s: %s", path, strerror (errno));
		rc = EXECUTION_FAILURE;
	}
	fclose (fp);

	unsigned char digest[32];
	char hex[65];
	memset (digest, 0, sizeof digest);
	hex[0] = '\0';
	if (rc == EXECUTION_SUCCESS) {
		if (mbedtls_sha256_finish (&ctx.sha, digest) != 0) {
			builtin_error ("policy-list: sha256 finish failed");
			rc = EXECUTION_FAILURE;
		} else {
			ctx.sha_ready = 0;
			ba_policy_hex (digest, sizeof digest, hex);
		}
	}
	mbedtls_sha256_free (&ctx.sha);
	if (rc != EXECUTION_SUCCESS) {
		ba_wipe (digest, sizeof digest);
		ba_policy_list_free (&st);
		return rc;
	}

	unsigned int entries = 0;
	(void) records;
	for (size_t i = 0; i < st.rule_len; i++) {
		struct ba_policy_list_rule *r = &st.rules[i];
		if (!ba_policy_user_token_matches (&st, r->user, subject, 0))
			continue;
		char *runas = ba_policy_expand_alias_list (&st, "Runas_Alias", r->runas, 0);
		char *runas_group = r->runas_group ?
			ba_policy_expand_alias_list (&st, "Runas_Alias", r->runas_group, 0) :
			strdup ("-");
		char *commands = ba_policy_expand_alias_list (&st, "Cmnd_Alias", r->commands, 0);
		if (!runas || !runas_group || !commands) {
			free (runas); free (runas_group); free (commands);
			rc = EXECUTION_FAILURE;
			break;
		}
		if (long_mode) {
			char *copy = strdup (commands);
			if (!copy) {
				free (runas); free (runas_group); free (commands);
				rc = EXECUTION_FAILURE;
				break;
			}
			char *save = NULL;
			for (char *cmd = strtok_r (copy, ",", &save); cmd;
			     cmd = strtok_r (NULL, ",", &save)) {
				cmd = ba_policy_trim (cmd);
				printf ("entry user=%s host=%s runas=%s runas_group=%s nopasswd=%d setenv=%d cmd=%s\n",
				        subject, r->host, runas, runas_group,
				        r->nopasswd, r->setenv, cmd);
				entries++;
			}
			free (copy);
		} else {
			printf ("list user=%s host=%s runas=%s runas_group=%s nopasswd=%d setenv=%d commands=%s\n",
			        subject, r->host, runas, runas_group,
			        r->nopasswd, r->setenv, commands);
			entries++;
		}
		free (runas);
		free (runas_group);
		free (commands);
	}
	if (rc == EXECUTION_SUCCESS)
		printf ("summary entries=%u digest_sha256=%s\n", entries, hex);
	ba_wipe (digest, sizeof digest);
	ba_policy_list_free (&st);
	return rc;
}

static int
ba_policy_fnmatch_cmd (WORD_LIST *args)
{
	if (!args || !args->next || args->next->next) {
		builtin_error ("policy-fnmatch: usage: policy-fnmatch PATTERN PATH");
		return EX_USAGE;
	}
	int matched = ba_policy_fnmatch (args->word->word, args->next->word->word);
	printf ("match=%d\n", matched ? 1 : 0);
	return matched ? EXECUTION_SUCCESS : EXECUTION_FAILURE;
}

/*
 * privcmd-token FD HANDLE — acquire a privilege token for a sealed-secret slot
 * without leaking secrets. The caller has already sealed its authentication
 * material into kernel slot HANDLE via `read-secret` (no password bytes pass
 * through argv, the environment, or Bash variables). This is the client entry
 * point that requests an authority-minted PRIVCMD token bound to that slot.
 *
 * Fail-closed: it returns failure (binding and exporting NOTHING) until the
 * kernel advertises BASHOS_AUTH_FEAT_PRIVCMD and the fd-bound token mint lands.
 * Unlike `verify-login`, it never hex-encodes a token into a Bash variable: a
 * PRIVCMD token's raw bytes stay fd-bound in the kernel and are never visible
 * to a Bash client. The authority-side fd-bound mint that consumes slot HANDLE
 * is gated behind BLOCK_TOKEN_MINT.
 */
static int
ba_privcmd_token_cmd (WORD_LIST *args)
{
	if (!args || !args->next || args->next->next) {
		builtin_error ("privcmd-token: usage: privcmd-token FD HANDLE");
		return EX_USAGE;
	}
	int fd;
	unsigned int handle;
	if (ba_parse_fd (args->word->word, &fd) < 0) {
		builtin_error ("privcmd-token: invalid fd: %s", args->word->word);
		return EX_USAGE;
	}
	if (ba_parse_handle (args->next->word->word, &handle) < 0) {
		builtin_error ("privcmd-token: invalid handle: %s",
		               args->next->word->word);
		return EX_USAGE;
	}
	/* The authority must advertise privcmd support; fail closed otherwise. */
	struct bashos_auth_version v;
	if (ba_privcmd_version_ok (fd, &v) < 0)
		return EXECUTION_FAILURE;
	/*
	 * Authority advertises privcmd, but the fd-bound PRIVCMD token mint that
	 * would consume sealed slot `handle` and keep the raw token in-kernel is
	 * gated behind BLOCK_TOKEN_MINT. Fail closed without minting, exporting,
	 * or binding any token material — no token bytes ever reach the shell.
	 */
	(void) handle;
	builtin_error ("privcmd-token: privilege-token mint not available "
	               "(fd-bound PRIVCMD token mint is gated)");
	return EXECUTION_FAILURE;
}

extern char *auth_doc[];

int
auth_builtin (WORD_LIST *list)
{
	if (!list) { builtin_usage (); return EX_USAGE; }
	const char *cmd = list->word->word;
	if (strcmp (cmd, "--help") == 0 || strcmp (cmd, "-h") == 0 ||
	    strcmp (cmd, "help") == 0) {
	    char **d;
	    for (d = auth_doc; *d; d++) puts (*d);
	    return EXECUTION_SUCCESS;
	}
	WORD_LIST *args = list->next;
	if (strcmp (cmd, "probe")       == 0) return ba_probe_cmd       (args);
	if (strcmp (cmd, "privcmd-probe") == 0) return ba_privcmd_probe_cmd (args);
	if (strcmp (cmd, "privcmd-authz") == 0) return ba_privcmd_authz_cmd (args);
	if (strcmp (cmd, "privcmd-exec") == 0) return ba_privcmd_exec_cmd (args);
	if (strcmp (cmd, "privcmd-handoff-test") == 0) return ba_privcmd_handoff_test_cmd (args);
	if (strcmp (cmd, "privcmd-exec-interactive") == 0) return ba_privcmd_exec_interactive_cmd (args);
	if (strcmp (cmd, "privcmd-interactive-lineage-test") == 0) return ba_privcmd_interactive_lineage_test_cmd (args);
	if (strcmp (cmd, "privcmd-token") == 0) return ba_privcmd_token_cmd (args);
	if (strcmp (cmd, "policy-info") == 0) return ba_policy_info_cmd (args);
	if (strcmp (cmd, "audit-read")  == 0) return ba_audit_read_cmd  (args);
	if (strcmp (cmd, "audit-read-text") == 0) return ba_audit_read_text_cmd (args);
	if (strcmp (cmd, "policy-parse") == 0) return ba_policy_parse_cmd (args);
	if (strcmp (cmd, "policy-list") == 0) return ba_policy_list_cmd (args);
	if (strcmp (cmd, "policy-fnmatch") == 0) return ba_policy_fnmatch_cmd (args);
	if (strcmp (cmd, "open")        == 0) return ba_open_cmd        (args);
	if (strcmp (cmd, "read-secret") == 0) return ba_read_secret_cmd (args);
	if (strcmp (cmd, "clear")       == 0) return ba_clear_cmd       (args);
	if (strcmp (cmd, "same-secret") == 0) return ba_same_secret_cmd (args);
	if (strcmp (cmd, "stats")       == 0) return ba_stats_cmd       (args);
	if (strcmp (cmd, "hash-secret") == 0) return ba_hash_secret_cmd (args);
	if (strcmp (cmd, "verify-login") == 0) return ba_verify_login_cmd (args);
	if (strcmp (cmd, "peruser")     == 0) return ba_peruser_cmd     (args);
	builtin_error ("unknown subcommand: %s (try probe/privcmd-probe/privcmd-authz/privcmd-exec/privcmd-handoff-test/privcmd-exec-interactive/privcmd-interactive-lineage-test/privcmd-token/policy-info/policy-parse/policy-list/policy-fnmatch/open/read-secret/clear/same-secret/stats/hash-secret/verify-login/peruser)", cmd);
	return EX_USAGE;
}

char *auth_doc[] = {
	"Talk to /dev/bashos-auth - kernel-mediated authority tokens.",
	"",
	"    auth probe              print 'abi=MAJOR.MINOR features=0xHEX'",
	"    auth privcmd-probe      require v2 sudo/doas authority support",
	"    auth privcmd-authz FD MODE TARGET_UID TARGET_GID [--] command [args...]",
	"                               request v2 sudo/doas authorization",
	"    auth privcmd-token FD HANDLE",
	"                               acquire a privilege token for sealed slot",
	"                               HANDLE (fd-bound; never exposed to the shell)",
	"    auth policy-info FD     print sudoers policy status/generation",
	"    auth policy-parse FILE  validate and normalize sudoers subset",
	"    auth policy-list FD-or-FILE [--user U] [--long]",
	"                               list caller-filtered sudoers projection",
	"    auth policy-fnmatch PATTERN PATH",
	"                               test mirror command-path glob matching",
	"    auth open FDVAR         open the device, bind fd into FDVAR",
	"    auth read-secret FD [-p PROMPT] HANDLEVAR",
	"                               read a tty secret into a sealed kernel slot",
	"    auth clear FD HANDLE    clear a kernel secret slot",
	"    auth same-secret FD HANDLE_A HANDLE_B",
	"                               compare sealed slots in the kernel",
	"    auth stats FD          print per-fd secret/token counters",
	"    auth hash-secret FD HANDLE SALT_HEX T M P HASHLEN OUTVAR",
	"                               bind an Argon2id PHC string into OUTVAR",
	"    auth verify-login FD HANDLE USER PHC TOKENVAR",
	"                               verify PHC and bind a kernel login token",
	"    auth privcmd-interactive-lineage-test FD MODE UID GID -- CMD [ARG...]",
	"                               test-only: prove interactive minting lineage",
	"    auth peruser bump USER  count a failed attempt for USER",
	"    auth peruser check USER exit 0 under cap; 1 if locked out",
	"    auth peruser reset USER clear USER's counter (call on success)",
	"    auth peruser status USER print 'fails=N locked=0|1 remaining=Ns'",
	"",
	"The fd from `open` owns all secret slots; close it with",
	"`exec {FDVAR}<&-` when done. Closing the fd clears its slots.",
	"",
	"peruser tracks per-user failed-attempt caps independent of the",
	"global login throttle. Env hooks: BASHAUTH_PERUSER_MAX (default 10),",
	"BASHAUTH_PERUSER_COOLDOWN (default 60s). State is process-local.",
	(char *) NULL
};

struct builtin auth_struct = {
	"auth",
	auth_builtin,
	BUILTIN_ENABLED,
	auth_doc,
	"auth probe|privcmd-probe|privcmd-authz|policy-info|policy-parse|policy-list|policy-fnmatch|open FDVAR|read-secret FD [-p PROMPT] HANDLEVAR|clear FD HANDLE|same-secret|stats|hash-secret|verify-login|peruser ...",
	0
};
