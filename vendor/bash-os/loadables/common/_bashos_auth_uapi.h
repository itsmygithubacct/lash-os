/* SPDX-License-Identifier: MIT */
/* _bashos_auth_uapi.h - flattened userspace mirror of the bashos-auth UAPI.
 *
 * SOURCE OF TRUTH: kernel/bashos-auth/uapi/linux/bashos_auth.h
 *
 * This file is a userspace-consumable copy of the kernel UAPI header for
 * /dev/bashos-auth, restructured for bash loadables that build outside the
 * kernel tree and may run on guest images whose <linux/bashos_auth.h> is
 * older than the kernel module they talk to.
 *
 * Generated: 2026-05-26.
 *
 * Underscore prefix follows the established convention for vendored /
 * project-internal flattened headers in this directory
 * (see _mbedtls_*.h, _monocypher_*.h, _bashauth_*.h).
 *
 * The kernel UAPI header is the authority. Every struct, ioctl, and
 * constant in this file is byte-for-byte equivalent to its counterpart
 * in the kernel file; any divergence is a compile-time signal that this
 * mirror is out of date and must be regenerated from the kernel UAPI.
 *
 * BASHOS_AUTH_FEAT_PRIVCMD: advertised by the kernel when
 * bashos_auth_privcmd_backend_ready() is true — i.e. privcmd_enable=1 (the
 * default since the 2026-06-02 ship flip) with the readiness blockers retired.
 * The shipped image still grants nothing by configuration (no /etc/sudoers
 * rules + /dev/bashos-auth is 0600 root-only); see BASHSUDO-FLIP-SIGNOFF.md.
 * Userspace probes the live bit via BASHOS_AUTH_IOC_VERSION.features; do not
 * change the constant value without an ABI-level review.
 */

#ifndef _BASHOS_AUTH_UAPI_H_
#define _BASHOS_AUTH_UAPI_H_

#include <linux/types.h>
#include <sys/ioctl.h>

#define BASHOS_AUTH_ABI_MAJOR  1u
/* 5u: 1.1 AUTH_REQUIRED + auth-channel ioctls, 1.2 AUDIT_READ + audit_read_req,
 * 1.3 SUDOEDIT EXEC_HANDOFF fields, 1.4 AUDIT_READ_TEXT (0x13) +
 * audit_read_text_req, 1.5 multi-target sudoedit (sudoedit_temp_fds vector carved
 * from reserved[3]) — all mirrored below. Kept in lockstep with the kernel UAPI
 * header (kernel/bashos-auth/uapi/linux/bashos_auth.h). */
#define BASHOS_AUTH_ABI_MINOR  5u

/* Feature bits returned by BASHOS_AUTH_IOC_VERSION.features. */
#define BASHOS_AUTH_FEAT_NONE     0u
#define BASHOS_AUTH_FEAT_SECRETS  (1ull << 0)
#define BASHOS_AUTH_FEAT_TOKENS   (1ull << 1)
#define BASHOS_AUTH_FEAT_STATS    (1ull << 2)
#define BASHOS_AUTH_FEAT_PRIVCMD  (1ull << 3) /* v2 sudo/doas authority */

#define BASHOS_AUTH_TOKEN_BYTES   32u
#define BASHOS_AUTH_USER_BYTES    64u
#define BASHOS_AUTH_TOKEN_LOGIN   1u
#define BASHOS_AUTH_TOKEN_SU      2u
#define BASHOS_AUTH_TOKEN_PRIVCMD 3u

#define BASHOS_AUTH_PATH_BYTES    256u
#define BASHOS_AUTH_REASON_BYTES  128u
#define BASHOS_AUTH_DIGEST_BYTES  32u

#define BASHOS_AUTH_POLICY_STATUS_OK       0u
#define BASHOS_AUTH_POLICY_STATUS_MISSING  1u
#define BASHOS_AUTH_POLICY_STATUS_UNSAFE   2u
#define BASHOS_AUTH_POLICY_STATUS_ERROR    3u

#define BASHOS_AUTH_PRIVCMD_MODE_EXEC            1u
#define BASHOS_AUTH_PRIVCMD_MODE_SHELL           2u
#define BASHOS_AUTH_PRIVCMD_MODE_LOGIN           3u
#define BASHOS_AUTH_PRIVCMD_MODE_VALIDATE        4u
#define BASHOS_AUTH_PRIVCMD_MODE_RESET_TIMESTAMP 5u
#define BASHOS_AUTH_PRIVCMD_MODE_SUDOEDIT        6u

#define BASHOS_AUTH_PRIVCMD_FLAG_RESET_ALL       (1u << 0)
#define BASHOS_AUTH_PRIVCMD_FLAG_EXPLICIT_GROUP  (1u << 1)

#define BASHOS_AUTH_PRIVCMD_DECISION_DENY        1u
#define BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EXEC  2u
#define BASHOS_AUTH_PRIVCMD_DECISION_ALLOW_EDIT  3u
#define BASHOS_AUTH_PRIVCMD_DECISION_RESET_OK    4u
#define BASHOS_AUTH_PRIVCMD_DECISION_VALIDATE_OK 5u
#define BASHOS_AUTH_PRIVCMD_DECISION_AUTH_REQUIRED 6u

#define BASHOS_AUTH_ENV_POLICY_SCRUB_DEFAULT     (1u << 0)
#define BASHOS_AUTH_ENV_POLICY_PRESERVE_SAFE     (1u << 1)
#define BASHOS_AUTH_ENV_POLICY_ALLOW_KEEPENV     (1u << 2)
#define BASHOS_AUTH_ENV_POLICY_ALLOW_SETENV      (1u << 3)

#define BASHOS_AUTH_AUDIT_EVENT_VERSION          1u
#define BASHOS_AUTH_AUDIT_OUTCOME_DENY           1u
#define BASHOS_AUTH_AUDIT_OUTCOME_ALLOW_EXEC     2u
#define BASHOS_AUTH_AUDIT_OUTCOME_ALLOW_EDIT     3u
#define BASHOS_AUTH_AUDIT_OUTCOME_VALIDATE_OK    4u
#define BASHOS_AUTH_AUDIT_OUTCOME_RESET_OK       5u
#define BASHOS_AUTH_AUDIT_OUTCOME_MALFORMED      6u
#define BASHOS_AUTH_AUDIT_OUTCOME_AUTH_FAILURE   7u
#define BASHOS_AUTH_AUDIT_OUTCOME_TIMESTAMP_MISS 8u
#define BASHOS_AUTH_AUDIT_OUTCOME_TOKEN_REJECT   9u
#define BASHOS_AUTH_AUDIT_OUTCOME_HANDOFF_FAIL   10u
#define BASHOS_AUTH_AUDIT_OUTCOME_AUDIT_FAIL     11u

#define BASHOS_AUTH_TIMESTAMP_KEY_VERSION        1u
#define BASHOS_AUTH_TIMESTAMP_SCOPE_TTY          1u
#define BASHOS_AUTH_TIMESTAMP_SCOPE_SESSION      2u
#define BASHOS_AUTH_TIMESTAMP_SCOPE_GLOBAL       3u

/*
 * Live trusted handoff binding for a single-use exec/edit token.
 *
 * This is kernel-owned token-store state, not an ioctl payload. PRIVCMD_AUTHZ
 * mints it on an allow, and EXEC_HANDOFF / EXEC_INTERACTIVE revalidate and
 * consume it through an opaque handle id. Raw exec_token bytes stay inside
 * /dev/bashos-auth; Bash clients receive only handle_id + expiry metadata.
 */
#define BASHOS_AUTH_EXEC_BINDING_VERSION 1u
#define BASHOS_AUTH_EXEC_BIND_GROUPS_GENERATION (1ull << 0)
#define BASHOS_AUTH_EXEC_BIND_GROUPS_DIGEST     (1ull << 1)

#define BASHOS_AUTH_HANDOFF_HANDLE_VERSION 1u
#define BASHOS_AUTH_HANDOFF_HANDLE_EXEC    1u
#define BASHOS_AUTH_HANDOFF_HANDLE_EDIT    2u

#define BASHOS_AUTH_EXEC_REJECT_REPLAY               1u
#define BASHOS_AUTH_EXEC_REJECT_EXPIRED              2u
#define BASHOS_AUTH_EXEC_REJECT_TOKEN_MISMATCH       3u
#define BASHOS_AUTH_EXEC_REJECT_REQUEST_MISMATCH     4u
#define BASHOS_AUTH_EXEC_REJECT_TARGET_MISMATCH      5u
#define BASHOS_AUTH_EXEC_REJECT_CWD_MISMATCH         6u
#define BASHOS_AUTH_EXEC_REJECT_MODE_MISMATCH        7u
#define BASHOS_AUTH_EXEC_REJECT_POLICY_GENERATION    8u
#define BASHOS_AUTH_EXEC_REJECT_TIMESTAMP_GENERATION 9u
#define BASHOS_AUTH_EXEC_REJECT_GROUPS_MISMATCH      10u
#define BASHOS_AUTH_EXEC_REJECT_LINEAGE              11u /* interactive: redeemer != minting task */

struct bashos_auth_version {
	__u32 abi_major;
	__u32 abi_minor;
	__u64 features;
	__u8  reserved[16];   /* zero on read; future ABI-additive fields */
};

struct bashos_auth_handle {
	__u32 id;
	__u32 flags;
};

struct bashos_auth_secret_write {
	__u32 id;
	__u32 len;
	__u64 user_ptr;
};

struct bashos_auth_secret_export {
	__u32 id;
	__u32 len;
	__u64 user_ptr;
};

struct bashos_auth_secret_compare {
	__u32 id_a;
	__u32 id_b;
	__u32 result;
	__u32 flags;
};

struct bashos_auth_token_req {
	__u32 uid;
	__u32 gid;
	__u32 purpose;
	__u32 expires_sec;
	__u8  token[BASHOS_AUTH_TOKEN_BYTES];
	char  user[BASHOS_AUTH_USER_BYTES];
	__u32 flags;
	__u32 reserved;
};

struct bashos_auth_stats {
	__u64 created_secrets;
	__u64 cleared_secrets;
	__u64 refused_exports;
	__u64 minted_tokens;
	__u64 consumed_tokens;
	__u64 expired_tokens;
	__u64 reserved[10];
};

struct bashos_auth_exec_binding {
	__u32 size;             /* set to sizeof(struct bashos_auth_exec_binding) */
	__u32 version;          /* BASHOS_AUTH_EXEC_BINDING_VERSION */
	__u64 flags;            /* BASHOS_AUTH_EXEC_BIND_* */
	__u32 caller_uid;
	__u32 caller_gid;
	__u32 target_uid;
	__u32 target_gid;
	__u32 mode;             /* BASHOS_AUTH_PRIVCMD_MODE_* */
	__u32 argc;
	__u32 envc;
	__u32 policy_generation;
	__u32 timestamp_generation;
	__u32 reserved0;
	__u64 expires_sec;
	__u64 session_id;
	__u64 tty_rdev;
	__u64 supplementary_groups_generation;
	__u8  exec_token[BASHOS_AUTH_TOKEN_BYTES];
	__u8  request_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  argv_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  env_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  cwd_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  supplementary_groups_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u64 reserved[8];
};

/*
 * Live fd-bound trusted handoff handle descriptor.
 *
 * Userspace receives an opaque handle tied to the authority fd, while raw
 * exec/edit token bytes stay inside /dev/bashos-auth and never cross argv,
 * environment, logs, diagnostics, Bash variables, or shell-visible strings.
 * BASHOS_AUTH_IOC_EXEC_HANDOFF validates this descriptor against the binding
 * digest before any trusted executor/edit transition.
 */
struct bashos_auth_handoff_handle {
	__u32 size;             /* set to sizeof(struct bashos_auth_handoff_handle) */
	__u32 version;          /* BASHOS_AUTH_HANDOFF_HANDLE_VERSION */
	__u32 type;             /* BASHOS_AUTH_HANDOFF_HANDLE_* */
	__u32 flags;
	__u64 handle_id;
	__u64 authority_fd_generation;
	__u64 expires_sec;
	__u8  binding_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  policy_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  normalized_policy_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u64 reserved[8];
};

/* Trusted-handoff exec request (mirrors the kernel UAPI). The client presents
 * the OPAQUE handle (handle.handle_id) + re-presented argv; never token bytes. */
struct bashos_auth_exec_handoff_req {
	__u32 size;
	__u32 mode;             /* BASHOS_AUTH_EXEC_HANDOFF_MODE_* */
	__u32 flags;            /* BASHOS_AUTH_EXEC_HANDOFF_FLAG_* (was reserved/zero) */
	__u32 argc;
	struct bashos_auth_handoff_handle handle;
	__u64 argv_user_ptr;
	__u32 argv_bytes;
	__u32 exit_code;        /* out */
	__u32 approval_status;  /* out: BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_* */
	__u32 interactive_eligible; /* out */
	__u32 reject_stage;     /* out */
	__u32 reserved0;
	/* SUDOEDIT live integration (ABI 1.3 additive, carved from reserved[6];
	 * offset- and sizeof()-stable). See the kernel UAPI header for the contract. */
	__u32 sudoedit_temp_fd;        /* in (COPYBACK): caller fd of the edited temp */
	__u32 sudoedit_temp_count;     /* out (OPEN): number of temp paths written */
	__u64 sudoedit_temp_paths_user_ptr; /* in/out (OPEN): NUL-separated temp paths buf */
	__u32 sudoedit_temp_paths_cap; /* in (OPEN): bytes available at the buffer */
	__u32 sudoedit_temp_paths_bytes; /* out (OPEN): bytes written */
	/* Multi-target sudoedit (ABI 1.5 additive, carved from reserved[3]; byte-stable). */
	__u64 sudoedit_temp_fds_user_ptr; /* in (COPYBACK): caller array of N __u32 edited-temp fds */
	__u32 sudoedit_temp_fds_count;    /* in (COPYBACK): N (== argc); 0 -> legacy single fd */
	__u32 sudoedit_temp_fds_reserved; /* pad; must be 0 */
	__u64 reserved[1];
};

#define BASHOS_AUTH_EXEC_HANDOFF_MODE_NONINTERACTIVE   1u
#define BASHOS_AUTH_EXEC_HANDOFF_MODE_INTERACTIVE      2u
#define BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_ALLOWED      1u
#define BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_DENIED       2u
#define BASHOS_AUTH_EXEC_HANDOFF_APPROVAL_FORCED_UMH   3u

/* EDIT-handle-only SUDOEDIT two-call protocol selectors (ABI 1.3 additive). */
#define BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_OPEN     (1u << 0)
#define BASHOS_AUTH_EXEC_HANDOFF_FLAG_SUDOEDIT_COPYBACK (1u << 1)

/*
 * Future authority-owned audit event payload.
 *
 * No ioctl exports this structure in ABI v1.0. It is reserved so every future
 * accepted, denied, malformed, token-rejected, handoff-failed, or audit-failed
 * privilege-command request can bind the same audit id, policy tuple, mode,
 * request digest, cwd digest, command path, timestamp-cache outcome, and
 * environment-policy summary without logging passwords, raw tokens, argv bytes,
 * environment bytes, or user pointers.
 */
struct bashos_auth_privcmd_audit_event {
	__u32 size;             /* set to sizeof(struct bashos_auth_privcmd_audit_event) */
	__u32 version;          /* BASHOS_AUTH_AUDIT_EVENT_VERSION */
	__u64 audit_id;
	__u32 outcome;          /* BASHOS_AUTH_AUDIT_OUTCOME_* */
	__u32 mode;             /* BASHOS_AUTH_PRIVCMD_MODE_* */
	__u32 caller_uid;
	__u32 caller_gid;
	__u32 target_uid;
	__u32 target_gid;
	__u32 policy_generation;
	__u32 policy_status;    /* BASHOS_AUTH_POLICY_STATUS_* */
	__u32 env_policy;       /* BASHOS_AUTH_ENV_POLICY_* summary bits */
	__u32 rule_index;
	__u32 timestamp_cache_hit;
	__u64 session_id;
	__u64 tty_rdev;
	__u8  request_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  argv_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  env_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  cwd_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  policy_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  normalized_policy_digest[BASHOS_AUTH_DIGEST_BYTES];
	char  command_path[BASHOS_AUTH_PATH_BYTES];
	char  cwd[BASHOS_AUTH_PATH_BYTES];
	char  reason[BASHOS_AUTH_REASON_BYTES];
	__u64 reserved[8];
};

/*
 * Future authority-owned sudo-like timestamp cache key.
 *
 * No ioctl consumes or exports this structure in ABI v1.0. It is reserved so
 * validate, reset, NOPASSWD, and password-required decisions can later bind
 * timestamp cache entries to the caller, target, tty/session scope, policy
 * generation, normalized policy digest, and authority-owned generation without
 * creating Bash-visible timestamp files, variables, or token material.
 */
struct bashos_auth_timestamp_key {
	__u32 size;             /* set to sizeof(struct bashos_auth_timestamp_key) */
	__u32 version;          /* BASHOS_AUTH_TIMESTAMP_KEY_VERSION */
	__u32 scope;            /* BASHOS_AUTH_TIMESTAMP_SCOPE_* */
	__u32 flags;
	__u32 caller_uid;
	__u32 caller_gid;
	__u32 target_uid;
	__u32 target_gid;
	__u32 policy_generation;
	__u32 timestamp_generation;
	__u32 timeout_sec;
	__u32 reserved0;
	__u64 session_id;
	__u64 tty_rdev;
	__u64 expires_sec;
	__u8  policy_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  normalized_policy_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  request_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u64 reserved[8];
};

struct bashos_auth_privcmd {
	__u32 size;             /* set to sizeof(struct bashos_auth_privcmd) */
	__u32 mode;             /* BASHOS_AUTH_PRIVCMD_MODE_* */
	__u32 flags;
	__u32 non_interactive;
	__u32 caller_uid;
	__u32 caller_gid;
	__u32 target_uid;
	__u32 target_gid;
	__u32 argc;
	__u32 envc;
	__u32 argv_bytes;
	__u32 env_bytes;
	__u64 argv_user_ptr;    /* NUL-separated argv blob */
	__u64 env_user_ptr;     /* NUL-separated requested env blob */
	__u8  auth_token[BASHOS_AUTH_TOKEN_BYTES];
	__u8  request_digest[32];
	char  caller_user[BASHOS_AUTH_USER_BYTES];
	char  target_user[BASHOS_AUTH_USER_BYTES];
	char  cwd[BASHOS_AUTH_PATH_BYTES];

	/* Response fields. The authority fills these before returning 0. */
	__u32 decision;         /* BASHOS_AUTH_PRIVCMD_DECISION_* */
	__u32 env_policy;
	__u32 timestamp_timeout;
	__u32 policy_generation;
	__u32 policy_status;    /* BASHOS_AUTH_POLICY_STATUS_* */
	__u32 reserved0;
	__u64 audit_id;
	__u8  exec_token[BASHOS_AUTH_TOKEN_BYTES];
	__u8  policy_digest[32];
	__u8  normalized_policy_digest[32];
	char  reason[BASHOS_AUTH_REASON_BYTES];
	/* Opaque handle transport (carved from reserved, offset-stable; mirrors the
	 * kernel UAPI). exec_token stays zero — the handle_id is the only transport. */
	__u64 handle_id;
	__u64 handle_expires_sec;
	__u64 reserved[6];
};

struct bashos_auth_policy_info {
	__u32 size;             /* set to sizeof(struct bashos_auth_policy_info) */
	__u32 status;           /* BASHOS_AUTH_POLICY_STATUS_* */
	__u32 mode;
	__u32 uid;
	__u32 gid;
	__u64 ino;
	__u64 size_bytes;
	__s64 mtime_sec;
	__s64 ctime_sec;
	__u32 generation;
	__u32 reserved0;
	__u8  policy_digest[32];
	__u8  normalized_policy_digest[32];
	char  path[BASHOS_AUTH_PATH_BYTES];
	char  reason[BASHOS_AUTH_REASON_BYTES];
};

struct bashos_auth_exec_verify_req {
	__u32 size;             /* set to sizeof(struct bashos_auth_exec_verify_req) */
	__u32 flags;            /* reserved, must be 0 */
	__u32 mode;             /* BASHOS_AUTH_PRIVCMD_MODE_* */
	__u32 caller_uid;
	__u32 caller_gid;
	__u32 target_uid;
	__u32 target_gid;
	__u32 policy_generation;
	__u32 timestamp_generation; /* response: live generation bound to pending */
	__u32 timeout_sec;      /* 0 => validate but do not cache */
	__u32 policy_status;    /* BASHOS_AUTH_POLICY_STATUS_* */
	__u32 reserved0;
	__u8  request_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u8  normalized_policy_digest[BASHOS_AUTH_DIGEST_BYTES];
	__u64 reserved[8];
};

struct bashos_auth_timestamp_mint_req {
	__u32 size;             /* set to sizeof(struct bashos_auth_timestamp_mint_req) */
	__u32 flags;            /* reserved, must be 0 */
	__u32 reject_stage;     /* response: BASHOS_AUTH_EXEC_REJECT_* or 0 */
	__u32 reserved0;
	__u64 reserved[8];
};

struct bashos_auth_verify_failure_req {
	__u32 size;             /* set to sizeof(struct bashos_auth_verify_failure_req) */
	__u32 flags;            /* reserved, must be 0 */
	__u32 failed_attempts;  /* attempts to add to throttle, must be >= 1 */
	__u32 reserved0;
	__u64 reserved[8];
};

#define BASHOS_AUTH_IOC_MAGIC  0xBA

#define BASHOS_AUTH_IOC_VERSION \
	_IOR(BASHOS_AUTH_IOC_MAGIC, 0x01, struct bashos_auth_version)
#define BASHOS_AUTH_IOC_NEW_SECRET \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x02, struct bashos_auth_handle)
#define BASHOS_AUTH_IOC_WRITE_SECRET \
	_IOW(BASHOS_AUTH_IOC_MAGIC, 0x03, struct bashos_auth_secret_write)
#define BASHOS_AUTH_IOC_SEAL_SECRET \
	_IOW(BASHOS_AUTH_IOC_MAGIC, 0x04, struct bashos_auth_handle)
#define BASHOS_AUTH_IOC_CLEAR_SECRET \
	_IOW(BASHOS_AUTH_IOC_MAGIC, 0x05, struct bashos_auth_handle)
#define BASHOS_AUTH_IOC_EXPORT_ONCE \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x06, struct bashos_auth_secret_export)
#define BASHOS_AUTH_IOC_SAME_SECRET \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x07, struct bashos_auth_secret_compare)
#define BASHOS_AUTH_IOC_MINT_TOKEN \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x08, struct bashos_auth_token_req)
#define BASHOS_AUTH_IOC_CONSUME_TOKEN \
	_IOW(BASHOS_AUTH_IOC_MAGIC, 0x09, struct bashos_auth_token_req)
#define BASHOS_AUTH_IOC_STATS \
	_IOR(BASHOS_AUTH_IOC_MAGIC, 0x0a, struct bashos_auth_stats)
#define BASHOS_AUTH_IOC_PRIVCMD_AUTHZ \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x0b, struct bashos_auth_privcmd)
#define BASHOS_AUTH_IOC_POLICY_INFO \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x0c, struct bashos_auth_policy_info)
#define BASHOS_AUTH_IOC_EXEC_HANDOFF \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x0d, struct bashos_auth_exec_handoff_req)
/* Interactive (tty) in-context elevation — see kernel UAPI. Mode must be
 * BASHOS_AUTH_EXEC_HANDOFF_MODE_INTERACTIVE; behind privcmd_interactive_enable. */
#define BASHOS_AUTH_IOC_EXEC_INTERACTIVE \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x0e, struct bashos_auth_exec_handoff_req)
#define BASHOS_AUTH_IOC_EXEC_VERIFY \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x0f, struct bashos_auth_exec_verify_req)
#define BASHOS_AUTH_IOC_MINT_TIMESTAMP \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x10, struct bashos_auth_timestamp_mint_req)
#define BASHOS_AUTH_IOC_NOTE_VERIFY_FAILURE \
	_IOW(BASHOS_AUTH_IOC_MAGIC, 0x11, struct bashos_auth_verify_failure_req)

/*
 * Operator audit retrieval (ABI 1.2 additive). A CAP_SYS_ADMIN reader drains the
 * authority's module-global bounded audit ring oldest-first. The per-record
 * payload (the in-kernel audit metadata layout) is intentionally NOT published
 * here so it can evolve additively — the first root-readable proof path reads
 * only the published counters below (returned_count/total_written/dropped); a
 * full record decoder would couple userspace to the unpublished layout. Mirror
 * of the kernel struct bashos_auth_audit_read_req.
 */
struct bashos_auth_audit_read_req {
	__u32 size;             /* sizeof(struct bashos_auth_audit_read_req) */
	__u32 max_count;        /* in: max records to return (1-64) */
	__u32 returned_count;   /* out: records copied to records_ptr */
	__u32 reserved0;
	__u64 cursor;           /* in: lifetime offset to start reading from */
	__u64 next_cursor;      /* out: next cursor for pagination */
	__u64 records_ptr;      /* in: user ptr to record buffer */
	__u64 dropped;          /* out: records overwritten by ring wrap (lifetime) */
	__u64 total_written;    /* out: lifetime audit-record count */
	__u64 reserved[5];
};
#define BASHOS_AUTH_IOC_AUDIT_READ \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x12, struct bashos_auth_audit_read_req)

/*
 * AUDIT_READ_TEXT (0x13, ABI 1.4 additive) — mirror of the kernel struct/IOC.
 * In-kernel projection of each audit record to the published fmt=v1 kind=event
 * TEXT; the verb relays the ASCII verbatim and never decodes the binary record.
 * Read-only, CAP_SYS_ADMIN-only. request_hash is a per-boot-keyed HMAC.
 */
#define BASHOS_AUTH_AUDIT_TEXT_LINE_MIN 320u  /* >= worst-case full line + NUL */
#define BASHOS_AUTH_AUDIT_TEXT_LINE_MAX 512u  /* hard per-record line cap incl '\n' */
#define BASHOS_AUTH_AUDIT_TEXT_BUF_MAX  (64u * BASHOS_AUTH_AUDIT_TEXT_LINE_MAX) /* 32768 */

struct bashos_auth_audit_read_text_req {
	__u32 size;            /* in:  sizeof(struct bashos_auth_audit_read_text_req) */
	__u32 max_count;       /* in:  max records to project this call (1..64) */
	__u32 returned_count;  /* out: records actually projected into buf */
	__u32 line_cap;        /* in:  max bytes per projected line incl '\n' (LINE_MIN..LINE_MAX) */
	__u64 cursor;          /* in:  lifetime absolute index to start from */
	__u64 next_cursor;     /* out: next absolute index to resume from (paging) */
	__u64 buf_ptr;         /* in:  user ptr to char buffer receiving text */
	__u64 buf_cap;         /* in:  capacity of buf in bytes (LINE_MAX..BUF_MAX) */
	__u64 bytes_written;   /* out: bytes written into buf (sum of lines, no NUL) */
	__u64 dropped;         /* out: records overwritten by ring wrap (lifetime) */
	__u64 total_written;   /* out: lifetime audit-record count */
	__u64 reserved[5];     /* in:  MUST be 0 (forward-compat tail) */
};
#define BASHOS_AUTH_IOC_AUDIT_READ_TEXT \
	_IOWR(BASHOS_AUTH_IOC_MAGIC, 0x13, struct bashos_auth_audit_read_text_req)

#endif /* _BASHOS_AUTH_UAPI_H_ */
