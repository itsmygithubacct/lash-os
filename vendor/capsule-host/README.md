# Capsule host loader

These files come from `ayles/bpf-capsule` revision
`6733c4531f06f95a32a35c2084b3dcf1a4263746`, `src/runtime/host` and
`src/runtime/internal`. Their original license notices are retained.

The local change adds `linux_bash_capsule_configure_at`, which reserves a
requested, vacant address window with `MAP_FIXED_NOREPLACE`. A forked host can
load independent maps at the original virtual addresses, preserving pointers
in a Bash memory snapshot. The original `bpf_capsule_configure` API selects a
fresh window as before. Loading and verifier checks are unchanged.
