# Compatibility boundaries

This is an experimental userspace-assisted kernel port, not a replacement for
the Linux POSIX process ABI. All 279 selected bash-os builtins are included in
the build; their existing source-level feature subsets still apply. Runtime
verification covers the cases in `tests/`, not every option of every builtin.

For 0.1.0, x86_64 is the primary tested target; ARM64 and RISC-V64 are experimental.
The production sandbox suite passed on x86_64. ARM64 passed native guest process,
network and terminal job cases, but still needs production sandbox validation
on a host supporting Landlock ABI 6. RISC-V64 passed emulated kernel/JIT and
guest smoke checks; native KVM, production host confinement, and complete
process/job tests remain unverified. See the [release notes](docs/releases/0.1.0.md).

Hosted launches default to a bundled KVM VM matching the executable's x86_64,
ARM64 or RISC-V64 architecture. The portable executable
includes its Linux kernel, userspace, QEMU and runtime libraries. The regular
outer loader still uses its Nix libraries. Sandbox mode requires KVM access,
Landlock ABI 6, and an executable temporary filesystem; it does not require
BPF privileges on the host. Missing isolation facilities fail startup.
`--host` selects direct execution explicitly; a trusted installed lash-os OS
identity selects it automatically. See [README.md](README.md) for mode selection.

Cross-architecture guest tests use full-system emulation and execute real eBPF
inside the target Linux kernel. They do not validate KVM or host confinement on
physical ARM64 or RISC-V64 machines. The ARM64 arena JIT requires LSE atomics;
the LL/SC fallback cannot handle arena atomic operations. The RISC-V arena JIT requires Zacas for
compare-and-exchange atomics; older RISC-V CPUs without that extension cannot
run this image. KVM must expose the required atomic extension to the guest.
The pinned ARM64 guest uses 4 KiB pages.
The RISC-V kernel build omits optional BTF global-variable records because the
pinned toolchain emits overlapping per-CPU offsets. BTF types, function
prototypes, kfunc metadata and kernel verification remain enabled.
Its RV64 JIT emits zero-extension operations directly, avoiding the verifier's
costly instruction-array expansion on large programs. Its JIT address window
is expanded to 1 GiB for the image and process snapshots. See [patches/README.md](patches/README.md).

Sandbox mode shares the launch folder read/write as `/home`, uses a temporary
guest root, and enables outbound NAT without inbound forwards. Internet, LAN,
and host services are reachable by default; `--sandbox-network=none` removes
the network adapter. Files in the shared folder retain the host user's access
permissions. This does not impose a storage quota on that folder. The VM gets
2 CPUs and 4 GiB RAM by default; QEMU's host address space is also limited.
Guest root authority is confined by the VM boundary, which depends on the
bundled QEMU and kernel as well as the host KVM implementation.

Only standard input/output/error and terminal settings cross the console
transport. Extra caller descriptors, host environment variables other than
`TERM`, host executables, accounts and devices are not inherited by the guest.
A PTY is used when all three standard descriptors are terminals; otherwise they
become streaming pipes, so host regular-file stdin is not seekable in the guest.
The main shell's exit ends all guest jobs. Optional plugins and worker threads
remain deferred in both execution modes.

Standard input has a one-byte stdio buffer, preserving the stream position
across commands that share descriptor 0. Redirected `sort`, implicit AWK input,
and pipelines into `sort` are covered by the regression suites; see
[docs/TESTING.md](docs/TESTING.md).

| Area | Implementation and boundary |
| --- | --- |
| Shell language | Real GNU Bash parser/evaluator, arrays, functions, expansions, redirections, Readline/history and job-control code |
| Starting directory | Sandbox: launch folder shared at `/home` automatically. Direct mode: optional `--mount-cwd` recursively bind-mounts the launch directory at `/home` in a private mount namespace and starts there with `HOME=/home`; children inherit the view, writes affect the original files, and other host paths remain accessible. Requires mount-namespace privileges and an existing directory at `/home`. |
| Processes | Independent Capsule snapshots and real Linux PIDs, pipes, process groups, signals, waits, and external `execve` |
| Files | Logical descriptors 0–255, including caller-inherited descriptors and their flags in direct mode; stat/directory ABI conversion; ownership, permissions, links, timestamps, xattrs, advisory locks, and ordinary I/O |
| Networking | Native socket I/O through the bridge; explicit message/iovec conversion; descriptor translation for SCM_RIGHTS; resolver results allocated in the Capsule arena |
| Libraries | Compiled C implementations of SQLite, mbedTLS/libssh, tree-sitter, PCRE2, zlib, zstd, xz and bzip2 as selected by the original project |
| Plugins and workers | Native `.so` loading and `pthread_create`/join are deferred; single-thread library mutex primitives remain available |
| Mappings | Arena-backed anonymous/private mappings and file copies; shared file mappings, executable mappings, and fixed-address remapping are unsupported |
| Device controls | Encoded buffer ioctls and selected terminal/network controls; ioctl interfaces containing further pointers need explicit marshalling and may return unsupported |
| System controls | Explicitly translated Linux operations; Linux capabilities, namespaces, seccomp, filesystem and device availability still determine whether a call succeeds |

The bridge uses Picolibc plus selected musl headers and portable functions, not
native glibc inside the kernel. It translates open/at flags, error numbers,
clocks, signals and structures where the ABIs differ. Locale is C; the default
libc local-time implementation is UTC. Some `sysconf`, path-configuration,
signal-info, ioctl and SysV IPC variants remain limited.

Raw syscall requests carry stable guest identifiers. The host maps its supported
calls to native syscall numbers after validating pointers and descriptors;
unknown identifiers return unsupported. Native seccomp profiles still need the
destination kernel's syscall ABI. The ptrace bridge exposes the x86 register
layout only on x86_64; architecture-specific register sets are not translated
for ARM64 or RISC-V64.

Direct `/dev/fd/N`, `/proc/self/fd/N`, and standard stream paths use Bash's
logical descriptor table. Other `/proc` views describe the native loader;
in sandbox mode those processes belong to the guest kernel; direct mode uses the host process tree.

Fork currently verifies a new image in the child. Dropping the privileges needed
to load BPF, entering a user namespace without those privileges, or installing
a seccomp policy that disallows the loader's BPF calls can prevent further
execution or process creation. Resource-limit changes also apply to the loader.
These administrative transitions are not covered by the ordinary shell tests.

Private file mappings are snapshots, not coherent native mappings. SQLite's
vendored builtin uses its documented unix-none VFS; this does not add concurrent
writers or shared-memory WAL support. GPU backends that require native driver
plugins are part of the deferred plugin support.

Signals are delivered to guest callbacks when the main fiber resumes or Bash
polls for them. Realtime signals are coalesced into pending bits; complete
`siginfo_t` event queues and all signal-action corner cases are not implemented.
