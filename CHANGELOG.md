# Changelog

## 0.1.1

- Forward arguments after the loader's `--` to GNU Bash, including through the
  bundled VM, so `-- --version` reports the Bash version.
- Initialize guest stdout and stderr with valid storage so Bash can print
  version information, help and errors before its normal stream setup.
- Recompile Bash and library bitcode when the pinned toolchain or Capsule
  patches change.
- Reject overlapping source and destination trees before source synchronization
  can modify or delete source files.
- Allow longer sandbox test timeouts on slow hosts and retain partial console
  output when a shell test times out.
- `make portable` now publishes its build-host runtime bundle to
  `portable-host/`, so it can no longer replace the pinned x86_64 release
  artifact in `portable/`. Host-runtime targets stop early on non-x86_64 build
  machines.
- Release packaging refuses executables that do not contain the pinned kernel
  and runtime, executables built from content that differs from the release
  commit, and dependency source archives collected from different builds.
  Executables record their build-time source state.
- Published inventories no longer contain local workspace paths, and neither the
  guest initramfs nor the VM test initramfs depends on the builder's umask. With a
  group-writable umask such as `0002`, the VM suites previously staged an untrusted
  `/etc/os-release` and fell back to sandbox mode inside the test VM.
- Dependency archives are verified before use and re-fetched when corrupt;
  extracted trees are keyed by checksum, so version changes never reuse an old
  tree. Interrupted sysroot and kernel preparation is never reported as complete.
- `make clean` removes only a recognizable lashos build tree, and test harnesses
  refuse work directories that are not dedicated to them. `test-vm.py` always
  stops its VM on interrupts and errors.
- Make fails loudly instead of silently dropping dependencies when build inputs
  cannot be listed or have names Make cannot track; ripgrep is no longer required,
  and Make paths may contain `@` and `+`. Native reference builds are refreshed
  when the pinned toolchain changes.
- Fix guest memory corruption from guest/host structure mismatches: `statvfs`
  and `fstatvfs` overran Bash's buffer by 24 bytes (`df`, `lsblk`, SFTP),
  `realpath` could write past a 1024-byte caller buffer (`stat`), and on ARM64
  and RISC-V64 `epoll_wait`, `semctl` status records and `timeval`-based calls
  used the wrong layout. Every structure still passed through unconverted now
  has build-time size checks on both sides.
- Guest signal handlers no longer re-enter for their own signal or `sa_mask`
  while running, and `SA_RESETHAND` is honoured.
- `select` and `pselect` accept all 256 logical descriptors; `munmap` and
  `mremap` handle partial ranges; `sleep` returns the unslept time; `errno` is
  preserved by successful calls; `statx` and other `AT_*` flags are translated,
  and unknown flags return `EINVAL`; `posix_spawn` default-signal and same-fd
  duplication actions match glibc.
- The host rejects out-of-range signal numbers before indexing its handler table.
- The sandboxed QEMU can no longer create UNIX or netlink sockets, and offline
  VMs cannot create IP sockets or TCP connections. The private runtime directory
  is never placed on a noexec filesystem or where the launch folder can reach it
  through bind mounts.
- The guest can no longer grow host files through its serial console: VM logs
  are bounded in-memory tails, printed only when the launcher fails, so a script
  that exits 125 no longer prints VM diagnostics.
- The launcher never makes the caller's standard streams non-blocking, cleans up
  on termination signals received during startup and on more signals overall,
  and supports `SIGTSTP`/`SIGCONT`. Idle hang-ups no longer busy-loop the
  launcher or guest init.
- The bundled Linux 6.18.52 kernels carry `linux-vmalloc-inline-purge.patch`,
  a defensive fix for a Linux deadlock between BPF program freeing and vmalloc
  purging. The deadlock hung fork-heavy direct-mode tests on the Debian 6.12
  kernel. It did not reproduce on 6.18.52 under fork-storm stress, and the
  patched kernel passed that stress and the production sandbox, guest-runtime
  and architecture suites. Host kernels used by direct mode keep the upstream
  behavior.
- The VM test init dumps every blocked task, workqueue function and CPU
  backtrace when kernel Bash stops making progress.
- Guest and loader builds remap source paths, so `__FILE__` strings and debug
  records in the shipped image and executables name `/lashos/...` instead of the
  build machine's directories. Published inventories already record
  workspace-relative labels, so identical sources no longer produce different
  bytes on different machines.

## 0.1.0

- GNU Bash 5.3.15 and all 279 selected bash-os builtins compiled into an eBPF image.
- Pipelines, subshells, command and process substitution, coprocesses, background
  jobs, external commands, and terminal job control through the Linux bridge.
- Self-contained Linux executables for x86_64, ARM64 and RISC-V64, with a matching
  kernel, QEMU, guest tools, runtime libraries and firmware bundled in each file.
- Hosted launches use a KVM sandbox with the working directory at `/home`, an
  ephemeral guest root, and outbound networking by default. Trusted installed
  lashos systems select direct execution.
- Pinned cross-compilers, runtime package inventories, kernel build recipes,
  architecture tests and checksum generation. Build and agent files stay in an
  external workspace; optional machine configuration stays outside the checkout.

This is an experimental release. Native plugins and worker threads remain
deferred. KVM and Landlock ABI 6 are required for hosted launches. ARM64 requires
LSE atomics, and RISC-V requires Zacas. x86_64 is the primary tested target;
ARM64 and RISC-V64 builds are explicitly experimental. Exact dependency sources,
patches and build recipes accompany the executables. See
[COMPATIBILITY.md](COMPATIBILITY.md) and the [release notes](docs/releases/0.1.0.md)
for the supported and tested boundaries.
