# Changelog

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
