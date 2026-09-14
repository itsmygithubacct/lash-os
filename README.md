# lashos

GNU Bash 5.3.15 and the **279 builtins in bash-os's full profile**, compiled to
eBPF with BPF Capsule. Bash parsing, expansion, evaluation, builtin algorithms,
and their linked C libraries execute through the Linux kernel JIT. A userspace
loader handles requested operating-system calls and resumes the Bash fiber.

The project vendors a pinned snapshot of [bash-os](https://github.com/itsmygithubacct/bash-os),
recorded in [SOURCE.json](SOURCE.json). It follows the architecture described in
[Doom in the Kernel, or fibers in eBPF](https://ayles.github.io/doom-in-kernel/)
and uses [BPF Capsule](https://github.com/ayles/bpf-capsule). All required bash-os build inputs are included in this repository.

## Workspace and local configuration

The Git checkout contains release source, tests, build recipes, licenses and
public documentation. Builds do not write into it. The default locations are:

| Location | Contents |
| --- | --- |
| `~/projects/lash-os/lashos` | Release Git checkout; it can also be cloned elsewhere |
| `~/research/projects/lash-os/lashos` | Build trees, downloads, executables, test reports and development research |
| `~/.local/projects/lash-os/lashos/config.json` | Optional settings for this machine |

`make paths` prints the resolved locations. Inside the research workspace,
`build/` holds intermediate files, `out/` holds executables, `downloads/` caches
verified sources, and `reports/` holds new test results. `make clean` removes
only the build tree; executables, downloads and reports are retained.

No local configuration is required for the default paths. To customize them:

```sh
mkdir -p ~/.local/projects/lash-os/lashos
cp config/local.example.json ~/.local/projects/lash-os/lashos/config.json
```

The JSON accepts `research`, `build`, `output`, `downloads`, `reports`,
`source_cache`, `kernel`, `modules` and `qemu` path settings. Relative paths
resolve beside the configuration file; `~` expands to the home directory.
`kernel` defaults to `/boot/vmlinuz-$(uname -r)`, `modules` to the matching
`/lib/modules` directory, and `qemu` to `/usr/bin/qemu-system-x86_64`. Select a
readable kernel with matching modules if the running kernel is unavailable.
`source_cache` optionally seeds checksum-verified downloads from another directory.

`LASHOS_CONFIG` selects a different JSON file. Environment overrides take
precedence: `LASHOS_RESEARCH_DIR`, `LASHOS_BUILD_DIR`, `LASHOS_OUTPUT_DIR`,
`LASHOS_DOWNLOADS_DIR`, `LASHOS_REPORTS_DIR`, `LASHOS_SOURCE_CACHE`,
`LASHOS_KERNEL`, `LASHOS_MODULES` and `LASHOS_QEMU`. Use distinct external
workspaces when building multiple checkouts concurrently. Output directories
must stay outside the checkout, and Make paths must contain only letters,
digits, underscores, dots, slashes and dashes.

Editing the local JSON causes the next build to repack the VM bundle. Use
`make bundle` to explicitly repack after changing environment overrides or
updating the selected kernel, modules or QEMU installation.

Build configuration is used only when building or testing. A copied portable
executable runs without the checkout, research workspace or local JSON file.

## Build and run

```sh
make
LASHOS_OUT="$(python3 -B scripts/workspace.py --get output)"
"$LASHOS_OUT/linux-bash-os" --stats -c 'printf "%s on %s\n" "$BASH_VERSION" "$MACHTYPE"'
"$LASHOS_OUT/linux-bash-os"                 # interactive Bash in a VM
"$LASHOS_OUT/linux-bash-os" script.sh arg1
```

On another operating system, both published executables default to a bundled
KVM virtual machine. The directory you launch from becomes writable `/home`;
Bash starts there with `HOME=/home`. The remaining guest filesystem is temporary.
The VM has **2 virtual CPUs, 4 GiB RAM, and outbound networking by default**.

Run as an ordinary user with access to `/dev/kvm`. Use the binary matching the
host CPU: x86_64, ARM64 (`aarch64`), or RISC-V64 (`riscv64`). The host needs Linux
with hardware virtualization, KVM, and Landlock ABI 6 (normally Linux 6.12 or
later with Landlock enabled). It needs an executable temporary filesystem at
`/tmp` or `/var/tmp` outside the exported folder. Missing requirements stop
startup. There is no automatic fallback to direct host execution or software
CPU emulation. For compatibility with earlier commands, `sudo` is accepted when its invoking
UID and GID match a nonroot passwd entry; the launcher drops to that account
before starting the VM. Otherwise, launch directly as an ordinary user.

```sh
"$LASHOS_OUT/linux-bash-os" --sandbox-network=none  # offline
"$LASHOS_OUT/linux-bash-os" --sandbox-memory=8192 --sandbox-cpus=4 script.sh
"$LASHOS_OUT/linux-bash-os" --help
```

Networking uses QEMU's user-mode NAT, with no inbound port forwards. The guest
can reach the Internet, the host's network, and host services through `10.0.2.2`.
Guest `localhost` refers to the guest. `--sandbox-network=none` omits its network
adapter. This is filesystem and process isolation, not a network destination
filter. The launch folder is shared read/write using virtio-9p; changes there
persist with the invoking host user's permissions. Do not share a folder whose
contents the guest should not access. Sharing the host root `/` is refused.

The launcher starts QEMU without host root privileges or Linux capabilities,
sets `no_new_privs`, enables [QEMU's seccomp restrictions](https://www.qemu.org/docs/master/system/security.html),
and applies [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
rules for the exported folder, private runtime, KVM device, and required system
information. It exports no host disks or other directories. The guest has its
own kernel and process tree; BPF-loading privileges remain inside that VM.
The VM and its jobs end when the main shell exits. Private runtime files are
removed on normal exit and handled termination signals. A host crash or
`SIGKILL` can leave a private `lash-os-*` temporary directory behind.

The build uses Nix, pinned LLVM/Capsule sources, and checksum-verified GNU Bash
and library downloads. Building the VM bundle additionally uses the build
machine's QEMU, kernel and matching modules, BusyBox, SeaBIOS, and `zstd`.
Package versions, input hashes, source locations, and
license notices are included in the bundle; the output JSON records its inventory.
`scripts/build-sandbox.py --kernel PATH --modules DIRECTORY --qemu PATH` selects
other compatible build inputs. Rebuild the bundle to incorporate kernel or QEMU
updates; a copied executable retains the versions it contains.

The first build includes the compiler. Subsequent builds reuse the native
source inventory and bitcode. Changes under `vendor/bash-os/` refresh the
isolated native source copy for each profile. `make pure` builds the smaller 28-builtin
profile for direct execution with `--host`; it does not bundle a VM.

The executable embeds its BPF object; `$LASHOS_OUT/bash.bpf.o` is retained for inspection.
BTF type and function information and linked/lowered bitcode checkpoints remain
available for diagnosis. CMake's `LINUX_BASH_DETAILED_DEBUG=ON` enables more detail.
Local compiler and runtime patches are explained in [patches/README.md](patches/README.md).
The verifier remains enabled, and the runtime requires no custom kernel module.

## Portable executable

```sh
make portable
LASHOS_OUT="$(python3 -B scripts/workspace.py --get output)"
cp "$LASHOS_OUT/portable/linux-bash-os" /path/to/my-folder/lash-os
cd /path/to/my-folder
./lash-os
./lash-os ./script.sh arg1
```

`$LASHOS_OUT/portable/linux-bash-os` is a single x86_64 Linux executable. It
statically links the outer loader with musl, libbpf, libelf, zlib and
zstd, and includes the VM runtime, its library closure and firmware, Linux,
and the guest filesystem. The guest contains the same full eBPF Bash image,
all 279 selected builtins, and BusyBox external tools. Nix, QEMU, shared-library
packages, and a host kernel with eBPF arena support are not needed at the
destination. The host KVM, Landlock, and temporary-filesystem requirements above
still apply. The executables target Linux.

Build the three architectures from an x86_64 or ARM64 Linux build machine:

```sh
make portable-all
# Or select one target:
make portable-x86_64
make portable-aarch64
make portable-riscv64
```

These targets build Linux 6.18.52 from the checksum-pinned source and fetch
checksum-pinned Debian 13 runtime packages into isolated sysroots. They do not
install those packages on the build host. Build tools, including cross-compilers,
QEMU emulators and `dpkg-deb`, come from the pinned Nix development shells.
`KERNEL_JOBS=4` controls compilation parallelism per kernel. All downloads,
sysroots, kernel trees, intermediates and outputs use the external workspace.

| Target | Portable output relative to `$LASHOS_OUT` |
| --- | --- |
| x86_64 | `portable/linux-bash-os` |
| ARM64 | `portable-aarch64/linux-bash-os` |
| RISC-V64 | `portable-riscv64/linux-bash-os` |

Each output is one executable with its matching QEMU, kernel and guest tools;
it runs the same architecture-independent eBPF Bash image. `--version` reports
the lashos release and target without starting a VM. Use `-- --version` to pass
that option to GNU Bash. ARM64 requires LSE atomics and uses 4 KiB guest pages;
RISC-V requires Zacas atomics. The host CPU and KVM must expose those extensions
to the VM. Native KVM and confinement must be
validated on each destination architecture; emulated guest tests alone do not
establish those properties.

The original `make portable` target still bundles the configured x86_64 build
host kernel and runtime. Use `make portable-x86_64` for the pinned release runtime.
Maintainers refresh package locks with `scripts/prepare-runtime.py --arch ARCH
--update-lock`, using authenticated Debian APT metadata; normal builds use the
checked-in locks in [config/runtime](config/runtime).

`make release-candidates` builds all three and collects versioned executables,
inventories and `SHA256SUMS` under `$LASHOS_OUT/releases/0.1.0/`. For existing
builds, run `scripts/dev.py python3 -B scripts/package-release.py`. This collects
local files; publishing a tagged release is a separate step.

The adjacent `portable.json` is an optional inventory, not a runtime dependency.
The regular executable in `$LASHOS_OUT/linux-bash-os` includes the same VM bundle but
its outer loader still needs its Nix runtime libraries. Guest configuration
includes its own root account, DNS settings, and a bundled CA certificate set.
Host environment variables and extra file descriptors are not passed into the
VM; `TERM` and standard input/output/error are transported explicitly. Pipe
input streams with EOF, stdout and stderr stay separate, and the guest's exit
status is returned. When all three standard streams are terminals, the launcher
provides a guest PTY with job control and window-size updates. Mixed terminal
and redirected streams use pipes; redirected streams do not retain seekability.

```sh
make test-sandbox
python3 -B scripts/elf_dependencies.py "$LASHOS_OUT/portable/linux-bash-os"
```

The sandbox suite copies and renames the actual portable artifact into a folder
with spaces and commas. It checks the guest kernel and filesystem, shared-file
persistence, builtin registration, shell processes, outbound HTTP/DNS, offline
mode, binary streaming, terminal jobs, fail-closed startup, and cleanup.
Reports go to the external workspace's `reports/sandbox/` directory.

## Installed OS and direct host mode

An installed lash-os system defaults to direct execution when its trusted
`/etc/os-release` (or `/usr/lib/os-release`) contains `ID=linux-bash-os`.
The file must be a regular root-owned file without group or other write access.
The installer can use [config/os-release](config/os-release) inside its OS image.
Building or running this project never changes the workstation's OS identity.
A folder marker or environment variable cannot select installed mode.

`--sandbox` explicitly requests the VM. `--host` explicitly runs directly in the
current kernel, with that system's filesystem, process tree, networking,
environment, and inherited descriptors 0–255. Direct mode requires BPF-loading
privileges and a kernel with BPF syscall programs, arena maps, JIT and BTF.
These flags cannot be combined. Sandbox tuning options imply a VM and cannot
be combined with `--host`.

```sh
sudo "$LASHOS_OUT/portable/linux-bash-os" --host -c 'printf "%s\n" "$MACHTYPE"'
sudo "$LASHOS_OUT/portable/linux-bash-os" --host --mount-cwd
```

In direct mode, `--mount-cwd` retains its earlier behavior: it recursively
bind-mounts the launch directory at `/home` in a private mount namespace,
sets `HOME=/home` and `PWD=/home`, and clears `OLDPWD`. It requires `CAP_SYS_ADMIN`
and an existing directory at `/home`. Other host paths remain accessible.
In sandbox mode the launch directory is already shared at `/home`, so
`--mount-cwd` is accepted without an additional mount.

Loader options precede Bash arguments. Use `--` to pass a script whose name
matches a loader option. Bash runs with `--noprofile --norc`; `--stats` reports
kernel execution statistics. Direct mode retains the caller's environment and
supplies `LC_ALL=C` and a kernel Bash prompt. Sandbox mode uses its guest environment.

`make test-portable`, `make test-portable-processes`, `make test-mount-cwd`, and
`make test-portable-mount-cwd` test direct execution inside dedicated test VMs.
The portable variants remove `/nix` before kernel cases. Their OS identity selects
direct execution and avoids nesting another VM.

## Processes and jobs

Pipelines, command substitution, subshells, background jobs, `wait`, process
substitution, and coprocesses use real Linux processes and pipes. Each Bash
child gets independent arena memory and a continuation at the same virtual
addresses. `exec` installs the logical file descriptors into the native process;
failed execution restores the loader's descriptors before returning to Bash.
External programs execute their ordinary native binaries.

```bash
printf 'pear\napple\n' | sort | head -n 1
result=$(printf 'hello from a child')
( value=child; printf '%s\n' "$value" )
sleep 1 &
wait "$!"
```

Interactive job control uses the controlling terminal and Linux process groups.
Signal handlers queue delivery to Bash at continuation and shell polling points.
Two Capsule fibers are reserved per process: one runs Bash and one services
short allocator requests from the bridge. This does not enable worker threads.

## Compatibility

All selected builtin names are listed in [config/builtin-names](config/builtin-names).
They use the vendored bash-os implementations, including their existing subset
limitations. Inclusion in the image is distinct from functional test coverage.
See [COMPATIBILITY.md](COMPATIBILITY.md) for bridge boundaries and limitations.

Optional native `.so` plugins and library worker threads are deferred. Loading native plugins or starting worker threads returns an explicit
unsupported error. Libraries needed by the regular full profile are compiled
into the eBPF image.

The loader currently provides 256 logical file descriptors, 64 directory
streams, a 64 MiB heap, and a 2 MiB stack per fiber. Fork copies and verifies a
new Capsule image, so process creation is considerably more expensive than
native Bash. Loading the full image can take tens of seconds;
ordinary commands run after that initial verification.
`LINUX_BASH_MAX_STEPS=N` optionally limits continuation invocations;
zero or an unset variable leaves the session unbounded. `LINUX_BASH_TRACE=1`
prints bridge operation numbers for diagnostics.

## Verify in an isolated VM

```sh
make test-vm
make test-host
make test-processes
make test-mlkem
make test-sha1dc
python3 -B tests/reachability-equivalence.py
```

The VM uses KVM and a readable local kernel, with no host disk, network adapter,
or filesystem sharing. It needs `qemu-system-x86_64`, `busybox`, `script`, a C
compiler, and access to `/dev/kvm`. The HTTP fixture uses only VM loopback.
The full suite allocates 8 GiB to accommodate simultaneous shell children;
the smaller compiler regressions use 2 GiB. The VM script accepts `--memory`
in MiB for other configurations.
Override the kernel with `scripts/test-vm.py --kernel /path/to/bzImage`.

Tests compare native and kernel output, check all 279 builtin registrations,
exercise representative text, JSON, archive, compression, hashing, database,
filesystem, process and network operations, and drive a real pseudoterminal
through stop/background/foreground/interrupt/trap transitions. They do not use
a native Bash fallback for kernel cases. Reports in the external workspace's `reports/vm/` contain the
kernel path, object hash, individual checks, and serial output.

The process regression pins execution to each of the VM's two CPUs, checking
fork before and after resolver allocations with either Capsule fiber ID,
external descriptor cleanup, and repeated recovery from failed `exec` calls.
The host regressions check queued and delayed signals across waits and polls,
mixed valid and invalid poll entries, inherited descriptors, and source-tree
refresh and rebuild dependencies. They require no BPF privileges or VM.

The separate ML-KEM regression compares deterministic native and kernel key
generation, encapsulation, and decapsulation. It exercises the compiler's
handling of large generated functions and arena-pointer spills.
The SHA-1 regression checks padding-boundary vectors and the generated collision
checks used by `obj`, `pack`, and `index`, including branch continuation behavior.

`make verify` runs the isolated VM suite. See [docs/TESTING.md](docs/TESTING.md)
for the test commands and coverage boundaries. Generated results are kept outside
the release checkout.

## Source layout

| Path | Purpose |
| --- | --- |
| `vendor/bash-os/` | Pinned original profiles, builtins, and build system |
| `scripts/prepare-bash.py` | Native reference and guest configuration |
| `scripts/compile-bash.py`, `compile-deps.py` | Bash and dependency bitcode |
| `scripts/build-portable.py`, `cmake/portable/` | Static musl loader using the full embedded image |
| `src/bash_bpf.c` | Kernel entry and continuation programs |
| `src/bridge_guest.c`, guest headers | Checked RPC calls and libc adaptation |
| `src/host.c`, host headers | Loader and Linux I/O services |
| `src/process_host.h`, `vendor/capsule-host/` | Independent process state |
| `src/paths_host.h` | Logical descriptor paths and standard stream aliases |
| `include/kernel_control.h` | Mailbox and explicit ABI structures |
| `scripts/generate-posix.py`, `generate-raw.py` | Reproducible adapter definitions |
| `tests/` | Native/kernel parity and terminal integration tests |

The combined Bash program is GPL-3.0-or-later; see [LICENSE](LICENSE). Vendored
sources retain their upstream notices, including the musl compatibility code
and Capsule's Apache-2.0-with-LLVM-exception/GPL-2.0 notices.
