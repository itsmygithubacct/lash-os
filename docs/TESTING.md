# Testing

Run tests from the checkout. `make paths` shows the external build, output and
report locations. Test logs, VM images and machine-specific inventories belong
in that workspace, outside the release Git tree.

| Command | Coverage |
| --- | --- |
| `make test-workspace` | Local configuration precedence, external output paths, safe cleanup, relocated CMake metadata, source refresh and Make dependencies |
| `make test-host` | Signals, polling, inherited descriptors, launcher policies and workspace tests with the regular host libc |
| `make test-vm` or `make verify` | Native/kernel shell parity, registration of 279 builtins, representative builtin behavior and terminal job control |
| `make test-processes` | Fork state, resolver allocations, descriptor cleanup and recovery after failed execution |
| `make test-portable` | Static musl host tests and full direct-mode VM tests with `/nix` removed |
| `make test-portable-processes` | Process regressions with the portable loader |
| `make test-mount-cwd` | Direct-mode working-directory mounts inside a dedicated VM |
| `make test-portable-mount-cwd` | The same mount checks with the portable loader |
| `make test-sandbox` | The copied, renamed portable executable: shared `/home`, persistence, processes, networking, offline mode, stream transport, terminal jobs, startup policy and cleanup |
| `make test-mlkem` | Deterministic ML-KEM key generation, encapsulation and decapsulation across native and kernel code |
| `make test-sha1dc` | SHA-1 padding vectors and collision-check continuation behavior |
| `python3 -B tests/reachability-equivalence.py` | Compiler reachability transformation equivalence |
| `scripts/dev.py python3 -B scripts/test-architecture.py --arch ARCH` | Extract an actual portable artifact, boot its matching guest kernel and check raw syscall translation plus all 279 builtin registrations |
| `scripts/dev.py python3 -B scripts/test-architecture.py --arch ARCH --full` | Full shell/builtin cases and PTY job-control tests inside that artifact's guest kernel |
| `scripts/dev.py python3 -B scripts/test-guest-runtime.py --arch ARCH` | Production guest init and console protocol, shared home, outbound networking and processes; `--smoke` omits the process cases |

The host C tests need no BPF privileges or VM; their Make targets build the
image first. Existing builds can be tested directly with `scripts/dev.py ctest
--test-dir PATH --output-on-failure` (add `--shell portable` before `ctest` for
the portable build).

`make portable-all` builds static loaders for x86_64, aarch64 and riscv64 and
runs the host tests for each. Cross-compiled host tests use QEMU user emulation.
The architecture boot harness uses KVM when available for the native target and
explicit TCG emulation otherwise. Its reports record that choice and the exact
artifact hash under `reports/architectures/`. TCG tests verify the target kernel,
eBPF image and guest behavior; native KVM and the production launcher's host
confinement require separate testing on a compatible machine. The production
launcher continues to require KVM.
For native targets, the harness runs the QEMU and libraries extracted from the
artifact itself. `--jobs-only` runs the PTY group separately, and `--network-only`
runs the loopback HTTP and post-DNS fork checks. The architecture
harness gives each PTY step up to five minutes for image verification; direct
users of the helper can set `LASHOS_TEST_STEP_TIMEOUT_MS` explicitly.

For the RISC-V kernel's JIT change, build the upstream test module with
`scripts/dev.py python3 -B scripts/build-kernel.py --arch riscv64 --jit-selftest`.
Pass `--jit-selftest PATH/TO/kernel/lib/test_bpf.ko` to the architecture harness
to run Linux's BPF instruction tests before the shell smoke check. The module
must match the bundled kernel and remains a test artifact outside the checkout.

The dedicated VM suites require KVM, QEMU, a readable compatible Linux kernel,
BusyBox, `script`, and a C compiler. They run without host disks, networking or
shared directories. Their installed OS identity selects direct kernel execution.
The full suite uses 8 GiB RAM, while the smaller compiler regressions use 2 GiB.
Use `scripts/test-vm.py --help` for explicit kernel, build, report and memory paths.

The sandbox suite uses the bundled VM and shares its temporary test directory
at `/home`. It needs the same host KVM, Landlock and temporary-filesystem support
as an ordinary portable launch. Networking checks use a local HTTP fixture
through the guest's outbound NAT and an HTTP/DNS request to `example.com`;
offline tests remove the network adapter.

These tests establish behavior for their individual cases. Builtin registration
does not establish support for every command option. Optional native plugins
and library worker threads remain deferred; see [COMPATIBILITY.md](../COMPATIBILITY.md)
for other boundaries. Generated reports identify the tested artifacts by hash.
