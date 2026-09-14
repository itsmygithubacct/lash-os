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

The host C tests need no BPF privileges or VM; their Make targets build the
image first. Existing builds can be tested directly with `scripts/dev.py ctest
--test-dir PATH --output-on-failure` (add `--shell portable` before `ctest` for
the portable build).

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
