The SDK remains pinned to the revision in SOURCE.json. The Nix derivation
applies the Capsule patches below locally. The runtime kernel recipe applies
the separately described Linux patches to its pinned source.

GNU awk's aggregate initialization exposed a compiler ordering issue: LLVM O2
materialized a `store double 0.0` from a constant aggregate after Capsule's
initial software floating-point pass. The normal no-float validator rejected
that instruction. The patch repeats software lowering after memory expansion,
before that same validator. It does not alter the kernel, verifier, or verifier
checks. The full kernel test exercises AWK arithmetic and library hashing.

capsule-reload-reachability.patch keeps the same predicate for localizing a
spill reload: a use needs its own reload if any resume root can reach it without
passing through the original reload block. The original implementation searched
the graph for each (load, use, resume) triple. The patch computes the union of
reachable blocks from all resume roots once per excluded block and caches it
until the function's CFG changes. This makes large generated functions practical
to compile. tests/reachability-equivalence.py checks the two predicates on every
three-node directed graph and every subset of roots, target, and excluded node.

`capsule-stack-anchor-barrier.patch` prevents LLVM from hoisting memory loads
above the marker where Capsule makes the fiber spill backing available. The
ML-KEM test exposed thousands of loads and register spills before that marker,
which correctly failed the native-stack budget check. Moving the frame load
after the marker and adding a memory clobber preserves the required order
without changing the algorithm, spill classification, or stack checks.
`tests/mlkem/` contains a deterministic
native/kernel round-trip comparison for this case.

`capsule-proven-arena-spills.patch` retains pointer provenance while allowing
the existing arena-pointer spill path when both compiler analyses agree that
every full-width access contains an arena pointer. Mixed, uncertain,
overlapping, helper-visible, and pre-marker slots retain their native-stack
requirements. Pointer spills are explicitly cast to addresses for storage and
restored to arena pointers on reload. The ML-KEM round trip exercises this
path and passed against the native reference in the stock-kernel VM.

`cmake/Codegen.cmake` shares the validated LLVM options between the complete
shell and this regression check. The fast scheduler reduces compile time;
separate stack slots preserve spill classifications. Late aggregate copies
are expanded in order instead of introducing an unresolved native `memcpy`.

`capsule-flatten-spill-metadata.patch` removes stale function-local frame-index
provenance from memory operands copied into a merged function. The physical
addresses, access sizes, flags, alignment, and ordering remain intact. LLVM's
late debug-variable analysis previously interpreted the old index against the
destination function's unrelated frame table and crashed. The replacement
memory reference conservatively carries no frame-index provenance.

`capsule-function-line-info.patch` adds an optional compact debug mode. It
retains BTF types, global records, function prototypes, and function locations,
while omitting instruction locations and local-variable debug records after
IR lowering. LLVM 23's BTF string table performs a linear lookup for each
source record; this dominated the full build's emission time. The project uses
compact mode by default. CMake's `LINUX_BASH_DETAILED_DEBUG=ON` restores detailed
records. The transformation removes only debugging records and preserves the
normal verifier and stack checks.
The implementation is described in LLVM's
[BTF emitter](https://github.com/llvm/llvm-project/blob/release/23.x/llvm/lib/Target/BPF/BTFDebug.cpp).

`capsule-wide-integer-widths.patch` extends the existing compiler-rt lowering
to integer widths 65 through 128. Checked multiplication with signed inputs
and an unsigned result introduced an i65 product which previously escaped
lowering and became a late unresolved `__multi3` call. Operands are extended to
the helper's i128 signature and the result is narrowed to its original width.
Signed division/remainder use sign extension; unsigned operations and modular
multiplication use zero extension. The managed call ABI is unchanged.

`capsule-large-image-budget.patch` permits up to 128 physical roots within the
existing 256-function budget. It also virtualizes managed application loops
instead of carrying verifier induction proofs through arena spills. The existing
function, native stack, and fiber-frame limits remain unchanged. Proven native
runtime loops retain their original lowering.

`capsule-large-block-continuations.patch` adds internal suspension boundaries
along long paths in managed functions containing at least 1,024 IR instructions.
A reverse-postorder traversal carries budgets of 256 instructions and four
branch/select/constant-bitmask points across forward edges and joins, resetting
them at managed calls and inserted boundaries. Besides machine branches, stock
Linux 6.12.96 can split scalar analysis states at constant AND/OR operations
(`maybe_fork_scalars` in the
[kernel verifier](https://github.com/gregkh/linux/blob/v6.12.96/kernel/bpf/verifier.c)).
The generated SHA-1 collision checks exercise this behavior. Backedges are
handled by the existing loop pass. Markers precede pointer-liveness validation
and SSA demotion, so values cross boundaries through the existing checked
fiber-frame mechanism. They resume internally with `ActionContinue`, preserving
mailbox handling for explicit guest I/O yields. Proven native runtime functions
are excluded.

`scripts/adapt-workspaces.py` is a separate source transformation applied to the
isolated bash-os build, for both the native reference and the eBPF compilation.
It moves oversized DNS and service-manager automatic arrays to the managed
heap. Each allocation uses Bash's unwind frames for normal-return and nonlocal
exit cleanup. This preserves Capsule's existing 2 MiB fiber-stack limit and
the reserve used for compiler-generated spills.

`linux-riscv64-jit-zext.patch` selects the RV64 JIT's existing conservative
zero-extension path. The verifier's optional sub-register optimization inserts
instructions one at a time and repeatedly shifts large instruction arrays;
this made loading the full image prohibitively slow under RISC-V emulation.
With `verifier_zext` false, the RV64 JIT emits the required zero extensions
itself. RV32 behavior and the verifier's CMPXCHG fixups remain unchanged. The
upstream `lib/test_bpf` suite exercises arithmetic, jumps, loads, stores and
atomics, including both zero-extension paths. The matching test module can be
built and run with the architecture harness documented in [TESTING.md](../docs/TESTING.md).

`linux-riscv64-jit-region.patch` expands RV64's BPF JIT address window from
128 MiB to 1 GiB for the full image and process snapshots. This stays within
the existing module area and the JIT's signed 32-bit relative-call reach of
the pinned kernel. It reserves virtual address space; physical pages are
allocated on demand. Allocation accounting, memory protections, verification
and the RV32 limit remain unchanged.

`linux-vmalloc-inline-purge.patch` makes `__purge_vmap_area_lazy()` purge lazily
freed vmap areas inline. Upstream queues `purge_vmap_node()` helpers on the
system workqueue and waits for them in `flush_work()` while `vmap_purge_lock` is
held. `bpf_prog_pack_free()` reaches that path through `vfree()` of an emptied
JIT pack while holding `pack_mutex`, from `bpf_prog_free_deferred()` on the same
workqueue. A forked shell loads a fresh full image and an exiting child frees
hundreds of programs, so every worker ahead of the helper can block on
`pack_mutex`, after which program loading and freeing stop. Captured guest
stacks showed one events worker in `__flush_work` under `bpf_prog_pack_free`,
dozens of workers and the forked shell waiting for `pack_mutex`, idle CPUs, and
no memory reclaim. The same deadlock is reported as Debian bug 1146730. Inline
purging gives up parallel purging across vmap nodes; lock order, TLB flushing
and area accounting are unchanged. The patch applies to all three runtime
kernels. Host kernels used by direct mode keep the upstream behavior.
