This isolates the original libssh ML-KEM implementation from the larger shell
to test Capsule's code generation and fiber spill storage.

`make test-mlkem` builds the same deterministic computation for the native CPU
and eBPF, then compares them in an isolated stock-kernel VM. It generates a key
pair, validates the public key, encapsulates a shared secret, and decapsulates
it. The shared secrets must agree. A fingerprint over the public key,
ciphertext, and recovered secret must also match native execution.

The byte sequences supplied as randomness are fixed test inputs. The printed
FNV fingerprint is only a compact parity check, not a cryptographic hash or a
standard conformance vector. The native result for this snapshot is
`MLKEM check=0 fingerprint=70c6ce4f2e1c3d0e`.

Before the cryptographic round trip, the check also exercises mixed signed
and unsigned checked multiplication. Seven cases cover zero, negative
products, positive products, and INT32_MIN/MAX boundaries. Clang uses an i65
temporary for this combination, which must go through managed wide-integer
lowering. Overflow cases must leave the output value unchanged.

The stack-marker regression was first visible as thousands of address
calculations and spills scheduled before the unified spill backing existed.
The compiler patch orders the frame load after that marker and gives the
marker a memory clobber. Normal native-stack and fiber-stack checks remain
enabled.
