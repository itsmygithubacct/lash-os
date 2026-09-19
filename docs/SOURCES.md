# Source distribution and rebuilding

The [0.1.1 release](https://github.com/itsmygithubacct/lash-os/releases/tag/v0.1.1)
provides two source archives next to the portable executables:

- `lashos-0.1.1-source.tar.zst`: the project at the release commit, including its
  vendored source, licenses, patches, configuration and build scripts.
- `lashos-0.1.1-dependency-sources.tar.zst`: exact upstream Bash archives and
  patches, guest libraries, Linux, 75 Debian source packages, and the Nix source
  inputs and evaluated recipes used by the three portable builds.

Use both archives for the complete corresponding source. GitHub's automatic
source ZIP/tarball contains the project repository only. Third-party copyright
notices and licenses are retained in the source files and in the runtime bundle.
Project-owned code is distributed under GNU GPL version 3, as supplied in
[LICENSE](../LICENSE); third-party components retain their own licenses.

## Rebuild the executables

Install Nix with flakes enabled and the basic host tools used by Make (Python 3,
GNU Make and GNU findutils), plus GNU tar and zstd for extracting the archives.
Build from an x86_64 or ARM64 Linux machine. The compiler
build needs substantial CPU time, memory and disk space. Runtime testing also
needs the KVM and Landlock requirements described in [README.md](../README.md).

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar --zstd -xf lashos-0.1.1-source.tar.zst
tar --zstd -xf lashos-0.1.1-dependency-sources.tar.zst
cd lashos-0.1.1
export LASHOS_DOWNLOADS_DIR="$(cd ../lashos-0.1.1-dependency-sources/downloads && pwd)"
make portable-all
make paths
```

This uses the supplied Bash, library and kernel download cache. Nix build tools
and the pinned Debian binary packages may still be downloaded. It is not an
offline build or a claim of byte-for-byte reproducibility. See `flake.lock`,
`config/runtime/*.json`, and the source archive's `manifest.json` for exact inputs.
The default build trees and outputs stay in the external research workspace;
no local configuration is required.

The dependency archive contains:

| Path | Contents and rebuild entry point |
| --- | --- |
| `downloads/bash-5.3.tar.gz`, `downloads/patches/` | GNU Bash and its 15 official patches; `scripts/prepare-bash.py` applies them and the project adaptations |
| `downloads/deps/` | Guest library archives; `scripts/compile-deps.py` supplies the guest build flags |
| `downloads/runtime/linux-6.18.52.tar.xz` | Linux source; `scripts/build-kernel.py` applies the project's patches and architecture configuration |
| `downloads/runtime/sources/PACKAGE/` | Debian `.dsc`, original archives and Debian patch/build recipes for the exact source versions recorded by the runtime locks |
| `nix/inputs/` | Source trees, archives and patches from the actual Nix builds: musl, libbpf, libelf, compression libraries, GCC runtime, Capsule, Picolibc, TLSF, compiler-rt, Linux UAPI headers and locked Nix expressions |
| `provenance/kernels/` | Full architecture kernel configurations and input manifests |
| `provenance/runtime/` | Binary-package locks and the authenticated source-package lock |
| `manifest.json` | File checksums, Nix NAR hashes, architecture roots and evaluated build recipes |

To inspect or rebuild a Debian component, use `dpkg-source -x PACKAGE_VERSION.dsc`
inside its source directory. The extracted `debian/` directory contains its
patches, configuration and package build rules. Use Debian's `sbuild` or
`dpkg-buildpackage` with the required build dependencies and target architecture.
The project's bundler extracts the pinned runtime packages without installing
them on the build host. Newly rebuilt packages can be used by updating the
corresponding lock URLs, sizes and hashes before preparing a new sysroot.

For Nix components, `manifest.json` maps the actual linked architecture roots to
their evaluated recipes, original sources and patches. The locked Nixpkgs and
Capsule source trees provide the original expressions, and the project's
`flake.nix` supplies its overrides. Source tree names retain the immutable Nix
store basename so recipe references can be matched directly to `nix/inputs/`.

## Prepare a source release

Commit the project source first, then build all three portable executables
from that commit with `make portable-all`. Each executable records the source
state it was built from. Packaging with sources refuses executables whose
non-documentation content differs from the release commit, a Nix source
inventory that no longer matches the current builds, and kernel or runtime
provenance that differs from the executables.

```sh
python3 -B scripts/prepare-runtime-sources.py
python3 -B scripts/collect-nix-sources.py
# The checkout must still match the commit the executables were built from.
scripts/dev.py python3 -B scripts/package-sources.py
scripts/dev.py python3 -B scripts/package-release.py --with-sources
```

Maintainers refresh `config/runtime/sources.json` with
`scripts/prepare-runtime-sources.py --update-lock`. That operation resolves exact
source versions through signed Debian APT metadata in an isolated workspace.
Normal downloads verify every file against the checked-in SHA256 and size.
The source packager verifies the Nix store inputs and refuses a dirty project
checkout when making the project archive. Outputs go under
`out/releases/0.1.1/` in the external workspace.
