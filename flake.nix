{
  description = "GNU Bash and bash-os builtins running through the Linux eBPF JIT";
  inputs.capsule.url = "github:ayles/bpf-capsule/6733c4531f06f95a32a35c2084b3dcf1a4263746";
  inputs.nixpkgs.follows = "capsule/nixpkgs";
  outputs = { self, capsule, nixpkgs }: let
    forSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
  in {
    devShells = forSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      musl = pkgs.pkgsCross.musl64;
      sdk = capsule.packages.${system}.default.overrideAttrs (old: {
        patches = (old.patches or []) ++ [
          ./patches/capsule-post-optimization-soft-float.patch
          ./patches/capsule-reload-reachability.patch
          ./patches/capsule-stack-anchor-barrier.patch
          ./patches/capsule-proven-arena-spills.patch
          ./patches/capsule-flatten-spill-metadata.patch
          ./patches/capsule-function-line-info.patch
          ./patches/capsule-wide-integer-widths.patch
          ./patches/capsule-large-image-budget.patch
          ./patches/capsule-large-block-continuations.patch
        ];
      });
    in {
      default = pkgs.mkShell {
        packages = with pkgs; [
          sdk cmake gnumake pkg-config bpftools libbpf elfutils zlib zstd pcre2 xz bzip2 ncurses
          python3 bison patch git curl binutils llvmPackages_23.libllvm
          llvmPackages_23.clang-unwrapped llvmPackages_23.clang-tools
        ];
        BZIP2_INCLUDE = "${pkgs.bzip2.dev}/include";
        LINUX_HEADERS = "${pkgs.linuxHeaders}/include";
        CAPSULE_SDK = "${sdk}";
        CMAKE_PREFIX_PATH = "${sdk}";
        LINUX_BASH_DEV_SHELL = "default";
      };
      portable = assert system == "x86_64-linux";
        (pkgs.mkShell.override { stdenv = musl.stdenv; }) {
          nativeBuildInputs = with pkgs; [ cmake gnumake pkg-config python3 binutils ];
          # These musl packages provide archives as well as shared libraries.
          # The portable loader links their archives with -static.
          buildInputs = with musl; [
            libbpf elfutils zlib zlib.static (zstd.override { static = true; })
          ];
          CAPSULE_SDK = "${sdk}";
          PORTABLE_CC = "${musl.stdenv.cc}/bin/${musl.stdenv.cc.targetPrefix}cc";
          LINUX_BASH_DEV_SHELL = "portable";
        };
    });
  };
}
