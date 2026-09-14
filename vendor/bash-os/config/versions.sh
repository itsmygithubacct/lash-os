# config/versions.sh — the pinned bash source. Sourced by build.sh.
BASH_SRC_VERSION=5.3
BASH_URL="https://ftp.gnu.org/gnu/bash/bash-${BASH_SRC_VERSION}.tar.gz"
BASH_SRC_SHA256=0d5cd86965f869a26cf64f4b71be7b96f90a3ba8b3d74e27e8e9d9d5550f31ba

# Official bash-5.3 patches, applied in order after unpacking; each pinned by
# sha256. Among them: a crash restoring a signal disposition in a subshell,
# a segfault on SIGINT during reverse-i-search, wrong bracket-range matches
# with globasciiranges, wait -n ignoring its pid arguments in posix mode, a
# use-after-free when a mapfile callback unsets the array, a subshell that
# takes a fatal signal with an inherited EXIT trap, and a read builtin that
# can index its input buffer at -1.
BASH_PATCH_URL="https://ftp.gnu.org/gnu/bash/bash-${BASH_SRC_VERSION}-patches"
BASH_PATCHES=(
  "bash53-001 1f608434364af86b9b45c8b0ea3fb3b165fb830d27697e6cdfc7ac17dee3287f"
  "bash53-002 e385548a00130765ec7938a56fbdca52447ab41fabc95a25f19ade527e282001"
  "bash53-003 f245d9c7dc3f5a20d84b53d249334747940936f09dc97e1dcb89fc3ab37d60ed"
  "bash53-004 9591d245045529f32f0812f94180b9d9ce9023f5a765c039b852e5dfc99747d0"
  "bash53-005 cca1ef52dbbf433bc98e33269b64b2c814028efe2538be1e2c9a377da90bc99d"
  "bash53-006 29119addefed8eff91ae37fd51822c31780ee30d4a28376e96002706c995ff10"
  "bash53-007 c0976bbfffa1453c7cfdd62058f206a318568ff2d690f5d4fa048793fa3eb299"
  "bash53-008 097cd723cbfb8907674ac32214063a3fd85282657ec5b4e544d2c0f719653fb4"
  "bash53-009 eee30fe78a4b0cb2fe20e010e00308899cfc613e0774ebb3c8557a1552f24f8c"
  "bash53-010 cf76f1cce2ea300c18bff9f002d21f280cc931acd17c28518110b93fe6e72569"
  "bash53-011 0298df8f5ea2a31d3be43ed7d269c5b3c7c342dd5b570bea7f64d66dcbbe7531"
  "bash53-012 d71379b39bebaedaf123414414e77fb458a0a43b9ad3116594c6df7ca6754573"
  "bash53-013 042f9cda967e24bf4211944697441e93d06ff42b4b998629a98a1b249279f200"
  "bash53-014 bd4360b401d38507e358783dcad8536a99c6789f0d3a5bd0cfb8c4a34144696c"
  "bash53-015 55b79ceee2fc27f6767eed697e939a7eb2fe2a28c01556bd75f18d581014f46e"
)
BASH_PATCHLEVEL=15          # what patchlevel.h must say after the set is applied
BASH_BUILD_NUMBER=0         # pinned build counter (reproducible binaries)
