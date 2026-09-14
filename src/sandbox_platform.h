#ifndef LASH_SANDBOX_PLATFORM_H
#define LASH_SANDBOX_PLATFORM_H
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ || __SIZEOF_POINTER__ != 8
#error "lashos requires a 64-bit little-endian target"
#endif
#if defined(__x86_64__)
#define SB_ARCH "x86_64"
#define SB_MACHINE "pc"
#define SB_BIOS "firmware/bios-256k.bin"
#define SB_CONSOLE "ttyS0"
#elif defined(__aarch64__)
#define SB_ARCH "aarch64"
#define SB_MACHINE "virt,gic-version=host"
#define SB_CONSOLE "ttyAMA0"
#elif defined(__riscv) && __riscv_xlen == 64
#define SB_ARCH "riscv64"
#define SB_MACHINE "virt"
#define SB_BIOS "firmware/fw_dynamic.bin"
#define SB_CONSOLE "ttyS0"
#else
#error "Unsupported lashos host architecture"
#endif
#endif
