#pragma once
#include_next <stdio.h>
/* Picolibc 1.8.12's unlocked putchar macro incorrectly has two parameters. */
#undef putchar_unlocked
static inline int bash_putchar_unlocked(int c) {
    return fputc(c, stdout);
}
#define putchar_unlocked bash_putchar_unlocked

#define fgets_unlocked fgets
#define fread_unlocked fread
#define fwrite_unlocked fwrite
#define fputc_unlocked fputc
#define fputs_unlocked fputs
#define fflush_unlocked fflush
