#pragma once
#include <stdint.h>
#include "bpf_capsule_types.h"
struct mlkem_state {
    uint64_t digest;
    int check;
    struct capsule_result result;
};
int mlkem_check(uint64_t *digest);
