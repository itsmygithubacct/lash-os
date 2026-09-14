#pragma once
#include <stdint.h>
#include "bpf_capsule_types.h"
struct sha1dc_state {
    uint64_t digest;
    int check;
    struct capsule_result result;
};
int sha1dc_check(uint64_t *digest);
