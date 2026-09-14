#pragma once
#include "bpf_capsule_host.h"
int linux_bash_capsule_configure_at(struct bpf_capsule *, struct bpf_object *,
                                    struct bpf_capsule_config, uintptr_t);
