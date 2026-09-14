/* Private host implementation. GNU Bash resumes in independent maps after fork. */
#pragma once
#include "capsule_process.h"

struct saved_map {
    char *name;
    size_t size;
    void *value;
};
struct process_snapshot {
    uintptr_t window, memory_address, image_address;
    size_t memory_size, image_size;
    void *memory, *image;
    struct saved_map maps[32];
    size_t map_count;
    uint32_t issued[2], free_fiber;
    int has_free_fiber;
    const char *step;
};

static void release_snapshot(struct process_snapshot *s) {
    for (size_t i = 0; i < s->map_count; i++) {
        free(s->maps[i].name);
        free(s->maps[i].value);
    }
    free(s->memory);
    free(s->image);
}

static int save_process(struct bridge_host *h, struct bash *skel, struct process_snapshot *s) {
    s->step = "copying arena memory";
    s->window = skel->rodata_bpfconfig->bpf_capsule_config.memory_view_base;
    s->memory_address = (uintptr_t)bpf_capsule_memory_start(h->capsule) + 4096;
    s->memory_size = bpf_capsule_memory_size(h->capsule) - 4096;
    s->image_address = (uintptr_t)h->image;
    s->image_size = h->image_size;
    s->memory = malloc(s->memory_size);
    s->image = malloc(s->image_size);
    if (!s->memory || !s->image) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(s->memory, (void *)s->memory_address, s->memory_size);
    memcpy(s->image, h->image, s->image_size);
    struct bpf_map *map;
    s->step = "copying writable maps";
    bpf_object__for_each_map(map, skel->obj) {
        if (!bpf_map__is_internal(map) || bpf_map__type(map) != BPF_MAP_TYPE_ARRAY ||
            (bpf_map__map_flags(map) & BPF_F_RDONLY_PROG))
            continue;
        if (s->map_count >= 32) {
            errno = E2BIG;
            return -1;
        }
        struct saved_map *m = &s->maps[s->map_count++];
        m->name = strdup(bpf_map__name(map));
        m->size = bpf_map__value_size(map);
        m->value = malloc(m->size);
        uint32_t zero = 0;
        if (!m->name || !m->value || bpf_map_lookup_elem(bpf_map__fd(map), &zero, m->value))
            return -1;
    }
    s->step = "reading the fiber pool";
    map = skel->maps.bpf_capsule_issued_fibers;
    if (bpf_map__type(map) != BPF_MAP_TYPE_HASH || bpf_map__key_size(map) != sizeof(uint32_t) ||
        bpf_map__value_size(map) != sizeof(uint32_t) || bpf_map__max_entries(map) != 2) {
        errno = EPROTO;
        return -1;
    }
    uint32_t key, previous, *cursor = NULL, issued_count = 0;
    while (!bpf_map_get_next_key(bpf_map__fd(map), cursor, &key)) {
        if (key >= 2 || s->issued[key]) {
            errno = EPROTO;
            return -1;
        }
        if (bpf_map_lookup_elem(bpf_map__fd(map), &key, &s->issued[key]))
            return -1;
        if (s->issued[key] != 1) {
            errno = EPROTO;
            return -1;
        }
        issued_count++;
        previous = key;
        cursor = &previous;
    }
    if (errno != ENOENT)
        return -1;
    /* The pinned Capsule ABI puts the fiber ID in the low 16 token bits.
     * Initial issuance starts at the current CPU, so neither ID has a fixed role. */
    uint32_t active = skel->data_ctrl->control.result.continuation & 0xffffu;
    if (active >= 2 || !s->issued[active]) {
        errno = EPROTO;
        return -1;
    }
    uint64_t token;
    if (!bpf_map_get_next_key(bpf_map__fd(skel->maps.bpf_capsule_continuation_claims), NULL,
                              &token)) {
        errno = EBUSY;
        return -1;
    }
    if (errno != ENOENT)
        return -1;
    uint32_t free_fiber;
    int rc =
        bpf_map_lookup_elem(bpf_map__fd(skel->maps.bpf_capsule_free_fibers), NULL, &free_fiber);
    if (!rc) {
        /* The other fiber is leased only for short bridge allocations and
         * must be idle before a process can be copied. */
        if (issued_count != 2 || free_fiber >= 2 || free_fiber == active ||
            !s->issued[free_fiber]) {
            errno = EBUSY;
            return -1;
        }
        s->has_free_fiber = 1;
        s->free_fiber = free_fiber;
        return 0;
    }
    if (errno == ENOENT && issued_count == 1)
        return 0;
    errno = EBUSY;
    return -1;
}

static int restore_process(struct bridge_host *h, struct bash **current,
                           const struct process_snapshot *s) {
    /* These close the child's references; the parent's map/link references live on. */
    bpf_capsule_release(h->capsule);
    bash__destroy(*current);
    *current = NULL;
    memset(h->capsule, 0, sizeof(*h->capsule));
    struct bash *skel = bash__open();
    *current = skel;
    if (!skel)
        return -1;
    if (linux_bash_capsule_configure_at(
            h->capsule, skel->obj,
            (struct bpf_capsule_config){.fiber_count = 2, .heap_bytes = 64ULL << 20}, s->window) ||
        bpf_object__load_skeleton(skel->skeleton) ||
        bpf_capsule_attach_freplace(h->capsule, skel->skeleton->data, skel->skeleton->data_sz) ||
        bpf_capsule_initialize(h->capsule))
        return -1;
    h->image = bpf_map__initial_value(skel->maps.arena, &h->image_size);
    if ((uintptr_t)bpf_capsule_memory_start(h->capsule) + 4096 != s->memory_address ||
        bpf_capsule_memory_size(h->capsule) - 4096 != s->memory_size ||
        (uintptr_t)h->image != s->image_address || h->image_size != s->image_size) {
        errno = EPROTO;
        return -1;
    }
    memcpy((void *)s->memory_address, s->memory, s->memory_size);
    memcpy((void *)h->image, s->image, s->image_size);
    uint32_t zero = 0;
    for (size_t i = 0; i < s->map_count; i++) {
        const struct saved_map *m = &s->maps[i];
        struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, m->name);
        if (!map || bpf_map__value_size(map) != m->size) {
            errno = EPROTO;
            return -1;
        }
        if (bpf_map_update_elem(bpf_map__fd(map), &zero, m->value, BPF_ANY))
            return -1;
    }
    for (uint32_t fiber = 0; fiber < 2; fiber++)
        if (s->issued[fiber] &&
            bpf_map_update_elem(bpf_map__fd(skel->maps.bpf_capsule_issued_fibers), &fiber,
                                &s->issued[fiber], BPF_NOEXIST))
            return -1;
    if (s->has_free_fiber && bpf_map_update_elem(bpf_map__fd(skel->maps.bpf_capsule_free_fibers),
                                                 NULL, &s->free_fiber, BPF_ANY))
        return -1;
    skel->data_ctrl->control.pid = getpid();
    skel->data_ctrl->control.ppid = getppid();
    return 0;
}

static pid_t fork_process(struct bridge_host *h, struct bash **skel, unsigned long clone_flags) {
    struct process_snapshot snapshot = {0};
    if (save_process(h, *skel, &snapshot)) {
        int saved = errno ? errno : EIO;
        fprintf(stderr, "cannot snapshot kernel Bash while %s: %s\n", snapshot.step,
                strerror(saved));
        release_snapshot(&snapshot);
        errno = saved;
        return -1;
    }
    pid_t result = clone_flags ? syscall(SYS_clone, clone_flags, NULL, NULL, NULL, 0UL) : fork();
    int saved = errno;
    if (result == 0 && restore_process(h, skel, &snapshot)) {
        fprintf(stderr, "cannot restore kernel Bash child: %s\n", strerror(errno));
        _exit(125);
    }
    release_snapshot(&snapshot);
    errno = result < 0 ? saved : 0;
    return result;
}
