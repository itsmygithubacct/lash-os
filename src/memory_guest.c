/* Guest mappings must stay in the Capsule arena so BPF can address them. */
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define PAGE 4096
#define PAGE_ROUND(n) (((n) + PAGE - 1) & ~(size_t)(PAGE - 1))
/* Partial unmaps split a mapping; the pieces share one allocation. */
struct allocation {
    void *memory;
    size_t references;
};
struct mapping {
    struct mapping *next;
    void *base;
    size_t size;
    struct allocation *allocation;
};
static struct mapping *mappings;
static void release(struct allocation *allocation) {
    if (!--allocation->references) {
        free(allocation->memory);
        free(allocation);
    }
}
void *mmap(void *address, size_t length, int protection, int flags, int descriptor, off_t offset) {
    (void)address;
    if (!length || length > SIZE_MAX - (2 * PAGE - 2) || offset < 0 || (offset & (PAGE - 1))) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    if ((flags & (MAP_FIXED | MAP_SHARED)) || (protection & PROT_EXEC)) {
        errno = ENOTSUP;
        return MAP_FAILED;
    }
    size_t size = PAGE_ROUND(length);
    struct mapping *item = calloc(1, sizeof(*item));
    struct allocation *allocation = calloc(1, sizeof(*allocation));
    void *memory = item && allocation ? malloc(size + PAGE - 1) : NULL;
    if (!memory) {
        free(item);
        free(allocation);
        errno = ENOMEM;
        return MAP_FAILED;
    }
    *allocation = (struct allocation){memory, 1};
    item->allocation = allocation;
    item->base = (void *)(((uintptr_t)memory + PAGE - 1) & ~(uintptr_t)(PAGE - 1));
    item->size = size;
    memset(item->base, 0, size);
    if (!(flags & MAP_ANONYMOUS))
        for (size_t done = 0; done < length;) {
            ssize_t n = pread(descriptor, (char *)item->base + done, length - done, offset + done);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0) {
                int error = errno;
                release(allocation);
                free(item);
                errno = error;
                return MAP_FAILED;
            }
            if (!n)
                break;
            done += n;
        }
    item->next = mappings;
    mappings = item;
    return item->base;
}
/* Like Linux, removing a range that is partly or wholly unmapped succeeds. */
int munmap(void *address, size_t length) {
    uintptr_t start = (uintptr_t)address;
    if (!length || (start & (PAGE - 1)) || length > SIZE_MAX - (PAGE - 1) ||
        PAGE_ROUND(length) > UINTPTR_MAX - start) {
        errno = EINVAL;
        return -1;
    }
    uintptr_t end = start + PAGE_ROUND(length);
    for (struct mapping **next = &mappings; *next;) {
        struct mapping *item = *next;
        uintptr_t base = (uintptr_t)item->base, limit = base + item->size;
        if (end <= base || start >= limit) {
            next = &item->next;
            continue;
        }
        if (start <= base && end >= limit) {
            *next = item->next;
            release(item->allocation);
            free(item);
            continue;
        }
        if (start > base && end < limit) {
            struct mapping *tail = calloc(1, sizeof(*tail));
            if (!tail) {
                errno = ENOMEM;
                return -1;
            }
            *tail = (struct mapping){item->next, (void *)end, limit - end, item->allocation};
            item->allocation->references++;
            item->next = tail;
            item->size = start - base;
            next = &tail->next;
            continue;
        }
        if (start <= base) {
            item->base = (void *)end;
            item->size = limit - end;
        } else
            item->size = start - base;
        next = &item->next;
    }
    return 0;
}
static struct mapping *containing(uintptr_t start, size_t size) {
    for (struct mapping *item = mappings; item; item = item->next) {
        uintptr_t base = (uintptr_t)item->base;
        if (start >= base && start - base < item->size && size <= item->size - (start - base))
            return item;
    }
    return NULL;
}
void *mremap(void *address, size_t old_size, size_t new_size, int flags, ...) {
    if (flags & ~MREMAP_MAYMOVE) {
        errno = ENOTSUP;
        return MAP_FAILED;
    }
    uintptr_t start = (uintptr_t)address;
    if ((start & (PAGE - 1)) || !old_size || !new_size || old_size > SIZE_MAX - (2 * PAGE - 2) ||
        new_size > SIZE_MAX - (2 * PAGE - 2)) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    size_t old_pages = PAGE_ROUND(old_size), new_pages = PAGE_ROUND(new_size);
    if (!containing(start, old_pages)) {
        errno = EFAULT;
        return MAP_FAILED;
    }
    if (new_pages <= old_pages) {
        if (new_pages < old_pages && munmap((char *)address + new_pages, old_pages - new_pages))
            return MAP_FAILED;
        return address;
    }
    if (!(flags & MREMAP_MAYMOVE)) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    void *out = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (out == MAP_FAILED)
        return out;
    memcpy(out, address, old_pages);
    munmap(address, old_pages);
    return out;
}
int mincore(void *address, size_t length, unsigned char *vector) {
    uintptr_t start = (uintptr_t)address;
    if (start & (PAGE - 1)) {
        errno = EINVAL;
        return -1;
    }
    size_t pages = length / PAGE + !!(length % PAGE);
    for (size_t i = 0; i < pages; i++)
        if (!containing(start + i * PAGE, PAGE)) {
            errno = ENOMEM;
            return -1;
        }
    memset(vector, 1, pages);
    return 0;
}
