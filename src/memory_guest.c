/* Guest mappings must stay in the Capsule arena so BPF can address them. */
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
struct mapping {
    struct mapping *next;
    void *base, *allocation;
    size_t size;
};
static struct mapping *mappings;
void *mmap(void *address, size_t length, int protection, int flags, int descriptor, off_t offset) {
    (void)address;
    if (!length || length > SIZE_MAX - 4095 || offset < 0 || (offset & 4095)) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    if ((flags & (MAP_FIXED | MAP_SHARED)) || (protection & PROT_EXEC)) {
        errno = ENOTSUP;
        return MAP_FAILED;
    }
    size_t size = (length + 4095) & ~(size_t)4095;
    struct mapping *item = calloc(1, sizeof(*item));
    if (!item)
        return MAP_FAILED;
    item->allocation = malloc(size + 4095);
    if (!item->allocation) {
        free(item);
        return MAP_FAILED;
    }
    item->base = (void *)(((uintptr_t)item->allocation + 4095) & ~(uintptr_t)4095);
    item->size = size;
    memset(item->base, 0, size);
    if (!(flags & MAP_ANONYMOUS))
        for (size_t done = 0; done < length;) {
            ssize_t n = pread(descriptor, (char *)item->base + done, length - done, offset + done);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0) {
                int error = errno;
                free(item->allocation);
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
int munmap(void *address, size_t length) {
    struct mapping **next = &mappings;
    while (*next) {
        struct mapping *item = *next;
        if (item->base == address && length && length <= item->size &&
            ((length + 4095) & ~(size_t)4095) == item->size) {
            *next = item->next;
            free(item->allocation);
            free(item);
            return 0;
        }
        next = &item->next;
    }
    errno = EINVAL;
    return -1;
}
void *mremap(void *address, size_t old_size, size_t new_size, int flags, ...) {
    if (flags & ~MREMAP_MAYMOVE) {
        errno = ENOTSUP;
        return MAP_FAILED;
    }
    struct mapping *item = mappings;
    while (item && item->base != address)
        item = item->next;
    if (!item || old_size > item->size || !new_size) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    if (new_size <= item->size)
        return address;
    if (!(flags & MREMAP_MAYMOVE)) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    void *out = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (out == MAP_FAILED)
        return out;
    memcpy(out, address, old_size);
    munmap(address, item->size);
    return out;
}
int mincore(void *address, size_t length, unsigned char *vector) {
    for (struct mapping *item = mappings; item; item = item->next) {
        uintptr_t delta = (uintptr_t)address - (uintptr_t)item->base;
        if (delta <= item->size && length <= item->size - delta) {
            memset(vector, 1, (length + 4095) / 4096);
            return 0;
        }
    }
    errno = ENOMEM;
    return -1;
}
