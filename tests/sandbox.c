#define _GNU_SOURCE
#include <assert.h>
#include "../src/sandbox_host.c"

static int identity(const char *text) {
    FILE *f = fmemopen((void *)text, strlen(text), "r");
    assert(f);
    int result = os_identity(f);
    fclose(f);
    return result;
}
int main(void) {
    assert(identity("NAME=other\nID=linux-bash-os\n"));
    assert(identity("ID=\"linux-bash-os\"\n"));
    assert(identity("ID='linux-bash-os'"));
    assert(!identity("ID=debian\nID_LIKE=linux-bash-os\n"));
    assert(!identity("ID=linux-bash-os-more\n"));
    assert(!identity("ID=linux-bash-os\nID=debian\n"));
    assert(!identity("# ID=linux-bash-os\n"));
    unsigned value;
    assert(!sandbox_number("4096", 1024, 65536, &value) && value == 4096);
    assert(sandbox_number("0", 1024, 65536, &value));
    assert(sandbox_number("65537", 1024, 65536, &value));
    assert(sandbox_number("999999999999999999999", 1024, 65536, &value));
    assert(sandbox_number("-1", 1, 64, &value));
    assert(sandbox_number("2x", 1, 64, &value));
    assert(safe_name("firmware/bios-256k.bin"));
    assert(!safe_name("/kernel"));
    assert(!safe_name("../kernel"));
    assert(!safe_name("lib/../kernel"));
    assert(!safe_name("lib//kernel"));
    assert(!safe_name("lib/"));
    assert(!safe_name("lib/./kernel"));
    struct sb_queue *q = calloc(1, sizeof(*q));
    assert(q);
    uint32_t type, size;
    void *data;
    uint32_t header[] = {SB_INPUT, 4};
    assert(!sb_append(q, header, 3));
    assert(sb_peek(q, &type, &size, &data) == 0);
    assert(!sb_append(q, (char *)header + 3, 5));
    assert(sb_peek(q, &type, &size, &data) == 0);
    assert(!sb_append(q, "a\0bc", 4));
    assert(sb_peek(q, &type, &size, &data) == 1);
    assert(type == SB_INPUT && size == 4 && !memcmp(data, "a\0bc", 4));
    sb_consume(q, 12);
    assert(sb_size(q) == 0);
    for (unsigned i = 0; i < SB_QUEUE / 12; i++)
        assert(!sb_packet(q, SB_OUTPUT, "test", 4));
    assert(sb_packet(q, SB_OUTPUT, "test", 4));
    while (sb_peek(q, &type, &size, &data) == 1)
        sb_consume(q, size + 8);
    assert(sb_size(q) == 0);
    header[1] = SB_CHUNK + 1;
    assert(!sb_append(q, header, sizeof(header)));
    assert(sb_peek(q, &type, &size, &data) == -1);
    free(q);
    puts("PASS: OS identity, numeric limits, archive names, console framing and backpressure");
    return 0;
}
