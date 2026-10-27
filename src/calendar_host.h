#pragma once
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "posix_extra.h"

static size_t format_calendar(char *out, size_t size, const char *format,
                              const struct bridge_calendar *value, const char *zone) {
    struct tm native = {.tm_sec = value->sec,
                        .tm_min = value->min,
                        .tm_hour = value->hour,
                        .tm_mday = value->mday,
                        .tm_mon = value->mon,
                        .tm_year = value->year,
                        .tm_wday = value->wday,
                        .tm_yday = value->yday,
                        .tm_isdst = value->isdst,
                        .tm_gmtoff = value->gmtoff,
                        .tm_zone = zone};
    if (!size)
        return 0;
    if (!strchr(format, 'Z'))
        return strftime(out, size, format, &native);
    /* musl accepts timezone-name pointers only from its own timezone database.
     * The guest owns this name, so quote %Z as literal text before formatting.
     * Keep all other conversions, including the explicit %z offset, native. */
    size_t length = strlen(format);
    if (size > (SIZE_MAX - length - 1) / 2)
        return 0;
    size_t capacity = length + 2 * size + 1, used = 0;
    char *expanded = malloc(capacity);
    if (!expanded)
        return 0;
    for (const char *at = format; *at;) {
        const char *start = at++;
        if (*start != '%') {
            if (used + 1 >= capacity)
                goto fail;
            expanded[used++] = *start;
            continue;
        }
        int pad = ' ', no_pad = 0, uppercase = 0;
        while (*at && strchr("_-0^#", *at)) {
            if (*at == '-')
                no_pad = 1;
            if (*at == '_' || *at == '0') {
                no_pad = 0;
                pad = *at == '0' ? '0' : ' ';
            }
            if (*at == '^' || *at == '#')
                uppercase = 1;
            at++;
        }
        size_t width = 0;
        while (*at >= '0' && *at <= '9') {
            unsigned digit = *at++ - '0';
            if (digit >= size || width > (size - digit) / 10)
                width = size;
            else
                width = width * 10 + digit;
        }
        if (*at != 'Z') {
            if (*at)
                at++;
            size_t count = at - start;
            if (count >= capacity - used)
                goto fail;
            memcpy(expanded + used, start, count);
            used += count;
            continue;
        }
        at++;
        const char *name = zone && value->isdst >= 0 ? zone : "";
        size_t name_length = strlen(name);
        size_t padding = !no_pad && width > name_length ? width - name_length : 0;
        if (name_length >= size || padding >= size - name_length || padding >= capacity - used)
            goto fail;
        memset(expanded + used, pad, padding);
        used += padding;
        for (; *name; name++) {
            if (used + 2 >= capacity)
                goto fail;
            if (*name == '%')
                expanded[used++] = '%';
            expanded[used++] = uppercase ? toupper((unsigned char)*name) : *name;
        }
    }
    expanded[used] = 0;
    size_t result = strftime(out, size, expanded, &native);
    free(expanded);
    return result;
fail:
    free(expanded);
    return 0;
}
