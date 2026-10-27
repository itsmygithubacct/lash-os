#define _GNU_SOURCE
#define LASHOS_TIME_IMPLEMENTATION
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../include/guest/git_time.h"
#include "../src/calendar_host.h"

int main(void) {
    time_t instant = 1700000000;
    const char *zones[] = {"UTC0", "IST-5:30", "EST5EDT,M3.2.0,M11.1.0"};
    for (unsigned i = 0; i < sizeof(zones) / sizeof(*zones); i++) {
        assert(!setenv("TZ", zones[i], 1));
        tzset();
        struct linux_bash_tm value;
        struct tm native;
        assert(linux_bash_localtime_r(&instant, &value));
        assert(localtime_r(&instant, &native));
        assert(value.tm_hour == native.tm_hour && value.tm_mday == native.tm_mday);
        assert(value.tm_gmtoff == native.tm_gmtoff && !strcmp(value.tm_zone, native.tm_zone));
        assert(linux_bash_mktime(&value) == instant);
        assert(linux_bash_gmtime_r(&instant, &value) && value.tm_gmtoff == 0);
        assert(linux_bash_timegm(&value) == instant);
    }
    struct bridge_calendar date = {.sec = 20,
                                   .min = 43,
                                   .hour = 3,
                                   .mday = 15,
                                   .mon = 10,
                                   .year = 123,
                                   .wday = 3,
                                   .yday = 318,
                                   .isdst = 0,
                                   .gmtoff = 19800};
    char out[128];
    assert(format_calendar(out, sizeof(out), "%Y-%m-%d %H:%M:%S %z %Z", &date, "IST"));
    if (strcmp(out, "2023-11-15 03:43:20 +0530 IST"))
        fprintf(stderr, "Calendar result: [%s]\n", out);
    assert(!strcmp(out, "2023-11-15 03:43:20 +0530 IST"));
    date.gmtoff = -12600;
    assert(format_calendar(out, sizeof(out), "%z", &date, "") == 5);
    assert(!strcmp(out, "-0330"));
    assert(format_calendar(out, sizeof(out), "A%%ZB", &date, "") == 4);
    assert(!strcmp(out, "A%ZB"));
    assert(format_calendar(out, sizeof(out), "A%ZB", &date, "") == 2);
    assert(!strcmp(out, "AB"));
    assert(format_calendar(out, sizeof(out), "%Z", &date, "%Y") == 2);
    assert(!strcmp(out, "%Y"));
    assert(format_calendar(out, sizeof(out), "%8Z|%08Z|%-8Z|%^Z|%#Z", &date, "utc"));
    assert(!strcmp(out, "     utc|00000utc|utc|UTC|UTC"));
    assert(!format_calendar(out, sizeof(out), "%999999999999999999999Z", &date, "UTC"));
    assert(!format_calendar(out, 4, "%Y", &date, ""));
    assert(!format_calendar(out, 0, "%Y", &date, ""));
    puts("Git timezone conversion and calendar formatting: passed");
}
