#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define LASHOS_TIME_IMPLEMENTATION
#include "../include/guest/git_time.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static struct tm calendar(const struct linux_bash_tm *value) {
    return (struct tm){.tm_sec = value->tm_sec,
                       .tm_min = value->tm_min,
                       .tm_hour = value->tm_hour,
                       .tm_mday = value->tm_mday,
                       .tm_mon = value->tm_mon,
                       .tm_year = value->tm_year,
                       .tm_wday = value->tm_wday,
                       .tm_yday = value->tm_yday,
                       .tm_isdst = value->tm_isdst};
}

static void copy_calendar(struct linux_bash_tm *out, const struct tm *value) {
    out->tm_sec = value->tm_sec;
    out->tm_min = value->tm_min;
    out->tm_hour = value->tm_hour;
    out->tm_mday = value->tm_mday;
    out->tm_mon = value->tm_mon;
    out->tm_year = value->tm_year;
    out->tm_wday = value->tm_wday;
    out->tm_yday = value->tm_yday;
    out->tm_isdst = value->tm_isdst;
}

static int local_offset(struct linux_bash_tm *out, const struct tm *value, time_t instant) {
    struct tm utc = *value;
    utc.tm_isdst = 0;
    time_t offset;
    if (__builtin_sub_overflow(timegm(&utc), instant, &offset) || offset < LONG_MIN ||
        offset > LONG_MAX) {
        errno = EOVERFLOW;
        return -1;
    }
    out->tm_gmtoff = (long)offset;
    out->tm_zone = tzname[value->tm_isdst > 0];
    return 0;
}

struct linux_bash_tm *linux_bash_gmtime_r(const time_t *instant, struct linux_bash_tm *out) {
    struct tm value;
    if (!gmtime_r(instant, &value))
        return NULL;
    copy_calendar(out, &value);
    out->tm_gmtoff = 0;
    out->tm_zone = "GMT";
    return out;
}

struct linux_bash_tm *linux_bash_localtime_r(const time_t *instant, struct linux_bash_tm *out) {
    struct tm value;
    if (!localtime_r(instant, &value))
        return NULL;
    copy_calendar(out, &value);
    return local_offset(out, &value, *instant) ? NULL : out;
}

time_t linux_bash_mktime(struct linux_bash_tm *out) {
    struct tm value = calendar(out);
    time_t instant = mktime(&value);
    copy_calendar(out, &value);
    if (local_offset(out, &value, instant))
        return (time_t)-1;
    return instant;
}

time_t linux_bash_timegm(struct linux_bash_tm *out) {
    struct tm value = calendar(out);
    time_t instant = timegm(&value);
    copy_calendar(out, &value);
    out->tm_gmtoff = 0;
    out->tm_zone = "GMT";
    return instant;
}
