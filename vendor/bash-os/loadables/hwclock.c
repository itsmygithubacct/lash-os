/* SPDX-License-Identifier: MIT */
/* hwclock.c — hwclock(8) subset over /dev/rtc0.
 *
 *   hwclock [--show] [--utc|--localtime] [--rtc PATH|--rtc=PATH]
 *   hwclock --hctosys [--utc|--localtime] [--rtc PATH|--rtc=PATH]
 *   hwclock --systohc [--utc|--localtime] [--rtc PATH|--rtc=PATH]
 *   hwclock --adjust [--adjfile PATH] [--rtc PATH|--rtc=PATH]
 *   hwclock --help | --version
 *
 * Default mode treats the RTC as UTC unless /etc/adjtime says LOCAL.
 *
 * Source counterparts:
 *   research/refs/util-linux/sys-utils/hwclock-rtc.c
 *   research/refs/busybox/util-linux/hwclock.c
 *
 * --- LICENSE --- MIT, same boilerplate as binhex.c.
 */

#include <config.h>
#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/rtc.h>

#include "loadables.h"

#define BHC_RTC_PATH "/dev/rtc0"
#define BHC_ADJTIME_PATH "/etc/adjtime"
#define BHC_SECONDS_PER_DAY 86400.0

enum bhc_time_mode
{
  BHC_UTC,
  BHC_LOCALTIME
};

struct bhc_adjtime
{
  double drift_factor;
  long long last_adjust;
  double not_adjusted;
  long long last_calib;
  enum bhc_time_mode mode;
};

static int
bhc_is_leap (long long y)
{
  return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
}

static long long
bhc_days_before_year (long long y)
{
  long long yy = y - 1;
  return yy * 365 + yy / 4 - yy / 100 + yy / 400;
}

static time_t
bhc_timegm_rtc (const struct rtc_time *r)
{
  static const int mdays_norm[12] =
    { 31,28,31,30,31,30,31,31,30,31,30,31 };
  long long year = (long long) r->tm_year + 1900;
  long long days = bhc_days_before_year (year) - bhc_days_before_year (1970);
  for (int m = 0; m < r->tm_mon; m++)
    {
      days += mdays_norm[m];
      if (m == 1 && bhc_is_leap (year))
        days++;
    }
  days += r->tm_mday - 1;
  return (time_t) (days * 86400LL + r->tm_hour * 3600
                   + r->tm_min * 60 + r->tm_sec);
}

static int
bhc_rtc_to_time (const struct rtc_time *rt, enum bhc_time_mode mode,
                 time_t *out)
{
  if (mode == BHC_LOCALTIME)
    {
      struct tm tmv;
      memset (&tmv, 0, sizeof tmv);
      tmv.tm_sec = rt->tm_sec;
      tmv.tm_min = rt->tm_min;
      tmv.tm_hour = rt->tm_hour;
      tmv.tm_mday = rt->tm_mday;
      tmv.tm_mon = rt->tm_mon;
      tmv.tm_year = rt->tm_year;
      tmv.tm_wday = rt->tm_wday;
      tmv.tm_yday = rt->tm_yday;
      tmv.tm_isdst = -1;
      errno = 0;
      *out = mktime (&tmv);
      if (*out == (time_t) -1 && errno != 0)
        {
          builtin_error ("mktime: %s", strerror (errno));
          return -1;
        }
      return 0;
    }

  *out = bhc_timegm_rtc (rt);
  return 0;
}

static int
bhc_time_to_rtc (time_t t, enum bhc_time_mode mode, struct rtc_time *rt)
{
  struct tm tmv;
  if ((mode == BHC_LOCALTIME ? localtime_r (&t, &tmv)
                             : gmtime_r (&t, &tmv)) == NULL)
    {
      builtin_error ("%s: %s",
                     mode == BHC_LOCALTIME ? "localtime_r" : "gmtime_r",
                     strerror (errno));
      return -1;
    }
  memset (rt, 0, sizeof *rt);
  rt->tm_sec = tmv.tm_sec;
  rt->tm_min = tmv.tm_min;
  rt->tm_hour = tmv.tm_hour;
  rt->tm_mday = tmv.tm_mday;
  rt->tm_mon = tmv.tm_mon;
  rt->tm_year = tmv.tm_year;
  rt->tm_wday = tmv.tm_wday;
  rt->tm_yday = tmv.tm_yday;
  rt->tm_isdst = 0;
  return 0;
}

static int
bhc_read_line (FILE *fp, char *buf, size_t len, const char *path)
{
  if (fgets (buf, len, fp) == NULL)
    {
      builtin_error ("%s: invalid adjtime file", path);
      return -1;
    }
  buf[strcspn (buf, "\r\n")] = '\0';
  return 0;
}

static int
bhc_parse_adjtime (const char *path, struct bhc_adjtime *adj)
{
  char line1[128], line2[128], line3[128];
  char *endp;
  FILE *fp;

  adj->drift_factor = 0.0;
  adj->last_adjust = 0;
  adj->not_adjusted = 0.0;
  adj->last_calib = 0;
  adj->mode = BHC_UTC;

  fp = fopen (path, "r");
  if (fp == NULL)
    {
      if (errno == ENOENT)
        return 0;
      builtin_error ("%s: %s", path, strerror (errno));
      return -1;
    }

  if (bhc_read_line (fp, line1, sizeof line1, path) < 0
      || bhc_read_line (fp, line2, sizeof line2, path) < 0
      || bhc_read_line (fp, line3, sizeof line3, path) < 0)
    {
      fclose (fp);
      return -1;
    }
  fclose (fp);

  if (sscanf (line1, "%lf %lld %lf",
              &adj->drift_factor, &adj->last_adjust,
              &adj->not_adjusted) != 3)
    {
      builtin_error ("%s: invalid adjtime drift line", path);
      return -1;
    }

  errno = 0;
  adj->last_calib = strtoll (line2, &endp, 10);
  if (errno != 0 || endp == line2 || (*endp != '\0' && *endp != ' '))
    {
      builtin_error ("%s: invalid adjtime calibration line", path);
      return -1;
    }

  if (strcmp (line3, "LOCAL") == 0)
    adj->mode = BHC_LOCALTIME;
  else if (strcmp (line3, "UTC") == 0)
    adj->mode = BHC_UTC;
  else
    {
      builtin_error ("%s: invalid adjtime mode line", path);
      return -1;
    }

  return 0;
}

static int
bhc_write_adjtime (const char *path, const struct bhc_adjtime *adj)
{
  FILE *fp = fopen (path, "w");
  if (fp == NULL)
    {
      builtin_error ("%s: %s", path, strerror (errno));
      return -1;
    }
  /* close the stream on the write-failure path too: short-circuiting the
     fclose behind the fprintf test leaked it */
  int failed = fprintf (fp, "%.6f %lld %.6f\n%lld\n%s\n",
                        adj->drift_factor, adj->last_adjust, adj->not_adjusted,
                        adj->last_calib,
                        adj->mode == BHC_LOCALTIME ? "LOCAL" : "UTC") < 0;
  if (fclose (fp) != 0)
    failed = 1;
  if (failed)
    {
      builtin_error ("%s: %s", path, strerror (errno));
      return -1;
    }
  return 0;
}

static double
bhc_drift_correction (const struct bhc_adjtime *adj, time_t rtc_time)
{
  if (adj->last_adjust == 0)
    return 0.0;
  return (((double) rtc_time - (double) adj->last_adjust)
          * adj->drift_factor / BHC_SECONDS_PER_DAY) + adj->not_adjusted;
}

static int
bhc_open_rtc (const char *path, int write_mode)
{
  int fd = open (path, write_mode ? O_WRONLY : O_RDONLY);
  if (fd < 0)
    builtin_error ("%s: %s", path, strerror (errno));
  return fd;
}

static int
bhc_read_rtc (const char *path, struct rtc_time *rt)
{
  int fd = bhc_open_rtc (path, 0);
  if (fd < 0)
    return -1;
  if (ioctl (fd, RTC_RD_TIME, rt) < 0)
    {
      builtin_error ("RTC_RD_TIME: %s", strerror (errno));
      close (fd);
      return -1;
    }
  close (fd);
  return 0;
}

static int
bhc_write_rtc (const char *path, const struct rtc_time *rt)
{
  int fd = bhc_open_rtc (path, 1);
  if (fd < 0)
    return -1;
  if (ioctl (fd, RTC_SET_TIME, rt) < 0)
    {
      builtin_error ("RTC_SET_TIME: %s", strerror (errno));
      close (fd);
      return -1;
    }
  close (fd);
  return 0;
}

static void
bhc_print_rtc (const struct rtc_time *rt)
{
  printf ("%04d-%02d-%02dT%02d:%02d:%02d\n",
          rt->tm_year + 1900, rt->tm_mon + 1, rt->tm_mday,
          rt->tm_hour, rt->tm_min, rt->tm_sec);
}

static int
bhc_show (const char *rtc_path)
{
  struct rtc_time rt;
  memset (&rt, 0, sizeof rt);
  if (bhc_read_rtc (rtc_path, &rt) < 0)
    return EXECUTION_FAILURE;
  bhc_print_rtc (&rt);
  return EXECUTION_SUCCESS;
}

static int
bhc_hctosys (const char *rtc_path, enum bhc_time_mode mode,
             const struct bhc_adjtime *adj, int use_adjtime)
{
  struct rtc_time rt;
  struct timespec ts;
  memset (&rt, 0, sizeof rt);
  if (bhc_read_rtc (rtc_path, &rt) < 0)
    return EXECUTION_FAILURE;
  if (bhc_rtc_to_time (&rt, mode, &ts.tv_sec) < 0)
    return EXECUTION_FAILURE;
  if (use_adjtime)
    ts.tv_sec -= (time_t) bhc_drift_correction (adj, ts.tv_sec);
  ts.tv_nsec = 0;
  if (clock_settime (CLOCK_REALTIME, &ts) < 0)
    {
      builtin_error ("clock_settime: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  return EXECUTION_SUCCESS;
}

static int
bhc_systohc (const char *rtc_path, enum bhc_time_mode mode)
{
  struct timespec ts;
  struct rtc_time rt;

  if (clock_gettime (CLOCK_REALTIME, &ts) < 0)
    {
      builtin_error ("clock_gettime: %s", strerror (errno));
      return EXECUTION_FAILURE;
    }
  if (bhc_time_to_rtc (ts.tv_sec, mode, &rt) < 0)
    return EXECUTION_FAILURE;
  if (bhc_write_rtc (rtc_path, &rt) < 0)
    return EXECUTION_FAILURE;
  return EXECUTION_SUCCESS;
}

static int
bhc_adjust (const char *rtc_path, const char *adj_path,
            enum bhc_time_mode mode, struct bhc_adjtime *adj)
{
  struct rtc_time rt;
  time_t rtc_time, adjusted;
  double correction;

  if (adj->last_adjust == 0)
    {
      builtin_error ("%s: last adjustment time is zero", adj_path);
      return EXECUTION_FAILURE;
    }

  memset (&rt, 0, sizeof rt);
  if (bhc_read_rtc (rtc_path, &rt) < 0)
    return EXECUTION_FAILURE;
  if (bhc_rtc_to_time (&rt, mode, &rtc_time) < 0)
    return EXECUTION_FAILURE;

  correction = bhc_drift_correction (adj, rtc_time);
  if (correction < 1.0 && correction > -1.0)
    return EXECUTION_SUCCESS;

  adjusted = rtc_time - (time_t) correction;
  if (bhc_time_to_rtc (adjusted, mode, &rt) < 0)
    return EXECUTION_FAILURE;
  if (bhc_write_rtc (rtc_path, &rt) < 0)
    return EXECUTION_FAILURE;

  adj->last_adjust = (long long) adjusted;
  adj->not_adjusted = 0.0;
  adj->mode = mode;
  if (bhc_write_adjtime (adj_path, adj) < 0)
    return EXECUTION_FAILURE;
  return EXECUTION_SUCCESS;
}

static int
bhc_help (void)
{
  puts ("hwclock — hwclock(8) subset over /dev/rtc0");
  puts ("usage: hwclock [--show] [--utc|--localtime] [--rtc PATH|--rtc=PATH]");
  puts ("       hwclock --hctosys [--utc|--localtime] [--rtc PATH|--rtc=PATH]");
  puts ("       hwclock --systohc [--utc|--localtime] [--rtc PATH|--rtc=PATH]");
  puts ("       hwclock --adjust [--adjfile PATH] [--rtc PATH|--rtc=PATH]");
  puts ("       hwclock --help | --version");
  puts ("Default mode treats RTC as UTC unless /etc/adjtime says LOCAL.");
  puts ("Short forms (util-linux): -r show, -s hctosys, -w systohc, -a adjust,");
  puts ("  -u utc, -l localtime, -f PATH rtc, -V version.");
  puts ("--adjfile PATH selects an alternate adjtime file; --noadjfile disables it.");
  puts ("--hctosys/--systohc need CAP_SYS_TIME.");
  return EXECUTION_SUCCESS;
}

int
hwclock_builtin (WORD_LIST *list)
{
  enum { BHC_SHOW, BHC_HCTOSYS, BHC_SYSTOHC, BHC_ADJUST } action = BHC_SHOW;
  int action_seen = 0;
  enum bhc_time_mode time_mode = BHC_UTC;
  int time_mode_seen = 0;
  int use_adjtime = 1;
  const char *rtc_path = BHC_RTC_PATH;
  const char *adj_path = BHC_ADJTIME_PATH;
  struct bhc_adjtime adj;

  for (; list; list = list->next)
    {
      const char *arg = list->word->word;
      if (strcmp (arg, "--help") == 0 || strcmp (arg, "-h") == 0)
        return bhc_help ();
      if (strcmp (arg, "--version") == 0 || strcmp (arg, "-V") == 0)
        { puts ("hwclock 0.4"); return EXECUTION_SUCCESS; }
      if (strcmp (arg, "--adjfile") == 0)
        {
          list = list->next;
          if (list == 0)
            {
              builtin_error ("--adjfile: option requires an argument");
              builtin_usage ();
              return EX_USAGE;
            }
          adj_path = list->word->word;
          use_adjtime = 1;
          continue;
        }
      if (strncmp (arg, "--adjfile=", 10) == 0)
        {
          adj_path = arg + 10;
          if (*adj_path == '\0')
            {
              builtin_error ("--adjfile: empty path");
              builtin_usage ();
              return EX_USAGE;
            }
          use_adjtime = 1;
          continue;
        }
      if (strcmp (arg, "--noadjfile") == 0)
        {
          use_adjtime = 0;
          continue;
        }
      if (strcmp (arg, "--utc") == 0 || strcmp (arg, "-u") == 0)
        {
          if (time_mode_seen && time_mode != BHC_UTC)
            goto multiple_time_modes;
          time_mode = BHC_UTC;
          time_mode_seen = 1;
          continue;
        }
      if (strcmp (arg, "--localtime") == 0 || strcmp (arg, "-l") == 0)
        {
          if (time_mode_seen && time_mode != BHC_LOCALTIME)
            goto multiple_time_modes;
          time_mode = BHC_LOCALTIME;
          time_mode_seen = 1;
          continue;
        }
      if (strcmp (arg, "--rtc") == 0 || strcmp (arg, "-f") == 0)
        {
          list = list->next;
          if (list == 0)
            {
              builtin_error ("--rtc: option requires an argument");
              builtin_usage ();
              return EX_USAGE;
            }
          rtc_path = list->word->word;
          continue;
        }
      if (strncmp (arg, "--rtc=", 6) == 0)
        {
          rtc_path = arg + 6;
          if (*rtc_path == '\0')
            {
              builtin_error ("--rtc: empty path");
              builtin_usage ();
              return EX_USAGE;
            }
          continue;
        }

      if (strcmp (arg, "--show") == 0 || strcmp (arg, "-r") == 0)
        {
          if (action_seen && action != BHC_SHOW)
            goto multiple_actions;
          action = BHC_SHOW;
          action_seen = 1;
          continue;
        }
      if (strcmp (arg, "--hctosys") == 0 || strcmp (arg, "-s") == 0)
        {
          if (action_seen)
            goto multiple_actions;
          action = BHC_HCTOSYS;
          action_seen = 1;
          continue;
        }
      if (strcmp (arg, "--systohc") == 0 || strcmp (arg, "-w") == 0)
        {
          if (action_seen)
            goto multiple_actions;
          action = BHC_SYSTOHC;
          action_seen = 1;
          continue;
        }
      if (strcmp (arg, "--adjust") == 0 || strcmp (arg, "-a") == 0)
        {
          if (action_seen)
            goto multiple_actions;
          action = BHC_ADJUST;
          action_seen = 1;
          continue;
        }

      builtin_error ("unknown option: %s", arg);
      builtin_usage ();
      return EX_USAGE;
    }

  if (use_adjtime)
    {
      if (bhc_parse_adjtime (adj_path, &adj) < 0)
        return EXECUTION_FAILURE;
      if (!time_mode_seen)
        time_mode = adj.mode;
      else
        adj.mode = time_mode;
    }
  else
    {
      memset (&adj, 0, sizeof adj);
      adj.mode = time_mode;
    }

  if (action == BHC_ADJUST && use_adjtime == 0)
    {
      builtin_error ("--adjust requires an adjtime file");
      builtin_usage ();
      return EX_USAGE;
    }

  switch (action)
    {
    case BHC_SHOW:
      return bhc_show (rtc_path);
    case BHC_HCTOSYS:
      return bhc_hctosys (rtc_path, time_mode, &adj, use_adjtime);
    case BHC_SYSTOHC:
      return bhc_systohc (rtc_path, time_mode);
    case BHC_ADJUST:
      return bhc_adjust (rtc_path, adj_path, time_mode, &adj);
    }
  return EXECUTION_FAILURE;

multiple_actions:
  builtin_error ("choose only one action");
  builtin_usage ();
  return EX_USAGE;

multiple_time_modes:
  builtin_error ("choose only one time mode");
  builtin_usage ();
  return EX_USAGE;
}

char *hwclock_doc[] = {
  "hwclock(8) subset over /dev/rtc0.",
  "",
  "    hwclock [--show] [--utc|--localtime] [--rtc PATH|--rtc=PATH]",
  "    hwclock --hctosys [--utc|--localtime] [--rtc PATH|--rtc=PATH]",
  "    hwclock --systohc [--utc|--localtime] [--rtc PATH|--rtc=PATH]",
  "    hwclock --adjust [--adjfile PATH] [--rtc PATH|--rtc=PATH]",
  "    hwclock --help | --version",
  "",
  "Default mode treats RTC as UTC unless adjtime says LOCAL.",
  "Short forms (util-linux): -r/-s/-w/-a actions; -u/-l mode; -f PATH rtc; -V version.",
  "--adjfile PATH selects an alternate adjtime file; --noadjfile disables it.",
  "Set paths need CAP_SYS_TIME.",
  (char *)0
};

struct builtin hwclock_struct = {
  "hwclock",
  hwclock_builtin,
  BUILTIN_ENABLED,
  hwclock_doc,
  "hwclock [-r|--show|-s|--hctosys|-w|--systohc|-a|--adjust] [-u|--utc|-l|--localtime] [--adjfile PATH] [-f|--rtc PATH]",
  0
};
