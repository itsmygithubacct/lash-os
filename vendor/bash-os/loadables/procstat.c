/* SPDX-License-Identifier: MIT */
/* Linux process/accounting snapshots. Written from the documented proc ABI:
   https://docs.kernel.org/filesystems/proc.html
   https://docs.kernel.org/admin-guide/iostats.html
   The upstream command/help surface supplies the verbs; its implementation
   is not incorporated here. Counters are snapshots, without interval sampling. */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include "loadables.h"

static const char *proc_root (void)
{
  const char *root = getenv ("BASHOS_PROC_ROOT");
  return root && *root ? root : "/proc";
}
static FILE *proc_open (const char *pid, const char *leaf, int quiet)
{
  const char *root = proc_root ();
  size_t n = strlen (root) + (pid ? strlen (pid) : 0) + strlen (leaf) + 3;
  char *path = xmalloc (n);
  snprintf (path, n, "%s/%s%s%s", root, pid ? pid : "", pid ? "/" : "", leaf);
  FILE *fp = fopen (path, "r");
  if (!fp && !quiet) builtin_error ("%s: %s", path, strerror (errno));
  free (path);
  return fp;
}
static int proc_pid (const char *s)
{
  if (!s || !*s) return 0;
  unsigned long n = 0;
  for (; *s; s++) {
    if (!isdigit ((unsigned char) *s) || n > (INT_MAX - (unsigned) (*s - '0')) / 10UL) return 0;
    n = n * 10 + (unsigned) (*s - '0');
  }
  return n > 0;
}
static int proc_end (FILE *fp)
{
  int failed = ferror (fp);
  if (fclose (fp) != 0) failed = 1;
  if (failed) builtin_error ("read failed");
  return failed;
}
static double proc_uptime (void)
{
  FILE *fp = proc_open (NULL, "uptime", 0);
  if (!fp) return -1;
  double value = 0;
  int valid = fscanf (fp, "%lf", &value) == 1 && value > 0;
  if (proc_end (fp) || !valid) return -1;
  return value;
}
static int proc_cpu (int all)
{
  FILE *fp = proc_open (NULL, "stat", 0);
  if (!fp) return 1;
  char *line = NULL; size_t cap = 0; int count = 0;
  puts ("CPU %usr %nice %sys %iowait %irq %soft %steal %guest %gnice %idle");
  while (getline (&line, &cap, fp) >= 0) {
    char label[32] = {0}; uint64_t v[10] = {0};
    int fields = sscanf (line, "%31s %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64
                         " %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64,
                         label, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9]);
    if (strncmp (label, "cpu", 3) || (label[3] && !isdigit ((unsigned char) label[3]))) continue;
    if (fields < 5) { free (line); proc_end (fp); builtin_error ("malformed CPU counters"); return 1; }
    if (!all && label[3]) continue;
    long double total = 0; for (int i = 0; i < 8; i++) total += v[i];
    long double scale = total > 0 ? 100 / total : 0;
    uint64_t user = v[0] >= v[8] ? v[0] - v[8] : 0;
    uint64_t nice = v[1] >= v[9] ? v[1] - v[9] : 0;
    printf ("%s %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf %.2Lf\n",
            label[3] ? label + 3 : "all", user*scale, nice*scale, v[2]*scale,
            v[4]*scale, v[5]*scale, v[6]*scale, v[7]*scale, v[8]*scale, v[9]*scale, v[3]*scale);
    count++;
  }
  free (line);
  return proc_end (fp) || count == 0;
}
static int proc_disks (void)
{
  double uptime = proc_uptime ();
  if (uptime <= 0) return 1;
  FILE *fp = proc_open (NULL, "diskstats", 0);
  if (!fp) return 1;
  char *line = NULL; size_t cap = 0;
  puts ("Device tps kB_read/s kB_wrtn/s kB_read kB_wrtn");
  while (getline (&line, &cap, fp) >= 0) {
    unsigned major, minor; char name[128]; uint64_t v[7];
    if (sscanf (line, "%u %u %127s %"SCNu64" %"SCNu64" %"SCNu64" %"SCNu64
                      " %"SCNu64" %"SCNu64" %"SCNu64,
                &major, &minor, name, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]) != 10) {
      free (line); proc_end (fp); builtin_error ("malformed disk counters"); return 1;
    }
    printf ("%s %.2Lf %.2Lf %.2Lf %.1Lf %.1Lf\n", name,
            ((long double) v[0]+v[4])/uptime, v[2]/(2.0L*uptime), v[6]/(2.0L*uptime), v[2]/2.0L, v[6]/2.0L);
  }
  free (line); return proc_end (fp);
}
/* stat's command is parenthesized and can contain spaces and ')' characters.
   Only fields needed by these reports are parsed; the final ')' delimits it. */
static int proc_task (const char *pid, int raw, int terse, double uptime, int quiet)
{
  FILE *fp = proc_open (pid, "stat", quiet);
  if (!fp) return quiet ? 0 : 1;
  char *line = NULL; size_t cap = 0;
  ssize_t length = getline (&line, &cap, fp);
  int failed = proc_end (fp);
  if (length < 0 || failed) { free (line); return 1; }
  if (raw) { fwrite (line, 1, (size_t) length, stdout); free (line); return 0; }
  char *start = strchr (line, '('), *end = strrchr (line, ')');
  uint64_t values[52] = {0}; char state = 0;
  int valid = start && end && end > start && end[1] == ' ' && end[2] && end[3] == ' ';
  if (valid) {
    state = end[2]; *end = 0;
    char *cursor = end + 4, *save = NULL;
    for (int field = 4; field <= 24; field++) {
      char *token = strtok_r (field == 4 ? cursor : NULL, " \t\n", &save);
      if (!token) { valid = 0; break; }
      /* Signed fields (tty, child times, priority) are skipped. */
      if (field != 4 && field != 14 && field != 15 && field != 20 && field != 22 && field != 23 && field != 24) continue;
      errno = 0; char *tail; values[field] = strtoull (token, &tail, 10);
      if (token[0] == '-' || errno || tail == token || *tail) { valid = 0; break; }
    }
  }
  if (!valid) { free (line); if (!quiet) builtin_error ("%s: malformed process stat", pid); return quiet ? 0 : 1; }
  long ticks = sysconf (_SC_CLK_TCK), pagesize = sysconf (_SC_PAGESIZE);
  if (ticks <= 0 || pagesize <= 0) { free (line); return 1; }
  if (terse) {
    double elapsed = uptime - (double) values[22]/ticks;
    double factor = elapsed > 0 ? 100.0 / ticks / elapsed : 0;
    printf ("%s %.2f %.2f %.2f %.0Lf %s\n", pid,
            values[14]*factor, values[15]*factor, ((double) values[14]+values[15])*factor,
            (long double) values[24]*pagesize/1024, start+1);
  } else {
    printf ("Process: %s (%s)\nState: %c\nParent: %"PRIu64"\nThreads: %"PRIu64
            "\nUser seconds: %.2f\nSystem seconds: %.2f\nVirtual bytes: %"PRIu64
            "\nResident KiB: %.0Lf\n", pid, start+1, state, values[4], values[20],
            (double) values[14]/ticks, (double) values[15]/ticks, values[23],
            (long double) values[24]*pagesize/1024);
  }
  free (line); return 0;
}
static int proc_dir_filter (const struct dirent *entry) { return proc_pid (entry->d_name); }
static int proc_pidstat (const char *pid)
{
  double uptime = proc_uptime ();
  if (uptime <= 0) return 1;
  puts ("PID %usr %system %CPU RSS_KiB Command");
  if (pid) return proc_task (pid, 0, 1, uptime, 0);
  struct dirent **entries;
  int n = scandir (proc_root (), &entries, proc_dir_filter, versionsort);
  if (n < 0) { builtin_error ("%s: %s", proc_root (), strerror (errno)); return 1; }
  int result = 0;
  for (int i = 0; i < n; i++) {
    result |= proc_task (entries[i]->d_name, 0, 1, uptime, 1);
    free (entries[i]);
  }
  free (entries); return result;
}
static int proc_maps (const char *pid, int extended, int libraries)
{
  FILE *fp = proc_open (pid, "maps", 0);
  if (!fp) return 1;
  char *line = NULL; size_t cap = 0; long double total = 0;
  char **seen = NULL; size_t count = 0;
  printf ("%s:\n", pid);
  if (!libraries) puts (extended ? "Address Kbytes Mode Offset Mapping" : "Address Kbytes Mode Mapping");
  int result = 0;
  while (getline (&line, &cap, fp) >= 0) {
    uint64_t start, end, offset, inode; unsigned major, minor; char mode[5]; int position = 0;
    if (sscanf (line, "%"SCNx64"-%"SCNx64" %4s %"SCNx64" %x:%x %"SCNu64" %n",
                &start, &end, mode, &offset, &major, &minor, &inode, &position) != 7 || end < start || !position) {
      builtin_error ("%s: malformed mapping", pid); result = 1; break;
    }
    char *name = line + position;
    name[strcspn (name, "\n")] = 0;
    if (libraries) {
      if (*name != '/' || !strstr (name, ".so")) continue;
      size_t i; for (i = 0; i < count; i++) if (!strcmp (seen[i], name)) break;
      if (i < count) continue;
      seen = xreallocarray (seen, count + 1, sizeof *seen);
      size_t len = strlen (name) + 1; seen[count] = xmalloc (len); memcpy (seen[count++], name, len);
      puts (name);
    } else {
      long double kib = (end - start)/1024.0L; total += kib;
      printf ("%016"PRIx64" %.0Lf %s ", start, kib, mode);
      if (extended) printf ("%016"PRIx64" ", offset);
      puts (*name ? name : "[anon]");
    }
  }
  for (size_t i = 0; i < count; i++) free (seen[i]); free (seen);
  if (!libraries) printf ("total %.0LfK\n", total);
  free (line); return proc_end (fp) || result;
}
static void proc_help (void)
{
  puts ("procstat iostat [-d] | mpstat [-P ALL] | sar [-u] | pidstat [-p PID]\n"
        "procstat prtstat [-r] PID... | pmap [-x] PID... | pldd PID\n"
        "Linux snapshots. CPU/disk averages are since boot; process CPU averages\n"
        "are since process start. pmap -x adds file offsets; pldd lists mapped\n"
        "shared-object paths. BASHOS_PROC_ROOT selects an alternate proc tree.");
}
int procstat_builtin (WORD_LIST *list)
{
  clearerr (stdout);
  if (!list) { proc_help (); return EX_USAGE; }
  const char *verb = list->word->word; WORD_LIST *args = list->next;
  if (!strcmp (verb, "--help") || (args && (!strcmp (args->word->word, "--help") || !strcmp (args->word->word, "-h")))) {
    proc_help (); return 0;
  }
  int result = EX_USAGE;
  if (!strcmp (verb, "iostat")) {
    if (!args || (!args->next && !strcmp (args->word->word, "-d"))) result = proc_disks ();
  } else if (!strcmp (verb, "mpstat") || !strcmp (verb, "sar")) {
    if (!args) result = proc_cpu (0);
    else if (!strcmp (verb, "sar") && !args->next && !strcmp (args->word->word, "-u")) result = proc_cpu (0);
    else if (!strcmp (verb, "mpstat") && args->next && !args->next->next && !strcmp (args->word->word, "-P") && !strcmp (args->next->word->word, "ALL")) result = proc_cpu (1);
  } else if (!strcmp (verb, "pidstat")) {
    if (!args) result = proc_pidstat (NULL);
    else if (!strcmp (args->word->word, "-p") && args->next && !args->next->next && proc_pid (args->next->word->word)) result = proc_pidstat (args->next->word->word);
  } else if (!strcmp (verb, "prtstat") || !strcmp (verb, "pmap") || !strcmp (verb, "pldd")) {
    int raw = 0, extended = 0, libraries = !strcmp (verb, "pldd");
    if (args && !strcmp (verb, "prtstat") && !strcmp (args->word->word, "-r")) { raw = 1; args = args->next; }
    if (args && !strcmp (verb, "pmap") && !strcmp (args->word->word, "-x")) { extended = 1; args = args->next; }
    int valid = args != NULL && (!libraries || !args->next);
    for (WORD_LIST *p = args; p; p = p->next) if (!proc_pid (p->word->word)) valid = 0;
    if (valid) {
      result = 0;
      for (WORD_LIST *p = args; p; p = p->next)
        result |= !strcmp (verb, "prtstat") ? proc_task (p->word->word, raw, 0, 0, 0) : proc_maps (p->word->word, extended, libraries);
    }
  }
  if (result == EX_USAGE) builtin_usage ();
  if (fflush (stdout) == EOF || ferror (stdout)) result = 1;
  return result;
}
char *procstat_doc[] = {
  "Linux CPU, disk, process, and mapping snapshots (procstat --help for options).",
  "CPU/disk counters are averaged since boot; process CPU usage since start.",
  "prtstat -r emits raw stat; pmap -x adds offsets; pldd lists mapped .so paths.",
  "BASHOS_PROC_ROOT selects the proc tree. No interval or history collection.",
  (char *) NULL
};
struct builtin procstat_struct = {
  "procstat", procstat_builtin, BUILTIN_ENABLED, procstat_doc,
  "procstat iostat|mpstat|sar|pidstat|prtstat|pmap|pldd [OPTIONS]", 0
};
