#!/usr/bin/env python3
"""Move oversized automatic workspaces to Bash-unwind-managed heap memory."""
import argparse
import re
from pathlib import Path

HEADER = ('#include "unwind_prot.h"\n'
          'static void linux_bash_workspace_free(void *pointer) { free(pointer); }\n\n')


def adapt(path, workspaces, types=''):
    source = path.read_text().replace(HEADER + types, '')
    for function, declaration, pointer, allocation, failure, at_entry in workspaces:
        start = source.index('static int\n' + function + ' (')
        body = source.index('\n{', start)
        end = source.index('\n}', body) + 2
        prefix = source[start:body + 2]
        contents = source[body + 2:end - 2]
        tag = 'linux-bash-os:' + function
        if tag in contents:
            continue
        declarations = [declaration] if isinstance(declaration, str) else declaration
        for declaration in declarations:
            assert declaration in contents, (path, function, declaration)
        setup = ('\n  void *workspace = malloc (' + allocation + ');\n'
                 '  if (!workspace) { ' + failure + ' }\n'
                 f'  begin_unwind_frame ("{tag}");\n'
                 '  add_unwind_protect (linux_bash_workspace_free, workspace);\n')
        if at_entry:
            before = ''
            after = contents
            for declaration in declarations:
                after = after.replace(declaration, '', 1)
        else:
            assert len(declarations) == 1
            before, after = contents.split(declaration, 1)
        tail = pointer + after
        # Guard returns before allocation remain unchanged. Every subsequent
        # normal return runs cleanup; nonlocal Bash exits unwind the same frame.
        tail = re.sub(
            r'\breturn\s+([^;]+);',
            lambda m: ('{ int workspace_result = (' + m[1] + '); '
                       f'run_unwind_frame ("{tag}"); return workspace_result; }}'),
            tail)
        source = source[:start] + prefix + before + setup + tail + '\n}' + source[end:]
    first = min(source.index('static int\n' + item[0] + ' (') for item in workspaces)
    source = source[:first] + HEADER + types + source[first:]
    path.write_text(source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    adapt(args.directory / 'dns.c', [
        ('sz_sign_zone_inplace', '  char names[SZ_RR_MAX][256];',
         '  char (*names)[256] = workspace;', 'sizeof (char[256]) * SZ_RR_MAX',
         'snprintf (err, errsz, "oom"); return -1;', False),
        ('bda_slave_read_xfr', '      bd_rr_t rrs[BDA_RR_MAX + 2];',
         '  bd_rr_t *rrs = workspace;\n', 'sizeof (bd_rr_t) * (BDA_RR_MAX + 2)',
         'return -1;', True),
    ])
    adapt(args.directory / 'sv.c', [
        (function, '  struct bsv_service_meta svcs[BSV_SERVICE_MAX];',
         '  struct bsv_service_meta *svcs = workspace;',
         'sizeof (struct bsv_service_meta) * BSV_SERVICE_MAX',
         'return EXECUTION_FAILURE;', False)
        for function in ['bsv_up_target', 'bsv_down_target', 'bsv_status_target',
                         'bsv_start_enabled_ordered', 'bsv_stop_enabled_ordered',
                         'bsv_each_service']
    ] + [
        ('bsv_restart_target', '      struct bsv_service_meta svcs[BSV_SERVICE_MAX];',
         '  struct bsv_service_meta *svcs = workspace;',
         'sizeof (struct bsv_service_meta) * BSV_SERVICE_MAX',
         'return EXECUTION_FAILURE;', True)
    ])
    adapt(args.directory / 'git.c', [
        ('git_cmd_remote', [
            '        struct { char shown[4096]; const char *state; } listed[256];',
            '        struct { char local[4096]; char remote[4096]; } pulls[256];',
        ],
         '  struct linux_bash_remote_workspace *arrays = workspace;\n'
         '  __typeof__ (arrays->listed[0]) *listed = arrays->listed;\n'
         '  __typeof__ (arrays->pulls[0]) *pulls = arrays->pulls;\n',
         'sizeof (struct linux_bash_remote_workspace)',
         'return GIT_EXIT_FATAL;', True)
    ], types=('struct linux_bash_remote_workspace {\n'
              '  struct { char shown[4096]; const char *state; } listed[256];\n'
              '  struct { char local[4096]; char remote[4096]; } pulls[256];\n'
              '};\n\n'))
    print('Adapted oversized DNS, service-manager and Git workspaces')


if __name__ == '__main__':
    main()
