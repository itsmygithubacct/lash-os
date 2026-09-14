#!/usr/bin/env python3
"""Move oversized automatic workspaces to Bash-unwind-managed heap memory."""
import argparse
import re
from pathlib import Path

HEADER = ('#include "unwind_prot.h"\n'
          'static void linux_bash_workspace_free(void *pointer) { free(pointer); }\n\n')


def adapt(path, workspaces):
    source = path.read_text().replace(HEADER, '')
    for function, declaration, pointer, allocation, failure, at_entry in workspaces:
        start = source.index('static int\n' + function + ' (')
        body = source.index('\n{', start)
        end = source.index('\n}', body) + 2
        prefix = source[start:body + 2]
        contents = source[body + 2:end - 2]
        tag = 'linux-bash-os:' + function
        if tag in contents:
            continue
        assert declaration in contents, (path, function)
        setup = ('\n  void *workspace = malloc (' + allocation + ');\n'
                 '  if (!workspace) { ' + failure + ' }\n'
                 f'  begin_unwind_frame ("{tag}");\n'
                 '  add_unwind_protect (linux_bash_workspace_free, workspace);\n')
        if at_entry:
            before = ''
            after = contents.replace(declaration, '', 1)
        else:
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
    source = source[:first] + HEADER + source[first:]
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
    ])
    print('Adapted oversized DNS and service-manager workspaces')


if __name__ == '__main__':
    main()
