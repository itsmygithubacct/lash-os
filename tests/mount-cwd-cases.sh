#!/usr/bin/env bash
# Run inside the mapped shell by mount-cwd-init.sh, using a relative script path.
set -e
[[ $# == 2 && $1 == --stats && $2 == --mount-cwd ]]
[[ $HOME == /home && $PWD == /home && ${OLDPWD-} != /previous-host-directory ]]
[[ ~ == /home && ${ pwd -P; } == /home ]]
[[ ${ stat -c '%d:%i' .; } == "$TEST_LAUNCH_ID" ]]
[[ ${ readlink /proc/self/ns/mnt; } != "$TEST_PARENT_MOUNT_NAMESPACE" ]]
printf 'PASS: relative script arguments, home environment, physical cwd, and private namespace\n'

[[ -f source && -L relative-link && ! -e /home/host-home-marker ]]
read -r value < /home/relative-link
[[ $value == original-data ]]
read -r value < nested/nested-source
[[ $value == nested-mount-data ]]
printf 'written-by-builtin\n' > /home/builtin-result
printf 'PASS: source files, relative symlinks, nested mounts, and builtin writes\n'

cd nested
cd
[[ $PWD == /home && ${ pwd -P; } == /home ]]
read -r -u 9 first
read -r -u 200 second
[[ $first == inherited-first && $second == inherited-second ]]
printf 'PASS: cd uses mapped HOME and inherited descriptors retain their shared offset\n'

parent_value=parent
( parent_value=child; [[ $PWD == /home && -f /home/source ]]; printf 'written-by-subshell\n' > /home/subshell-result )
[[ $parent_value == parent ]]
printf 'beta\nalpha\n' | sort > /home/pipeline-result
printf 'alpha\nbeta\n' > pipeline-expected
cmp pipeline-expected pipeline-result
printf 'PASS: subshells and pipelines inherit the /home mount\n'

/bin/busybox sh -c 'test "$HOME" = /home && test "$PWD" = /home && test "$(pwd -P)" = /home && test -f /home/source && test ! -e /home/host-home-marker && printf "written-by-external\n" > /home/external-result'
printf 'PASS: native external programs inherit the same /home view\n'
printf 'MOUNT_CWD_CASES_PASSED\n'
