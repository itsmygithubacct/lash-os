#!/usr/bin/env bash
set -e
value=parent
( value=child; printf 'subshell: %s\n' "$value" )
[[ $value == parent ]]
curl -fsS http://localhost:18999/ > response
read -r reply < response
[[ $reply == fiber-pool-fixture ]]
# Resolver allocations use the second fiber. Copy its idle state, then lease
# it again in the child; neither fiber ID has a fixed role.
captured=$(curl -fsS http://localhost:18999/ > response && printf 'child after resolver')
[[ $captured == 'child after resolver' ]]
printf '%s\n' "$captured"
/bin/busybox sh -c 'test ! -e /proc/self/fd/100 && printf "external descriptors: yes\n"'
shopt -s execfail
set +e
for ((attempt=0;attempt<20;attempt++)); do
    exec /linux_bash_missing_exec 2> exec-error
    [[ $? == 127 ]] || exit 71
done
set -e
printf 'repeated exec rollback: yes\n'
printf 'PROCESS_CASES_PASSED\n'
