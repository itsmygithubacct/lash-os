#!/usr/bin/env bash
set -e
# The HTTP peer is an isolated VM-local test fixture. A kernel Bash child
# verifies its image before executing it, which can take minutes on slow CPUs.
printf 'local-http-ok\n' > index.html
/bin/busybox httpd -f -p 127.0.0.1:18999 -h . &
server=$!
trap 'kill "$server" 2>/dev/null || :; wait "$server" 2>/dev/null || :' EXIT
http_ready=0
for ((attempt=0;attempt<3000;attempt++)); do
    if curl -fsS --max-time 30 http://127.0.0.1:18999/ > response 2>curl-error; then
        http_ready=1
        break
    fi
    sleep 0.1
done
if [[ $http_ready == 0 ]]; then
    cat curl-error >&2
    printf 'HTTP fixture did not become ready\n' >&2
    exit 73
fi
cmp index.html response
printf 'HTTP loopback: yes\n'
post_dns=$(curl -fsS --max-time 30 http://localhost:18999/ > child-response && printf 'fork after name lookup')
[[ $post_dns == 'fork after name lookup' ]]
cmp index.html child-response
printf '%s\n' "$post_dns"
kill "$server"
wait "$server" 2>/dev/null || :
trap - EXIT
rm index.html response child-response curl-error
printf 'NETWORK_CASES_PASSED\n'
