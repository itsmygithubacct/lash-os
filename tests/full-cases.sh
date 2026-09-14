#!/usr/bin/env bash
set -e
export LC_ALL=C
source /core-cases.sh
# Registration is checked independently of functional coverage.
while IFS= read -r name; do
    type -t "$name" > type-result
    read -r kind < type-result
    [[ $kind == builtin ]] || { printf 'missing builtin: %s\n' "$name"; exit 61; }
    help "$name" >/dev/null
    ((++registered))
done < /builtin-names
printf 'registered bash-os builtins: %d\n' "$registered"
[[ $registered == 279 ]]
printf 'gamma 3\nalpha 1\nbeta 2\n' > data
printf 'alpha 1\nbeta 2\ngamma 3\n' > sorted-expected
sort < data > sorted-stdin
cmp sorted-expected sorted-stdin
awk 'END {print NR}' < data > records
read -r record_count < records
[[ $record_count == 3 ]]
# A stdio consumer must leave the next byte for a subsequent shell builtin.
{ head -n 1; read -r remainder; printf '%s\n' "$remainder"; } < data > shared-stdin
printf 'gamma 3\nalpha 1\n' > shared-expected
cmp shared-expected shared-stdin
printf 'beta 2\nalpha 1\ngamma 3\n' | sort > sorted-pipe
cmp sorted-expected sorted-pipe
printf 'implicit stdin, shared input, and sort pipeline: yes\n'
rm sorted-expected sorted-stdin sorted-pipe records shared-stdin shared-expected
exec {path_fd}<data
[[ -L /dev/fd/$path_fd && -f /proc/self/fd/$path_fd ]]
read -r fd_line < /dev/fd/$path_fd
[[ $fd_line == 'gamma 3' ]]
read -r fd_line < /proc/self/fd/$path_fd
[[ $fd_line == 'gamma 3' ]]
exec {path_fd}<&-
[[ ! -e /dev/fd/$path_fd ]]
fd_alias=${ printf 'stream alias' > /dev/stdout; }
[[ $fd_alias == 'stream alias' ]]
printf 'descriptor paths: yes\n'
printf 'sort: '; sort data | head -n 1
printf 'grep: '; grep -E 'b.ta[[:space:]]+[0-9]'  data
pcre match '(?<=alpha )([0-9]+)' 'alpha 123'
[[ ${BPCRE_MATCH[1]} == 123 ]]
printf 'pcre capture: %s\n' "${BPCRE_MATCH[1]}"
printf 'sed: '; sed -n 's/alpha/first/p' data
printf 'awk: '; awk '{sum += $2} END {print sum}' data
printf '{"items":[1,2,3]}\n' > input.json
printf 'jq: '; jq '.items | map(. * 2)' input.json
printf 'abc' > message
obj hash --stdin -V object_hash < message
[[ $object_hash == f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f ]]
printf 'object hash: %s\n' "$object_hash"
printf 'sha256: '; crypto sha256 -x message
printf 'base64: '; bashbase64 < message; printf '\n'
cp data copied
cmp data copied
mv copied renamed
truncate -s 128 renamed
[[ $(stat -c %s renamed) == 128 ]]
printf 'files: yes\n'
zstd -c data > data.zst
zstd -dc data.zst > restored
cmp data restored
printf 'zstd round trip: yes\n'
pax -w -f bundle.tar data message
mkdir extract
(cd extract; pax -r -f ../bundle.tar)
cmp data extract/data
printf 'archive round trip: yes\n'
sqlite open state.db -h db
sqlite exec "$db" 'CREATE TABLE numbers(n INTEGER); INSERT INTO numbers VALUES(7),(9);'
sqlite prepare "$db" 'SELECT sum(n) FROM numbers' -h query
sqlite step "$query" -V row
printf 'sqlite row: %s\n' "$row"
sqlite finalize "$query"
sqlite close "$db"
printf 'random: '; token=$(crypto random 8 -x); [[ ${#token} == 16 ]]; printf '8 bytes\n'
# Exercise repeated large-workspace allocation and cleanup in a private tree.
mkdir services service-run service-log
export BASHSV_DIR="$PWD/services" BASHSV_RUNDIR="$PWD/service-run" BASHSV_LOGDIR="$PWD/service-log"
for ((service_check=0;service_check<32;service_check++)); do sv status; done
unset BASHSV_DIR BASHSV_RUNDIR BASHSV_LOGDIR
rmdir services service-run service-log
printf 'service workspace reuse: yes\n'
read -r line < <(printf 'process-substitution\n')
printf '%s\n' "$line"
coproc worker { read -r value; printf 'coprocess:%s\n' "$value"; }
worker_pid_saved=$worker_PID
printf 'hello\n' >&"${worker[1]}"
read -r response <&"${worker[0]}"
printf '%s\n' "$response"
wait "$worker_pid_saved"
source /network-cases.sh
rm -r input.json type-result data message renamed data.zst restored bundle.tar extract state.db
printf 'FULL_CASES_PASSED\n'
