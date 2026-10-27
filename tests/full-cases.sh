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
[[ $registered == 286 ]]
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
mkdir -p at-tree/sub
ln message at-tree/hard
[[ message -ef at-tree/hard ]]
ln -s ../message at-tree/symbolic
ln at-tree/symbolic at-tree/symbolic-hard
[[ -L at-tree/symbolic-hard ]]
mkdir at-tree/followed at-tree/preserved
cp -aL at-tree/symbolic at-tree/symbolic-hard at-tree/followed
[[ ! -L at-tree/followed/symbolic && at-tree/followed/symbolic -ef at-tree/followed/symbolic-hard ]]
cp -a at-tree/symbolic at-tree/symbolic-hard at-tree/preserved
[[ -L at-tree/preserved/symbolic ]]
stat -c %i at-tree/preserved/symbolic > at-tree/inode-a
stat -c %i at-tree/preserved/symbolic-hard > at-tree/inode-b
cmp at-tree/inode-a at-tree/inode-b
mkfifo at-tree/pipe
[[ -p at-tree/pipe ]]
printf 'before\n' > at-tree/edit
sed -i 's/before/after/' at-tree/edit
read -r edited < at-tree/edit
[[ $edited == after ]]
rsync message at-tree/copied
cmp message at-tree/copied
fstrim --dry-run --all > /dev/null
rm -r at-tree
printf 'descriptor-relative filesystem operations: yes\n'
zstd -c data > data.zst
zstd -dc data.zst > restored
cmp data restored
printf 'zstd round trip: yes\n'
pax -w -f bundle.tar data message
mkdir extract
(cd extract; pax -r -f ../bundle.tar)
cmp data extract/data
printf 'archive round trip: yes\n'
# New full-profile builtins and APIs from bash-os 0.1.2.
base64 message > encoded
read -r encoded_line < encoded
[[ $encoded_line == YWJj ]]
base64 -d encoded > decoded
cmp message decoded
sha256sum message > digest
read -r digest_value digest_name < digest
[[ $digest_value == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad ]]
gzip -c data > data.gz
gzip -dc data.gz > decoded
cmp data decoded
tar -cf modern.tar data message
mkdir modern-extract
tar -xf modern.tar -C modern-extract
cmp message modern-extract/message
printf '2+2\nquit\n' > calculator-input
bc < calculator-input > calculator-output
read -r answer < calculator-output
[[ $answer == 4 ]]
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME=itsmygithubacct GIT_COMMITTER_NAME=itsmygithubacct
export GIT_AUTHOR_EMAIL=itsmygithubacct@users.noreply.github.com
export GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL
git init -q sample-repo
cp message sample-repo/message
git -C sample-repo add message
GIT_AUTHOR_DATE='1700000000 +0530' GIT_COMMITTER_DATE='1700000000 +0530' git -C sample-repo commit -q -m fixture
git -C sample-repo log -1 --format=%ad --date='format:%Y-%m-%d %H:%M:%S %z' > git-date
read -r git_date < git-date
[[ $git_date == '2023-11-15 03:43:20 +0530' ]]
git -C sample-repo remote add origin ../remote-fixture
git -C sample-repo remote show -n origin > remote-info
if git -C sample-repo remote get-url missing > /dev/null 2>&1; then exit 64; fi
grep -q 'Fetch URL: ../remote-fixture' remote-info
rm remote-info
ipcmk --posix-semaphore --name /lashos-sem-$$ > /dev/null
[[ -f /dev/shm/sem.lashos-sem-$$ ]]
if ipcmk --posix-semaphore --name /lashos-sem-$$ > /dev/null 2>&1; then exit 62; fi
rm /dev/shm/sem.lashos-sem-$$
ipcmk --posix-mqueue --name /lashos-mq-$$ > /dev/null
[[ -e /dev/mqueue/lashos-mq-$$ ]]
rm /dev/mqueue/lashos-mq-$$
rm -r encoded decoded digest data.gz modern.tar modern-extract calculator-input calculator-output sample-repo git-date
printf 'bash-os 0.1.2 archive, hash, Git, calculator and IPC builtins: yes\n'
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
for ((service_check=0;service_check<32;service_check++)); do
    sv status
    if sv restart missing > /dev/null 2>&1; then exit 63; fi
done
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
