# Run by both the native reference and the kernel build in a temporary directory.
set -e
printf 'GNU Bash %s\n' "$BASH_VERSION"
printf 'arithmetic: %d\n' "$(( (19 * 23) - 17 ))"
sum=0
for ((i=0; i<1000; i++)); do ((sum+=i)) || :; done
printf 'loop: %d\n' "$sum"
factorial() { local n=$1; if ((n<2)); then result=1; else factorial "$((n-1))"; ((result*=n)); fi; }
factorial 8
printf 'recursion: %s\n' "$result"
a=('hello world' beta gamma)
printf 'array: <%s>\n' "${a[@]}"
declare -A map=([red]=17 [blue]=42)
printf 'associative: %s %s\n' "${map[red]}" "${map[blue]}"
text='alpha/beta/gamma'
printf 'expansion: %s %s %s\n' "${text##*/}" "${text/alpha/omega}" "${text:6:4}"
case $text in alpha/*) printf 'case: yes\n';; *) exit 41;; esac
[[ abc123 == abc* ]] && printf 'pattern: yes\n'
set -- 'one two' three
printf 'arguments: %s <%s> <%s>\n' "$#" "$1" "$2"
printf 'braces: %s\n' {a,b}{1,2}
printf 'seq: '; seq -s , 2 2 8
printf 'basename: '; basename /one/two/file.txt .txt
printf 'dirname: '; dirname /one/two/file.txt
printf 'redirection\n'
printf 'alpha:1\nbeta:2\ngamma:3\n' > input
printf 'cat:\n'; cat input
printf 'cut:\n'; cut -d : -f 2 input
printf 'head:\n'; head -n 2 input
printf 'tee:\n'; tee copy < input
[[ -f input && -s input ]] || exit 42
chmod 600 input
printf 'stat: '; stat -c '%s %a' input
ln -s input linked
[[ -L linked ]] || exit 43
printf 'glob: %s\n' inp* lin*
printf 'source_value=loaded\n' > sourced.sh
. ./sourced.sh
printf 'source: %s\n' "$source_value"
printf 'read:\n'
while IFS=: read -r name value; do printf '%s=%s\n' "$name" "$value"; done < input
mkdir child
cd child
[[ $PWD == */child ]] || exit 44
cd ..
rmdir child
mktemp -d -v temporary_dir scratch.XXXXXX > /dev/null
[[ -d $temporary_dir ]] || exit 45
rmdir "$temporary_dir"
printf 'temporary directory: yes\n'
resolved=${ realpath .; }
[[ $resolved == "$PWD" ]] || exit 46
printf 'realpath: yes\n'
mkfifo fifo
[[ -p fifo ]] || exit 47
unlink fifo
printf 'fifo: yes\n'
printf 'identity: '; id -u
printf 'whoami: '; whoami
printf 'uname: '; uname -s
printf 'nofork substitution: <%s>\n' "${ printf 'captured'; }"
set +e
trap 'printf "ERR trap\n"' ERR
false
trap - ERR
set -e
printf 'trap names: %s %s\n' "${ trap -p; }" "${ kill -l INT; }"
parent_value=parent
( parent_value=child; printf 'subshell: %s\n' "$parent_value" )
printf 'parent after subshell: %s\n' "$parent_value"
captured=$(printf 'command substitution')
printf 'capture: %s\n' "$captured"
printf 'first:1\nsecond:2\n' | cut -d : -f 1 | cat
sleep 0.01 &
child_pid=$!
wait "$child_pid"
printf 'background wait: yes\n'
set -o pipefail
if false | true; then exit 51; fi
set +o pipefail
false | true
printf 'pipeline statuses: %s %s\n' "${PIPESTATUS[0]}" "${PIPESTATUS[1]}"
seq 1 20000 | { count=0; while read -r line; do ((++count)); done; printf 'large pipe: %d\n' "$count"; }
/bin/busybox printf 'external program: yes\n'
set +e
shopt -s execfail
exec /linux_bash_missing_exec 2>exec-error
[[ $? == 127 ]] || exit 52
set -e
printf 'failed exec rollback: yes\n'
if ( exec /bin/busybox sh -c 'exit 23' ); then exit 53; else [[ $? == 23 ]]; fi
printf 'external exit status: yes\n'
rm input copy linked sourced.sh exec-error
trap 'printf "EXIT trap\n"' EXIT
printf 'ALL_CASES_PASSED\n'
