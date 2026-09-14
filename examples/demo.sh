printf 'GNU Bash %s running on %s\n' "$BASH_VERSION" "$MACHTYPE"
printf 'These are statically linked commands:\n'
type cat cut seq stat uname
declare -A squares
for ((i=1; i<=5; i++)); do squares[$i]=$((i*i)); done
printf 'Squares calculated in the kernel:'
for i in 1 2 3 4 5; do printf ' %s' "${squares[$i]}"; done
printf '\n'
name=${ uname -s; }
printf 'Host kernel: %s\n' "$name"
printf 'File metadata through the host bridge:\n'
stat -c '%n: %s bytes' examples/demo.sh
