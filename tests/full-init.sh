#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /dev/pts
/bin/busybox mount -t devpts devpts /dev/pts
/bin/busybox ln -s /proc/self/fd /dev/fd
/bin/busybox ln -s /proc/self/fd/0 /dev/stdin
/bin/busybox ln -s /proc/self/fd/1 /dev/stdout
/bin/busybox ln -s /proc/self/fd/2 /dev/stderr
export PATH=/bin LC_ALL=C HOME=/root
/bin/busybox mkdir -p /tmp/native /tmp/kernel
/bin/busybox ip link set lo up
echo "RUN: native reference"
cd /tmp/native
/native-bash --noprofile --norc /cases.sh > /tmp/native.out 2> /tmp/native.err
native_rc=$?
printf 'inherited-nine\ninherited-high\n' > /tmp/inherited-input
inherited_case='read -r -u 9 first && read -r -u 200 second && test "$first" = inherited-nine && test "$second" = inherited-high && printf "INHERITED_FDS_OK\n"'
/native-bash --noprofile --norc -c "$inherited_case" 9< /tmp/inherited-input 200<&9 > /tmp/native-fds.out
native_fds_rc=$?
if [ -f /portable-test ]; then
    /bin/busybox rm -rf /nix
    if [ -e /nix ]; then
        echo 'FAIL: could not remove Nix runtime'
        echo 'KERNEL_BASH_TEST_EXIT=1'
        /bin/busybox poweroff -f
    fi
    echo 'PASS: kernel cases run without /nix'
fi
echo "RUN: kernel Bash"
cd /tmp/kernel
# Each fork verifies a fresh full image. Report progress during the longer run.
(
    previous_line=
    unchanged=0
    while /bin/busybox sleep 20; do
        last_line=$(/bin/busybox tail -n 1 /tmp/kernel.out)
        printf 'PROGRESS: %s\n' "${last_line:-waiting for first output}"
        if [ "$last_line" = "$previous_line" ]; then
            unchanged=$((unchanged + 1))
        else
            unchanged=0
        fi
        previous_line=$last_line
        if [ "$unchanged" = 4 ]; then
            echo 'DIAGNOSTIC: shell process wait states'
            /bin/busybox ps -o pid,ppid,stat,args
            # Shell processes and every uninterruptible task, including kernel
            # workers that may hold a lock the shell is waiting for.
            for task in /proc/[0-9]*; do
                name=$(/bin/busybox cat "$task/comm" 2>/dev/null)
                status=$(/bin/busybox cat "$task/stat" 2>/dev/null) || continue
                state=${status##*) }
                state=${state%% *}
                if [ "$name" = kernel-bash ] || [ "$state" = D ]; then
                    echo "DIAGNOSTIC: $task $name state=$state"
                    /bin/busybox cat "$task/wchan" "$task/syscall" "$task/stack" 2>/dev/null
                    if [ "$name" = kernel-bash ]; then
                        /bin/busybox ls -l "$task/fd" | /bin/busybox grep -v bpf
                    fi
                fi
            done
            # Blocked tasks with their workqueue functions, and every CPU's
            # backtrace; quiet hides these at the default console level.
            printk_levels=$(/bin/busybox cat /proc/sys/kernel/printk)
            echo 8 > /proc/sys/kernel/printk
            echo 1 > /proc/sys/kernel/sysrq
            echo w > /proc/sysrq-trigger
            echo l > /proc/sysrq-trigger
            /bin/busybox sleep 2
            echo "$printk_levels" > /proc/sys/kernel/printk
            echo 'DIAGNOSTIC: kernel task dump complete'
            /bin/busybox tail -c 8192 /tmp/kernel.err
        fi
    done
) &
progress_pid=$!
/bin/busybox timeout -s KILL 1200 /kernel-bash --stats /cases.sh > /tmp/kernel.out 2> /tmp/kernel.err
kernel_rc=$?
kill "$progress_pid"
wait "$progress_pid" 2>/dev/null || :
echo 'OUTPUT: kernel Bash'
/bin/busybox cat /tmp/kernel.out
/bin/busybox tail -c 32768 /tmp/kernel.err
result=0
if [ "$native_rc" != 0 ] || [ "$kernel_rc" != 0 ]; then
    echo "FAIL: native=$native_rc kernel=$kernel_rc"
    echo 'OUTPUT: native reference'
    /bin/busybox cat /tmp/native.out /tmp/native.err
    result=1
elif ! /bin/busybox cmp /tmp/native.out /tmp/kernel.out; then
    echo 'FAIL: native and kernel output differ'
    /bin/busybox diff -u /tmp/native.out /tmp/kernel.out
    result=1
else
    echo 'PASS: native and kernel stdout match byte for byte'
fi
/kernel-bash -c 'exit 37'
if [ "$?" != 37 ]; then echo 'FAIL: exit status'; result=1; else echo 'PASS: exit status 37'; fi
/kernel-bash -c 'if then' > /tmp/error.out 2>&1
if [ "$?" != 2 ]; then echo 'FAIL: syntax error'; result=1; else echo 'PASS: syntax error status'; fi
/kernel-bash -c 'linux_bash_missing_command' > /tmp/error.out 2>&1
if [ "$?" != 127 ]; then echo 'FAIL: missing command'; result=1; else echo 'PASS: missing command status'; fi
printf 'printf "STDIN_SCRIPT_OK\\n"\n' | /kernel-bash > /tmp/stdin.out
if [ "$?" != 0 ] || ! /bin/busybox grep -qx STDIN_SCRIPT_OK /tmp/stdin.out; then
    echo 'FAIL: stdin script'; result=1
else echo 'PASS: stdin script'; fi
printf 'v=interactive; printf "PTY_%%s_OK\\n" "$v"\nexit\n' | /bin/busybox timeout -s KILL 60 /bin/script -qec '/kernel-bash -i' /tmp/tty.log > /tmp/tty.out 2>&1
if [ "$?" != 0 ] || ! /bin/busybox grep -q PTY_interactive_OK /tmp/tty.out; then
    echo 'FAIL: interactive terminal'; /bin/busybox cat /tmp/tty.out; result=1
else echo 'PASS: interactive terminal'; fi
if /job-control-test /kernel-bash; then echo 'PASS: terminal job control and signal traps';
else echo 'FAIL: terminal job control and signal traps'; result=1; fi
/kernel-bash -c "$inherited_case" 9< /tmp/inherited-input 200<&9 > /tmp/kernel-fds.out
kernel_fds_rc=$?
if [ "$native_fds_rc" != 0 ] || [ "$kernel_fds_rc" != 0 ] || ! /bin/busybox cmp /tmp/native-fds.out /tmp/kernel-fds.out || ! /bin/busybox grep -qx INHERITED_FDS_OK /tmp/kernel-fds.out; then
    echo 'FAIL: inherited descriptors'; result=1
else echo 'PASS: inherited low and high descriptors'; fi
echo "KERNEL_BASH_TEST_EXIT=$result"
/bin/busybox poweroff -f
