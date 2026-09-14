#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /dev/pts
/bin/busybox mount -t devpts devpts /dev/pts
export PATH=/bin LC_ALL=C HOME=/root
/bin/busybox mkdir -p /tmp/native /tmp/kernel
echo "RUN: native reference"
cd /tmp/native
/native-bash --noprofile --norc /cases.sh > /tmp/native.out 2> /tmp/native.err
native_rc=$?
echo "RUN: kernel Bash"
cd /tmp/kernel
/bin/busybox timeout -s KILL 40 /kernel-bash --stats /cases.sh > /tmp/kernel.out 2> /tmp/kernel.err
kernel_rc=$?
/bin/busybox cat /tmp/kernel.out /tmp/kernel.err
result=0
if [ "$native_rc" != 0 ] || [ "$kernel_rc" != 0 ]; then
    echo "FAIL: native=$native_rc kernel=$kernel_rc"
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
printf 'v=interactive; printf "PTY_%%s_OK\\n" "$v"\nexit\n' | /bin/busybox timeout -s KILL 20 /bin/script -qec '/kernel-bash -i' /tmp/tty.log > /tmp/tty.out 2>&1
if [ "$?" != 0 ] || ! /bin/busybox grep -q PTY_interactive_OK /tmp/tty.out; then
    echo 'FAIL: interactive terminal'; /bin/busybox cat /tmp/tty.out; result=1
else echo 'PASS: interactive terminal'; fi
if /job-control-test /kernel-bash; then echo 'PASS: terminal job control and signal traps';
else echo 'FAIL: terminal job control and signal traps'; result=1; fi
echo "KERNEL_BASH_TEST_EXIT=$result"
/bin/busybox poweroff -f
