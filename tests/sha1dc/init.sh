#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /tmp
/native-bash > /tmp/native.out 2> /tmp/native.err
native_rc=$?
/bin/busybox timeout -s KILL 100 /kernel-bash > /tmp/kernel.out 2> /tmp/kernel.err
kernel_rc=$?
/bin/busybox cat /tmp/native.out /tmp/kernel.out
/bin/busybox tail -c 32768 /tmp/kernel.err
result=1
if [ "$native_rc" = 0 ] && [ "$kernel_rc" = 0 ] && /bin/busybox cmp /tmp/native.out /tmp/kernel.out; then
    echo 'PASS: SHA-1 native and kernel vectors match'
    result=0
else
    echo "FAIL: SHA-1 collision-check native=$native_rc kernel=$kernel_rc"
fi
echo "KERNEL_BASH_TEST_EXIT=$result"
/bin/busybox poweroff -f
