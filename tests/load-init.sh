#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
export PATH=/bin LC_ALL=C HOME=/root
/bin/busybox timeout -s KILL 180 /kernel-bash --stats -c 'printf "KERNEL_LOAD_OK\n"' > /tmp/load.out 2> /tmp/load.err
result=$?
/bin/busybox cat /tmp/load.out
/bin/busybox tail -c 32768 /tmp/load.err
if [ "$result" = 0 ]; then echo 'PASS: full image loads and executes';
else echo "FAIL: full image load, status=$result"; fi
echo "KERNEL_BASH_TEST_EXIT=$result"
/bin/busybox poweroff -f
