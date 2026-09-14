#!/bin/sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
export PATH=/bin LC_ALL=C HOME=/root
/bin/busybox ip link set lo up
/bin/busybox mkdir -p /tmp/http /tmp/native /tmp/kernel
echo fiber-pool-fixture > /tmp/http/index.html
/bin/busybox httpd -f -p 127.0.0.1:18999 -h /tmp/http &
server=$!
/bin/busybox sleep 1
cd /tmp/native
/native-bash /cases.sh > /tmp/native.out 2> /tmp/native.err
native_rc=$?
if [ "$native_rc" != 0 ]; then
    echo "FAIL: native process fixture, status=$native_rc"
    /bin/busybox cat /tmp/native.out /tmp/native.err
    echo 'KERNEL_BASH_TEST_EXIT=1'
    /bin/busybox poweroff -f
fi
if [ -f /portable-test ]; then
    /bin/busybox rm -rf /nix
    if [ -e /nix ]; then
        echo 'FAIL: could not remove Nix runtime'
        echo 'KERNEL_BASH_TEST_EXIT=1'
        /bin/busybox poweroff -f
    fi
    echo 'PASS: kernel cases run without /nix'
fi
result=0
cd /tmp/kernel
for cpu in 0 1; do
    echo "RUN: fork and resolver on CPU $cpu"
    /bin/busybox taskset -c "$cpu" /kernel-bash --stats /cases.sh > /tmp/kernel.out 2> /tmp/kernel.err
    kernel_rc=$?
    /bin/busybox cat /tmp/kernel.out
    /bin/busybox tail -c 32768 /tmp/kernel.err
    if [ "$native_rc" != 0 ] || [ "$kernel_rc" != 0 ] || ! /bin/busybox cmp /tmp/native.out /tmp/kernel.out; then
        echo "FAIL: process parity on CPU $cpu, native=$native_rc kernel=$kernel_rc"
        /bin/busybox cat /tmp/native.out /tmp/native.err
        result=1
    else
        echo "PASS: process parity on CPU $cpu"
    fi
done
kill "$server"
wait "$server" 2>/dev/null || :
echo "KERNEL_BASH_TEST_EXIT=$result"
/bin/busybox poweroff -f
