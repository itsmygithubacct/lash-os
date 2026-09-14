#!/bin/sh
# This fixture runs only in the isolated test VM, without host filesystem sharing.
set -eu
trap 'result=$?; trap - EXIT; echo "KERNEL_BASH_TEST_EXIT=$result"; /bin/busybox poweroff -f' EXIT
fail() { echo "FAIL: $*"; exit 1; }
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /dev/pts /home /previous-host-directory
/bin/busybox mount -t devpts devpts /dev/pts
/bin/busybox ln -s /proc/self/fd /dev/fd
export PATH=/bin HOME=/root LC_ALL=C
if [ -f /portable-test ]; then
    /bin/busybox rm -rf /nix
    [ ! -e /nix ] || fail 'could not remove Nix runtime'
    echo 'PASS: kernel cases run without /nix'
fi

# An inherited shared /home catches accidental propagation back to the caller.
/bin/busybox mount -o bind /home /home
/bin/busybox mount --make-rshared /home
printf 'original-host-home\n' > /home/host-home-marker
work='/home/original/work space'
/bin/busybox mkdir -p "$work/nested"
printf 'original-data\n' > "$work/source"
/bin/busybox ln -s source "$work/relative-link"
/bin/busybox mount -t tmpfs tmpfs "$work/nested"
printf 'nested-mount-data\n' > "$work/nested/nested-source"
/bin/busybox cp /cases.sh "$work/checks.sh"
/bin/busybox ln -s "$work" /launch-alias
cd /launch-alias
export TEST_LAUNCH_ID=$(/bin/busybox stat -c '%d:%i' .)
export TEST_PARENT_MOUNT_NAMESPACE=$(/bin/busybox readlink /proc/self/ns/mnt)
export TEST_ORIGINAL_PWD=$PWD OLDPWD=/previous-host-directory
/bin/busybox cp /proc/self/mountinfo /tmp/mounts-before
printf 'inherited-first\ninherited-second\n' > /tmp/inherited-input

echo 'RUN: mapped directory and child-process checks'
if /bin/busybox timeout -s KILL 360 /kernel-bash --stats --mount-cwd ./checks.sh --stats --mount-cwd < /dev/null 9< /tmp/inherited-input 200<&9 > /tmp/mapped.out 2> /tmp/mapped.err; then
    /bin/busybox cat /tmp/mapped.out /tmp/mapped.err
else
    /bin/busybox cat /tmp/mapped.out /tmp/mapped.err
    fail 'mapped shell cases'
fi
/bin/busybox grep -qx MOUNT_CWD_CASES_PASSED /tmp/mapped.out || fail 'mapped completion marker'
/bin/busybox cmp /tmp/mounts-before /proc/self/mountinfo || fail 'caller mount table changed'
[ "$(/bin/busybox cat /home/host-home-marker)" = original-host-home ] || fail 'caller /home changed'
[ "$(/bin/busybox cat "$work/builtin-result")" = written-by-builtin ] || fail 'builtin write did not reach source'
[ "$(/bin/busybox cat "$work/subshell-result")" = written-by-subshell ] || fail 'subshell write did not reach source'
[ "$(/bin/busybox cat "$work/external-result")" = written-by-external ] || fail 'external write did not reach source'
echo 'PASS: file writes reach the original directory and caller mounts remain unchanged'

/kernel-bash --mount-cwd --stats -c '[[ $HOME == /home && $PWD == /home && -f source ]] && printf "REVERSED_FLAGS_OK\n"' > /tmp/reversed.out
/bin/busybox grep -qx REVERSED_FLAGS_OK /tmp/reversed.out || fail 'reversed loader option order'
echo 'PASS: --mount-cwd and --stats work in either order'

/kernel-bash --stats -c '[[ $HOME == /root && $PWD == "$TEST_ORIGINAL_PWD" && $OLDPWD == /previous-host-directory && -f /home/host-home-marker && $1 == --mount-cwd && $2 == --stats ]] && printf "DEFAULT_VIEW_OK\n"' shell --mount-cwd --stats > /tmp/default.out
/bin/busybox grep -qx DEFAULT_VIEW_OK /tmp/default.out || fail 'default launch or command arguments changed'
echo 'PASS: default launch preserves the host view and command arguments'

printf '[[ $HOME == /root && -f /home/host-home-marker ]] && printf "OPTION_SCRIPT_OK\\n"\n' > ./--mount-cwd
/kernel-bash -- --mount-cwd > /tmp/option-script.out
/bin/busybox grep -qx OPTION_SCRIPT_OK /tmp/option-script.out || fail 'option delimiter'
echo 'PASS: -- allows a script named --mount-cwd'

printf '[[ $HOME == /home && $PWD == /home && -f source ]] && printf "MAPPED_INTERACTIVE_OK\\n"\nexit\n' | /bin/busybox timeout -s KILL 60 /bin/script -qec '/kernel-bash --mount-cwd -i' /tmp/interactive.log > /tmp/interactive.out 2>&1
/bin/busybox grep -q '^MAPPED_INTERACTIVE_OK' /tmp/interactive.out || fail 'mapped interactive shell'
echo 'PASS: interactive startup uses the mapped home'

# Invalid targets must fail before loading Bash or changing the filesystem.
cd /tmp
/bin/busybox umount -l /home
/bin/busybox mv /home /saved-home
if /kernel-bash --mount-cwd -c 'printf UNEXPECTED_START' > /tmp/missing.out 2> /tmp/missing.err; then
    fail 'missing /home was accepted'
fi
[ ! -e /home ] && [ ! -s /tmp/missing.out ] || fail 'missing /home was created or shell was started'
/bin/busybox grep -q 'checking the /home mount point' /tmp/missing.err || fail 'missing target diagnostic'
/bin/busybox ln -s /saved-home /home
if /kernel-bash --mount-cwd -c 'printf UNEXPECTED_START' > /tmp/symlink.out 2> /tmp/symlink.err; then
    fail 'symlink /home was accepted'
fi
[ -L /home ] && [ ! -s /tmp/symlink.out ] || fail 'symlink changed or shell was started'
/bin/busybox grep -q 'checking the /home mount point' /tmp/symlink.err || fail 'symlink target diagnostic'
echo 'PASS: missing and symlink mount targets fail with a clear diagnostic'
