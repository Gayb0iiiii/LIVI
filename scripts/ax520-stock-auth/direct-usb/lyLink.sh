#!/bin/sh
# Stock startup remains first; the optional USB bridge runs afterwards.
export LY_BOOT_MODE=normal
export WORKDIR=/mnt/customer/app
export PATH=/tmp/app:/mnt/customer/app:/sbin:/bin:/usr/sbin:/usr/bin
export LD_LIBRARY_PATH=/tmp/app:/mnt/customer/app:/lib:/usr/lib
/mnt/customer/app/lyLink.sh normal "${LY_DEBUG_MODE:-normal}"
(
    trap '' HUP
    exec /bin/sh /mnt/UDISK/app/ax520-start.sh
) </dev/null >/tmp/livi-ax520-bootstrap.status 2>&1 &
exit 0
