#!/bin/sh
set -eu
cd "$(dirname "$0")"
cc -std=c11 -O2 -Wall -Wextra -Werror -DRELAY_NO_MAIN -fPIC -shared relay.c -o librelay.so
cc -std=c11 -O2 -Wall -Wextra -Werror relay.c -o relay-host
python3 -m unittest -v test_relay
cc -std=c11 -O2 -Wall -Wextra -Werror -Dmain=relay_main -c relay.c -o relay-test.o
cc -std=c11 -O2 -Wall -Wextra -Werror test_run.c relay-test.o -Wl,--wrap=socket,--wrap=ioctl,--wrap=bind,--wrap=setsockopt,--wrap=recvfrom,--wrap=sendto,--wrap=close -o test-run
./test-run
cc -std=c11 -O2 -Wall -Wextra -Werror test_probe.c relay-test.o -Wl,--wrap=socket,--wrap=ioctl,--wrap=bind,--wrap=setsockopt,--wrap=recvfrom,--wrap=sendto,--wrap=close,--wrap=send,--wrap=sendmsg,--wrap=read,--wrap=recv,--wrap=recvmsg -o test-probe
./test-probe
