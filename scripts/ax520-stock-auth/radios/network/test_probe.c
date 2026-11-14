/* Offline syscall-boundary fixture for: relay-host --probe wlan0.
 * Build relay.c with -Dmain=relay_main, then link this file with:
 * -Wl,--wrap=socket,--wrap=ioctl,--wrap=close,--wrap=bind
 * -Wl,--wrap=setsockopt,--wrap=send,--wrap=sendto,--wrap=sendmsg
 * -Wl,--wrap=read,--wrap=recv,--wrap=recvfrom,--wrap=recvmsg
 * No real packet socket is opened and no device is accessed.
 */
#define _GNU_SOURCE
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int relay_main(int argc, char **argv);
ssize_t __real_read(int fd, void *buffer, size_t length);
int __real_close(int fd);

enum { PROBE_FD = 197 };
static int socket_calls, close_calls;
static unsigned queried;

static void fail(const char *message) {
    fprintf(stderr, "FAIL probe contract: %s\n", message);
    exit(1);
}

#define REQUIRE(condition, message) do { if (!(condition)) fail(message); } while (0)

int __wrap_socket(int domain, int type, int protocol) {
    REQUIRE(++socket_calls == 1, "probe opened multiple sockets");
    REQUIRE(domain == AF_PACKET, "probe socket family is not AF_PACKET");
    REQUIRE((type & 15) == SOCK_RAW, "probe socket is not SOCK_RAW");
    REQUIRE((type & ~(15 | SOCK_CLOEXEC | SOCK_NONBLOCK)) == 0,
            "probe requested unexpected socket flags");
    REQUIRE(protocol == 0, "probe enabled packet reception with a nonzero protocol");
    return PROBE_FD;
}

int __wrap_ioctl(int fd, unsigned long request, ...) {
    REQUIRE(fd == PROBE_FD, "ioctl used a different descriptor");
    va_list arguments;
    va_start(arguments, request);
    struct ifreq *ifr = va_arg(arguments, struct ifreq *);
    va_end(arguments);
    REQUIRE(ifr != NULL, "ioctl lacked an ifreq");
    REQUIRE(memchr(ifr->ifr_name, '\0', IFNAMSIZ) != NULL,
            "interface name was not terminated");
    REQUIRE(strcmp(ifr->ifr_name, "wlan0") == 0, "probe inspected another interface");
    switch (request) {
    case SIOCGIFINDEX:
        queried |= 1u;
        ifr->ifr_ifindex = 3;
        return 0;
    case SIOCGIFHWADDR:
        queried |= 2u;
        ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr->ifr_hwaddr.sa_data, "\x02\x11\x22\x33\x44\x55", 6);
        return 0;
    case SIOCGIFFLAGS:
        queried |= 4u;
        ifr->ifr_flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST;
        return 0;
    case SIOCGIFMTU:
        queried |= 8u;
        ifr->ifr_mtu = 1500;
        return 0;
    default:
        fail("probe issued a non-whitelisted or mutating ioctl");
    }
    return -1;
}

int __wrap_close(int fd) {
    if (fd != PROBE_FD)
        return __real_close(fd);
    REQUIRE(++close_calls == 1, "probe closed its packet socket more than once");
    return 0;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length) {
    (void)fd; (void)address; (void)length;
    fail("probe bound a socket");
    return -1;
}

int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length) {
    (void)fd; (void)level; (void)option; (void)value; (void)length;
    fail("probe changed socket options or multicast membership");
    return -1;
}

ssize_t __wrap_send(int fd, const void *data, size_t length, int flags) {
    (void)fd; (void)data; (void)length; (void)flags;
    fail("probe transmitted data");
    return -1;
}

ssize_t __wrap_sendto(int fd, const void *data, size_t length, int flags,
                      const struct sockaddr *address, socklen_t address_length) {
    (void)fd; (void)data; (void)length; (void)flags;
    (void)address; (void)address_length;
    fail("probe transmitted a datagram");
    return -1;
}

ssize_t __wrap_sendmsg(int fd, const struct msghdr *message, int flags) {
    (void)fd; (void)message; (void)flags;
    fail("probe transmitted a message");
    return -1;
}

ssize_t __wrap_read(int fd, void *buffer, size_t length) {
    REQUIRE(fd != PROBE_FD, "probe read packet payloads");
    return __real_read(fd, buffer, length);
}

ssize_t __wrap_recv(int fd, void *buffer, size_t length, int flags) {
    (void)fd; (void)buffer; (void)length; (void)flags;
    fail("probe received payloads");
    return -1;
}

ssize_t __wrap_recvfrom(int fd, void *buffer, size_t length, int flags,
                        struct sockaddr *address, socklen_t *address_length) {
    (void)fd; (void)buffer; (void)length; (void)flags;
    (void)address; (void)address_length;
    fail("probe received a datagram");
    return -1;
}

ssize_t __wrap_recvmsg(int fd, struct msghdr *message, int flags) {
    (void)fd; (void)message; (void)flags;
    fail("probe received a message");
    return -1;
}

int main(void) {
    char name[] = "relay-host";
    char mode[] = "--probe";
    char interface[] = "wlan0";
    char *arguments[] = {name, mode, interface, NULL};
    int result = relay_main(3, arguments);
    REQUIRE(result == 0, "metadata-only probe did not succeed");
    REQUIRE(socket_calls == 1, "probe did not open exactly one protocol-zero packet socket");
    REQUIRE(queried == 15u, "probe did not check index, hardware type, flags and MTU");
    REQUIRE(close_calls == 1, "probe leaked its packet socket");
    puts("PASS probe uses protocol zero and read-only metadata ioctls; no packet IO");
    return 0;
}
