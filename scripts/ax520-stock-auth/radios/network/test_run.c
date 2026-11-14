/* Offline --run lifecycle test: real loopback TCP, fake packet interface.
 * Compile relay.c with -Dmain=relay_main, then link this file with:
 * -Wl,--wrap=socket,--wrap=ioctl,--wrap=bind,--wrap=setsockopt
 * -Wl,--wrap=recvfrom,--wrap=sendto,--wrap=close
 * No physical interface is opened or modified.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int relay_main(int argc, char **argv);
int __real_socket(int domain, int type, int protocol);
int __real_ioctl(int fd, unsigned long request, ...);
int __real_bind(int fd, const struct sockaddr *address, socklen_t length);
int __real_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
ssize_t __real_recvfrom(int fd, void *buffer, size_t length, int flags,
                        struct sockaddr *address, socklen_t *address_length);
ssize_t __real_sendto(int fd, const void *buffer, size_t length, int flags,
                      const struct sockaddr *address, socklen_t address_length);
int __real_close(int fd);

static int packet_pair[2] = {-1, -1};
static int raw_opened, raw_bound, raw_closed, memberships;
static unsigned metadata;
static pid_t child_pid = -1;
static const unsigned char pi_mac[6] = {0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5};
static const unsigned char peer_mac[6] = {0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9};

static int64_t clock_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(2);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void fail(const char *message) {
    fprintf(stderr, "FAIL run contract: %s\n", message);
    if (child_pid > 0) {
        kill(child_pid, SIGKILL);
        while (waitpid(child_pid, NULL, 0) < 0 && errno == EINTR) {}
    }
    exit(1);
}

#define REQUIRE(condition, message) do { if (!(condition)) fail(message); } while (0)

int __wrap_socket(int domain, int type, int protocol) {
    if (domain != AF_PACKET) {
        REQUIRE(domain == AF_INET, "unexpected socket family");
        return __real_socket(domain, type, protocol);
    }
    REQUIRE(++raw_opened == 1, "multiple raw sockets");
    REQUIRE((type & 15) == SOCK_RAW, "packet socket not raw");
    REQUIRE(protocol == 0, "packet reception enabled before client admission");
    REQUIRE(packet_pair[0] >= 0, "fixture packet socket absent");
    if (type & SOCK_NONBLOCK)
        REQUIRE(fcntl(packet_pair[0], F_SETFL, O_NONBLOCK) == 0, "fake nonblock setup failed");
    return packet_pair[0];
}

int __wrap_ioctl(int fd, unsigned long request, ...) {
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    REQUIRE(fd == packet_pair[0], "unexpected ioctl descriptor");
    struct ifreq *ifr = argument;
    REQUIRE(ifr && memchr(ifr->ifr_name, '\0', IFNAMSIZ), "invalid interface name");
    REQUIRE(strcmp(ifr->ifr_name, "wlan0") == 0, "wrong interface queried");
    switch (request) {
    case SIOCGIFINDEX:
        metadata |= 1; ifr->ifr_ifindex = 3; return 0;
    case SIOCGIFHWADDR:
        metadata |= 2; ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr->ifr_hwaddr.sa_data, "\x02\x11\x22\x33\x44\x55", 6);
        return 0;
    case SIOCGIFFLAGS:
        metadata |= 4; ifr->ifr_flags = IFF_UP | IFF_BROADCAST | IFF_MULTICAST; return 0;
    case SIOCGIFMTU:
        metadata |= 8; ifr->ifr_mtu = 1500; return 0;
    default:
        fail("non-whitelisted or mutating ioctl");
    }
    return -1;
}

int __wrap_bind(int fd, const struct sockaddr *address, socklen_t length) {
    if (fd != packet_pair[0]) {
        REQUIRE(length >= sizeof(struct sockaddr_in), "short TCP bind address");
        const struct sockaddr_in *in = (const struct sockaddr_in *)address;
        REQUIRE(in->sin_family == AF_INET && in->sin_addr.s_addr == htonl(INADDR_LOOPBACK),
                "relay attempted a non-loopback TCP bind");
        return __real_bind(fd, address, length);
    }
    REQUIRE(++raw_bound == 1, "raw socket bound multiple times");
    REQUIRE(length >= sizeof(struct sockaddr_ll), "short packet bind address");
    const struct sockaddr_ll *ll = (const struct sockaddr_ll *)address;
    REQUIRE(ll->sll_family == AF_PACKET && ll->sll_ifindex == 3,
            "packet bind selected wrong interface");
    REQUIRE(ll->sll_protocol == htons(ETH_P_ALL), "packet bind protocol differs");
    return 0;
}

int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length) {
    if (fd != packet_pair[0])
        return __real_setsockopt(fd, level, option, value, length);
    REQUIRE(level == SOL_PACKET, "unexpected packet socket level");
    REQUIRE(option == PACKET_ADD_MEMBERSHIP || option == PACKET_DROP_MEMBERSHIP,
            "unexpected packet socket option");
    REQUIRE(length == sizeof(struct packet_mreq), "invalid packet membership size");
    const struct packet_mreq *member = value;
    REQUIRE(member->mr_ifindex == 3, "membership selected wrong interface");
    REQUIRE(member->mr_type == PACKET_MR_PROMISC || member->mr_type == PACKET_MR_ALLMULTI,
            "unexpected membership type");
    if (option == PACKET_ADD_MEMBERSHIP) memberships++;
    return 0;
}

ssize_t __wrap_recvfrom(int fd, void *buffer, size_t length, int flags,
                        struct sockaddr *address, socklen_t *address_length) {
    if (fd != packet_pair[0])
        return __real_recvfrom(fd, buffer, length, flags, address, address_length);
    ssize_t result = __real_recvfrom(fd, buffer, length, flags, NULL, NULL);
    if (result >= 0) {
        REQUIRE(address && address_length && *address_length >= sizeof(struct sockaddr_ll),
                "packet receive omitted source metadata");
        struct sockaddr_ll ll = {0};
        ll.sll_family = AF_PACKET;
        ll.sll_ifindex = 3;
        ll.sll_hatype = ARPHRD_ETHER;
        ll.sll_pkttype = PACKET_HOST;
        ll.sll_halen = 6;
        memcpy(ll.sll_addr, peer_mac, 6);
        memcpy(address, &ll, sizeof(ll));
        *address_length = sizeof(ll);
    }
    return result;
}

ssize_t __wrap_sendto(int fd, const void *buffer, size_t length, int flags,
                      const struct sockaddr *address, socklen_t address_length) {
    if (fd != packet_pair[0])
        return __real_sendto(fd, buffer, length, flags, address, address_length);
    REQUIRE(length >= 14 && length <= 1514, "invalid Ethernet size reached injection");
    REQUIRE(address && address_length >= sizeof(struct sockaddr_ll),
            "packet injection omitted destination metadata");
    const struct sockaddr_ll *ll = (const struct sockaddr_ll *)address;
    REQUIRE(ll->sll_family == AF_PACKET && ll->sll_ifindex == 3 && ll->sll_halen == 6,
            "packet injection selected wrong interface/address length");
    REQUIRE(memcmp(ll->sll_addr, buffer, 6) == 0, "injection destination differs from frame");
    return __real_sendto(fd, buffer, length, flags, NULL, 0);
}

int __wrap_close(int fd) {
    if (fd == packet_pair[0]) {
        REQUIRE(++raw_closed == 1, "raw socket double-close");
    }
    return __real_close(fd);
}

static int ready(int fd, short events, int within_ms) {
    struct pollfd p = {.fd = fd, .events = events};
    int result;
    do { result = poll(&p, 1, within_ms); } while (result < 0 && errno == EINTR);
    return result > 0 && (p.revents & events);
}

static void receive_exact(int fd, unsigned char *buffer, size_t count) {
    size_t done = 0;
    int64_t deadline = clock_ms() + 400;
    while (done < count) {
        int remaining = (int)(deadline - clock_ms());
        REQUIRE(remaining > 0 && ready(fd, POLLIN, remaining), "TCP frame reply timed out");
        ssize_t got = recv(fd, buffer + done, count - done, 0);
        REQUIRE(got > 0, "TCP frame reply ended early");
        done += (size_t)got;
    }
}

static int reserve_port(void) {
    int fd = __real_socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0, "port-selection socket failed");
    struct sockaddr_in in = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    REQUIRE(__real_bind(fd, (struct sockaddr *)&in, sizeof(in)) == 0, "port selection failed");
    socklen_t size = sizeof(in);
    REQUIRE(getsockname(fd, (struct sockaddr *)&in, &size) == 0, "port query failed");
    int port = ntohs(in.sin_port);
    __real_close(fd);
    return port;
}

static void start_child(int port, int client_expected, char *duration) {
    REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, packet_pair) == 0, "packet socketpair failed");
    child_pid = fork();
    REQUIRE(child_pid >= 0, "fixture fork failed");
    if (child_pid == 0) {
        __real_close(packet_pair[1]);
        char port_text[16];
        snprintf(port_text, sizeof(port_text), "%d", port);
        char *args[] = {"relay-host", "--run", "wlan0", port_text, duration,
                        "02:a1:b2:c3:d4:e5", NULL};
        int result = relay_main(6, args);
        REQUIRE(result == 0, "relay run did not exit successfully");
        REQUIRE(raw_opened == 1 && raw_bound == client_expected && raw_closed == 1,
                "packet socket lifecycle incomplete");
        REQUIRE(metadata == 15, "interface metadata checks incomplete");
        REQUIRE(client_expected ? memberships > 0 : memberships == 0,
                "packet membership did not follow client admission");
        _exit(0);
    }
    __real_close(packet_pair[0]);
}

static int connect_client(int port) {
    struct sockaddr_in in = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
                             .sin_port = htons((uint16_t)port)};
    int64_t deadline = clock_ms() + 500;
    while (clock_ms() < deadline) {
        int fd = __real_socket(AF_INET, SOCK_STREAM, 0);
        REQUIRE(fd >= 0, "client socket failed");
        if (connect(fd, (struct sockaddr *)&in, sizeof(in)) == 0) return fd;
        __real_close(fd);
        int status;
        pid_t result = waitpid(child_pid, &status, WNOHANG);
        if (result == child_pid) {
            child_pid = -1;
            fail("relay exited before loopback listener became ready");
        }
        usleep(5000);
    }
    fail("relay loopback listener never became ready");
    return -1;
}

static void wait_success(int within_ms) {
    int64_t deadline = clock_ms() + within_ms;
    while (clock_ms() < deadline) {
        int status;
        pid_t result = waitpid(child_pid, &status, WNOHANG);
        if (result == child_pid) {
            child_pid = -1;
            REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0, "relay child failed");
            return;
        }
        REQUIRE(result == 0 || (result < 0 && errno == EINTR), "waitpid failed");
        usleep(5000);
    }
    fail("relay did not exit within its lifecycle deadline");
}

static void make_frame(unsigned char frame[60], int toward_wifi) {
    memset(frame, 0x5a, 60);
    memcpy(frame, toward_wifi ? peer_mac : pi_mac, 6);
    memcpy(frame + 6, toward_wifi ? pi_mac : peer_mac, 6);
    frame[12] = toward_wifi ? 0x08 : 0x86;
    frame[13] = toward_wifi ? 0x00 : 0xdd;
}

static void directions_and_eof(void) {
    int port = reserve_port();
    start_child(port, 1, "300");
    int client = connect_client(port);
    unsigned char frame[60], framed[62], got[1514];
    make_frame(frame, 1);
    framed[0] = 0; framed[1] = 60;
    memcpy(framed + 2, frame, 60);
    REQUIRE(send(client, framed, sizeof(framed), MSG_NOSIGNAL) == sizeof(framed),
            "client send failed");
    REQUIRE(ready(packet_pair[1], POLLIN, 400), "host frame not injected");
    REQUIRE(recv(packet_pair[1], got, sizeof(got), 0) == 60 && memcmp(got, frame, 60) == 0,
            "injected host frame changed");

    make_frame(frame, 0);
    REQUIRE(send(packet_pair[1], frame, 60, MSG_NOSIGNAL) == 60, "Wi-Fi fixture send failed");
    receive_exact(client, got, 62);
    REQUIRE(got[0] == 0 && got[1] == 60 && memcmp(got + 2, frame, 60) == 0,
            "Wi-Fi frame was not framed intact");

    memcpy(frame + 6, pi_mac, 6);
    REQUIRE(send(packet_pair[1], frame, 60, MSG_NOSIGNAL) == 60, "reflection fixture send failed");
    REQUIRE(!ready(client, POLLIN, 100), "Pi-source reflection was forwarded");
    __real_close(client);
    wait_success(500);
    __real_close(packet_pair[1]);
    packet_pair[0] = packet_pair[1] = -1;
    puts("PASS bidirectional forwarding, reflection filtering and client-EOF cleanup");
}

static void no_client_deadline(void) {
    int port = reserve_port();
    int64_t start = clock_ms();
    start_child(port, 0, "1");
    wait_success(2500);
    int64_t elapsed = clock_ms() - start;
    REQUIRE(elapsed >= 700 && elapsed < 2500, "one-second no-client deadline not enforced");
    __real_close(packet_pair[1]);
    packet_pair[0] = packet_pair[1] = -1;
    puts("PASS no-client deadline closes the temporary packet socket");
}

static void maximum_duration_signal(void) {
    int port = reserve_port();
    start_child(port, 1, "300");
    int client = connect_client(port);
    usleep(50000);
    REQUIRE(kill(child_pid, SIGTERM) == 0, "signal relay");
    wait_success(1000);
    __real_close(client);
    __real_close(packet_pair[1]);
    packet_pair[0] = packet_pair[1] = -1;
    puts("PASS 300-second relay accepts bounded runtime and cleans up on SIGTERM");
}

int main(void) {
    directions_and_eof();
    no_client_deadline();
    maximum_duration_signal();
    return 0;
}
