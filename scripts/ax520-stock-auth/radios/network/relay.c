#define _GNU_SOURCE
#include "relay.h"
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

static volatile sig_atomic_t stopped;

int64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int parse_mac(const char *s, uint8_t mac[6]) {
    if (!s || !mac || strlen(s) != 17) { errno = EINVAL; return -1; }
    uint8_t parsed[6];
    for (int i = 0; i < 6; i++) {
        int a = hex(s[i*3]), b = hex(s[i*3+1]);
        if (a < 0 || b < 0 || (i < 5 && s[i*3+2] != ':')) {
            errno = EINVAL; return -1;
        }
        parsed[i] = (uint8_t)(a*16 + b);
    }
    if ((parsed[0] & 3) != 2) { errno = EINVAL; return -1; }
    memcpy(mac, parsed, 6);
    return 0;
}

static int zero_mac(const uint8_t *mac) {
    static const uint8_t zero[6];
    return !memcmp(mac, zero, 6);
}

int frame_allowed(const uint8_t *frame, size_t len, const uint8_t mac[6],
                  int from_wifi, int packet_type) {
    if (!frame || !mac || len < FRAME_MIN || len > FRAME_MAX) return 0;
    unsigned type = ((unsigned)frame[12] << 8) | frame[13];
    if (type != 0x0800 && type != 0x0806 && type != 0x86dd) return 0;
    const uint8_t *src = frame + 6;
    if ((src[0] & 1) || zero_mac(src) || zero_mac(frame)) return 0;
    if (from_wifi) {
        if (packet_type == 4 || !memcmp(src, mac, 6)) return 0;
        return (frame[0] & 1) || !memcmp(frame, mac, 6);
    }
    return !memcmp(src, mac, 6) && memcmp(frame, mac, 6) != 0;
}

static int wait_fd(int fd, short events, int64_t deadline) {
    for (;;) {
        if (stopped) { errno = EINTR; return -1; }
        int64_t remaining = deadline - now_ms();
        if (remaining <= 0) { errno = ETIMEDOUT; return -1; }
        int timeout = (int)(remaining > 200 ? 200 : remaining);
        struct pollfd p = { fd, events, 0 };
        int n = poll(&p, 1, timeout);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (!n) continue;
        if (p.revents & POLLNVAL) { errno = EBADF; return -1; }
        if (p.revents & (events | POLLHUP | POLLERR)) return 0;
    }
}

static int transfer(int fd, uint8_t *data, size_t len, int writing, int64_t deadline) {
    size_t done = 0;
    while (done < len) {
        if (wait_fd(fd, writing ? POLLOUT : POLLIN, deadline)) return -1;
        ssize_t n = writing
            ? send(fd, data + done, len - done, MSG_DONTWAIT | MSG_NOSIGNAL)
            : recv(fd, data + done, len - done, MSG_DONTWAIT);
        if (n > 0) { done += (size_t)n; continue; }
        if (!n) { errno = ECONNRESET; return -1; }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
        return -1;
    }
    return 0;
}

int read_frame(int fd, uint8_t *buf, size_t cap, int64_t deadline) {
    uint8_t header[2];
    if (!buf) { errno = EINVAL; return -1; }
    if (transfer(fd, header, 2, 0, deadline)) return -1;
    size_t n = ((size_t)header[0] << 8) | header[1];
    if (n < FRAME_MIN || n > FRAME_MAX || n > cap) { errno = EMSGSIZE; return -1; }
    if (transfer(fd, buf, n, 0, deadline)) return -1;
    return (int)n;
}

int write_frame(int fd, const uint8_t *buf, size_t len, int64_t deadline) {
    if (!buf || len < FRAME_MIN || len > FRAME_MAX) { errno = EMSGSIZE; return -1; }
    uint8_t wire[FRAME_MAX + 2];
    wire[0] = (uint8_t)(len >> 8); wire[1] = (uint8_t)len;
    memcpy(wire + 2, buf, len);
    return transfer(fd, wire, len + 2, 1, deadline);
}

#ifndef RELAY_NO_MAIN
#include <arpa/inet.h>
#include <inttypes.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>

struct interface { int index, mtu; short flags; uint8_t mac[6]; };

static int interface_read(int fd, struct interface *view) {
    struct ifreq req;
    memset(&req, 0, sizeof req);
    memcpy(req.ifr_name, "wlan0", 6);
    if (ioctl(fd, SIOCGIFINDEX, &req)) return -1;
    view->index = req.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &req)) return -1;
    if (req.ifr_hwaddr.sa_family != ARPHRD_ETHER) { errno = EPROTOTYPE; return -1; }
    memcpy(view->mac, req.ifr_hwaddr.sa_data, 6);
    if (ioctl(fd, SIOCGIFFLAGS, &req)) return -1;
    view->flags = req.ifr_flags;
    if (ioctl(fd, SIOCGIFMTU, &req)) return -1;
    view->mtu = req.ifr_mtu;
    if (view->index <= 0 || view->mtu != 1500 || !(view->flags & IFF_UP) ||
        !(view->flags & IFF_MULTICAST)) { errno = ENETDOWN; return -1; }
    return 0;
}

static int probe(void) {
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { printf("probe_error stage=socket errno=%d\n", errno); return 1; }
    struct interface view;
    int rc = interface_read(fd, &view), error = errno;
    close(fd);
    if (rc) { printf("probe_error stage=interface errno=%d\n", error); return 1; }
    puts("probe_ok iface=wlan0 ethernet=1 up=1 mtu=1500 packet_socket=1");
    return 0;
}

static void stop_signal(int sig) { (void)sig; stopped = 1; }

struct counts {
    uint64_t to_wifi, to_host, wifi_filtered, host_filtered, tx_busy;
};

static int64_t io_deadline(int64_t end) {
    int64_t short_end = now_ms() + 2000;
    return short_end < end ? short_end : end;
}

/* Socket-owned packet membership is the only temporary interface change.
 * No persistent files, addresses, routes, USB functions or radio settings. */
static int run(unsigned port, unsigned duration, const uint8_t mac[6]) {
    int packet = -1, listener = -1, client = -1, rc = 1, error = 0;
    const char *reason = "setup";
    struct counts count = {0};
    int64_t start = now_ms(), end = start + (int64_t)duration * 1000;
    struct interface view;
    stopped = 0;
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = stop_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) goto done;
    pid_t parent = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) || getppid() != parent) { errno = ESRCH; goto done; }

    packet = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (packet < 0) { reason = "packet_socket"; goto done; }
    if (interface_read(packet, &view)) { reason = "interface"; goto done; }
    if (!memcmp(view.mac, mac, 6)) { errno = EADDRINUSE; reason = "same_mac"; goto done; }
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listener < 0) { reason = "listener_socket"; goto done; }
    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local.sin_port = htons((uint16_t)port);
    if (bind(listener, (struct sockaddr *)&local, sizeof local) || listen(listener, 1)) {
        reason = "loopback_listen"; goto done;
    }
    printf("relay_ready iface=wlan0 loopback_port=%u seconds=%u\n", port, duration);
    fflush(stdout);
    for (;;) {
        if (wait_fd(listener, POLLIN, end)) {
            if (errno == ETIMEDOUT || stopped) { rc = 0; reason = stopped ? "signal" : "deadline"; }
            else reason = "accept_wait";
            goto done;
        }
        struct sockaddr_in peer;
        socklen_t len = sizeof peer;
        client = accept4(listener, (struct sockaddr *)&peer, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (client < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            reason = "accept"; goto done;
        }
        if (len != sizeof peer || peer.sin_family != AF_INET ||
            peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            errno = EPERM; reason = "nonloopback_peer"; goto done;
        }
        break;
    }
    close(listener); listener = -1;
    int one = 1;
    if (setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one)) {
        reason = "nodelay"; goto done;
    }
    struct sockaddr_ll link;
    memset(&link, 0, sizeof link);
    link.sll_family = AF_PACKET;
    link.sll_protocol = htons(3); /* ETH_P_ALL; capture starts only after admission. */
    link.sll_ifindex = view.index;
    if (bind(packet, (struct sockaddr *)&link, sizeof link)) { reason = "packet_bind"; goto done; }
    struct packet_mreq membership;
    memset(&membership, 0, sizeof membership);
    membership.mr_ifindex = view.index;
    membership.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(packet, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &membership, sizeof membership)) {
        reason = "packet_membership"; goto done;
    }
    puts("relay_connected"); fflush(stdout);
    rc = 0; reason = "deadline";
    while (!stopped && now_ms() < end) {
        int64_t left = end - now_ms();
        if (left <= 0) break;
        struct pollfd fds[2] = {{client, POLLIN, 0}, {packet, POLLIN, 0}};
        int n = poll(fds, 2, (int)(left > 100 ? 100 : left));
        if (n < 0) { if (errno == EINTR) continue; rc = 1; reason = "poll"; break; }
        if (!n) continue;
        uint8_t frame[FRAME_MAX];
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
            int len = read_frame(client, frame, sizeof frame, io_deadline(end));
            if (len < 0) {
                reason = errno == ECONNRESET ? "stream_closed" : "stream_read";
                rc = errno == ECONNRESET || stopped || now_ms() >= end ? 0 : 1;
                break;
            }
            if (!frame_allowed(frame, (size_t)len, mac, 0, 0)) count.host_filtered++;
            else {
                struct sockaddr_ll dst;
                memset(&dst, 0, sizeof dst);
                dst.sll_family = AF_PACKET;
                dst.sll_ifindex = view.index;
                dst.sll_protocol = htons(((unsigned)frame[12] << 8) | frame[13]);
                dst.sll_halen = 6;
                memcpy(dst.sll_addr, frame, 6);
                ssize_t sent = sendto(packet, frame, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL,
                                      (struct sockaddr *)&dst, sizeof dst);
                if (sent == len) count.to_wifi++;
                else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) count.tx_busy++;
                else { if (sent >= 0) errno = EIO; rc = 1; reason = "packet_send"; break; }
            }
        }
        if (fds[1].revents & POLLIN) {
            struct sockaddr_ll from;
            memset(&from, 0, sizeof from);
            socklen_t size = sizeof from;
            ssize_t len = recvfrom(packet, frame, sizeof frame, MSG_DONTWAIT | MSG_TRUNC,
                                   (struct sockaddr *)&from, &size);
            if (len < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                rc = 1; reason = "packet_receive"; break;
            }
            if (size != sizeof from || from.sll_family != AF_PACKET || from.sll_ifindex != view.index ||
                !frame_allowed(frame, (size_t)len, mac, 1, from.sll_pkttype)) count.wifi_filtered++;
            else if (write_frame(client, frame, (size_t)len, io_deadline(end))) {
                rc = stopped || now_ms() >= end ? 0 : 1; reason = "stream_write"; break;
            } else count.to_host++;
        }
        if (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL)) { rc = 1; reason = "packet_lost"; break; }
    }
    if (stopped) reason = "signal";
done:
    error = rc ? errno : 0;
    if (packet >= 0) close(packet); /* also releases our PROMISC membership */
    if (client >= 0) close(client);
    if (listener >= 0) close(listener);
    printf("relay_end reason=%s errno=%d elapsed_ms=%" PRId64
           " to_wifi=%" PRIu64 " to_host=%" PRIu64 " wifi_filtered=%" PRIu64
           " host_filtered=%" PRIu64 " tx_busy=%" PRIu64 "\n",
           reason, error, now_ms()-start, count.to_wifi, count.to_host,
           count.wifi_filtered, count.host_filtered, count.tx_busy);
    return rc;
}

static int number(const char *s, unsigned low, unsigned high, unsigned *out) {
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return -1;
    errno = 0; char *end;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || *end || n < low || n > high) return -1;
    *out = (unsigned)n;
    return 0;
}

int main(int argc, char **argv) {
    unsigned port, duration; uint8_t mac[6];
    if (argc == 3 && !strcmp(argv[1], "--probe") && !strcmp(argv[2], "wlan0")) return probe();
    if (argc != 6 || strcmp(argv[1], "--run") || strcmp(argv[2], "wlan0") ||
        number(argv[3], 1024, 65535, &port) || number(argv[4], 1, 300, &duration) ||
        parse_mac(argv[5], mac)) {
        fputs("usage: relay --probe wlan0 | --run wlan0 PORT SECONDS LOCAL_PI_MAC\n", stderr);
        return 2;
    }
    return run(port, duration, mac);
}
#endif
