#define _GNU_SOURCE
#include "relay.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifndef RELAY_PORT
#define RELAY_PORT 15039
#endif
#define PACKET_MAX 4096
static long long now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
int relay_packet_valid(const unsigned char *p, size_t n, int from_host) {
    if (!n || n > PACKET_MAX || (from_host && (n < 4 || n > 1028))) return 0;
    switch (p[0]) {
    case 1: return from_host && n >= 4 && n == 4U + p[3];
    case 2: return n >= 5 && n == 5U + p[3] + ((unsigned)p[4] << 8);
    case 3: return n >= 4 && n == 4U + p[3];
    case 4: return !from_host && n >= 3 && n == 3U + p[2];
    default: return 0;
    }
}
/* Fresh pairing uses the host's bonds; never read, write or delete stock stored keys. */
static int blocked_opcode(unsigned opcode) {
    return opcode == 0x0c0d || opcode == 0x0c11 || opcode == 0x0c12 || (opcode >> 10) == 0x3f;
}
int relay_packet_allowed(const unsigned char *p, size_t n, int from_host) {
    if (!relay_packet_valid(p, n, from_host)) return 0;
    if (from_host && p[0] == 1) {
        unsigned opcode = p[1] | ((unsigned)p[2] << 8);
        return !blocked_opcode(opcode);
    }
    if (!from_host && p[0] == 4) {
        if (p[1] == 0x15 || p[1] == 0xff) return 0;
        if (p[1] == 0x0e) return n >= 6 && !blocked_opcode(p[4] | ((unsigned)p[5] << 8));
        if (p[1] == 0x0f) return n == 7 && !blocked_opcode(p[5] | ((unsigned)p[6] << 8));
    }
    return 1;
}
static int again(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static int done(struct relay_stats *s, unsigned why) {
    s->stop_reason = why;
    if (why == RELAY_MALFORMED) errno = EPROTO;
    else if (why == RELAY_POLICY) errno = EACCES;
    else if (why == RELAY_STALL) errno = ETIMEDOUT;
    return why == RELAY_EOF || why == RELAY_DEADLINE ? 0 : -1;
}
int relay_pump(int hci_fd, int tcp_fd, unsigned duration_ms, unsigned stall_ms, struct relay_stats *out) {
    unsigned char input[PACKET_MAX + 2], output[PACKET_MAX + 2];
    size_t have = 0, want = 2, queued = 0, sent = 0;
#ifndef RELAY_ALLOW_UNRESTRICTED_TEST_TRANSPORT
    unsigned reset_phase = 0; /* 0:first command, 1:queued Reset, 2:sent, 3:confirmed. */
#endif
    long long now = now_ms(), input_progress = 0, output_progress = 0;
    memset(out, 0, sizeof *out);
    if (now < 0 || !duration_ms || duration_ms > 300000 || !stall_ms || stall_ms > duration_ms) return done(out, RELAY_IO);
    const long long end = now + duration_ms;
    for (;;) {
        now = now_ms();
        if (now < 0) return done(out, RELAY_IO);
        if (now >= end) return done(out, RELAY_DEADLINE);
        if ((have && now - input_progress >= stall_ms) || (queued && now - output_progress >= stall_ms)) return done(out, RELAY_STALL);
        int ready = want > 2 && have == want;
        struct pollfd p[2] = {
            {tcp_fd, (short)((!ready ? POLLIN : 0) | (queued ? POLLOUT : 0)), 0},
            {hci_fd, (short)((!queued ? POLLIN : 0) | (ready ? POLLOUT : 0)), 0}
        };
        long long wait = end - now;
        if (have && input_progress + stall_ms - now < wait) wait = input_progress + stall_ms - now;
        if (queued && output_progress + stall_ms - now < wait) wait = output_progress + stall_ms - now;
        int rc = poll(p, 2, (int)wait);
        if (rc < 0) { if (errno == EINTR) continue; return done(out, RELAY_IO); }
        if (!rc) continue;
        if ((p[0].revents | p[1].revents) & POLLNVAL) return done(out, RELAY_IO);
        if (ready && (p[1].revents & POLLOUT)) {
            ssize_t n = send(hci_fd, input + 2, want - 2, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n < 0) { if (!again()) return done(out, RELAY_IO); }
            else if ((size_t)n != want - 2) return done(out, RELAY_IO); /* HCI is atomic. */
            else {
#ifndef RELAY_ALLOW_UNRESTRICTED_TEST_TRANSPORT
                if (reset_phase == 1) reset_phase = 2;
#endif
                out->to_controller++; memset(input, 0, want); have = 0; want = 2; input_progress = 0; ready = 0;
            }
        }
        if (queued && (p[0].revents & POLLOUT)) {
            ssize_t n = send(tcp_fd, output + sent, queued - sent, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n < 0) { if (!again()) return done(out, RELAY_IO); }
            else if (!n) return done(out, RELAY_IO);
            else {
                sent += (size_t)n; output_progress = now_ms();
                if (sent == queued) { out->to_host++; memset(output, 0, queued); queued = sent = 0; output_progress = 0; }
            }
        }
        if (!ready && (p[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(tcp_fd, input + have, want - have, MSG_DONTWAIT);
            if (n < 0) { if (!again()) return done(out, RELAY_IO); }
            else if (!n) return done(out, have ? RELAY_MALFORMED : RELAY_EOF);
            else {
                have += (size_t)n; input_progress = now_ms();
                if (want == 2 && have == 2) {
                    size_t payload = ((size_t)input[0] << 8) | input[1];
                    if (!payload || payload > PACKET_MAX || payload > 1028) return done(out, RELAY_MALFORMED);
                    want = payload + 2;
                }
                if (want > 2 && have == want) {
                    if (!relay_packet_valid(input + 2, want - 2, 1)) return done(out, RELAY_MALFORMED);
#ifndef RELAY_ALLOW_UNRESTRICTED_TEST_TRANSPORT
                    if (!relay_packet_allowed(input + 2, want - 2, 1)) return done(out, RELAY_POLICY);
                    int is_reset = want == 6 && input[2] == 1 && input[3] == 3 && input[4] == 0x0c && input[5] == 0;
                    if (reset_phase < 3 && (reset_phase != 0 || !is_reset)) return done(out, RELAY_POLICY);
                    if (is_reset) reset_phase = 1;
#endif
                }
            }
        }
        if (!queued && (p[1].revents & POLLIN)) {
            ssize_t n = recv(hci_fd, output + 2, PACKET_MAX, MSG_DONTWAIT | MSG_TRUNC);
            if (n < 0) { if (!again()) return done(out, RELAY_IO); }
            else if (n <= 0 || n > PACKET_MAX || !relay_packet_valid(output + 2, (size_t)n, 0)) return done(out, RELAY_MALFORMED);
            else {
#ifndef RELAY_ALLOW_UNRESTRICTED_TEST_TRANSPORT
                if (!relay_packet_allowed(output + 2, (size_t)n, 0)) return done(out, RELAY_POLICY);
                if (reset_phase < 3) {
                    const unsigned char *p = output + 2;
                    if (reset_phase != 2 || n != 7 || p[0] != 4 || p[1] != 0x0e || p[2] != 4 ||
                        p[4] != 3 || p[5] != 0x0c || p[6] != 0) return done(out, RELAY_POLICY);
                    reset_phase = 3;
                }
#endif
                output[0] = (unsigned)n >> 8; output[1] = (unsigned)n; queued = (size_t)n + 2; sent = 0; output_progress = now_ms();
            }
        }
        if ((p[1].revents & (POLLHUP | POLLERR)) && !(p[1].revents & POLLIN)) return done(out, RELAY_IO);
        if ((p[0].revents & POLLERR) && !(p[0].revents & POLLIN)) return done(out, RELAY_IO);
    }
}
int relay_listen(void) {
    int f = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (f < 0) return -1;
    int one = 1;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(RELAY_PORT); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (setsockopt(f, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) || bind(f, (struct sockaddr *)&a, sizeof a) || listen(f, 1)) {
        int saved = errno; close(f); errno = saved; return -1;
    }
    return f;
}
int relay_accept(int listener, unsigned wait_ms) {
    long long now = now_ms();
    if (now < 0 || !wait_ms || wait_ms > 20000) { errno = EINVAL; return -1; }
    const long long end = now + wait_ms;
    while ((now = now_ms()) >= 0 && now < end) {
        struct pollfd p = {listener, POLLIN, 0};
        int rc = poll(&p, 1, (int)(end - now));
        if (rc < 0) { if (errno == EINTR) continue; return -1; }
        if (!rc) break;
        struct sockaddr_in peer; socklen_t length = sizeof peer;
        int f = accept4(listener, (struct sockaddr *)&peer, &length, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (f < 0) { if (again()) continue; return -1; }
        if (length != sizeof peer || peer.sin_family != AF_INET || peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) { close(f); errno = EACCES; return -1; }
        int one = 1, keepidle = 1, keepinterval = 1, keepcount = 2, timeout = 3000;
        if (setsockopt(f, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) ||
            setsockopt(f, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one) ||
            setsockopt(f, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof keepidle) ||
            setsockopt(f, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof keepinterval) ||
            setsockopt(f, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof keepcount) ||
            setsockopt(f, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, sizeof timeout)) {
            int saved = errno; close(f); errno = saved; return -1;
        }
        return f;
    }
    errno = ETIMEDOUT; return -1;
}
