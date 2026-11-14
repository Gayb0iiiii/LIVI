#define _GNU_SOURCE
#include "radio.h"
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define HCIDEVUP _IOW('H', 201, int)
#define HCIDEVDOWN _IOW('H', 202, int)
#ifndef COMMAND_MS
#define COMMAND_MS 3000
#endif
struct hci_address { sa_family_t family; unsigned short dev, channel; };
_Static_assert(sizeof(struct hci_address) == 6, "Linux HCI sockaddr ABI size");
static int radio_ioctl(unsigned long request) {
    int f = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, 1);
    if (f < 0) return -1;
    int rc = ioctl(f, request, 0UL), saved = errno;
    close(f); errno = saved;
    if (request == HCIDEVUP && rc && errno == EALREADY) return 0;
    return rc;
}
int hw_down(void) { return radio_ioctl(HCIDEVDOWN); }
int hw_up(void) { return radio_ioctl(HCIDEVUP); }
int hw_user_open(void) {
    int f = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, 1);
    if (f < 0) return -1;
    struct hci_address a = {AF_BLUETOOTH, 0, 1};
    if (bind(f, (struct sockaddr *)&a, sizeof a)) { int e = errno; close(f); errno = e; return -1; }
    return f;
}
/* Returns 1 for our completed command, 0 for unrelated/waiting, -1 malformed. */
int decode_version(const unsigned char *p, size_t n, struct radio_version *v) {
    memset(v, 0, sizeof *v);
    if (!n) return -1;
    if (p[0] != 4) return 0; /* Ignore other packet types; never expose them. */
    if (n < 3 || n != (size_t)p[2] + 3) return -1;
    if (p[1] == 0x0e) {
        if (n < 6) return -1;
        if (p[4] != 1 || p[5] != 0x10) return 0;
        if (n < 7) return -1;
        v->status = p[6];
        if (v->status) return 1;
        if (n != 15) return -1;
        v->hci_version = p[7]; v->lmp_version = p[10]; return 1;
    }
    if (p[1] == 0x0f) {
        if (n != 7) return -1;
        if (p[5] != 1 || p[6] != 0x10) return 0;
        v->status = p[3]; return v->status ? 1 : 0;
    }
    return 0;
}
static long long monotonic_ms(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
int hw_read_version(int fd, struct radio_version *version) {
    static const unsigned char command[] = {1, 1, 0x10, 0}; /* H4 Read Local Version, opcode 0x1001. */
    if (send(fd, command, sizeof command, MSG_DONTWAIT | MSG_NOSIGNAL) != sizeof command) return -1;
    long long now = monotonic_ms(); if (now < 0) return -1;
    long long end = now + COMMAND_MS;
    unsigned char packet[260]; unsigned events = 0;
    while ((now = monotonic_ms()) >= 0 && now < end && events < 64) {
        struct pollfd p = {fd, POLLIN, 0};
        int rc = poll(&p, 1, (int)(end - now));
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) return -1;
        if (!rc) break;
        if (!(p.revents & POLLIN)) { errno = EIO; return -1; }
        ssize_t n = recv(fd, packet, sizeof packet, MSG_DONTWAIT | MSG_TRUNC);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0 || n > (ssize_t)sizeof packet) { errno = EPROTO; return -1; }
        events++;
        rc = decode_version(packet, (size_t)n, version);
        memset(packet, 0, sizeof packet);
        if (rc < 0) { errno = EPROTO; return -1; }
        if (rc == 1) return 0;
    }
    errno = ETIMEDOUT; return -1;
}
