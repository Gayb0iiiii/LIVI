/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Standalone prototype: stdin/stdout <-> fixed IPv4 loopback only.
 * Usage: relay [port]; default 15000, or AX520_RELAY_PORT.
 * AX520_RELAY_IDLE_MS: decimal 1..60000, default 5000.
 * Exit 0: both directions drained; 1: I/O/timeout; 2: configuration.
 * No protocol interpretation or payload logging. Intended for dedicated pipes.
 * Native tests do not validate the stock ARM32 runtime. No static ARM toolchain
 * has been validated here; do not deploy a native build to the dongle.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

struct buffer {
    unsigned char data[8192];
    size_t offset;
    size_t length;
};

static int parse_decimal(const char *text, unsigned maximum, unsigned *value) {
    unsigned n = 0;
    if (!text || !*text) return -1;
    for (; *text; ++text) {
        unsigned digit;
        if (*text < '0' || *text > '9') return -1;
        digit = (unsigned)(*text - '0');
        if (n > (maximum - digit) / 10) return -1;
        n = n * 10 + digit;
    }
    if (!n || n > maximum) return -1;
    *value = n;
    return 0;
}

static int64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* An interrupted poll consumes the same deadline; it cannot extend the bound. */
static int wait_ready(struct pollfd *fds, nfds_t count, int64_t deadline) {
    for (;;) {
        int64_t now = now_ms();
        int result;
        if (now < 0) return -1;
        if (now >= deadline) return 0;
        result = poll(fds, count, (int)(deadline - now));
        if (result < 0 && errno == EINTR) continue;
        return result;
    }
}

static int transient(void) {
    return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK;
}

static int move_bytes(int fd, struct buffer *buffer, int writing, int *eof,
                      int *progress) {
    ssize_t n;
    if (writing) {
        n = write(fd, buffer->data + buffer->offset, buffer->length);
        if (n > 0) {
            buffer->offset += (size_t)n;
            buffer->length -= (size_t)n;
            if (!buffer->length) buffer->offset = 0;
        }
    } else {
        n = read(fd, buffer->data, sizeof(buffer->data));
        if (n > 0) {
            buffer->offset = 0;
            buffer->length = (size_t)n;
        } else if (n == 0) {
            *eof = 1;
        }
    }
    if (n < 0 && !transient()) return -1;
    if (writing && n == 0) return -1;
    if (n > 0) *progress = 1;
    return 0;
}

static int pump(int sock, unsigned idle_ms) {
    struct buffer to_peer = {{0}, 0, 0}, to_stdout = {{0}, 0, 0};
    int stdin_eof = 0, peer_eof = 0, write_closed = 0;
    int64_t now = now_ms(), deadline;
    if (now < 0) return -1;
    deadline = now + idle_ms;
    for (;;) {
        struct pollfd fds[3];
        int progress = 0;
        if (stdin_eof && !to_peer.length && !write_closed) {
            if (shutdown(sock, SHUT_WR) < 0) return -1;
            write_closed = 1;
        }
        if (stdin_eof && peer_eof && !to_peer.length && !to_stdout.length)
            return 0;
        fds[0] = (struct pollfd){!stdin_eof && !to_peer.length ? STDIN_FILENO : -1,
                                POLLIN, 0};
        fds[1] = (struct pollfd){sock, 0, 0};
        if (!peer_eof && !to_stdout.length) fds[1].events |= POLLIN;
        if (to_peer.length) fds[1].events |= POLLOUT;
        if (!fds[1].events) fds[1].fd = -1;
        fds[2] = (struct pollfd){to_stdout.length ? STDOUT_FILENO : -1, POLLOUT, 0};
        if (wait_ready(fds, 3, deadline) <= 0) return -1;
        for (size_t i = 0; i < 3; ++i)
            if (fds[i].revents & (POLLNVAL | POLLERR)) return -1;
        if (fds[2].revents & POLLHUP) return -1;
        if ((fds[0].revents & (POLLIN | POLLHUP)) &&
            move_bytes(STDIN_FILENO, &to_peer, 0, &stdin_eof, &progress) < 0)
            return -1;
        if ((fds[1].revents & POLLOUT) && to_peer.length &&
            move_bytes(sock, &to_peer, 1, &peer_eof, &progress) < 0)
            return -1;
        if ((fds[1].revents & (POLLIN | POLLHUP)) &&
            !peer_eof && !to_stdout.length &&
            move_bytes(sock, &to_stdout, 0, &peer_eof, &progress) < 0)
            return -1;
        if ((fds[2].revents & POLLOUT) && to_stdout.length &&
            move_bytes(STDOUT_FILENO, &to_stdout, 1, &peer_eof, &progress) < 0)
            return -1;
        if (progress) {
            now = now_ms();
            if (now < 0) return -1;
            deadline = now + idle_ms;
        }
    }
}

int main(int argc, char **argv) {
    const char *port_text = getenv("AX520_RELAY_PORT");
    const char *idle_text = getenv("AX520_RELAY_IDLE_MS");
    unsigned port = 15000, idle_ms = 5000;
    int sock = -1, result = 1, stdin_flags = -1, stdout_flags = -1;
    struct sockaddr_in address = {0};
    struct sigaction action = {0};
    if (argc > 2 ||
        (argc == 2 && parse_decimal(argv[1], 65535, &port) < 0) ||
        (argc == 1 && port_text && parse_decimal(port_text, 65535, &port) < 0) ||
        (idle_text && parse_decimal(idle_text, 60000, &idle_ms) < 0)) {
        fputs("relay: invalid configuration\n", stderr);
        return 2;
    }
    action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) < 0 || sigaction(SIGPIPE, &action, NULL) < 0)
        goto cleanup;
    stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
    stdout_flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (stdin_flags < 0 || stdout_flags < 0 ||
        fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK) < 0 ||
        fcntl(STDOUT_FILENO, F_SETFL, stdout_flags | O_NONBLOCK) < 0)
        goto cleanup;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 || fcntl(sock, F_SETFL, O_NONBLOCK) < 0 ||
        fcntl(sock, F_SETFD, FD_CLOEXEC) < 0)
        goto cleanup;
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
        struct pollfd connection = {sock, POLLOUT, 0};
        int error = 0, connect_error = errno;
        socklen_t size = sizeof(error);
        int64_t now = now_ms();
        if (connect_error != EINPROGRESS || now < 0 ||
            wait_ready(&connection, 1, now + idle_ms) <= 0 ||
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error)
            goto cleanup;
    }
    if (pump(sock, idle_ms) == 0) result = 0;
cleanup:
    if (sock >= 0) close(sock);
    if (stdin_flags >= 0 && fcntl(STDIN_FILENO, F_SETFL, stdin_flags) < 0) result = 1;
    if (stdout_flags >= 0 && fcntl(STDOUT_FILENO, F_SETFL, stdout_flags) < 0) result = 1;
    if (result) fputs("relay: connection, I/O or idle timeout failure\n", stderr);
    return result;
}
