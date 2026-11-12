/* SPDX-License-Identifier: GPL-3.0-or-later
 * Review prototype: default build observes/serializes, but opens NO listener.
 * Network code is available only with the synthetic test provider, never stock.
 * No vendor code, authentication identity, or key material belongs in this file.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef AX520_ENABLE_DEVICE_BRIDGE
#error "Device bridge blocked: target ABI, lifecycle and protocol metadata need review"
#endif

typedef int (*setter_fn)(void *, int, const char *);
typedef int (*sign_fn)(const void *, size_t, unsigned char **, size_t *);
typedef int (*cert_fn)(unsigned char **, size_t *);

/* These are real pthread types from the build's headers, never guessed storage. */
static pthread_mutex_t provider_lock = PTHREAD_MUTEX_INITIALIZER;
static setter_fn stock_setter;
static sign_fn stock_sign;
static cert_fn stock_cert;
static pid_t constructor_pid;
static int atfork_ok, fork_child, selected;
static int observer_reader = -1, observer_writer = -1;

#ifdef AX520_SYNTHETIC_TEST
static int listener_fd = -1, client_fd = -1, server_started;
static pthread_mutex_t lifecycle_lock = PTHREAD_MUTEX_INITIALIZER;
static void start_server_locked(void);
#else
static void start_server_locked(void) {}
#endif

static void resolve_locked(void) {
    if (!stock_setter) stock_setter = (setter_fn)dlsym(RTLD_NEXT, "SetiAPI2CAddr");
    if (!stock_sign) stock_sign = (sign_fn)dlsym(RTLD_NEXT, "AuthDeviceCreateSignature");
    if (!stock_cert) stock_cert = (cert_fn)dlsym(RTLD_NEXT, "AuthDeviceCopyCertificate");
}

static int pipe_descriptor(const char **text, char terminator) {
    unsigned long value = 0;
    const char *start = *text;
    while (**text && **text != terminator) {
        unsigned char digit = (unsigned char)*(*text)++;
        if (digit < '0' || digit > '9') return -1;
        digit -= '0';
        if (value > ((unsigned long)INT_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
    }
    if (*text == start || **text != terminator || value < 3) return -1;
    if (terminator) ++*text;
    return (int)value;
}

static void observer_initialize(void) {
    const char *pair = getenv("AX520_OBSERVER_FDS");
    if (!pair) return;
    int reader = pipe_descriptor(&pair, ':');
    int writer = pipe_descriptor(&pair, '\0');
    struct stat read_stat, write_stat;
    if (reader < 0 || writer < 0 || reader == writer ||
        fstat(reader, &read_stat) || fstat(writer, &write_stat) ||
        !S_ISFIFO(read_stat.st_mode) || !S_ISFIFO(write_stat.st_mode) ||
        read_stat.st_dev != write_stat.st_dev || read_stat.st_ino != write_stat.st_ino)
        return;
    int read_flags = fcntl(reader, F_GETFL), write_flags = fcntl(writer, F_GETFL);
    if (read_flags < 0 || write_flags < 0 || (read_flags & O_ACCMODE) != O_RDONLY ||
        (write_flags & O_ACCMODE) != O_WRONLY || !(write_flags & O_NONBLOCK)) return;
    observer_reader = fcntl(reader, F_DUPFD_CLOEXEC, 3);
    if (observer_reader < 0) return;
    observer_writer = fcntl(writer, F_DUPFD_CLOEXEC, 3);
    if (observer_writer < 0) { close(observer_reader); observer_reader = -1; }
}

static void observer_event(unsigned char flags) {
    if (observer_writer < 0) return;
    int saved_errno = errno;
    uint32_t pid = (uint32_t)getpid();
    unsigned char event[12] = {'A', 'X', 'O', 'B', 1, flags, 0, 0,
        (unsigned char)(pid >> 24), (unsigned char)(pid >> 16),
        (unsigned char)(pid >> 8), (unsigned char)pid};
    /* One nonblocking write, below PIPE_BUF. Full pipes drop the event. Keeping
     * our own read end avoids SIGPIPE even after the collector disappears.
     * The caller must not change the dedicated pipe's O_NONBLOCK status. */
    (void)write(observer_writer, event, sizeof event);
    errno = saved_errno;
}

static void fork_prepare(void) {
    pthread_mutex_lock(&provider_lock);
#ifdef AX520_SYNTHETIC_TEST
    pthread_mutex_lock(&lifecycle_lock);
#endif
}
static void fork_parent(void) {
#ifdef AX520_SYNTHETIC_TEST
    pthread_mutex_unlock(&lifecycle_lock);
#endif
    pthread_mutex_unlock(&provider_lock);
}
static void fork_reset(void) {
    /* Only this thread survives fork. Parent sockets must never be shutdown. */
    selected = 0;
    fork_child = 1;
#ifdef AX520_SYNTHETIC_TEST
    if (listener_fd >= 0) close(listener_fd);
    if (client_fd >= 0) close(client_fd);
    listener_fd = client_fd = -1;
    server_started = 0;
    pthread_mutex_unlock(&lifecycle_lock);
#endif
    pthread_mutex_unlock(&provider_lock);
}

__attribute__((constructor)) static void initialize(void) {
    constructor_pid = getpid();
    /* No thread, socket, provider operation or selection is performed here. */
    atfork_ok = pthread_atfork(fork_prepare, fork_parent, fork_reset) == 0;
    observer_initialize();
    observer_event(0);
}

int SetiAPI2CAddr(void *context, int address, const char *path) {
    int result = -1;
    pthread_mutex_lock(&provider_lock);
    selected = 0;
    resolve_locked();
    if (stock_setter) result = stock_setter(context, address, path);
    /* Observe the original call AFTER forwarding it, with no altered arguments.
     * A zero return alone is insufficient: exact observed selector and child
     * lifecycle are also required. The real device gate remains unresolved. */
    if (result == 0 && address == 0x20 && path && !strcmp(path, "ly_iap") &&
        atfork_ok && fork_child && getpid() != constructor_pid) {
        selected = 1;
        start_server_locked();
    }
#ifdef AX520_SYNTHETIC_TEST
    /* Revocation stops an existing response/session as well as future calls.
     * This is intentionally shutdown here, but close-only in the fork child. */
    pthread_mutex_lock(&lifecycle_lock);
    if (!selected && client_fd >= 0) shutdown(client_fd, SHUT_RDWR);
    pthread_mutex_unlock(&lifecycle_lock);
#endif
    observer_event(1 | (selected ? 2 : 0) | (fork_child ? 4 : 0) | (result ? 8 : 0));
    pthread_mutex_unlock(&provider_lock);
    return result;
}

int AuthDeviceCreateSignature(const void *digest, size_t length,
                              unsigned char **output, size_t *output_length) {
    int result = -1;
    pthread_mutex_lock(&provider_lock);
    resolve_locked();
    /* Preserve stock callers' original arguments and ownership. Broker bounds
     * are applied separately; this lock covers BOTH types of caller. */
    if (stock_sign) result = stock_sign(digest, length, output, output_length);
    else {
        if (output) *output = NULL;
        if (output_length) *output_length = 0;
    }
    pthread_mutex_unlock(&provider_lock);
    return result;
}

int AuthDeviceCopyCertificate(unsigned char **output, size_t *output_length) {
    int result = -1;
    pthread_mutex_lock(&provider_lock);
    resolve_locked();
    if (stock_cert) result = stock_cert(output, output_length);
    else {
        if (output) *output = NULL;
        if (output_length) *output_length = 0;
    }
    pthread_mutex_unlock(&provider_lock);
    return result;
}

#ifdef AX520_SYNTHETIC_TEST
/* This symbol exists only in tests/mock_vendor.c. A test build accidentally
 * loaded beside the stock library still cannot open a signer listener. No env
 * variable or user-provided protocol number can override this gate. */
static int synthetic_provider(void) {
    typedef int (*marker_fn)(void);
    marker_fn marker = (marker_fn)dlsym(RTLD_NEXT, "ax520_synthetic_test_provider");
    Dl_info owner, setter, signer, certificate;
    return marker && dladdr((void *)marker, &owner) &&
        dladdr((void *)stock_setter, &setter) && dladdr((void *)stock_sign, &signer) &&
        dladdr((void *)stock_cert, &certificate) &&
        owner.dli_fbase == setter.dli_fbase && owner.dli_fbase == signer.dli_fbase &&
        owner.dli_fbase == certificate.dli_fbase && marker() == 0x41583532;
}

static int configured_port(void) {
    const char *text = getenv("AX520_AUTH_PORT");
    if (!text) return 15000;
    if (!*text) return -1;
    unsigned int port = 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return -1;
        port = port * 10 + (*p - '0');
        if (port > 65535) return -1;
    }
    return port ? (int)port : -1;
}

static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int nonblocking_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ? -1 : 0;
}

static int provider_lock_until(int64_t deadline) {
    for (;;) {
        int64_t now = milliseconds();
        if (now < 0 || now >= deadline) return -1;
        int result = pthread_mutex_trylock(&provider_lock);
        if (result == 0) {
            now = milliseconds();
            if (now >= 0 && now < deadline) return 0;
            pthread_mutex_unlock(&provider_lock);
            return -1;
        }
        if (result != EBUSY) return -1;
        struct timespec pause = {0, 1000000};
        (void)nanosleep(&pause, NULL);
    }
}

/* One fixed deadline bounds partial/slow reads or blocked response writes.
 * This does not, and cannot, safely cancel an in-process vendor function. */
static int transfer(int fd, void *buffer, size_t size, int sending, int64_t deadline) {
    unsigned char *bytes = buffer;
    while (size) {
        int64_t now = milliseconds();
        if (now < 0 || now >= deadline) return -1;
        struct pollfd item = {fd, sending ? POLLOUT : POLLIN, 0};
        int ready = poll(&item, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return -1;
        ssize_t amount = sending ? send(fd, bytes, size, MSG_NOSIGNAL) : recv(fd, bytes, size, 0);
        if (amount < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (amount <= 0) return -1;
        bytes += amount;
        size -= (size_t)amount;
    }
    return 0;
}

static int reply(int fd, int status, const unsigned char *data, size_t length) {
    unsigned char header[3] = {(unsigned char)status, (unsigned char)(length >> 8), (unsigned char)length};
    int64_t now = milliseconds();
    if (now < 0 || transfer(fd, header, sizeof header, 1, now + 2000)) return -1;
    return length ? transfer(fd, (void *)data, length, 1, now + 2000) : 0;
}

static void erase(void *data, size_t length) {
    volatile unsigned char *p = data;
    while (length--) *p++ = 0;
}

static void serve(int fd) {
    for (;;) {
        unsigned char op, digest[32] = {0}, response[4096];
        size_t response_length = 0;
        int status = 1;
        int64_t now = milliseconds();
        if (now < 0 || transfer(fd, &op, 1, 0, now + 2000)) return;
        if (op == 2) {
            unsigned char encoded_length[2];
            if (transfer(fd, encoded_length, 2, 0, now + 2000)) return;
            if (encoded_length[0] != 0 || encoded_length[1] != 32) {
                (void)reply(fd, 1, NULL, 0);
                return; /* Never consume an unbounded advertised payload. */
            }
            if (transfer(fd, digest, sizeof digest, 0, now + 2000)) {
                erase(digest, sizeof digest);
                return;
            }
        } else if (op != 1 && op != 3) return;

        if (provider_lock_until(now + 2000)) {
            erase(digest, sizeof digest);
            (void)reply(fd, 1, NULL, 0);
            return;
        }
        if (selected && stock_sign && stock_cert) {
            if (op == 3) {
                /* Synthetic fixture metadata only; real major is a blocked gate. */
                response[0] = 3;
                response_length = 1;
                status = 0;
            } else {
                unsigned char *output = NULL;
                size_t length = 0;
                int result = op == 1 ? stock_cert(&output, &length) :
                    stock_sign(digest, sizeof digest, &output, &length);
                int valid = output && result == 0 &&
                    (op == 1 ? length > 0 && length <= sizeof response : length == 64);
                if (valid) {
                    memcpy(response, output, length);
                    response_length = length;
                    status = 0;
                }
                /* Called within the same process/libc that allocated output.
                 * Do not dereference or erase an untrusted claimed length. */
                free(output);
            }
        }
        pthread_mutex_unlock(&provider_lock);
        erase(digest, sizeof digest);
        int sent = reply(fd, status, response, response_length);
        erase(response, response_length);
        if (sent) return;
    }
}

static void *server_main(void *unused) {
    (void)unused;
    for (;;) {
        struct pollfd item;
        pthread_mutex_lock(&lifecycle_lock);
        item = (struct pollfd){listener_fd, POLLIN, 0};
        pthread_mutex_unlock(&lifecycle_lock);
        int result = poll(&item, 1, -1);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || (item.revents & (POLLERR | POLLNVAL))) break;
        pthread_mutex_lock(&lifecycle_lock);
        /* The lock makes newly accepted descriptors visible to atfork reset. */
        int fd = accept(listener_fd, NULL, NULL);
        if (fd >= 0 && nonblocking_cloexec(fd)) { close(fd); fd = -1; }
        client_fd = fd;
        pthread_mutex_unlock(&lifecycle_lock);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        serve(fd);
        pthread_mutex_lock(&lifecycle_lock);
        close(fd);
        client_fd = -1;
        pthread_mutex_unlock(&lifecycle_lock);
    }
    pthread_mutex_lock(&lifecycle_lock);
    if (listener_fd >= 0) close(listener_fd);
    listener_fd = -1;
    server_started = 0;
    pthread_mutex_unlock(&lifecycle_lock);
    return NULL;
}

static void start_server_locked(void) {
    if (!stock_sign || !stock_cert || !synthetic_provider()) return;
    int port = configured_port();
    if (port < 0) return;
    pthread_mutex_lock(&lifecycle_lock);
    if (server_started) { pthread_mutex_unlock(&lifecycle_lock); return; }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { pthread_mutex_unlock(&lifecycle_lock); return; }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (nonblocking_cloexec(fd) || bind(fd, (struct sockaddr *)&address, sizeof address) || listen(fd, 8)) {
        close(fd);
        pthread_mutex_unlock(&lifecycle_lock);
        return;
    }
    listener_fd = fd;
    pthread_t thread;
    if (pthread_create(&thread, NULL, server_main, NULL)) {
        close(fd);
        listener_fd = -1;
        pthread_mutex_unlock(&lifecycle_lock);
        return;
    }
    server_started = 1;
    pthread_detach(thread);
    pthread_mutex_unlock(&lifecycle_lock);
}
#endif
