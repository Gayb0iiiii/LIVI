/* Test-only radio boundary. All process identity, signals and watchdog code are real. */
#define _GNU_SOURCE
#include "radio.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>
struct state { int up; int owner; };
static int load(struct state *s) {
    int f = open(getenv("RADIO_STATE"), O_RDWR);
    if (f < 0 || flock(f, LOCK_EX)) abort();
    if (pread(f, s, sizeof *s, 0) != sizeof *s) abort();
    if (s->owner && kill(s->owner, 0) && errno == ESRCH) { s->owner = 0; s->up = 0; }
    return f;
}
static void save(int f, struct state *s) {
    if (pwrite(f, s, sizeof *s, 0) != sizeof *s) abort();
    close(f);
}
static void event(const char *msg) {
    int f = open(getenv("RADIO_EVENTS"), O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (f < 0) abort();
    dprintf(f, "%s\n", msg); close(f);
}
static int mode(const char *name) { return getenv("RADIO_FAIL") && !strcmp(getenv("RADIO_FAIL"), name); }
static void block_reaping(void) {
    char path[1024]; snprintf(path, sizeof path, "%s.blocked", getenv("RADIO_STATE"));
    int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (f < 0) abort();
    dprintf(f, "%ld\n", (long)getpid()); close(f);
    for (;;) pause();
}
int __real_kill(pid_t pid, int signal);
int __wrap_kill(pid_t pid, int signal) {
    /* Simulate a kernel-uninterruptible owned child at the OS signal boundary. */
    if (signal == SIGKILL && (mode("unreaped_main") || mode("unreaped_restore"))) {
        char path[1024]; snprintf(path, sizeof path, "%s.blocked", getenv("RADIO_STATE"));
        FILE *f = fopen(path, "r"); long blocked = 0;
        if (f) { if (fscanf(f, "%ld", &blocked) != 1) blocked = 0; fclose(f); }
        if (blocked == pid) return 0;
    }
    return __real_kill(pid, signal);
}
int hw_topology(void) { return 0; }
int hw_info(struct radio_info *i) {
    struct state s; int f = load(&s);
    i->flags = s.up ? 1 : 0; i->bus = 3; i->connections = 0;
    save(f, &s); return 0;
}
int hw_down(void) {
    event("DOWN");
    struct state s; int f = load(&s); s.up = 0; save(f, &s);
    if (mode("down_error")) { errno = EIO; return -1; }
    return 0;
}
int hw_up(void) {
    event("UP");
    if (mode("unreaped_restore")) block_reaping();
    struct state s; int f = load(&s);
    if (s.owner) abort(); /* Ownership must be gone before restore. */
    if (mode("up_error")) { save(f, &s); errno = EIO; return -1; }
    s.up = 1; save(f, &s); return 0;
}
int hw_user_open(void) {
    event("USER");
    if (mode("bind_error")) { errno = EBUSY; return -1; }
    struct state s; int f = load(&s); if (s.up || s.owner) abort();
    s.owner = getpid(); s.up = 1; save(f, &s);
    if (getenv("RADIO_RELAY")) {
        int pair[2]; if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, pair)) abort();
        return pair[0]; /* The idle peer is private to this short-lived fake worker. */
    }
    return open("/dev/null", O_RDWR);
}
int hw_read_version(int fd, struct radio_version *v) {
    (void)fd; event("VERSION");
    if (mode("crash")) kill(getpid(), SIGKILL);
    if (mode("timeout")) for (;;) pause();
    if (mode("unreaped_main")) block_reaping();
    if (mode("command_error")) { errno = EPROTO; return -1; }
    v->status = 0; v->hci_version = 9; v->lmp_version = 9; return 0;
}
