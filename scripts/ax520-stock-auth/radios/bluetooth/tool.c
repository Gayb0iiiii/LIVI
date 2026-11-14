#define _GNU_SOURCE
#include "radio.h"
#include "relay.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef STOCK_EXE
#define STOCK_EXE "/mnt/customer/app/btapp"
#endif
#ifndef STOCK_TTY
#define STOCK_TTY "/dev/ttyS2"
#endif
#ifndef TRIAL_MS
#define TRIAL_MS 15000
#endif
#ifndef RESTORE_MS
#define RESTORE_MS 10000
#endif
#ifndef LOCK_PATH
#define LOCK_PATH "/tmp/ax520-hci-proof.lock"
#endif
#ifndef RELAY_WAIT_MS
#define RELAY_WAIT_MS 20000
#endif
#ifndef RELAY_LIVE_MS
#define RELAY_LIVE_MS 300000
#endif
#ifndef RELAY_TRIAL_MS
#define RELAY_TRIAL_MS 330000
#endif
#ifndef RELAY_STALL_MS
#define RELAY_STALL_MS 3000
#endif
_Static_assert(RELAY_WAIT_MS <= 20000 && RELAY_LIVE_MS <= 300000 && RELAY_TRIAL_MS <= 330000 && RESTORE_MS <= 10000,
               "pairing artifact duration bounds must remain explicit");
struct identity { pid_t pid, ppid, pgrp; unsigned long long start; char state; };
struct pins { struct identity sup, worker; char hash[65]; unsigned ttyfd; };
struct owned { volatile sig_atomic_t sup_stop, worker_stop, down_attempt, proof_ok, host_seen; volatile uint32_t original_flags; };
static struct owned *owned;
static struct pins pins;
static struct radio_info baseline;
static int status_fd = -1;
static volatile sig_atomic_t interrupted;
static int relay_mode;
static long long now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(90);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void tick(void) { struct timespec t = {0, 10000000}; nanosleep(&t, NULL); }
static void note(const char *message) { dprintf(status_fd, "%lld %s\n", now_ms(), message); }
static void error_note(const char *message) { int e = errno; dprintf(status_fd, "%lld %s errno=%d\n", now_ms(), message, e); }
static void on_signal(int sig) { (void)sig; interrupted = 1; }
static int number(const char *s, unsigned long long *out) {
    if (!s || !*s || !isdigit((unsigned char)*s)) return -1;
    errno = 0; char *end; unsigned long long v = strtoull(s, &end, 10);
    if (errno || *end) return -1;
    *out = v; return 0;
}
static int read_text(const char *path, char *out, size_t capacity) {
    int f = open(path, O_RDONLY | O_CLOEXEC);
    if (f < 0) return -1;
    ssize_t n = read(f, out, capacity - 1); int saved = errno; close(f); errno = saved;
    if (n <= 0 || (size_t)n >= capacity - 1) return -1;
    out[n] = 0; return 0;
}
static int process_path(const char *path, pid_t pid, struct identity *out) {
    char text[2048];
    if (read_text(path, text, sizeof text)) return -1;
    char *end = strrchr(text, ')');
    if (!end || end[1] != ' ') return -1;
    char *save = NULL; unsigned field = 3; memset(out, 0, sizeof *out); out->pid = pid;
    for (char *s = strtok_r(end + 2, " \n", &save); s; s = strtok_r(NULL, " \n", &save), field++) {
        unsigned long long v;
        if (field == 3) out->state = s[0];
        if (field == 4 || field == 5 || field == 22) {
            if (number(s, &v)) return -1;
            if (field == 22) { out->start = v; return 0; }
            if (v > INT_MAX) return -1;
            if (field == 4) out->ppid = (pid_t)v; else out->pgrp = (pid_t)v;
        }
    }
    return -1;
}
static int process(pid_t pid, struct identity *out) {
    char path[64]; snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    return process_path(path, pid, out);
}
static int same_process(const struct identity *want, int hash_check) {
    struct identity got; char path[64], target[PATH_MAX], hash[65];
    if (process(want->pid, &got) || got.start != want->start || got.ppid != want->ppid ||
        got.pgrp != want->pgrp || got.state == 'Z' || got.state == 'X') return 0;
    snprintf(path, sizeof path, "/proc/%ld/exe", (long)want->pid);
    ssize_t n = readlink(path, target, sizeof target - 1);
    if (n < 0 || n >= (ssize_t)sizeof target - 1) return 0;
    target[n] = 0;
    if (strcmp(target, STOCK_EXE)) return 0;
    return !hash_check || (!sha256_file(path, hash) && !strcmp(hash, pins.hash));
}
static int tty_owned(void) {
    char path[80], target[PATH_MAX]; struct stat a, b;
    snprintf(path, sizeof path, "/proc/%ld/fd/%u", (long)pins.worker.pid, pins.ttyfd);
    ssize_t n = readlink(path, target, sizeof target - 1);
    if (n < 0 || n >= (ssize_t)sizeof target - 1) return 0;
    target[n] = 0;
    return !strcmp(target, STOCK_TTY) && !stat(path, &a) && !stat(STOCK_TTY, &b) &&
        S_ISCHR(a.st_mode) && S_ISCHR(b.st_mode) && a.st_rdev == b.st_rdev;
}
static int thread_states(pid_t pid, int stopped) {
    char dirpath[64]; snprintf(dirpath, sizeof dirpath, "/proc/%ld/task", (long)pid);
    DIR *d = opendir(dirpath); if (!d) return 0;
    struct dirent *entry; unsigned count = 0; int ok = 1;
    while ((entry = readdir(d))) {
        if (entry->d_name[0] == '.') continue;
        unsigned long long tid;
        if (number(entry->d_name, &tid) || tid > INT_MAX || ++count > 128) { ok = 0; break; }
        char path[128]; struct identity p;
        snprintf(path, sizeof path, "%s/%ld/stat", dirpath, (long)tid);
        if (process_path(path, (pid_t)tid, &p)) { ok = 0; break; }
        if (stopped ? p.state != 'T' : !(p.state == 'S' || p.state == 'R' || p.state == 'I')) { ok = 0; break; }
    }
    closedir(d); return ok && count;
}
static int identities(int hash_check) {
    return same_process(&pins.sup, hash_check) && same_process(&pins.worker, hash_check) &&
        pins.worker.ppid == pins.sup.pid && pins.worker.pgrp == pins.sup.pgrp && tty_owned();
}
static int preflight(void) {
    struct radio_info info;
    if (!identities(1) || !thread_states(pins.sup.pid, 0) || !thread_states(pins.worker.pid, 0) ||
        hw_topology() || hw_info(&info) || info.bus != 3 || (info.flags & (1U << 1))) return -1;
    baseline = info; return 0;
}
static int pause_process(const struct identity *p, volatile sig_atomic_t *attempt) {
    if (!same_process(p, 1) || !thread_states(p->pid, 0)) return -1;
    *attempt = 1; /* Record intent before a signal that might outlive this process. */
    if (kill(p->pid, SIGSTOP)) return -1;
    long long end = now_ms() + 2000;
    do { if (!same_process(p, 0)) return -1; if (thread_states(p->pid, 1)) return 0; tick(); } while (now_ms() < end);
    return -1;
}
static void worker(pid_t guardian_pid) {
    signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != guardian_pid) _exit(10);
    int peer = -1;
    if (relay_mode) {
        int listener = relay_listen();
        if (listener < 0) { error_note("relay_listen_failed_no_mutation"); _exit(20); }
        note("relay_listening_loopback_only");
        peer = relay_accept(listener, RELAY_WAIT_MS);
        int saved = errno; close(listener); errno = saved;
        if (peer < 0) { int timed_out = errno == ETIMEDOUT; error_note("relay_no_host_no_mutation"); _exit(timed_out ? 0 : 21); }
        owned->host_seen = 1;
        if (preflight()) { note("relay_connected_preflight_failed_no_mutation"); close(peer); _exit(22); }
        owned->original_flags = baseline.flags;
        dprintf(status_fd, "%lld relay_host_connected original_flags=%u\n", now_ms(), baseline.flags);
    }
    if (!identities(1) || hw_topology()) _exit(11);
    struct radio_info info;
    if (hw_info(&info) || info.flags != baseline.flags) _exit(12);
    if (pause_process(&pins.sup, &owned->sup_stop)) { error_note("pause_supervisor_failed"); _exit(13); }
    if (pause_process(&pins.worker, &owned->worker_stop)) { error_note("pause_worker_failed"); _exit(14); }
    if (!identities(0) || !thread_states(pins.sup.pid, 1) || !thread_states(pins.worker.pid, 1) || hw_topology()) _exit(15);
    note("stock_pair_all_threads_paused_uart_fd_preserved");
    if (hw_info(&info) || info.flags != baseline.flags) { note("paused_controller_baseline_changed_no_mutation"); _exit(15); }
    owned->down_attempt = 1;
    if (hw_down()) { error_note("hci_down_failed"); _exit(16); }
    if (hw_info(&info) || (info.flags & 1)) { note("hci_down_unverified"); _exit(17); }
    note("hci_down_verified");
    int fd = hw_user_open();
    if (fd < 0) { error_note("hci_user_bind_failed"); _exit(18); }
    note("hci_user_owned");
    if (relay_mode) {
        struct relay_stats stats;
        int rc = relay_pump(fd, peer, RELAY_LIVE_MS, RELAY_STALL_MS, &stats);
        dprintf(status_fd, "%lld relay_stop_reason=%u to_controller=%llu to_host=%llu\n", now_ms(), stats.stop_reason,
            (unsigned long long)stats.to_controller, (unsigned long long)stats.to_host);
        owned->proof_ok = rc == 0;
        close(peer);
        close(fd);
        _exit(rc ? 23 : 0);
    }
    struct radio_version version = {0};
    int rc = hw_read_version(fd, &version);
    if (rc) error_note("read_local_version_failed");
    else dprintf(status_fd, "%lld version_status=%u hci_version=%u lmp_version=%u\n", now_ms(), version.status, version.hci_version, version.lmp_version);
    owned->proof_ok = !rc && version.status == 0;
    close(fd); /* The guardian never inherits this socket. */
    _exit(owned->proof_ok ? 0 : 19);
}
/* Exit closes USER synchronously in the kernel. Reap before controller restoration. */
static int wait_owned(pid_t child, unsigned timeout, int *success) {
    int status; long long end = now_ms() + timeout;
    while (now_ms() < end && !interrupted) {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) { *success = WIFEXITED(status) && WEXITSTATUS(status) == 0; return 0; }
        if (r < 0 && errno != EINTR) return -1;
        tick();
    }
    if (kill(child, SIGKILL) && errno != ESRCH) return -1;
    end = now_ms() + 1000;
    do {
        pid_t r = waitpid(child, &status, WNOHANG);
        if (r == child) { *success = 0; return 0; }
        if (r < 0 && errno != EINTR) return -1;
        tick();
    } while (now_ms() < end);
    return -1;
}
static int bounded_radio_restore(void) {
    pid_t guardian_pid = getpid();
    pid_t child = fork();
    if (child < 0) return -1;
    if (!child) {
        signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != guardian_pid) _exit(2);
        int rc;
        if (owned->original_flags & 1) rc = hw_up(); else {
            struct radio_info info; rc = hw_info(&info);
            if (!rc && (info.flags & 1)) rc = hw_down();
        }
        if (rc) error_note("controller_restore_failed");
        _exit(rc ? 1 : 0);
    }
    struct identity helper;
    if (!process(child, &helper)) dprintf(status_fd, "%lld restore_helper_pid=%ld start=%llu\n", now_ms(), (long)child, helper.start);
    int success = 0;
    sig_atomic_t was_interrupted = interrupted; interrupted = 0;
    int rc = wait_owned(child, RESTORE_MS, &success);
    interrupted |= was_interrupted;
    if (rc) note("restore_helper_unreaped");
    return rc ? -2 : success ? 0 : -1;
}
static int resume_process(const struct identity *p, int attempted) {
    if (!attempted) return 0;
    if (!same_process(p, 1)) { note("resume_identity_changed_no_signal"); return -1; }
    if (kill(p->pid, SIGCONT)) return -1;
    long long end = now_ms() + 1000;
    do { if (same_process(p, 0) && thread_states(p->pid, 0)) return 0; tick(); } while (now_ms() < end);
    return -1;
}
static int restore(int worker_reaped) {
    int ok = worker_reaped;
    if (!worker_reaped) {
        note("worker_release_unverified_no_controller_operation_stock_pair_left_paused");
        return -1;
    }
    if (worker_reaped && owned->down_attempt) {
        if (!identities(1) || hw_topology()) { note("restore_identity_or_topology_changed"); ok = 0; }
        else {
            int rc = bounded_radio_restore();
            if (rc == -2) { note("restore_helper_release_unverified_stock_pair_left_paused"); return -1; }
            if (rc) ok = 0;
        }
    }
    /* Resume only exact pinned stock processes, even if controller restoration failed. */
    if (resume_process(&pins.worker, owned->worker_stop)) ok = 0;
    if (resume_process(&pins.sup, owned->sup_stop)) ok = 0;
    struct radio_info info;
    if (!identities(1) || !thread_states(pins.worker.pid, 0) || !thread_states(pins.sup.pid, 0) ||
        hw_topology() || hw_info(&info) || ((info.flags ^ owned->original_flags) & 1)) ok = 0;
    note(ok ? "structural_restore_verified_phone_link_not_verified" : "structural_restore_unverified");
    return ok ? 0 : -1;
}
static void null_stdio(void) {
    int f = open("/dev/null", O_RDWR);
    if (f < 0) _exit(91);
    for (int i = 0; i < 3; i++) if (dup2(f, i) < 0) _exit(91);
    if (f > 2) close(f);
}
static void guard(int handshake) {
    if (setsid() < 0) _exit(30);
    signal(SIGHUP, SIG_IGN); signal(SIGPIPE, SIG_IGN); signal(SIGCHLD, SIG_DFL);
    signal(SIGTERM, on_signal); signal(SIGINT, on_signal);
    null_stdio();
    struct identity self;
    if (process(getpid(), &self)) _exit(30);
    unsigned trial_ms = relay_mode ? RELAY_TRIAL_MS : TRIAL_MS;
    dprintf(status_fd, "%lld watchdog_armed pid=%ld start=%llu trial_ms=%u recovery_ms=%d\n", now_ms(), (long)getpid(), self.start, trial_ms, RESTORE_MS);
    if (write(handshake, "A", 1) != 1) _exit(31);
    close(handshake);
    pid_t guardian_pid = getpid(), child = fork();
    if (child < 0) { note("RESULT launch_failed_no_mutation"); _exit(32); }
    if (!child) worker(guardian_pid);
    struct identity child_identity;
    if (!process(child, &child_identity)) dprintf(status_fd, "%lld trial_worker_pid=%ld start=%llu\n", now_ms(), (long)child, child_identity.start);
    int success = 0;
    int reaped = wait_owned(child, trial_ms, &success) == 0;
    note(reaped ? "worker_reaped_user_socket_released" : "worker_reap_failed");
    int recovered = restore(reaped) == 0;
    if (!recovered) note("RESULT restoration_unverified_no_retry");
    else if (relay_mode) note(!owned->host_seen && success ? "RESULT relay_no_host_restored" :
         success && owned->proof_ok ? "RESULT relay_complete_restored" : "RESULT relay_failed_restored");
    else note(success && owned->proof_ok ? "RESULT proof_ok_restored" : "RESULT proof_failed_restored");
    fsync(status_fd); _exit(recovered ? 0 : 33);
}
static int parse_pid(const char *s, pid_t *pid) {
    unsigned long long v;
    if (number(s, &v) || v <= 1 || v > INT_MAX) return -1;
    *pid = (pid_t)v; return 0;
}
static int load_pins(pid_t sup, pid_t worker_pid, unsigned ttyfd) {
    if (sup == worker_pid || process(sup, &pins.sup) || process(worker_pid, &pins.worker)) return -1;
    pins.ttyfd = ttyfd;
    char path[64]; snprintf(path, sizeof path, "/proc/%ld/exe", (long)worker_pid);
    return sha256_file(path, pins.hash);
}
static int inspect(int argc, char **argv) {
    pid_t sup, worker_pid; unsigned long long fd;
    if (argc != 5 || parse_pid(argv[2], &sup) || parse_pid(argv[3], &worker_pid) ||
        number(argv[4], &fd) || fd > 1024 || load_pins(sup, worker_pid, (unsigned)fd) || preflight()) {
        fputs("inspect blocked: identity, topology or GET-only HCI capability unverified\n", stderr); return 3;
    }
    printf("{\"supervisor_pid\":%ld,\"supervisor_start\":%llu,\"worker_pid\":%ld,\"worker_start\":%llu,\"sha256\":\"%s\",\"tty_fd\":%u,\"hci_id\":0,\"hci_flags\":%u,\"hci_up\":%s,\"hci_bus\":%u,\"connections\":%u,\"raw_socket_get_capable\":true}\n",
        (long)pins.sup.pid, pins.sup.start, (long)pins.worker.pid, pins.worker.start, pins.hash, pins.ttyfd,
        baseline.flags, (baseline.flags & 1) ? "true" : "false", baseline.bus, baseline.connections);
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--bounds")) {
        printf("{\"mode\":\"fresh_pairing_300s\",\"loopback_port\":%d,\"accept_ms\":%d,\"relay_ms\":%d,\"worker_ms\":%d,\"restore_ms\":%d,\"worker_reap_ms\":1000,\"restore_reap_ms\":1000,\"resume_each_ms\":1000,\"pending_io_stall_ms\":%d}\n",
               RELAY_PORT, RELAY_WAIT_MS, RELAY_LIVE_MS, RELAY_TRIAL_MS, RESTORE_MS, RELAY_STALL_MS);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--inspect")) return inspect(argc, argv);
#ifdef INSPECT_ONLY
    fputs("inspect-only build: --inspect SUP_PID WORKER_PID TTY_FD\n", stderr); return 2;
#else
    if (argc != 9 || (strcmp(argv[1], "--launch") && strcmp(argv[1], "--relay-launch"))) {
        fputs("usage: --inspect SUP_PID WORKER_PID TTY_FD | --launch|--relay-launch EXISTING_PRIVATE_RUN_DIR SUP_PID SUP_START WORKER_PID WORKER_START SHA256 TTY_FD\n", stderr); return 2;
    }
    relay_mode = !strcmp(argv[1], "--relay-launch");
    pid_t sup, worker_pid; unsigned long long ss, ws, fd;
    if (parse_pid(argv[3], &sup) || number(argv[4], &ss) || parse_pid(argv[5], &worker_pid) ||
        number(argv[6], &ws) || strlen(argv[7]) != 64 || number(argv[8], &fd) || fd > 1024) return 2;
    for (unsigned i = 0; i < 64; i++) if (!strchr("0123456789abcdef", argv[7][i])) return 2;
    if (load_pins(sup, worker_pid, (unsigned)fd) || pins.sup.start != ss || pins.worker.start != ws ||
        strcmp(pins.hash, argv[7]) || preflight()) { fputs("preflight blocked\n", stderr); return 3; }
    umask(077); struct stat st;
    if (argv[2][0] != '/' || lstat(argv[2], &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) return 2;
    int lock = open(LOCK_PATH, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (lock < 0 || fstat(lock, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0600 || st.st_nlink != 1 || flock(lock, LOCK_EX | LOCK_NB)) return 3;
    int dir = open(argv[2], O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) return 3;
    status_fd = openat(dir, "status", O_CREAT | O_EXCL | O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0600);
    close(dir); if (status_fd < 0) return 3;
    owned = mmap(NULL, sizeof *owned, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (owned == MAP_FAILED) return 3;
    memset(owned, 0, sizeof *owned);
    owned->original_flags = baseline.flags;
    dprintf(status_fd, "%lld preflight_verified supervisor=%ld/%llu worker=%ld/%llu sha256=%s tty_fd=%u original_flags=%u connections=%u\n", now_ms(), (long)sup, ss, (long)worker_pid, ws, pins.hash, pins.ttyfd, baseline.flags, baseline.connections);
    int handshake[2]; if (pipe2(handshake, O_CLOEXEC)) return 3;
    pid_t child = fork();
    if (!child) { close(handshake[0]); guard(handshake[1]); _exit(34); }
    close(handshake[1]);
    if (child < 0) { close(handshake[0]); return 3; }
    struct pollfd p = {handshake[0], POLLIN, 0}; char mark = 0;
    if (poll(&p, 1, 3000) > 0) (void)read(handshake[0], &mark, 1);
    close(handshake[0]);
    if (mark != 'A') { fputs("launch unverified; inspect status before any retry\n", stderr); return 4; }
    printf("{\"watchdog_pid\":%ld,\"started\":true}\n", (long)child);
    return 0;
#endif
}
