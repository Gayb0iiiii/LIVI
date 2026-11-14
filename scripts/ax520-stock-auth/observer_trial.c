/* SPDX-License-Identifier: GPL-3.0-or-later
 * Stock process owner: bounded trials or an explicitly selected managed bridge.
 * Linux 4.9 has no pidfds: PID/starttime checks reduce but cannot remove races.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef AX520_LAUNCHER_TEST
#define STOCK_PATH AX520_TEST_STOCK
#define CONSOLE_PATH AX520_TEST_CONSOLE
#define STOCK_NICE 0
#define STOP_MS 500
#define START_MS 1500
#define TRIAL_MS 500
#else
#define STOCK_PATH "/mnt/customer/app/lylinkapp"
#define CONSOLE_PATH "/dev/console"
#define STOCK_NICE (-15)
#define STOP_MS 2000
#define START_MS 5000
#define TRIAL_MS 20000
#endif

#if defined(AX520_LAUNCHER_ENABLE_MANAGED) && !defined(AX520_LAUNCHER_ENABLE_BRIDGE)
#error "Managed mode requires the explicit bridge capability"
#endif

extern char **environ;
struct identity { pid_t pid, parent, group; unsigned long long start; char state; };
struct resources {
    int executable, shim, null_fd, console, status;
    struct stat executable_stat;
    struct sigaction hup, pipe, term;
    sigset_t mask;
};
static struct resources resource;
static const char *env_keys[] = {"WORKDIR", "LD_LIBRARY_PATH", "PATH", "LY_PLATFORM",
                               "LY_MFI_I2C_BUS", "LY_ENCRYPT_I2C_BUS"};
static volatile sig_atomic_t interrupted;
static int device_bridge, managed_bridge;
static int observation_ms = TRIAL_MS;

static int64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int within(int64_t deadline) { int64_t now = now_ms(); return now >= 0 && now < deadline; }
static void tick(void) { struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL); }
static void note(const char *text) { (void)dprintf(resource.status, "%s\n", text); }
static void interrupt_trial(int signal_number) { (void)signal_number; interrupted = 1; }

static ssize_t read_small(const char *path, char *buffer, size_t capacity) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t length = read(fd, buffer, capacity - 1);
    int saved_errno = errno;
    close(fd);
    if (length < 0) { errno = saved_errno; return -1; }
    if ((size_t)length == capacity - 1) { errno = EOVERFLOW; return -1; }
    buffer[length] = 0;
    return length;
}

static int identity_at(const char *path, pid_t pid, struct identity *result) {
    char data[2048];
    if (read_small(path, data, sizeof data) < 0) return -1;
    char *last = strrchr(data, ')');
    if (!last || last[1] != ' ') { errno = EINVAL; return -1; }
    char *cursor = last + 2;
    memset(result, 0, sizeof *result);
    result->pid = pid;
    for (int field = 3; field <= 22; ++field) {
        char *token = strsep(&cursor, " ");
        if (!token || !*token) { errno = EINVAL; return -1; }
        if (field == 3) result->state = *token;
        if (field == 4) result->parent = (pid_t)strtol(token, NULL, 10);
        if (field == 5) result->group = (pid_t)strtol(token, NULL, 10);
        if (field == 22) result->start = strtoull(token, NULL, 10);
    }
    if (!result->start) { errno = EINVAL; return -1; }
    return 0;
}

static int process(pid_t pid, struct identity *result) {
    char path[80];
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    return identity_at(path, pid, result);
}

/* An unavailable task directory alone does not prove death: old kernels may
 * hide it after the main thread exits while siblings continue running. */
static int gone_or_uncertain(const struct identity *recorded) {
    struct identity current;
    if (process(recorded->pid, &current)) return errno == ENOENT || errno == ESRCH ? 0 : -1;
    return current.start != recorded->start ? 0 : -1;
}

/* A Z/X thread-group leader can still have live siblings. Return a live task's
 * proc directory for identity checks; only a fully dead group returns zero.
 * Signals still target the recorded TGID, never this representative TID. */
static int live_task_path(const struct identity *leader, char *path, size_t capacity) {
    if (leader->state != 'Z' && leader->state != 'X') {
        snprintf(path, capacity, "/proc/%ld/task/%ld", (long)leader->pid, (long)leader->pid);
        return 1;
    }
    char tasks[80];
    snprintf(tasks, sizeof tasks, "/proc/%ld/task", (long)leader->pid);
    DIR *directory = opendir(tasks);
    if (!directory) return gone_or_uncertain(leader);
    int result = 0, scanned = 0;
    int64_t deadline = now_ms() + STOP_MS;
    for (;;) {
        if (!within(deadline)) { result = -1; break; }
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = -1; break; }
        char *end, stat_path[128];
        long tid = strtol(entry->d_name, &end, 10);
        if (*end || tid <= 1 || tid > INT_MAX) continue;
        snprintf(stat_path, sizeof stat_path, "%s/%ld/stat", tasks, tid);
        struct identity task;
        if (identity_at(stat_path, (pid_t)tid, &task)) {
            if (errno == ENOENT || errno == ESRCH) continue;
            result = -1;
            break;
        }
        ++scanned;
        if (task.state != 'Z' && task.state != 'X') {
            snprintf(path, capacity, "%s/%ld", tasks, tid);
            result = 1;
            break;
        }
    }
    closedir(directory);
    if (result == 0 && !scanned) return gone_or_uncertain(leader);
    return result;
}

static int link_is(pid_t pid, const char *suffix, const char *expected) {
    char path[80], value[PATH_MAX];
    snprintf(path, sizeof path, "/proc/%ld/%s", (long)pid, suffix);
    ssize_t size = readlink(path, value, sizeof value - 1);
    if (size < 0 || (size_t)size >= sizeof value - 1) return 0;
    value[size] = 0;
    return !strcmp(value, expected);
}

static int stock_at(const char *task_path) {
    char path[256], arguments[PATH_MAX + 8], executable_path[PATH_MAX];
    struct stat current;
    snprintf(path, sizeof path, "%s/exe", task_path);
    if (stat(path, &current) || current.st_dev != resource.executable_stat.st_dev ||
        current.st_ino != resource.executable_stat.st_ino) return 0;
    ssize_t path_size = readlink(path, executable_path, sizeof executable_path - 1);
    if (path_size < 0 || (size_t)path_size >= sizeof executable_path - 1) return 0;
    executable_path[path_size] = 0;
    if (strcmp(executable_path, STOCK_PATH)) return 0;
    snprintf(path, sizeof path, "%s/cmdline", task_path);
    ssize_t length = read_small(path, arguments, sizeof arguments);
    size_t first = sizeof STOCK_PATH;
    return length == (ssize_t)(first + 3) && !memcmp(arguments, STOCK_PATH, first) &&
        !memcmp(arguments + first, "-w", 3);
}

static int is_stock(pid_t pid) {
    struct identity identity;
    char path[128];
    return !process(pid, &identity) && live_task_path(&identity, path, sizeof path) == 1 && stock_at(path);
}

/* Returns 0 when the recorded process has gone, 1 when it still matches, -1
 * for an unexpected live identity. This is best effort, not atomic pidfd use. */
static int alive(const struct identity *identity) {
    struct identity current;
    if (process(identity->pid, &current)) return errno == ENOENT || errno == ESRCH ? 0 : -1;
    if (current.start != identity->start) return 0;
    char path[128];
    int live = live_task_path(&current, path, sizeof path);
    if (live != 1) return live;
    if (current.parent != identity->parent || !stock_at(path)) return -1;
    return 1;
}

static int signal_exact(const struct identity *identity, int signal_number) {
    int state = alive(identity);
    if (state != 1) return state == 0 ? 0 : -1;
    return kill(identity->pid, signal_number) == 0 || errno == ESRCH ? 0 : -1;
}

static int wait_gone(const struct identity *identity, int duration) {
    int64_t deadline = now_ms() + duration;
    do {
        int state = alive(identity);
        if (state == 0) return 0;
        /* Exit can invalidate exe/cmdline after a live stat snapshot. Observe
         * again within the original deadline; uncertainty never permits a
         * signal or counts as death, and signal_exact remains strict. */
        tick();
    } while (within(deadline));
    return -1;
}

static int terminate_exact(const struct identity *identity) {
    if (signal_exact(identity, SIGTERM)) return -1;
    if (!wait_gone(identity, STOP_MS)) return 0;
    if (signal_exact(identity, SIGKILL)) return -1;
    return wait_gone(identity, STOP_MS);
}

static int child_of(pid_t parent, struct identity *child) {
    /* The optional /proc/PID/task/PID/children file is absent on some kernels.
     * Inspect only process identity metadata to find this parent's children. */
    DIR *directory = opendir("/proc");
    if (!directory) return -1;
    struct dirent *entry;
    int count = 0;
    int64_t deadline = now_ms() + STOP_MS;
    while ((entry = readdir(directory))) {
        if (!within(deadline)) { count = -1; break; }
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        struct identity candidate;
        if (*end || pid <= 1 || pid > INT_MAX || process((pid_t)pid, &candidate) || candidate.parent != parent) continue;
        char task_path[128];
        int live = live_task_path(&candidate, task_path, sizeof task_path);
        if (!live) continue;
        if (live < 0 || ++count != 1 || !stock_at(task_path)) { count = -1; break; }
        *child = candidate;
    }
    closedir(directory);
    return count == 1 ? 0 : -1;
}

/* Before recovery, refuse duplicate controllers even if a trial descendant
 * escaped its session. Never signal an untracked process discovered here. */
static int stock_live_count(void) {
    DIR *directory = opendir("/proc");
    if (!directory) return -1;
    struct dirent *entry;
    int count = 0;
    int64_t deadline = now_ms() + STOP_MS;
    const char *base = strrchr(STOCK_PATH, '/');
    base = base ? base + 1 : STOCK_PATH;
    while ((entry = readdir(directory))) {
        char *end, path[256], name[128], task_path[128];
        long pid = strtol(entry->d_name, &end, 10);
        if (*end || pid <= 1 || pid > INT_MAX) continue;
        if (now_ms() < 0 || now_ms() >= deadline) { count = -1; break; }
        struct identity identity;
        int state_result = process((pid_t)pid, &identity);
        int state_errno = errno;
        if (!state_result) {
            int live = live_task_path(&identity, task_path, sizeof task_path);
            if (!live) continue;
            if (live < 0) { count = -1; break; }
        } else snprintf(task_path, sizeof task_path, "/proc/%ld", pid);
        struct stat executable;
        snprintf(path, sizeof path, "%s/exe", task_path);
        if (stat(path, &executable)) {
            if (errno == ENOENT || errno == ESRCH) {
                /* Kernel threads legitimately have no exe. Recheck liveness
                 * only for a potentially relevant stock-named process here. */
                snprintf(path, sizeof path, "/proc/%ld/comm", pid);
                ssize_t length = read_small(path, name, sizeof name);
                if (length > 0 && name[length - 1] == '\n') name[length - 1] = 0;
                if (length <= 0 || strcmp(name, base)) continue;
                /* The selected task may have exited after enumeration while
                 * siblings survive. Its missing exe does not prove group death. */
                struct identity current;
                if (process((pid_t)pid, &current)) {
                    if (errno == ENOENT || errno == ESRCH) continue;
                } else if (!state_result && current.start != identity.start) continue;
                else if (live_task_path(&current, task_path, sizeof task_path) == 0) continue;
                count = -1;
                break;
            }
            snprintf(path, sizeof path, "/proc/%ld/comm", pid);
            ssize_t length = read_small(path, name, sizeof name);
            if (length > 0 && name[length - 1] == '\n') name[length - 1] = 0;
            if (length > 0 && !strcmp(name, base)) { count = -1; break; }
            continue;
        }
        if (executable.st_dev != resource.executable_stat.st_dev ||
            executable.st_ino != resource.executable_stat.st_ino) continue;
        if (state_result && (state_errno == ENOENT || state_errno == ESRCH)) continue;
        if (state_result || !stock_at(task_path)) { count = -1; break; }
        ++count;
    }
    closedir(directory);
    return count;
}

/* Compare only six allowed values. Other entries are skipped, never printed or
 * written to a file. A bounded read rejects oversized or malformed inputs. */
static int environment_matches(pid_t pid) {
    char path[80], name[128], chunk[1024];
    const char *expected[6];
    unsigned seen = 0;
    for (int i = 0; i < 6; ++i) if (!(expected[i] = getenv(env_keys[i]))) return 0;
    snprintf(path, sizeof path, "/proc/%ld/environ", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    size_t name_size = 0, position = 0, total = 0;
    int in_value = 0, key = -1, valid = 1;
    ssize_t size;
    while (valid && (size = read(fd, chunk, sizeof chunk)) > 0) {
        total += (size_t)size;
        if (total > 65536) { valid = 0; break; }
        for (ssize_t i = 0; valid && i < size; ++i) {
            unsigned char c = (unsigned char)chunk[i];
            if (!in_value && c == '=') {
                name[name_size] = 0;
                key = -1;
                for (int n = 0; n < 6; ++n) if (!strcmp(name, env_keys[n])) key = n;
                if (!strcmp(name, "LD_PRELOAD") || !strcmp(name, "AX520_OBSERVER_FDS") ||
                    !strcmp(name, "AX520_DEVICE_BRIDGE")) key = -2;
                in_value = 1;
            } else if (!c) {
                if (key >= 0) {
                    if (expected[key][position] || (seen & (1U << key))) valid = 0;
                    seen |= 1U << key;
                }
                name_size = position = 0;
                in_value = 0;
                key = -1;
            } else if (!in_value) {
                if (name_size + 1 >= sizeof name) valid = 0;
                else name[name_size++] = (char)c;
            } else if (key == -2) valid = 0;
            else if (key >= 0) {
                if (!expected[key][position] || c != (unsigned char)expected[key][position]) valid = 0;
                else ++position;
            }
        }
    }
    close(fd);
    return valid && size == 0 && !in_value && !name_size && seen == 63;
}

static int normal_state(pid_t pid) {
    char path[80], data[4096];
    snprintf(path, sizeof path, "/proc/%ld/status", (long)pid);
    if (read_small(path, data, sizeof data) < 0) return 0;
    char *mask = strstr(data, "\nUmask:");
    unsigned umask_value;
    errno = 0;
    int nice_value = getpriority(PRIO_PROCESS, (id_t)pid);
    return !errno && nice_value == STOCK_NICE && mask && sscanf(mask, "\nUmask:\t%o", &umask_value) == 1 &&
        umask_value == 0022 && link_is(pid, "cwd", "/") && link_is(pid, "fd/0", "/dev/null") &&
        link_is(pid, "fd/1", CONSOLE_PATH) && link_is(pid, "fd/2", CONSOLE_PATH) && environment_matches(pid);
}

static void close_except(const int *keep, size_t count) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) _exit(125);
    int directory_fd = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*end || fd < 3 || fd > INT_MAX || fd == directory_fd) continue;
        size_t i;
        for (i = 0; i < count && keep[i] != fd; ++i) {}
        if (i == count) close((int)fd);
    }
    closedir(directory);
}

static void child_failed(int fd) {
    char failure = 'E';
    ssize_t written = write(fd, &failure, 1);
    (void)written;
    _exit(126);
}

static int clear_instrumentation_environment(void) {
    const char *keys[] = {"LD_PRELOAD", "AX520_OBSERVER_FDS", "AX520_DEVICE_BRIDGE",
                          "AX520_AUTH_PORT", "AX520_SYNTHETIC_TEST"};
    for (size_t i = 0; i < sizeof keys / sizeof *keys; ++i)
        if (unsetenv(keys[i])) return -1;
#ifndef AX520_LAUNCHER_TEST
    /* Production never passes synthetic fixture controls into a stock process.
     * Test builds retain them solely to exercise the same lifecycle machinery. */
    for (char **entry = environ; *entry;) {
        if (!strncmp(*entry, "AX520_TEST_", 11)) {
            char *end = strchr(*entry, '=');
            if (!end) return -1;
            char *name = strndup(*entry, (size_t)(end - *entry));
            if (!name) return -1;
            int result = unsetenv(name);
            free(name);
            if (result) return -1;
            entry = environ;
        } else ++entry;
    }
#endif
    return 0;
}

static pid_t launch_stock(int trial, const int observer[2]) {
    int error_pipe[2];
    if (pipe2(error_pipe, O_CLOEXEC | O_NONBLOCK)) return -1;
    pid_t pid = fork();
    if (!pid) {
        close(error_pipe[0]);
        if (setsid() < 0 || chdir("/") || setpriority(PRIO_PROCESS, 0, STOCK_NICE) ||
            sigaction(SIGHUP, &resource.hup, NULL) || sigaction(SIGPIPE, &resource.pipe, NULL) ||
            sigaction(SIGTERM, &resource.term, NULL) || sigprocmask(SIG_SETMASK, &resource.mask, NULL))
            child_failed(error_pipe[1]);
        umask(0022);
        int output = trial ? resource.null_fd : resource.console;
        if (dup2(resource.null_fd, 0) < 0 || dup2(output, 1) < 0 || dup2(output, 2) < 0)
            child_failed(error_pipe[1]);
        if (clear_instrumentation_environment()) child_failed(error_pipe[1]);
        if (trial) {
            char descriptors[48], preload[64];
            snprintf(descriptors, sizeof descriptors, "%d:%d", observer[0], observer[1]);
            snprintf(preload, sizeof preload, "/proc/self/fd/%d", resource.shim);
            if (fcntl(observer[0], F_SETFD, 0) || fcntl(observer[1], F_SETFD, 0) ||
                fcntl(resource.shim, F_SETFD, 0) || setenv("AX520_OBSERVER_FDS", descriptors, 1) ||
                setenv("LD_PRELOAD", preload, 1)) child_failed(error_pipe[1]);
            if (device_bridge && (setenv("AX520_DEVICE_BRIDGE", "1", 1) ||
                                  setenv("AX520_AUTH_PORT", "15000", 1))) child_failed(error_pipe[1]);
        }
        int keep[] = {resource.executable, error_pipe[1], trial ? resource.shim : -1,
                      trial ? observer[0] : -1, trial ? observer[1] : -1};
        close_except(keep, sizeof keep / sizeof *keep);
        char executable[64];
        snprintf(executable, sizeof executable, "/proc/self/fd/%d", resource.executable);
        char *arguments[] = {(char *)STOCK_PATH, "-w", NULL};
        execve(executable, arguments, environ);
        child_failed(error_pipe[1]);
    }
    close(error_pipe[1]);
    if (pid < 0) { close(error_pipe[0]); return -1; }
    struct pollfd descriptor = {error_pipe[0], POLLIN | POLLHUP, 0};
    int ready = -1;
    int64_t deadline = now_ms() + START_MS;
    /* A stop request can arrive before the child establishes its own session.
     * Finish the bounded exec handshake before attempting group cleanup. */
    while (within(deadline)) {
        int remaining = (int)(deadline - now_ms());
        if (remaining <= 0) break;
        ready = poll(&descriptor, 1, remaining);
        if (ready < 0 && errno == EINTR) continue;
        break;
    }
    char failure;
    ssize_t size = ready > 0 ? read(error_pipe[0], &failure, 1) : -1;
    close(error_pipe[0]);
    /* Always return the owned PID, even if exec failed, so cleanup can reap it. */
    if (size != 0) note(trial ? "trial exec_failed" : "restore exec_failed");
    return pid;
}

static int group_live(pid_t group) {
    DIR *directory = opendir("/proc");
    if (!directory) return -1;
    struct dirent *entry;
    int found = 0;
    int64_t deadline = now_ms() + STOP_MS;
    while ((entry = readdir(directory))) {
        if (!within(deadline)) { found = -1; break; }
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        struct identity identity;
        if (!*end && pid > 1 && pid <= INT_MAX && !process((pid_t)pid, &identity) && identity.group == group) {
            char task_path[128];
            int live = live_task_path(&identity, task_path, sizeof task_path);
            if (live) { found = live; break; }
        }
    }
    closedir(directory);
    return found;
}

static int stop_trial(pid_t pid) {
    if (pid < 0) return 0;
    /* Keep the direct child unreaped through all group signals: its ID cannot
     * be recycled. Expected -w workers stay in this group; escaped descendants
     * remain a documented limitation rather than a claimed recovery guarantee. */
    if (kill(-pid, SIGTERM) && errno != ESRCH) return -1;
    int64_t deadline = now_ms() + STOP_MS;
    while (group_live(pid) == 1 && within(deadline)) tick();
    /* The unreaped leader reserves the group ID. A final KILL is harmless for
     * a dead group and terminates remaining siblings of zombie leaders. */
    if (kill(-pid, SIGKILL) && errno != ESRCH) return -1;
    deadline = now_ms() + STOP_MS;
    while (group_live(pid) == 1 && within(deadline)) tick();
    if (group_live(pid) != 0) return -1;
    int status;
    deadline = now_ms() + STOP_MS;
    pid_t reaped;
    do {
        reaped = waitpid(pid, &status, WNOHANG);
        if (reaped == pid) return 0;
        if (reaped < 0 && errno != EINTR) return -1;
        tick();
    } while (within(deadline));
    return -1;
}

static int stop_original(const struct identity *supervisor, const struct identity *worker) {
    if (signal_exact(supervisor, SIGSTOP)) return -1;
    struct identity current, child;
    int64_t deadline = now_ms() + STOP_MS;
    int frozen = 0;
    do {
        if (!process(supervisor->pid, &current) && current.start == supervisor->start &&
            (current.state == 'T' || current.state == 't')) { frozen = 1; break; }
        tick();
    } while (within(deadline));
    if (!frozen || alive(supervisor) != 1 || child_of(supervisor->pid, &child) ||
        child.pid != worker->pid || child.start != worker->start || alive(worker) != 1 ||
        terminate_exact(worker)) {
        (void)signal_exact(supervisor, SIGCONT);
        return -1;
    }
    /* Supervisor is stopped, so it cannot respawn a worker while being removed. */
    if (signal_exact(supervisor, SIGKILL) || wait_gone(supervisor, STOP_MS)) {
        (void)signal_exact(supervisor, SIGCONT);
        return -1;
    }
    return 0;
}

static void observe(int fd, pid_t trial) {
    unsigned char event[12];
    int selected_seen = 0;
    int64_t deadline = now_ms() + observation_ms;
    while (!interrupted && (managed_bridge || within(deadline))) {
        if (managed_bridge) {
            /* Observe this unreaped child without consuming its wait status.
             * Existing cleanup still owns termination and reaping, including
             * any worker remaining after its supervisor exits. */
            siginfo_t state = {0};
            int result = waitid(P_PID, (id_t)trial, &state, WEXITED | WNOHANG | WNOWAIT);
            if (result < 0 && errno != EINTR) {
                note("managed supervisor_unverified");
                break;
            }
            if (!result && state.si_pid == trial) {
                note("managed supervisor_exited");
                break;
            }
        }
        struct pollfd descriptor = {fd, POLLIN, 0};
        int ready = poll(&descriptor, 1, 20);
        if (ready > 0 && (descriptor.revents & POLLIN)) {
            ssize_t size = read(fd, event, sizeof event);
            if (size != sizeof event || memcmp(event, "AXOB\1", 5) || event[6] || event[7]) continue;
            uint32_t pid = (uint32_t)event[8] << 24 | (uint32_t)event[9] << 16 |
                           (uint32_t)event[10] << 8 | event[11];
            struct identity child;
            if (pid == (uint32_t)trial && !event[5]) note("observer loaded");
            else if (!selected_seen && (event[5] & 7) == 7 && !(event[5] & 8) && pid <= INT_MAX &&
                     !process((pid_t)pid, &child) && child.parent == trial && child.group == trial &&
                     is_stock((pid_t)pid)) {
                selected_seen = 1;
                note("observer selected");
            }
        }
    }
    if (!selected_seen) note("observer no_selection_observed");
}

static void watchdog(const struct identity *supervisor, const struct identity *worker, int armed) {
    struct sigaction ignored = {0}, caught = {0};
    ignored.sa_handler = SIG_IGN;
    caught.sa_handler = interrupt_trial;
    sigemptyset(&ignored.sa_mask);
    sigemptyset(&caught.sa_mask);
    if (setsid() < 0 || sigaction(SIGHUP, &ignored, NULL) || sigaction(SIGPIPE, &ignored, NULL) ||
        sigaction(SIGTERM, &caught, NULL) || dup2(resource.null_fd, 0) < 0 ||
        dup2(resource.null_fd, 1) < 0 || dup2(resource.null_fd, 2) < 0) _exit(2);
    int keep[] = {resource.executable, resource.shim, resource.null_fd, resource.console, resource.status, armed};
    close_except(keep, sizeof keep / sizeof *keep);
    int observer[2];
    if (pipe2(observer, O_CLOEXEC | O_NONBLOCK)) _exit(2);
    note(managed_bridge ? "mode managed_device_bridge" : device_bridge ? "mode device_bridge" : "mode observer");
    note("stage armed");
    char ready = 'A';
    if (write(armed, &ready, 1) != 1) _exit(2);
    close(armed);
    if (interrupted) {
        note("result original_unchanged");
        _exit(3);
    }
    int stopped = stop_original(supervisor, worker);
    if (stopped) {
        int supervisor_state = alive(supervisor), worker_state = alive(worker);
        if (supervisor_state == 1 && !signal_exact(supervisor, SIGCONT)) {
            note("result original_supervisor_resumed");
            _exit(3);
        }
        if (supervisor_state != 0 || worker_state != 0) {
            note("result rollback_blocked_original_state");
            _exit(4);
        }
        note("stage original_already_gone_skip_trial");
    } else note("stage original_stopped");
    pid_t trial = stopped ? -1 : launch_stock(1, observer);
    if (trial > 0) observe(observer[0], trial);
    if (stop_trial(trial)) { note("result rollback_blocked_live_trial"); _exit(4); }
    close(observer[0]);
    close(observer[1]);
    note("stage trial_stopped");
    if (alive(supervisor) != 0 || alive(worker) != 0) {
        note("result rollback_blocked_original_identity");
        _exit(4);
    }
    if (stock_live_count() != 0) { note("result rollback_blocked_existing_stock"); _exit(4); }
    pid_t restored = launch_stock(0, NULL);
    int64_t deadline = now_ms() + START_MS;
    struct identity child;
    while (restored > 0 && within(deadline)) {
        if (!child_of(restored, &child) && normal_state(restored) && normal_state(child.pid) && stock_live_count() == 2) {
            (void)dprintf(resource.status, "restored_pid %ld\n", (long)restored);
            note("result restored");
            _exit(0);
        }
        tick();
    }
    note("result restore_unverified_no_retry");
    _exit(5);
}

static int parse_pid(const char *text, pid_t *pid) {
    unsigned long value = 0;
    if (!*text) return -1;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9' || value > ((unsigned long)INT_MAX - (*text - '0')) / 10) return -1;
        value = value * 10 + (*text - '0');
    }
    if (value <= 1 || value == (unsigned long)getpid()) return -1;
    *pid = (pid_t)value;
    return 0;
}

int main(int argc, char **argv) {
    pid_t supervisor_pid, worker_pid;
#ifdef AX520_LAUNCHER_ENABLE_MANAGED
    if (argc == 5 && !strcmp(argv[1], "--managed-device-bridge")) {
        managed_bridge = device_bridge = 1;
        --argc;
        ++argv;
    }
#endif
#ifdef AX520_LAUNCHER_ENABLE_BRIDGE
    if (argc == 6 && !strcmp(argv[1], "--device-bridge")) {
        unsigned seconds = 0;
        const char *duration = argv[2];
        if (!*duration) return 2;
        for (; *duration; ++duration) {
            if (*duration < '0' || *duration > '9' || seconds > 300) return 2;
            seconds = seconds * 10 + (unsigned)(*duration - '0');
        }
        if (!seconds || seconds > 300) return 2;
        device_bridge = 1;
        observation_ms = (int)seconds * 1000;
        argc -= 2;
        argv += 2;
    }
#endif
    if (argc != 4 || parse_pid(argv[1], &supervisor_pid) || parse_pid(argv[2], &worker_pid) ||
        supervisor_pid == worker_pid || argv[3][0] != '/' ||
        (getenv("LD_PRELOAD") && *getenv("LD_PRELOAD")) || getenv("AX520_OBSERVER_FDS") ||
        getenv("AX520_DEVICE_BRIDGE")) return 2;
    resource.executable = open(STOCK_PATH, O_RDONLY | O_CLOEXEC);
    resource.shim = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    resource.null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    resource.console = open(CONSOLE_PATH, O_WRONLY | O_APPEND | O_CLOEXEC);
    struct identity supervisor, worker;
    unsigned char magic[4];
    if (resource.executable < 0 || resource.shim < 0 || resource.null_fd < 0 || resource.console < 0 ||
        fstat(resource.executable, &resource.executable_stat) ||
        !S_ISREG(resource.executable_stat.st_mode) || read(resource.shim, magic, 4) != 4 || memcmp(magic, "\177ELF", 4) ||
        process(supervisor_pid, &supervisor) || process(worker_pid, &worker) || worker.parent != supervisor_pid ||
        !is_stock(supervisor_pid) || !is_stock(worker_pid) || !normal_state(supervisor_pid) || !normal_state(worker_pid) ||
        sigaction(SIGHUP, NULL, &resource.hup) || sigaction(SIGPIPE, NULL, &resource.pipe) ||
        sigaction(SIGTERM, NULL, &resource.term) || sigprocmask(SIG_SETMASK, NULL, &resource.mask)) {
        fputs("observer-trial: preflight failed; original processes untouched\n", stderr);
        return 2;
    }
    struct identity only_child;
    if (child_of(supervisor_pid, &only_child) || only_child.pid != worker_pid || only_child.start != worker.start ||
        stock_live_count() != 2) return 2;
    pid_t probe = fork();
    if (!probe) _exit(setpriority(PRIO_PROCESS, 0, STOCK_NICE) ? 1 : 0);
    int probe_status = 0;
    pid_t probe_done = 0;
    int64_t probe_deadline = now_ms() + START_MS;
    if (probe < 0) return 2;
    do {
        probe_done = waitpid(probe, &probe_status, WNOHANG);
        if (probe_done == probe || (probe_done < 0 && errno != EINTR)) break;
        tick();
    } while (within(probe_deadline));
    if (probe_done != probe) { kill(probe, SIGKILL); return 2; }
    if (!WIFEXITED(probe_status) || WEXITSTATUS(probe_status)) return 2;
    char directory[] = "/tmp/ax520-observer-trial-XXXXXX", status_path[128];
    umask(0077);
    if (!mkdtemp(directory)) return 2;
    snprintf(status_path, sizeof status_path, "%s/status", directory);
    resource.status = open(status_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int armed[2];
    if (resource.status < 0 || pipe2(armed, O_CLOEXEC)) return 2;
    pid_t daemon = fork();
    if (!daemon) { close(armed[0]); watchdog(&supervisor, &worker, armed[1]); _exit(2); }
    close(armed[1]);
    if (daemon < 0) return 2;
    struct pollfd descriptor = {armed[0], POLLIN | POLLHUP, 0};
    char ready;
    int success = poll(&descriptor, 1, START_MS) > 0 && read(armed[0], &ready, 1) == 1 && ready == 'A';
    close(armed[0]);
    if (!success) return 2;
    printf("watchdog=%ld status=%s\n", (long)daemon, status_path);
    return 0;
}
