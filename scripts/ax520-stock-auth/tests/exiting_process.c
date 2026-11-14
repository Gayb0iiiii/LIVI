/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Reproduce an owned process exiting between its stat and executable reads. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t target_pid;
static int force_exit;
static int exit_observed;

static int changing_stat(const char *path, struct stat *result) {
    char target[128];
    snprintf(target, sizeof target, "/proc/%ld/task/%ld/exe", (long)target_pid, (long)target_pid);
    if (strcmp(path, target)) return stat(path, result);
    if (force_exit) {
        force_exit = 0;
        kill(target_pid, SIGTERM);
        char stat_path[80], data[2048];
        snprintf(stat_path, sizeof stat_path, "/proc/%ld/stat", (long)target_pid);
        for (int i = 0; i < 1000; ++i) {
            FILE *file = fopen(stat_path, "r");
            if (file) {
                char *line = fgets(data, sizeof data, file);
                fclose(file);
                char *end = line ? strrchr(data, ')') : NULL;
                if (end && end[2] == 'Z') { exit_observed = 1; break; }
            }
            struct timespec delay = {0, 1000000};
            nanosleep(&delay, NULL);
        }
        errno = ENOENT;
    } else errno = EACCES;
    return -1;
}

#define stat(path, result) changing_stat(path, result)
#define main unused_launcher_entry
#include "../observer_trial.c"
#undef main
#undef stat

static pid_t paused_child(void) {
    int ready[2];
    if (pipe(ready)) return -1;
    pid_t child = fork();
    if (!child) {
        close(ready[0]);
        char value = 'R';
        if (write(ready[1], &value, 1) != 1) _exit(3);
        close(ready[1]);
        for (;;) pause();
    }
    close(ready[1]);
    char value = 0;
    ssize_t received = child > 0 ? read(ready[0], &value, 1) : -1;
    close(ready[0]);
    return received == 1 && value == 'R' ? child : -1;
}

int main(void) {
    struct identity recorded;
    target_pid = paused_child();
    if (target_pid <= 1 || process(target_pid, &recorded)) return 2;
    force_exit = 1;
    int transition = wait_gone(&recorded, 100);
    kill(target_pid, SIGKILL);
    waitpid(target_pid, NULL, 0);
    target_pid = paused_child();
    if (target_pid <= 1 || process(target_pid, &recorded)) return 2;
    int64_t started = now_ms();
    int uncertain = wait_gone(&recorded, 100);
    int waited = now_ms() - started >= 90;
    int strict_signal = signal_exact(&recorded, SIGTERM);
    struct identity current;
    int untouched = !process(target_pid, &current) && current.state != 'Z' && current.state != 'X';
    kill(target_pid, SIGKILL);
    waitpid(target_pid, NULL, 0);
    printf("transition=%d uncertain=%d waited=%d signal=%d untouched=%d\n",
           transition, uncertain, waited, strict_signal, untouched);
    return exit_observed && transition == 0 && uncertain == -1 && waited && strict_signal == -1 && untouched ? 0 : 1;
}
