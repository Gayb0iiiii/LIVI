/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Exercise real zombie/live-thread state with an unavailable task directory. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int visibility;
static pid_t hidden_pid;
static const char *empty_directory;

static DIR *visibility_opendir(const char *path) {
    char hidden[80];
    snprintf(hidden, sizeof hidden, "/proc/%ld/task", (long)hidden_pid);
    if (!strcmp(path, hidden)) {
        if (visibility == 1) { errno = ENOENT; return NULL; }
        if (visibility == 2) return opendir(empty_directory);
    }
    return opendir(path);
}

#define opendir visibility_opendir
#define main unused_launcher_entry
#include "../observer_trial.c"
#undef main
#undef opendir

static void *sibling(void *unused) {
    (void)unused;
    for (;;) pause();
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    empty_directory = argv[1];
    hidden_pid = fork();
    if (hidden_pid < 0) return 3;
    if (!hidden_pid) {
        pthread_t thread;
        if (pthread_create(&thread, NULL, sibling, NULL)) _exit(4);
        pthread_exit(NULL);
    }
    struct identity leader;
    int ready = 0;
    int64_t deadline = now_ms() + 2000;
    while (within(deadline)) {
        if (!process(hidden_pid, &leader) && leader.state == 'Z') { ready = 1; break; }
        tick();
    }
    int missing = 99, empty = 99;
    if (ready) {
        char path[128];
        visibility = 1;
        missing = live_task_path(&leader, path, sizeof path);
        visibility = 2;
        empty = live_task_path(&leader, path, sizeof path);
    }
    kill(hidden_pid, SIGKILL);
    waitpid(hidden_pid, NULL, 0);
    printf("missing=%d empty=%d\n", missing, empty);
    return ready && missing == -1 && empty == -1 ? 0 : 1;
}
