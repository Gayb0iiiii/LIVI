/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Synthetic process lifecycle fixture; no stock code or identity material. */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern int SetiAPI2CAddr(void *, int, const char *);

static void record(const char *kind, pid_t worker) {
    FILE *log = fopen(getenv("AX520_TEST_EVENTS"), "a");
    if (!log) _exit(4);
    fprintf(log, "%s %ld %ld %d %d\n", kind, (long)getpid(), (long)worker,
            getenv("LD_PRELOAD") != NULL, getpriority(PRIO_PROCESS, 0));
    fclose(log);
}

static void record_settings(void) {
    FILE *log = fopen(getenv("AX520_TEST_EVENTS"), "a");
    if (!log) _exit(4);
    const char *bridge = getenv("AX520_DEVICE_BRIDGE"), *port = getenv("AX520_AUTH_PORT");
    fprintf(log, "settings %ld 0 %d %d %d %d %d %d\n", (long)getpid(), getenv("LD_PRELOAD") != NULL,
            bridge && !strcmp(bridge, "1"), port && !strcmp(port, "15000"),
            getenv("AX520_OBSERVER_FDS") != NULL, getenv("AX520_SYNTHETIC_TEST") != NULL, port != NULL);
    fclose(log);
}

static void *paused_thread(void *unused) {
    (void)unused;
    for (;;) pause();
    return NULL;
}

static void wait_worker(void) {
    const char *on_term = getenv("AX520_TEST_ZOMBIE_ON_TERM");
    int trial = getenv("LD_PRELOAD") != NULL;
    int zombie_on_term = on_term && (!strcmp(on_term, "trial") ? trial : !trial);
    int zombie_now = trial && getenv("AX520_TEST_ZOMBIE_START");
    if (zombie_on_term || zombie_now) {
        /* Block TERM before creating the sibling; sigwait is the only consumer.
         * pthread_exit of the main thread then leaves a real Z,S task group. */
        sigset_t term;
        sigemptyset(&term);
        sigaddset(&term, SIGTERM);
        if (pthread_sigmask(SIG_BLOCK, &term, NULL)) _exit(13);
        pthread_t sibling;
        if (pthread_create(&sibling, NULL, paused_thread, NULL)) _exit(14);
        record("worker", 0);
        if (!zombie_now) {
            int received;
            if (sigwait(&term, &received)) _exit(15);
        }
        record("leader_exit", 0);
        pthread_exit(NULL);
    }
    record("worker", 0);
    for (;;) pause();
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '-' || argv[1][1] != 'w' || argv[1][2]) return 2;
    record("start", 0);
    record_settings();
    if (getenv("AX520_TEST_TRIAL_EXIT") && getenv("LD_PRELOAD")) return 9;
    if (getenv("AX520_TEST_RESTORE_EXIT") && !getenv("LD_PRELOAD")) {
        FILE *log = fopen(getenv("AX520_TEST_EVENTS"), "r");
        char line[128];
        int starts = 0;
        if (!log) return 10;
        while (fgets(line, sizeof line, log)) if (!strncmp(line, "start ", 6)) ++starts;
        fclose(log);
        if (starts > 1) return 11;
    }
    for (;;) {
        pid_t worker = fork();
        if (worker < 0) return 3;
        if (!worker) {
            if (getenv("AX520_TEST_ESCAPE_TRIAL") && getenv("LD_PRELOAD") && setsid() < 0) return 12;
            if (getenv("AX520_TEST_IGNORE_TERM")) signal(SIGTERM, SIG_IGN);
            SetiAPI2CAddr(NULL, 0x20, "ly_iap");
            wait_worker();
        }
        record("child", worker);
        int status;
        while (waitpid(worker, &status, 0) < 0) {}
    }
}
