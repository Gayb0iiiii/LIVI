/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Deterministically interrupt the watchdog before its trial child setsid. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static unsigned session_calls;
static pid_t delayed_setsid(void) {
    const char *marker = getenv("AX520_TEST_INTERRUPT_EXEC");
    if (session_calls++ && marker) {
        int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            close(fd);
            kill(getppid(), SIGTERM);
            struct timespec delay = {0, 800000000};
            nanosleep(&delay, NULL);
        }
    }
    return setsid();
}

#define setsid delayed_setsid
#include "../observer_trial.c"
