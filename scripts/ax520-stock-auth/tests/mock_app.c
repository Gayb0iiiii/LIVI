/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Exercise actual dynamic symbol interposition, only against mock_vendor.c. */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern int SetiAPI2CAddr(void *, int, const char *);
extern int AuthDeviceCreateSignature(const void *, size_t, unsigned char **, size_t *);
extern void MockFault(int);
extern void MockCounts(int *);

static void *work(void *unused) {
    (void)unused;
    unsigned char digest[32] = {0};
    for (int n = 0; n < 24; ++n) {
        unsigned char *out = NULL;
        size_t length = 0;
        AuthDeviceCreateSignature(digest, sizeof digest, &out, &length);
        free(out);
    }
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (getenv("MOCK_SELECT_BEFORE_FORK"))
        SetiAPI2CAddr(NULL, 0x20, "ly_iap");
    if (!getenv("MOCK_NO_FORK")) {
        pid_t child = fork();
        if (child < 0) return 2;
        if (child > 0) {
            int status;
            if (waitpid(child, &status, 0) < 0) return 3;
            return WIFEXITED(status) ? WEXITSTATUS(status) : 4;
        }
    }
    puts("ready");
    char line[80];
    pthread_t workers[4];
    int running = 0;
    while (fgets(line, sizeof line, stdin)) {
        if (!strcmp(line, "select\n")) {
            printf("selected %d\n", SetiAPI2CAddr(NULL, 0x20, "ly_iap"));
        } else if (!strcmp(line, "bad\n")) {
            printf("bad %d\n", SetiAPI2CAddr(NULL, 0x21, "ly_iap"));
        } else if (!strcmp(line, "hardware\n")) {
            printf("hardware %d\n", SetiAPI2CAddr(NULL, 0x10, "/dev/i2c-2"));
        } else if (!strncmp(line, "refork ", 7)) {
            line[strcspn(line, "\n")] = 0;
            pid_t child = fork();
            if (child < 0) return 7;
            if (child > 0) {
                int status;
                waitpid(child, &status, 0);
                return 0;
            }
            if (setenv("AX520_AUTH_PORT", line + 7, 1)) return 8;
            puts("reforked");
        } else if (!strcmp(line, "counts\n")) {
            int values[4];
            MockCounts(values);
            printf("%d %d %d %d\n", values[0], values[1], values[2], values[3]);
        } else if (!strncmp(line, "fault ", 6)) {
            MockFault(atoi(line + 6));
            puts("fault set");
        } else if (!strcmp(line, "work\n") && !running) {
            for (int i = 0; i < 4; ++i)
                if (pthread_create(&workers[i], NULL, work, NULL)) return 5;
            running = 1;
            puts("working");
        } else if (!strcmp(line, "join\n") && running) {
            for (int i = 0; i < 4; ++i) pthread_join(workers[i], NULL);
            running = 0;
            puts("joined");
        } else if (!strcmp(line, "quit\n")) {
            break;
        } else return 6;
    }
    if (running)
        for (int i = 0; i < 4; ++i) pthread_join(workers[i], NULL);
    return 0;
}
