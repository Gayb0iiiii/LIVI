/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Synthetic test provider only. Contains no vendor code or identity material. */
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static atomic_int setters, signatures, certificates, active, peak, fault;

#ifndef MOCK_WITHOUT_MARKER
int ax520_synthetic_test_provider(void) { return 0x41583532; }
#endif

static void enter(void) {
    int n = atomic_fetch_add(&active, 1) + 1;
    int previous = atomic_load(&peak);
    while (previous < n && !atomic_compare_exchange_weak(&peak, &previous, n)) {}
    struct timespec pause = atomic_load(&fault) == 5 ?
        (struct timespec){3, 0} : (struct timespec){0, 2000000};
    nanosleep(&pause, NULL);
}

int SetiAPI2CAddr(void *context, int address, const char *path) {
    (void)context;
    atomic_fetch_add(&setters, 1);
    /* The harness checks that the interposer forwards these exact arguments. */
    if (address == 0x20 && path && !strcmp(path, "ly_iap")) return 0;
    if (address == 0x10 && path && !strcmp(path, "/dev/i2c-2")) return 23;
    return -71;
}

int AuthDeviceCreateSignature(const void *data, size_t length,
                              unsigned char **output, size_t *size) {
    atomic_fetch_add(&signatures, 1);
    enter();
    int mode = atomic_load(&fault);
    *size = mode == 2 ? 65 : 64;
    *output = mode == 3 ? NULL : malloc(*size);
    if (*output) {
        for (size_t i = 0; i < *size; ++i)
            (*output)[i] = length ? ((const unsigned char *)data)[i % length] ^ 0x5a : 0;
    }
    atomic_fetch_sub(&active, 1);
    return mode == 4 ? -5 : 0;
}

int AuthDeviceCopyCertificate(unsigned char **output, size_t *size) {
    atomic_fetch_add(&certificates, 1);
    enter();
    *size = atomic_load(&fault) == 1 ? 4097 : 14;
    *output = malloc(*size);
    if (*output) {
        memset(*output, 0, *size);
        memcpy(*output, "SYNTHETIC-CERT", 14);
    }
    atomic_fetch_sub(&active, 1);
    return 0;
}

void MockFault(int value) { atomic_store(&fault, value); }
void MockCounts(int *values) {
    values[0] = atomic_load(&setters);
    values[1] = atomic_load(&signatures);
    values[2] = atomic_load(&certificates);
    values[3] = atomic_load(&peak);
}
