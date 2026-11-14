#ifndef AX520_RADIO_RELAY_H
#define AX520_RADIO_RELAY_H
#include <stddef.h>
#include <stdint.h>
#define FRAME_MIN 14
#define FRAME_MAX 1514
int64_t now_ms(void);
int parse_mac(const char *, uint8_t [6]);
int frame_allowed(const uint8_t *, size_t, const uint8_t [6], int, int);
int read_frame(int, uint8_t *, size_t, int64_t);
int write_frame(int, const uint8_t *, size_t, int64_t);
#endif
