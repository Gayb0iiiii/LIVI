#ifndef AX520_RELAY_H
#define AX520_RELAY_H
#include <stddef.h>
#include <stdint.h>
#ifndef RELAY_PORT
#define RELAY_PORT 15039
#endif
enum { RELAY_EOF=1, RELAY_DEADLINE=2, RELAY_MALFORMED=3, RELAY_IO=4, RELAY_STALL=5, RELAY_POLICY=6 };
struct relay_stats { uint64_t to_controller, to_host; unsigned stop_reason; };
int relay_packet_valid(const unsigned char *p, size_t n, int from_host);
int relay_packet_allowed(const unsigned char *p, size_t n, int from_host);
int relay_pump(int hci_fd, int tcp_fd, unsigned duration_ms, unsigned stall_ms, struct relay_stats *out);
int relay_listen(void);
int relay_accept(int listener, unsigned wait_ms);
#endif
