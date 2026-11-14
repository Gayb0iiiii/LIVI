#ifndef AX520_RADIO_H
#define AX520_RADIO_H
#include <stddef.h>
#include <stdint.h>
struct radio_info { uint32_t flags; unsigned bus; unsigned connections; };
struct radio_version { unsigned status, hci_version, lmp_version; };
int hw_info(struct radio_info *info);
int hw_topology(void);
int hw_down(void);
int hw_up(void);
int hw_user_open(void);
int hw_read_version(int fd, struct radio_version *version);
int decode_version(const unsigned char *packet, size_t n, struct radio_version *v);
int sha256_file(const char *path, char hex[65]);
#endif
