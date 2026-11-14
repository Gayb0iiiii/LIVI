/* Linux v4.9 ioctl ABI; no libbluetooth or target libc dependency. */
#define _GNU_SOURCE
#include "radio.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#define HCIGETDEVINFO _IOR('H', 211, int)
struct device_info {
    uint16_t id; char name[8]; unsigned char address[6];
    uint32_t flags; uint8_t type, features[8];
    uint32_t packet_type, link_policy, link_mode;
    uint16_t acl_mtu, acl_packets, sco_mtu, sco_packets;
    uint32_t stats[10];
};
_Static_assert(sizeof(struct device_info) == 92, "Linux HCI ioctl ABI size");
_Static_assert(offsetof(struct device_info, flags) == 16, "Linux HCI flags ABI offset");
int hw_topology(void) {
    char path[PATH_MAX];
    if (!realpath("/sys/class/bluetooth/hci0/device", path)) return -1;
    const char *base = strrchr(path, '/');
    if (!base || strcmp(base, "/ttyS2")) { errno = EXDEV; return -1; }
    return 0;
}
int hw_info(struct radio_info *out) {
    int fd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, 1);
    if (fd < 0) return -1;
    struct device_info info; memset(&info, 0, sizeof info);
    int rc = ioctl(fd, HCIGETDEVINFO, &info), saved = errno;
    close(fd); errno = saved;
    if (rc) return -1;
    if (strncmp(info.name, "hci0", sizeof info.name)) { errno = EXDEV; return -1; }
    out->flags = info.flags; out->bus = info.type & 15; out->connections = 0;
    /* Count link object names only; do not request or output peer identifiers. */
    DIR *d = opendir("/sys/class/bluetooth");
    if (!d) return -1;
    struct dirent *entry;
    while ((entry = readdir(d))) if (!strncmp(entry->d_name, "hci0:", 5)) out->connections++;
    closedir(d);
    memset(&info, 0, sizeof info);
    return 0;
}
