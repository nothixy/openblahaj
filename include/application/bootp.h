#ifndef OB_BOOTP_H
#define OB_BOOTP_H

#include "generic/protocol.h"

#define BOOTP_VENDOR_MAGIC 0x63825363

struct bootp_header {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    /**
     * vend[] should at least be 64 bytes if BOOTP, or 312 bytes if DHCP,
     * but it is not always true
     */
    uint8_t vend[5];
};

/*
+----------+----------+----------+----------+
|    OP    |  HTYPE   |   HLEN   |   HOPS   |
+----------+----------+----------+----------+
|                    XID                    |
+---------------------+---------------------+
|         SECS        |        FLAGS        |
+---------------------+---------------------+
|                  CIADDR                   |
+-------------------------------------------+
|                  YIADDR                   |
+-------------------------------------------+
|                  SIADDR                   |
+-------------------------------------------+
|                  GIADDR                   |
+-------------------------------------------+
/                                           /
/                  CHADDR                   / (16 bytes)
/                                           /
+-------------------------------------------+
/                                           /
/                   SNAME                   / (64 bytes)
/                                           /
+-------------------------------------------+
/                                           /
/                   FILE                    / (128 bytes)
/                                           /
+-------------------------------------------+
/                                           /
/                  VENDOR                   / (64 bytes)
/                                           /
+-------------------------------------------+
*/

void bootp_dump(struct ob_protocol* buffer);

#endif
