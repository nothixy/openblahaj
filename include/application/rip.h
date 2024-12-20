#ifndef OB_RIP_H
#define OB_RIP_H

#include "generic/protocol.h"

struct rip_entry {
    uint16_t AddressFamilyIdentifier;
    uint16_t RouteTag;
    uint32_t Address;
    uint32_t Mask;
    uint32_t NextHop;
    uint32_t Metric;
};

struct rip_header {
    uint8_t Command;
    uint8_t Version;
    uint16_t Zero;
};

/*
Header
+----------+----------+---------------------+
| COMMAND  |  VERSION |         ZERO        |
+----------+----------+---------------------+
/                                           /
/              Entries (x1-25)              /
/                                           /
+-------------------------------------------+

Entry
+---------------------+---------------------+
|  Address family ID  |      Route tag      |
+---------------------+---------------------+
|                IP Address                 |
+-------------------------------------------+
|                Subnet mask                |
+-------------------------------------------+
|                 Next hop                  |
+-------------------------------------------+
|                  Metric                   |
+-------------------------------------------+
*/

void rip_dump(struct ob_protocol* buffer);

#endif
