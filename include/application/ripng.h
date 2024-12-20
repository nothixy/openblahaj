#ifndef OB_RIPNG_H
#define OB_RIPNG_H

#include "generic/protocol.h"

struct ripng_entry {
    uint16_t Prefix[8];
    uint16_t RouteTag;
    uint8_t PrefixLength;
    uint8_t Metric;
};

struct ripng_header {
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
+-------------------------------------------+
|                                           |
|                IPv6 Prefix                |
|                                           |
|                                           |
+---------------------+----------+----------+
|     Route tag       |Prexix len|  Metric  |
+---------------------+----------+----------+ 
*/

void ripng_dump(struct ob_protocol* buffer);

#endif
