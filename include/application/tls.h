#ifndef OB_TLS_H
#define OB_TLS_H

#include "generic/protocol.h"

struct tls_header {
    uint8_t ContentType;
    uint16_t LegacyVersion;
    uint16_t Length;
} __attribute__((packed));

void tls_dump(struct ob_protocol* buffer);

#endif
