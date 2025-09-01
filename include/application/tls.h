#ifndef OB_TLS_H
#define OB_TLS_H

#include "generic/protocol.h"

struct tls_header {
    uint8_t ContentType;
    uint16_t LegacyVersion;
    uint16_t Length;
} __attribute__((packed));

struct tls_handshake_header {
    uint8_t MessageType;
    uint32_t Length : 24;
};

struct tls_server_hello {
    uint16_t LegacyVersion;
    uint8_t Random[32];
};

void tls_dump(struct ob_protocol* buffer);
ssize_t tls_dump_handshake(struct ob_protocol* buffer);

#endif
