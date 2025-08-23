#ifndef OB_QUIC_H
#define OB_QUIC_H

#include <stdint.h>
#include "generic/protocol.h"

struct quic_header_long {
    uint8_t TypeSpecificBits : 4;
    uint8_t LongPacketType : 2;
    uint8_t FixedBit : 1;
    uint8_t HeaderForm : 1;
    uint32_t VersionID;
} __attribute__((packed));

struct quic_header_short {
    uint8_t P : 2;
    uint8_t KeyPhase : 1;
    uint8_t Reserved : 2;
    uint8_t SpinBits : 1;
    uint8_t FixedBit : 1;
    uint8_t HeaderForm : 1;
    uint8_t DCID[20];
} __attribute__((packed));

void quic_dump(struct ob_protocol* buffer);
ssize_t quic_read_variable_number(const uint8_t* hdr, uint64_t* number);

#endif
