#ifndef OB_COOKED_H
#define OB_COOKED_H

#include "generic/protocol.h"

struct cooked_header {
    uint16_t packet_type;
    uint16_t arphrd_type;
    uint16_t address_length;
    uint64_t address;
    uint16_t protocol_type;
} __attribute__((packed));

void cooked_dump(struct ob_protocol* buffer);

#endif
