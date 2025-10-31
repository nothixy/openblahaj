#ifndef OB_BGP_H
#define OB_BGP_H

#include <stdint.h>

#include "generic/protocol.h"

struct bgp_notification_message {
    uint8_t ErrorCode;
    uint8_t ErrorSubcode;
};

struct bgp_open_message {
    uint8_t Version;
    uint16_t MyAS;
    uint16_t HoldTime;
    uint32_t Identifier;
    uint8_t OptionalParametersLength;
} __attribute__((packed));

struct bgp_header {
    uint8_t Marker[16];
    uint16_t Length;
    uint8_t Type;
} __attribute__((packed));

void bgp_dump(struct ob_protocol* buffer);

#endif
