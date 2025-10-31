#ifndef OB_ZIGBEE_ENCAPSULATION_H
#define OB_ZIGBEE_ENCAPSULATION_H

#include "generic/protocol.h"

struct zep_header {
    uint16_t Preamble;
    uint8_t Version;
} __attribute__((packed));

struct zep_header_v1 {
    uint8_t Channel;
    uint16_t DeviceID;
    uint8_t LQIMode;
    uint8_t LQIVal;
    uint8_t Reserved[7];
    uint8_t Length;
} __attribute__((packed));

struct zep_header_v2 {
    uint8_t Type;
};

struct zep_header_v2_data {
    uint8_t Channel;
    uint16_t DeviceID;
    uint8_t LQIMode;
    uint8_t LQIVal;
    time_t Timestamp;
    uint32_t Sequence;
    uint8_t Reserved[10];
    uint8_t Length;
} __attribute__((packed));

struct zep_header_v2_ack {
    uint32_t Sequence;
};

void zep_dump(struct ob_protocol* buffer);

#endif
