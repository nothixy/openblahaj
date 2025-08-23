#ifndef OB_NTP_H
#define OB_NTP_H

#include "generic/protocol.h"

enum FRACTION_SIZE {
    FRACTION_SIZE_SHORT,
    FRACTION_SIZE_TIMESTAMP,
    FRACTION_SIZE_DATE
};

struct ntp_short {
    uint16_t Seconds;
    uint16_t Fraction;
};

struct ntp_timestamp {
    uint32_t Seconds;
    uint32_t Fraction;
};

struct ntp_header {
    uint8_t Mode : 3;
    uint8_t VN : 3;
    uint8_t LI : 2;
    uint8_t Stratum;
    int8_t Poll;
    int8_t Precision;
    struct ntp_short RootDelay;
    struct ntp_short RootDispersion;
    uint32_t ReferenceID;
    struct ntp_timestamp ReferenceTimestamp;
    struct ntp_timestamp OriginTimestamp;
    struct ntp_timestamp ReceiveTimestamp;
    struct ntp_timestamp TransmitTimestamp;
};

struct ntp_autokey_header {
    uint8_t Response : 1;
    uint8_t Error : 1;
    uint8_t Code : 6;
    uint8_t FieldType;
    uint16_t Length;
    uint32_t AssociationID;
    uint32_t Timestamp;
    uint32_t FileStamp;
};

void ntp_dump(struct ob_protocol* buffer);

#endif
