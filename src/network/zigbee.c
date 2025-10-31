#include "network/zigbee.h"
#include "generic/constants.h"
#include "generic/protocol.h"
#include "link/802_15_4.h"
#include <endian.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

static const uint16_t ZEP_PREAMBLE = 0x4558;
static const uint8_t ZEP_LENGTH_MASK = 0x7f;

ssize_t zep_dump_header_v2(struct ob_protocol* buffer, const uint8_t* hdr, ssize_t length, uint8_t type)
{
    ssize_t read_bytes = 0;
    if (type == 1)
    {
        struct zep_header_v2_data zd;
        memcpy(&zd, hdr, sizeof(struct zep_header_v2_data));
        read_bytes += sizeof(struct zep_header_v2_data);

        printf("%-45s = %u\n", "Channel", zd.Channel);
        printf("%-45s = %u\n", "Device ID", be16toh(zd.DeviceID));
        printf("%-45s = %u\n", "LQI mode", zd.LQIMode);
        printf("%-45s = %u\n", "LQI value", zd.LQIVal);
        printf("%-45s = %ld\n", "Timestamp", zd.Timestamp);
        printf("%-45s = %u\n", "Sequence", be32toh(zd.Sequence));
        printf("%-45s = %u\n", "Length", zd.Length & ZEP_LENGTH_MASK);
    }
    else
    {
        struct zep_header_v2_ack za;
        memcpy(&za, hdr, sizeof(struct zep_header_v2_ack));
        read_bytes += sizeof(struct zep_header_v2_ack);

        printf("%-45s = %u\n", "Sequence", za.Sequence);
    }

    return read_bytes;
}

ssize_t zep_dump_v3(struct ob_protocol* buffer, const uint8_t* hdr, ssize_t length, uint8_t version)
{
    ssize_t read_bytes = 0;

    if (version == 1)
    {
        struct zep_header_v1 zh;
        memcpy(&zh, hdr, sizeof(struct zep_header_v1));
        read_bytes += sizeof(struct zep_header_v1);

        printf("%-45s = %u\n", "Channel", zh.Channel);
        printf("%-45s = %u\n", "Device ID", be16toh(zh.DeviceID));
        printf("%-45s = %u\n", "LQI mode", zh.LQIMode);
        printf("%-45s = %u\n", "LQI value", zh.LQIVal);
        printf("%-45s = %u\n", "Length", zh.Length & ZEP_LENGTH_MASK);
    }
    else
    {
        struct zep_header_v2 zh;
        memcpy(&zh, hdr, sizeof(struct zep_header_v2));
        read_bytes += sizeof(struct zep_header_v2);

        printf("%-45s = %u\n", "Type", zh.Type);

        read_bytes += zep_dump_header_v2(buffer, &hdr[read_bytes], length - read_bytes, zh.Type);
    }
    
    return read_bytes;
}

void zep_dump(struct ob_protocol* buffer)
{
    struct zep_header zh;
    uint8_t* hdr = buffer->hdr;
    ssize_t read_bytes = 0;
    if (buffer->length < sizeof(struct zep_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    memcpy(&zh, buffer->hdr, sizeof(struct zep_header));
    read_bytes += sizeof(struct zep_header);

    if (be16toh(zh.Preamble) == be16toh(ZEP_PREAMBLE))
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_HIGH:
            printf("--- BEGIN ZIGBEE ENCAPSULATION HEADER ---\n");
            printf("%-45s = %s\n", "Preamble", (char*) &(zh.Preamble));
            printf("%-45s = %u\n", "Version", zh.Version);
            read_bytes += zep_dump_v3(buffer, &hdr[read_bytes], buffer->length - read_bytes, zh.Version);
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            break;

        case OB_VERBOSITY_LEVEL_LOW:
            printf("> ZIGBEE ENCAPSULATION ");
            break;
    }

    buffer->hdr = &hdr[read_bytes];
    buffer->length -= read_bytes;

    buffer->dump = lrwpan_dump;
    buffer->dump(buffer);
}
