#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network/ip4.h"
#include "network/ip6.h"
#include "application/mqtt.h"

static const char* MQTT_PACKET_TYPE[] = {
    "Reserved",
    "Connect",
    "Connack",
    "Publish",
    "Puback",
    "Pubrec",
    "Pubrel",
    "Pubcomp",
    "Subscribe",
    "Suback",
    "Unsubscribe",
    "Unsuback",
    "Pingreq",
    "Pingresp",
    "Disconnect",
    "Auth"
};

static const char* mqtt_get_packet_type(uint8_t type)
{
    if (type > sizeof(MQTT_PACKET_TYPE) / sizeof(const char*))
    {
        return "Unknown";
    }
    return MQTT_PACKET_TYPE[type];
}

static ssize_t mqtt_decode_number(struct ob_protocol* buffer, ssize_t offset, uint64_t* value)
{
    const uint8_t* hdr = buffer->hdr;
    ssize_t length = 0;
    uint32_t multiplier = 1;
    uint8_t encoded_byte;
    *value = 0;

    do
    {
        encoded_byte = hdr[offset + length];
        *value += (encoded_byte & 0x7F) * multiplier;
        if (multiplier > 128 * 128 * 128)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }
        multiplier *= 128;
        ++length;
    }
    while ((encoded_byte & 128) != 0);

    return length;
}

static void mqtt_dump_v3(struct ob_protocol* buffer, struct mqtt_header* mh)
{
    uint64_t length;
    mqtt_decode_number(buffer, sizeof(uint8_t), &length);

    printf("--- BEGIN MQTT MESSAGE ---\n");
    printf("%-45s = %u (%s)\n", "Packet type", mh->type, mqtt_get_packet_type(mh->type));
    printf("%-45s = %u\n", "Flags", mh->flags);
    printf("%-45s = %lu\n", "Length", length);
}

static void mqtt_dump_v2(struct ob_protocol* buffer, struct mqtt_header* mh)
{
    uint64_t length;
    mqtt_decode_number(buffer, sizeof(uint8_t), &length);

    printf("MQTT => ");
    printf("Packet type : %s, ", mqtt_get_packet_type(mh->type));
    printf("Flags : %u, ", mh->flags);
    printf("Length : %lu\n", length);
}

void mqtt_dump(struct ob_protocol* buffer)
{
    struct mqtt_header mh;

    if ((ssize_t) sizeof(struct mqtt_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&mh, buffer->hdr, sizeof(struct mqtt_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> MQTT ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            mqtt_dump_v2(buffer, &mh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            mqtt_dump_v3(buffer, &mh);
            break;
    }
}
