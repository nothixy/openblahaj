#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip4.h"
#include "network/ip6.h"
#include "generic/bytes.h"
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
    while ((encoded_byte & (uint8_t) 128) != 0);

    return length;
}

static void mqtt_dump_publish(struct ob_protocol* buffer, struct mqtt_header* mh, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    uint64_t topic_name_length;
    uint64_t property_length;
    ssize_t property_length_bytes;
    ssize_t topic_name_length_bytes;

    // fprintf(stderr, "HERE WE ARAE, OFFSET = %u, QOS = %d\n", offset, (mh->flags & 0b110) >> 1);

    property_length_bytes = mqtt_decode_number(buffer, offset, &property_length);
    
    if (property_length_bytes != 0)
    {
        # warning THIS IS INVALID
        offset += property_length_bytes + property_length;
    }
    else
    {
        offset += property_length_bytes;
    }

    topic_name_length_bytes = mqtt_decode_number(buffer, offset, &topic_name_length);

    printf("%-45s = %lu\n", "Topic length", topic_name_length);
    printf("%-45s = ", "Topic");
    for (uint64_t i = 0; i < topic_name_length; ++i)
    {
        printf("%c", hdr[offset + topic_name_length_bytes + i]);
    }
    printf("\n");

    /**
     * NOT IMPLEMENTED
     * QOS = 0
     */
    if ((mh->flags & 0b0110) == 0)
    {

    }
    else
    {
        // fprintf(stderr, "HAS CTRL PACKET\n");
    }

    printf("%-45s = %u\n", "Packet identifier", be16toh(read_u16_unaligned(&hdr[offset + topic_name_length + topic_name_length_bytes])));

    printf("%-45s = ", "Payload");
    for (ssize_t i = 0; i < length - topic_name_length - topic_name_length_bytes - property_length - property_length_bytes - sizeof(uint16_t); ++i)
    {
        printf("%02x", hdr[offset + topic_name_length + topic_name_length_bytes + sizeof(uint16_t)]);
    }
    printf("\n");
}

static void mqtt_dump_v3(struct ob_protocol* buffer, struct mqtt_header* mh)
{
    uint64_t length;
    ssize_t length_bytes = mqtt_decode_number(buffer, sizeof(uint8_t), &length);

    printf("--- BEGIN MQTT MESSAGE ---\n");
    printf("%-45s = %u (%s)\n", "Packet type", mh->type, mqtt_get_packet_type(mh->type));
    printf("%-45s = %u\n", "Flags", mh->flags);
    printf("%-45s = %lu\n", "Length", length);

    switch (mh->type)
    {
        case 3:
            mqtt_dump_publish(buffer, mh, length_bytes + offsetof(struct mqtt_header, length), length);
    }
}

static void mqtt_dump_v2(struct ob_protocol* buffer, struct mqtt_header* mh)
{
    uint64_t length;
    (void) mqtt_decode_number(buffer, sizeof(uint8_t), &length);

    printf("MQTT => ");
    printf("Packet type : %s, ", mqtt_get_packet_type(mh->type));
    printf("Flags : %u, ", mh->flags);
    printf("Length : %lu\n", length);
}

void mqtt_dump(struct ob_protocol* buffer)
{
    /**
     * MQTT can contain multiple messages inside a single TCP segment
     */
    while (buffer->length > 0)
    {
        uint8_t* hdr = buffer->hdr;
        struct mqtt_header mh;
        uint64_t packet_length;

        if ((ssize_t) sizeof(struct mqtt_header) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&mh, buffer->hdr, sizeof(struct mqtt_header));
        (void) mqtt_decode_number(buffer, offsetof(struct mqtt_header, length), &packet_length);

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

        buffer->hdr = &hdr[packet_length + 2];
        buffer->length -= (packet_length + 2);
    }
}
