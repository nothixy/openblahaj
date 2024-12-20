#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "link/dbus.h"
#include "generic/protocol.h"

/**
 * Note for implementation : some messages will be encoded in little endian,
 * some in big endian
 */

static uint32_t dbe32toh(uint32_t x)
{
    return be32toh(x);
}

static uint32_t dle32toh(uint32_t x)
{
    return le32toh(x);
}

static const char* dbus_get_message_type(uint8_t MessageType)
{
    switch (MessageType)
    {
        case 0:
            return "Invalid";

        case 1:
            return "Method Call";

        case 2:
            return "Method Return";

        case 3:
            return "Error";

        case 4:
            return "Signal";

        default:
            return "Unknown";
    }
}

static void dbus_dump_single_flag(uint8_t Flags, uint8_t i)
{
    switch (i)
    {
        case 0:
            printf("No reply expected");
            if ((Flags >> (i + 1)) != 0)
            {
                printf(" | ");
            }
            break;

        case 1:
            printf("No auto start");
            if ((Flags >> (i + 1)) != 0)
            {
                printf(" | ");
            }
            break;

        case 2:
            printf("Allow interactive authorization");
            if ((Flags >> (i + 1)) != 0)
            {
                printf(" | ");
            }
            break;

        default:
            printf("Unknown");
            if ((Flags >> (i + 1)) != 0)
            {
                printf(" | ");
            }
            break;
    }
}

static void dbus_dump_flags(uint8_t Flags)
{
    for (uint8_t i = 0; i < 8; ++i)
    {
        if (!((Flags >> i) & 1))
        {
            continue;
        }

        dbus_dump_single_flag(Flags, i);
    }
}

static void dbus_dump_v3(const struct dbus_header* dh)
{
    uint32_t (*de32toh)(uint32_t);

    if (dh->Endianness == 'l')
    {
        de32toh = dle32toh;
    }
    else if (dh->Endianness == 'B')
    {
        de32toh = dbe32toh;
    }
    else
    {
        return;
    }

    printf("--- BEGIN DBUS MESSAGE ---\n");

    printf("%-45s = %s\n", "Endianness", dh->Endianness == 'l' ? "Little" : "Big");
    printf("%-45s = %u (%s)\n", "Message Type", dh->MessageType, dbus_get_message_type(dh->MessageType));
    printf("%-45s = ", "Flags");
    dbus_dump_flags(dh->Flags);
    printf("\n");
    printf("%-45s = %u\n", "Major", dh->Major);
    printf("%-45s = %u\n", "Length", de32toh(dh->Length));
    printf("%-45s = %u\n", "Serial", de32toh(dh->Serial));
}

static void dbus_dump_v2(const struct dbus_header* dh)
{
    printf("DBus => ");
    printf("Endianness : %s, ", dh->Endianness == 'l' ? "Little" : "Big");
    printf("Message Type : %s, ", dbus_get_message_type(dh->MessageType));
    printf("Major : %u\n", dh->Major);
}

void dbus_dump(struct ob_protocol* buffer)
{
    struct dbus_header dh;

    if ((ssize_t) sizeof(struct dbus_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    
    memcpy(&dh, buffer->hdr, sizeof(struct dbus_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> DBus ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            dbus_dump_v2(&dh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            dbus_dump_v3(&dh);
            break;
    }
}
