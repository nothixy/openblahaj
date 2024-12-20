#include <stdio.h>
#include <endian.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "link/link.h"
#include "link/cooked.h"
#include "network/arp.h"
#include "generic/binary.h"
#include "network/network.h"

/**
 * Cooked packet capture is specific to Linux
 */

static const char* cooked_get_packet_type(uint16_t ptype)
{
    switch (ptype)
    {
        case 0:
            return "Specifically sent to us";

        case 1:
            return "Broadcast by someone else";

        case 2:
            return "Multicast by someone else";

        case 3:
            return "Sent to someone else by someone else";

        case 4:
            return "Sent by us";

        default:
            return "Unknown";
    }
}

static void cooked_dump_v3(const struct ob_protocol* buffer, const struct cooked_header* ch)
{
    char* ethernet = ether_ntoa((struct ether_addr*) &(ch->address));

    const char* link_type = link_get_name(buffer->link_type);

    printf("--- BEGIN ");
    for (size_t i = 0; link_type[i] != 0; ++i)
    {
        printf("%c", toupper(link_type[i]));
    }
    printf(" MESSAGE ---\n");
    printf("%-45s = 0x%x (%s)\n", "Packet type", be16toh(ch->packet_type), cooked_get_packet_type(be16toh(ch->packet_type)));
    printf("%-45s = %u\n", "Address length", be16toh(ch->address_length));
    printf("%-45s = 0x%x (%s)\n", "ARPHRD type", be16toh(ch->arphrd_type), arp_get_htype(be16toh(ch->arphrd_type)));
    if (be16toh(ch->address_length) == 6)
    {
        printf("%-45s = %s\n", "Link-layer address", ethernet);
    }
    else
    {
        printf("%-45s = %08lx\n", "Beginning of link-layer address", ch->address);
    }
    printf("%-45s = 0x%x (%s)\n", "Protocol type", be16toh(ch->protocol_type), network_get_name(be16toh(ch->protocol_type)));
}

static void cooked_dump_v2(const struct ob_protocol* buffer, const struct cooked_header* ch)
{
    char* ethernet = ether_ntoa((struct ether_addr*) &(ch->address));

    printf("%s => ", link_get_name(buffer->link_type));
    printf("Packet type : %s, ", cooked_get_packet_type(be16toh(ch->packet_type)));
    printf("ARPHRD type : %s, ", arp_get_htype(be16toh(ch->arphrd_type)));
    if (be16toh(ch->address_length) == 6)
    {
        printf("Link-layer address : %s, ", ethernet);
    }
    else
    {
        printf("Beginning of link-layer address : %08lx, ", ch->address);
    }
    printf("Protocol type = %s\n", network_get_name(be16toh(ch->protocol_type)));
}

void cooked_dump(struct ob_protocol* buffer)
{
    struct cooked_header ch;
    uint8_t* hdr = buffer->hdr;
    ssize_t offset = (ssize_t) sizeof(struct cooked_header);

    if (offset > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ch, buffer->hdr, sizeof(struct cooked_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> %s ", link_get_name(buffer->link_type));
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            cooked_dump_v2(buffer, &ch);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            cooked_dump_v3(buffer, &ch);
            break;
    }

    if (be16toh(ch.arphrd_type) == 0x1 || be16toh(ch.arphrd_type) == 0xFFFE)
    {
        network_cast(be16toh(ch.protocol_type), buffer);
    }
    else
    {
        buffer->dump = binary_dump;
    }

    buffer->length -= offset;
    buffer->hdr = &hdr[offset];

    buffer->dump(buffer);
}
