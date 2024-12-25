#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "link/eth.h"
#include "network/network.h"
#include "generic/protocol.h"

static void eth_dump_v3(const struct ether_header* hdr)
{
    char* ethernet;

    printf("--- BEGIN ETHERNET MESSAGE ---\n");

    ethernet = ether_ntoa((const struct ether_addr*) &(hdr->ether_shost));
    printf("%-45s = %s\n", "Destination", ethernet);
    ethernet = ether_ntoa((const struct ether_addr*) &(hdr->ether_dhost));
    printf("%-45s = %s\n", "Source", ethernet);

    printf("%-45s = 0x%x (%s)\n", "Type", be16toh(hdr->ether_type), network_get_name(be16toh(hdr->ether_type)));
}

static void eth_dump_v2(const struct ether_header* hdr)
{
    char* ethernet;

    printf("Ethernet => ");

    ethernet = ether_ntoa((const struct ether_addr*) &(hdr->ether_dhost));
    printf("Destination : %s, ", ethernet);
    ethernet = ether_ntoa((const struct ether_addr*) &(hdr->ether_shost));
    printf("Source : %s, ", ethernet);

    printf("Type : %s\n", network_get_name(be16toh(hdr->ether_type)));
}

void eth_dump(struct ob_protocol* buffer)
{
    ssize_t ether_header_length = (ssize_t) sizeof(struct ether_header);
    uint8_t* hdr = buffer->hdr;
    struct ether_header eh;

    if ((ssize_t) sizeof(struct ether_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&eh, buffer->hdr, sizeof(struct ether_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> Ethernet ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            eth_dump_v2(&eh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            eth_dump_v3(&eh);
            break;
    }

    network_cast(be16toh(eh.ether_type), buffer);
    buffer->length -= (ssize_t) ether_header_length;
    buffer->hdr = &hdr[ether_header_length];

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }
}
