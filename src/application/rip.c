#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "network/ip4.h"
#include "application/rip.h"
#include "generic/protocol.h"

static const char* rip_get_command(uint8_t Command)
{
    switch (Command)
    {
        case 1:
            return "Request";

        case 2:
            return "Response";

        case 3:
            return "Traceon";

        case 4:
            return "Traceoff";

        case 5:
            return "Reserved";

        default:
            return "Unknown";
    }
}

static void rip_dump_v3(const struct ob_protocol* buffer, const struct rip_header* rh, size_t entry_count)
{
    const uint8_t* header = buffer->hdr;

    printf("--- BEGIN RIP MESSAGE ---\n");

    printf("%-45s = %d (%s)\n", "Command", rh->Command, rip_get_command(rh->Command));
    printf("%-45s = %d\n", "Version", rh->Version);

    for (size_t i = 0; i < entry_count; ++i)
    {
        const void* rip_entry_address = &header[sizeof(struct rip_header) + i * sizeof(struct rip_entry)];
        struct rip_entry entry;
        char ipv4_address[INET_ADDRSTRLEN] = {0};
        char subnet_mask[INET_ADDRSTRLEN] = {0};

        memcpy(&entry, rip_entry_address, sizeof(struct rip_entry));

        printf("--- BEGIN RIP ENTRY ---\n");

        inet_ntop(AF_INET, &(entry.Address), ipv4_address, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &(entry.Mask), subnet_mask, INET_ADDRSTRLEN * sizeof(char));

        printf("%-45s = %u\n", "Address Family Identifier", be16toh(entry.AddressFamilyIdentifier));
        if (rh->Version > 1)
        {
            printf("%-45s = %u\n", "Route tag", be16toh(entry.RouteTag));
        }
        printf("%-45s = %s\n", "IP Address", ipv4_address);
        if (rh->Version > 1)
        {
            printf("%-45s = %s\n", "Subnet Mask", subnet_mask);
            printf("%-45s = %u\n", "Next Hop", be32toh(entry.NextHop));
        }
        printf("%-45s = %u\n", "Metric", be32toh(entry.Metric));
    }
}

static void rip_dump_v2(const struct ob_protocol* buffer, const struct rip_header* rh, size_t entry_count)
{
    const uint8_t* header = buffer->hdr;

    printf("RIP => ");
    printf("Command : %s, ", rip_get_command(rh->Command));

    printf("[");
    for (size_t i = 0; i < entry_count; ++i)
    {
        const void* rip_entry_address = &header[sizeof(struct rip_header) + i * sizeof(struct rip_entry)];
        struct rip_entry entry;
        char ipv4_address[INET_ADDRSTRLEN] = {0};

        memcpy(&entry, rip_entry_address, sizeof(struct rip_entry));

        inet_ntop(AF_INET, &(entry.Address), ipv4_address, INET_ADDRSTRLEN * sizeof(char));

        printf("Address Family Identifier : %u, ", be16toh(entry.AddressFamilyIdentifier));
        printf("IP Address : %s, ", ipv4_address);
        printf("Metric : %u", be32toh(entry.Metric));

        if (i + 1 != entry_count)
        {
            printf("; ");
        }
    }
    printf("]\n");
}

void rip_dump(struct ob_protocol* buffer)
{
    size_t entry_count;

    struct rip_header rh;

    memcpy(&rh, buffer->hdr, sizeof(struct rip_header));
    entry_count = ((size_t) buffer->length - sizeof(struct rip_header)) / sizeof(struct rip_entry);

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> RIP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            rip_dump_v2(buffer, &rh, entry_count);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            rip_dump_v3(buffer, &rh, entry_count);
            break;
    }
}
