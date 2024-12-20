#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "network/ip6.h"
#include "generic/protocol.h"
#include "application/ripng.h"

static const char* ripng_get_command(uint8_t Command)
{
    switch (Command)
    {
        case 1:
            return "Request";

        case 2:
            return "Response";

        default:
            return "Unknown";
    }
}

static void ripng_dump_v3(const struct ob_protocol* buffer, const struct ripng_header* rh, size_t entry_count)
{
    const uint8_t* header = buffer->hdr;

    printf("--- BEGIN RIPng MESSAGE ---\n");

    printf("%-45s = %d (%s)\n", "Command", rh->Command, ripng_get_command(rh->Command));
    printf("%-45s = %d\n", "Version", rh->Version);

    for (size_t i = 0; i < entry_count; ++i)
    {
        const void* ripng_entry_address = &header[sizeof(struct ripng_header) + (size_t) i * sizeof(struct ripng_entry)];
        struct ripng_entry entry;
        char ipv6_prefix[INET6_ADDRSTRLEN] = {0};

        memcpy(&entry, ripng_entry_address, sizeof(struct ripng_entry));

        printf("--- BEGIN RIPng ENTRY ---\n");

        inet_ntop(AF_INET6, &(entry.Prefix), ipv6_prefix, INET6_ADDRSTRLEN * sizeof(char));

        if (entry.Metric == 0xFF)
        {
            printf("%-45s = %s\n", "IPv6 Next Hop address", ipv6_prefix);
        }
        else
        {
            printf("%-45s = %s/%u\n", "IPv6 Prefix", ipv6_prefix, entry.PrefixLength);
            printf("%-45s = %u\n", "Route Tag", entry.RouteTag);
            printf("%-45s = %u\n", "Prefix Length", entry.PrefixLength);
            printf("%-45s = %u\n", "Metric", entry.Metric);
        }
    }
}

static void ripng_dump_v2(const struct ob_protocol* buffer, const struct ripng_header* rh, size_t entry_count)
{
    const uint8_t* header = buffer->hdr;

    printf("RIPng => ");

    printf("Command : %s, ", ripng_get_command(rh->Command));

    printf("[");
    for (size_t i = 0; i < entry_count; ++i)
    {
        const void* ripng_entry_address = &header[sizeof(struct ripng_header) + i * sizeof(struct ripng_entry)];
        struct ripng_entry entry;
        char ipv6_prefix[INET6_ADDRSTRLEN] = {0};

        memcpy(&entry, ripng_entry_address, sizeof(struct ripng_entry));

        inet_ntop(AF_INET6, &(entry.Prefix), ipv6_prefix, INET6_ADDRSTRLEN * sizeof(char));

        if (entry.Metric == 0xFF)
        {
            printf("Next hop : %s, ", ipv6_prefix);
        }
        else
        {
            printf("IPv6 Prefix : %s/%u, ", ipv6_prefix, entry.PrefixLength);
            printf("Metric : %u, ", entry.Metric);
        }

        if (i + 1 != entry_count)
        {
            printf("; ");
        }
    }
    printf("]");
}

void ripng_dump(struct ob_protocol* buffer)
{
    struct ripng_header rh;
    size_t entry_count;

    memcpy(&rh, buffer->hdr, sizeof(struct ripng_header));
    
    entry_count = ((size_t) buffer->length - sizeof(struct ripng_header)) / sizeof(struct ripng_entry);

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> RIPng ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ripng_dump_v2(buffer, &rh, entry_count);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ripng_dump_v3(buffer, &rh, entry_count);
            break;
    }
}
