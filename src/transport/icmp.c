#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip4.h"
#include "generic/bytes.h"
#include "transport/icmp.h"
#include "generic/protocol.h"

static const char* ICMP_DESTINATION_HOST_UNREACHABLE_MESSAGES[] = {
    "Net Unreachable",
    "Host Unreachable",
    "Protocol Unreachable",
    "Port Unreachable",
    "Fragmentation Needed and DF Set",
    "Source Route Failed"
};

static const char* icmp4_get_control_message(uint8_t control)
{
    switch (control)
    {
        case 0:
            return "Echo reply";

        case 3:
            return "Destination unreachable";

        case 4:
            return "Source quench";

        case 5:
            return "Redirect";

        case 8:
            return "Echo request";

        case 9:
            return "Router advertisement";

        case 10:
            return "Router sollicitation";

        case 11:
            return "Time exceeded";

        case 12:
            return "Parameter problem";

        case 13:
            return "Timestamp";

        case 14:
            return "Timestamp reply";

        case 15:
            return "Information request";

        case 16:
            return "Information reply";

        case 17:
            return "Address mask request";

        case 18:
            return "Address mask reply";

        case 30:
            return "Traceroute";

        case 42:
            return "Extended echo request";

        case 43:
            return "Extended echo reply";

        default:
            return "Reserved / deprecated";
    }
}

static const char* icmp4_get_destination_host_unreachable_message(uint8_t code)
{
    if (code >= sizeof(ICMP_DESTINATION_HOST_UNREACHABLE_MESSAGES) / sizeof(const char*))
    {
        return "Unknown";
    }
    return ICMP_DESTINATION_HOST_UNREACHABLE_MESSAGES[code];
}

static void icmp4_dump_rest_header(const struct icmphdr* ih)
{
    char ipv4[INET_ADDRSTRLEN] = {0};

    switch (ih->type)
    {
        case ICMP_ECHOREPLY:
        case ICMP_ECHO:
            printf("%-45s = %u\n", "Identifier", be16toh(ih->un.echo.id));
            printf("%-45s = %u\n", "Sequence Number", be16toh(ih->un.echo.sequence));
            break;

        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
            printf("%-45s = %u\n", "Identifier", be16toh(ih->un.echo.id));
            printf("%-45s = %u\n", "Sequence Number", be16toh(ih->un.echo.sequence));
            break;

        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
            printf("%-45s = %u\n", "Identifier", be16toh(ih->un.echo.id));
            printf("%-45s = %u\n", "Sequence Number", be16toh(ih->un.echo.id));
            break;

        case ICMP_PARAMETERPROB:
            printf("%-45s = %u\n", "Pointer", be32toh(ih->un.gateway));
            break;

        case ICMP_REDIRECT:
            inet_ntop(AF_INET, &(ih->un.gateway), ipv4, INET_ADDRSTRLEN * sizeof(char));
            printf("%-45s = %s\n", "Gateway Internet Address", ipv4);
            break;

        default:
            printf("%-45s = 0x%x\n", "Rest header", be32toh(ih->un.gateway));
            break;
    }
}

static void icmp4_dump_data(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    struct icmphdr ih;

    memcpy(&ih, buffer->hdr, sizeof(struct icmphdr));

    switch (ih.type)
    {
        case 0x0d:
        case 0x0e:
            if (offset + (ssize_t) (3 * sizeof(uint32_t)) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("%-45s = %u\n", "Originate Timestamp", be32toh(read_u32_unaligned(&hdr[offset + 0])));
            printf("%-45s = %u\n", "Receive Timestamp", be32toh(read_u32_unaligned(&hdr[offset + 4])));
            printf("%-45s = %u\n", "Transmit Timestamp", be32toh(read_u32_unaligned(&hdr[offset + 8])));
            break;

        case 0x3:
        case 0xb:
        case 0xc:
        case 0x4:
        case 0x5:
            printf("IP HEADER\n");
            break;

        case 0x9:
            if (offset + (ssize_t) (2 * ih.un.gateway * sizeof(uint32_t)) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
            }

            for (uint32_t i = 0; i < ih.un.gateway; ++i)
            {
                uint32_t Level = be32toh(read_u32_unaligned(&hdr[offset + 8 * i + 4]));

                char ipv4_address[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &hdr[offset + 8 * i], ipv4_address, INET_ADDRSTRLEN * sizeof(char));
                printf("%-45s = %s\n", "Router Address", ipv4_address);
                printf("%-45s = %u\n", "Router Level", Level);
            }
            break;

        default:
            printf("%-45s = ", "Raw Data");
            for (ssize_t i = offset; i < buffer->length; ++i)
            {
                printf("%x ", hdr[i]);
            }
            printf("\n");
            break;
    }
}

static void icmp4_dump_code(const struct icmphdr* ih)
{
    switch (ih->code)
    {
        case 0x3:
            printf("%-45s = 0x%x (%s)\n", "Code", ih->code, icmp4_get_destination_host_unreachable_message(ih->code));
            break;

        default:
            printf("%-45s = 0x%x\n", "Code", ih->code);
            break;
    }
}

static void icmp4_dump_v3(const struct ob_protocol* buffer, const struct icmphdr* ih)
{
    printf("--- BEGIN ICMP MESSAGE ---\n");
    printf("%-45s = 0x%x (%s)\n", "ICMP Message type", ih->type, icmp4_get_control_message(ih->type));
    icmp4_dump_code(ih);
    printf("%-45s = 0x%x %s\n", "Checksum", be16toh(ih->checksum), checksum_16bitonescomplement_validate(buffer, buffer->length, 0, false));
    icmp4_dump_rest_header(ih);
    icmp4_dump_data(buffer, sizeof(struct icmphdr));
}

static void icmp4_dump_v2(const struct icmphdr* ih)
{
    printf("ICMPv4 => ");
    printf("ICMP Message type : %s\n", icmp4_get_control_message(ih->type));
}

void icmp4_dump(struct ob_protocol* buffer)
{
    struct icmphdr ih;

    if ((ssize_t) sizeof(struct icmphdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ih, buffer->hdr, sizeof(struct icmphdr));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> ICMPv4 ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            icmp4_dump_v2(&ih);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            icmp4_dump_v3(buffer, &ih);
            break;
    }
}
