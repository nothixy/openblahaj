#include <stdio.h>
#include <endian.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "network/ip6.h"
#include "generic/bytes.h"
#include "transport/icmp6.h"
#include "generic/protocol.h"

static const char* ICMPv6_DESTINATION_HOST_UNREACHABLE_MESSAGES[] = {
    "No route to destination",
    "Communication with destination administratively prohibited",
    "Beyond scope of source address",
    "Address unreachable",
    "Port unreachable",
    "Source address failed ingress/egress policy",
    "Reject route to destination",
    "Error in Source Routing Header"
};

static const char* icmp6_get_control_message(uint8_t control)
{
    switch (control)
    {
        case 1:
            return "Destination Unreachable";

        case 2:
            return "Packet Too Big";

        case 3:
            return "Time Exceeded";

        case 4:
            return "Parameter Problem";

        case 128:
            return "Echo Request";

        case 129:
            return "Echo Reply";

        case 130:
            return "Multicast Listener Query";

        case 131:
            return "Multicast Listener Report";

        case 132:
            return "Multicast Listener Done";

        case 133:
            return "Router Solicitation";

        case 134:
            return "Router Advertisement";

        case 135:
            return "Neighbor Solicitation";

        case 136:
            return "Neighbor Advertisement";

        case 137:
            return "Redirect Message";

        case 138:
            return "Router Renumbering";

        case 139:
            return "ICMP Node Information Query";

        case 140:
            return "ICMP Node Information Response";

        case 141:
            return "Inverse Neighbor Discovery Solicitation Message";

        case 142:
            return "Inverse Neighbor Discovery Advertisement Message";

        case 143:
            return "Version 2 Multicast Listener Report";

        case 144:
            return "Home Agent Address Discovery Request Message";

        case 145:
            return "Home Agent Address Discovery Reply Message";

        case 146:
            return "Mobile Prefix Solicitation";

        case 147:
            return "Mobile Prefix Advertisement";

        case 148:
            return "Certification Path Solicitation Message";

        case 149:
            return "Certification Path Advertisement Message";

        case 150:
            return "ICMP messages utilized by experimental mobility protocols such as Seamoby";

        case 151:
            return "Multicast Router Advertisement";

        case 152:
            return "Multicast Router Solicitation";

        case 153:
            return "Multicast Router Termination";

        case 154:
            return "FMIPv6 Messages";

        case 155:
            return "RPL Control Message";

        case 156:
            return "ILNPv6 Locator Update Message";

        case 157:
            return "Duplicate Address Request";

        case 158:
            return "Duplicate Address Confirmation";

        case 159:
            return "MPL Control Message";

        case 160:
            return "Extended Echo Request";

        case 161:
            return "Extended Echo Reply";

        default:
            return "Unknown";
    }
}

static const char* icmp6_get_destination_host_unreachable_message(uint8_t code)
{
    if (code >= sizeof(ICMPv6_DESTINATION_HOST_UNREACHABLE_MESSAGES) / sizeof(const char*))
    {
        return "Unknown";
    }
    return ICMPv6_DESTINATION_HOST_UNREACHABLE_MESSAGES[code];
}

static void icmp6_dump_rest_header(const struct icmp6_hdr* ih)
{
    uint8_t R;
    uint8_t S;
    uint8_t O;
    uint32_t Reserved;
    uint32_t Flags;

    switch (ih->icmp6_type)
    {
        case 0x01:
            printf("%-45s = %u\n", "Unused", be32toh(ih->icmp6_dataun.icmp6_un_data32[0]));
            break;

        case 0x02:
            printf("%-45s = %u\n", "MTU", be32toh(ih->icmp6_dataun.icmp6_un_data32[0]));
            break;

        case 0x03:
            printf("%-45s = %u\n", "Unused", be32toh(ih->icmp6_dataun.icmp6_un_data32[0]));
            break;

        case 0x04:
            printf("%-45s = %u\n", "Pointer", be32toh(ih->icmp6_dataun.icmp6_un_data32[0]));
            break;

        case 0x80:
        case 0x81:
            printf("%-45s = %u\n", "Identifier", be16toh(ih->icmp6_dataun.icmp6_un_data16[0]));
            printf("%-45s = %u\n", "Sequence Number", be16toh(ih->icmp6_dataun.icmp6_un_data16[1]));
            break;

        case 0x88:
            Flags = ih->icmp6_dataun.icmp6_un_data32[0];
            R = (uint8_t) (Flags >> 31) & 1;
            S = (uint8_t) (Flags >> 30) & 1;
            O = (uint8_t) (Flags >> 29) & 1;
            Reserved = (Flags << 3) >> 3;
            printf("%-45s = %u\n", "R", R);
            printf("%-45s = %u\n", "S", S);
            printf("%-45s = %u\n", "O", O);
            printf("%-45s = %u\n", "Reserved", Reserved);
            break;

        default:
            printf("%-45s = 0x%x\n", "Rest header", ih->icmp6_dataun.icmp6_un_data32[0]);
            break;
    }
}

static void icmp6_dump_data(struct ob_protocol* buffer, ssize_t offset)
{
    uint8_t* hdr = buffer->hdr;
    struct icmp6_hdr ih;

    char ipv6_addr[INET6_ADDRSTRLEN] = {0};

    memcpy(&ih, buffer->hdr, sizeof(struct icmp6_hdr));

    switch (ih.icmp6_type)
    {
        case 1:
            buffer->length -= (ssize_t) sizeof(struct icmp6_hdr);
            buffer->hdr = &hdr[sizeof(struct icmp6_hdr)];
            ipv6_dump(buffer);
            break;

        case 0x87:
        case 0x88:
            if (offset + (ssize_t) (8 * sizeof(uint16_t)) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            inet_ntop(AF_INET6, &hdr[offset], ipv6_addr, INET6_ADDRSTRLEN * sizeof(char));
            printf("%-45s = %s\n", "Address", ipv6_addr);
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

static void icmp6_dump_code(const struct icmp6_hdr* ih)
{
    switch (ih->icmp6_code)
    {
        case 0x3:
            printf("%-45s = 0x%x (%s)\n", "Code", ih->icmp6_code, icmp6_get_destination_host_unreachable_message(ih->icmp6_code));
            break;

        default:
            printf("%-45s = 0x%x\n", "Code", ih->icmp6_code);
            break;
    }
}

static void icmp6_dump_v3(struct ob_protocol* buffer, const struct icmp6_hdr* ih)
{
    uint8_t* hdr = buffer->hdr;
    struct ip6_pseudo_header ip6h;
    ssize_t checksum_offset = offsetof(struct icmp6_hdr, icmp6_cksum);
    uint32_t checksum;

    memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));

    printf("--- BEGIN ICMPv6 MESSAGE ---\n");
    printf("%-45s = 0x%x (%s)\n", "ICMP Message type", ih->icmp6_type, icmp6_get_control_message(ih->icmp6_type));
    icmp6_dump_code(ih);
    printf("%-45s = 0x%x", "Checksum", be16toh(ih->icmp6_cksum));

    checksum = be16toh(ih->icmp6_cksum);
    checksum += ip6h.ip6_len;
    checksum += (checksum >> 16);
    checksum = (uint16_t) checksum;
    for (uint8_t i = 0; i < 8; ++i)
    {
        checksum += be16toh(ip6h.ip6_src.s6_addr16[i]);
        checksum += (checksum >> 16);
        checksum = (uint16_t) checksum;
        checksum += be16toh(ip6h.ip6_dst.s6_addr16[i]);
        checksum += (checksum >> 16);
        checksum = (uint16_t) checksum;
    }
    checksum += (checksum >> 16);
    checksum = (uint16_t) checksum;
    checksum += ip6h.ip6_next_header;
    checksum += (checksum >> 16);
    checksum = (uint16_t) checksum;
    hdr[checksum_offset] = (uint8_t) (checksum >> 8);
    hdr[checksum_offset + 1] = (uint8_t) (checksum);

    printf(" %s\n", checksum_16bitonescomplement_validate(buffer, buffer->length, 0, false));
    icmp6_dump_rest_header(ih);
    icmp6_dump_data(buffer, sizeof(struct icmp6_hdr));
}

static void icmp6_dump_v2(const struct icmp6_hdr* ih)
{
    printf("ICMPv6 => ");
    printf("ICMP Message type : %s\n", icmp6_get_control_message(ih->icmp6_type));
}

void icmp6_dump(struct ob_protocol* buffer)
{
    struct icmp6_hdr ih;

    if ((ssize_t) sizeof(struct icmp6_hdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ih, buffer->hdr, sizeof(struct icmp6_hdr));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> ICMPv6 ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            icmp6_dump_v2(&ih);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            icmp6_dump_v3(buffer, &ih);
            break;
    }
}
