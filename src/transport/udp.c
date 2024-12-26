#include <stdio.h>
#include <endian.h>
#include <stddef.h>
#include <string.h>
#include <netinet/udp.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip4.h"
#include "network/ip6.h"
#include "generic/bytes.h"
#include "transport/udp.h"
#include "generic/protocol.h"
#include "application/application.h"

static void udp_dump_v3(const struct ob_protocol* buffer, const struct udphdr* uh)
{
    uint8_t ip_version;
    uint8_t* hdr = buffer->hdr;
    struct ip_pseudo_header iph;
    struct ip6_pseudo_header ip6h;
    ssize_t checksum_offset = offsetof(struct udphdr, uh_sum);
    uint32_t checksum;

    ip_version = *(uint8_t*) buffer->pseudo_header;

    printf("--- BEGIN UDP MESSAGE ---\n");

    printf("%-45s = %u (%s)\n", "Source port", be16toh(uh->uh_sport), application_get_name(T_TRANSPORT_UDP, be16toh(uh->uh_sport)));
    printf("%-45s = %u (%s)\n", "Destination port", be16toh(uh->uh_dport), application_get_name(T_TRANSPORT_UDP, be16toh(uh->uh_dport)));
    printf("%-45s = %u\n", "Length", be16toh(uh->uh_ulen));
    printf("%-45s = 0x%x", "Checksum", be16toh(uh->uh_sum));

    switch (ip_version)
    {
        case 4:
            memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
            checksum = be16toh(uh->uh_sum);
            checksum += iph.ip_len;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_dst.s_addr));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_dst.s_addr >> 16));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_src.s_addr));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_src.s_addr >> 16));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += iph.ip_proto;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            hdr[checksum_offset] = (uint8_t) (checksum >> 8);
            hdr[checksum_offset + 1] = (uint8_t) (checksum);
            break;

        case 6:
            memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
            checksum = be16toh(uh->uh_sum);
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
            break;

        default:
            break;
    }

    printf(" %s\n", checksum_16bitonescomplement_validate(buffer, be16toh(uh->uh_ulen), be16toh(uh->uh_sum), true));
}

static void udp_dump_v2(const struct udphdr* uh)
{
    printf("UDP => ");
    printf("Source port : %u, ", be16toh(uh->uh_sport));
    printf("Destination port : %u\n", be16toh(uh->uh_dport));
}

void udp_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct udphdr uh;

    if ((ssize_t) sizeof(struct udphdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&uh, buffer->hdr, sizeof(struct udphdr));

    if (be16toh(uh.uh_ulen) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> UDP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            udp_dump_v2(&uh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            udp_dump_v3(buffer, &uh);
            break;
    }

    if (!application_cast(T_TRANSPORT_UDP, be16toh(uh.uh_sport), buffer))
    {
        application_cast(T_TRANSPORT_UDP, be16toh(uh.uh_dport), buffer);
    }

    buffer->length -= (ssize_t) sizeof(struct udphdr);
    buffer->hdr = &hdr[sizeof(struct udphdr)];

    buffer->dump(buffer);
}
