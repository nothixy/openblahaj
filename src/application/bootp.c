#include <stdio.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "link/eth.h"
#include "network/ip4.h"
#include "generic/bytes.h"
#include "application/dhcp.h"
#include "generic/protocol.h"
#include "application/bootp.h"

static void bootp_dump_client_hardware_address(const struct bootp_header* header)
{
    const char* hardware_address;
    uint16_t double_byte;

    if (header->htype == 1)
    {
        hardware_address = ether_ntoa((struct ether_addr*) header->chaddr);
        printf("%s", hardware_address);
        return;
    }

    for (int i = 0; i < 8; ++i)
    {
        double_byte = read_u16_unaligned(&header->chaddr[i * 2]);
        printf("%04x", double_byte);
        if (i != 2 * 4 - 1)
        {
            printf(" ");
        }
    }
}

static void bootp_dump_v3(const struct bootp_header* bh)
{
    char local_ciaddr[INET_ADDRSTRLEN] = {0};
    char local_yiaddr[INET_ADDRSTRLEN] = {0};
    char local_siaddr[INET_ADDRSTRLEN] = {0};
    char local_giaddr[INET_ADDRSTRLEN] = {0};

    printf("--- BEGIN BOOTP MESSAGE ---\n");

    printf("%-45s = %u\n", "OP", bh->op);
    printf("%-45s = %u\n", "Hardware address type", bh->htype);
    printf("%-45s = %u\n", "Hardware address length", bh->hlen);
    printf("%-45s = %u\n", "Hops", bh->hops);
    printf("%-45s = %u\n", "Transaction ID", bh->xid);
    printf("%-45s = %u\n", "Seconds elapsed", bh->secs);
    printf("%-45s = %u\n", "Flags", bh->flags);
    printf("%-45s = %s\n", "Client IP address", inet_ntop(AF_INET, &(bh->ciaddr), local_ciaddr, INET_ADDRSTRLEN * sizeof(char)));
    printf("%-45s = %s\n", "Your IP address", inet_ntop(AF_INET, &(bh->yiaddr), local_yiaddr, INET_ADDRSTRLEN * sizeof(char)));
    printf("%-45s = %s\n", "Server IP address", inet_ntop(AF_INET, &(bh->siaddr), local_siaddr, INET_ADDRSTRLEN * sizeof(char)));
    printf("%-45s = %s\n", "Gateway IP address", inet_ntop(AF_INET, &(bh->giaddr), local_giaddr, INET_ADDRSTRLEN * sizeof(char)));

    printf("%-45s = ", "Client hardware address");
    bootp_dump_client_hardware_address(bh);
    printf("\n");

    printf("%-45s = ", "Server host name");
    for (int i = 0; i < 64; ++i)
    {
        printf("%c", bh->sname[i]);
    }
    printf("\n");

    printf("%-45s = ", "Boot file name");
    for (int i = 0; i < 128; ++i)
    {
        printf("%c", bh->file[i]);
    }
    printf("\n");
}

static void bootp_dump_v2(struct bootp_header* bh)
{
    char local_ciaddr[INET_ADDRSTRLEN] = {0};
    char local_yiaddr[INET_ADDRSTRLEN] = {0};
    char local_siaddr[INET_ADDRSTRLEN] = {0};
    char local_giaddr[INET_ADDRSTRLEN] = {0};

    printf("BOOTP => ");
    if (bh->ciaddr != 0)
    {
        printf("Client IP address : %s, ", inet_ntop(AF_INET, &(bh->ciaddr), local_ciaddr, INET_ADDRSTRLEN * sizeof(char)));
    }
    if (bh->yiaddr != 0)
    {
        printf("Your IP address : %s, ", inet_ntop(AF_INET, &(bh->yiaddr), local_yiaddr, INET_ADDRSTRLEN * sizeof(char)));
    }
    if (bh->siaddr != 0)
    {
        printf("Server IP address : %s, ", inet_ntop(AF_INET, &(bh->siaddr), local_siaddr, INET_ADDRSTRLEN * sizeof(char)));
    }
    if (bh->giaddr != 0)
    {
        printf("Gateway IP address : %s, ", inet_ntop(AF_INET, &(bh->giaddr), local_giaddr, INET_ADDRSTRLEN * sizeof(char)));
    }
    printf("Hardware address : ");
    bootp_dump_client_hardware_address(bh);
    printf(", ");
    if (bh->sname[0] != 0)
    {
        printf("Server host name : ");
        for (int i = 0; i < 64; ++i)
        {
            printf("%c", bh->sname[i]);
        }
        printf(", ");
    }
    if (bh->file[0] != 0)
    {
        printf("Boot file name : ");
        for (int i = 0; i < 128; ++i)
        {
            printf("%c", bh->file[i]);
        }
    }
    printf("\n");
}

void bootp_dump(struct ob_protocol* buffer)
{
    struct bootp_header bh;
    uint8_t subprotocol;
    uint32_t cookie;

    if ((ssize_t) sizeof(struct bootp_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&bh, buffer->hdr, sizeof(struct bootp_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> Bootp ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            bootp_dump_v2(&bh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            bootp_dump_v3(&bh);
            break;
    }

    cookie = be32toh(read_u32_unaligned(bh.vend));
    subprotocol = bh.vend[4];

    if (cookie == BOOTP_VENDOR_MAGIC && subprotocol == 0x35)
    {
        uint8_t* dhcp_bytes = (uint8_t*) buffer->hdr;

        buffer->length -= (ssize_t) (sizeof(struct bootp_header) + sizeof(bh.vend) - 1);
        buffer->hdr = &dhcp_bytes[sizeof(struct bootp_header) - sizeof(bh.vend) + 1];
        buffer->dump = dhcp_dump;

        buffer->dump(buffer);
    }
}

