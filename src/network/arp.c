#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "link/eth.h"
#include "network/arp.h"
#include "network/ip4.h"
#include "generic/bytes.h"
#include "network/network.h"
#include "generic/protocol.h"

const char* arp_get_htype(uint16_t Htype)
{
    switch (Htype)
    {
        case 0:
            return "Reserved";

        case 1:
            return "Ethernet";

        case 2:
            return "Experimental Ethernet";

        case 3:
            return "Amateur radio";

        case 4:
            return "Proteon ProNET Token Ring";

        case 5:
            return "Chaos";

        case 6:
            return "IEEE 802 Networks";

        case 7:
            return "ARCNET";

        case 8:
            return "Hyperchannel";

        case 9:
            return "Lanstar";

        case 10:
            return "Autonet Short Address";

        case 11:
            return "LocalTalk";

        case 12:
            return "LocalNet (IBM PCNet or SYTEK LocalNET)";

        case 13:
            return "Ultra link";

        case 14:
            return "SMDS";

        case 15:
            return "Frame Relay";

        case 16:
            return "Asynchronous Transmission Mode (ATM)";

        case 17:
            return "HDLC";

        case 18:
            return "Fibre Channel";

        case 19:
            return "Asynchronous Transmission Mode (ATM)";

        case 20:
            return "Serial Line";

        case 21:
            return "Asynchronous Transmission Mode (ATM)";

        case 22:
            return "MIL-STD-188-220";

        case 23:
            return "Metricom";

        case 24:
            return "IEEE 1394.1995";

        case 25:
            return "MAPOS";

        case 26:
            return "Twinaxial";

        case 27:
            return "EUI-64";

        case 28:
            return "HIPARP";

        case 29:
            return "IP and ARP over ISO 7816-3";

        case 30:
            return "ARPSec";

        case 31:
            return "IPsec tunnel";

        case 32:
            return "InfiniBand (TM)";

        case 33:
            return "TIA-102 Project 25 Common Air Interface (CAI)";

        case 34:
            return "Wiegand Interface";

        case 35:
            return "Pure IP";

        case 36:
            return "HW_EXP1";

        case 37:
            return "HFI";

        case 38:
            return "Unified Bus (UB)";

        case 256:
            return "HW_EXP2";

        case 257:
            return "AEthernet";

        case 65535:
            return "Reserved";

        default:
            return "Unknown";
    }
}

static void arp_dump_v3(const struct ob_protocol* buffer, const struct arphdr* ah)
{
    const uint8_t* hdr = buffer->hdr;

    printf("--- BEGIN ARP MESSAGE ---\n");

    printf("%-45s = %u (%s)\n", "Hardware type", be16toh(ah->ar_hrd), arp_get_htype(be16toh(ah->ar_hrd)));
    printf("%-45s = %u (%s)\n", "Protocol type", be16toh(ah->ar_pro), network_get_name(be16toh(ah->ar_pro)));
    printf("%-45s = %u (%s)\n", "Operation", be16toh(ah->ar_op), be16toh(ah->ar_op) == 2 ? "Reply" : "Request");

    /**
     * For now only IPv4 over Ethernet is supported
     */

    if (be16toh(ah->ar_hrd) == ARP_HARDWARE_TYPE_ETHERNET)
    {
        /**
         * We must print a string right after ether_ntoa otherwise it will be
         * overriden by another call to ether_ntoa
         */
        char* ethernet;

        if ((ssize_t) (sizeof(struct arphdr) + ah->ar_pln + ah->ar_hln + sizeof(struct ether_addr)) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        ethernet = ether_ntoa((const struct ether_addr*) &hdr[sizeof(struct arphdr)]);
        printf("%-45s = %s\n", "Sender hardware address", ethernet);
        ethernet = ether_ntoa((const struct ether_addr*) &hdr[sizeof(struct arphdr) + ah->ar_pln + ah->ar_hln]);
        printf("%-45s = %s\n", "Target hardware address", ethernet);
    }

    if (be16toh(ah->ar_pro) == ARP_PROTOCOL_TYPE_IPV4)
    {
        char ip_src_str[INET_ADDRSTRLEN] = {0};
        char ip_dst_str[INET_ADDRSTRLEN] = {0};

        uint32_t ip_src;
        uint32_t ip_dst;

        if ((ssize_t) (sizeof(struct arphdr) + ah->ar_pln + 2 * ah->ar_hln + sizeof(uint32_t)) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        ip_src = read_u32_unaligned(&hdr[sizeof(struct arphdr) + ah->ar_hln]);
        ip_dst = read_u32_unaligned(&hdr[sizeof(struct arphdr) + ah->ar_pln + 2 * ah->ar_hln]);

        inet_ntop(AF_INET, &ip_src, ip_src_str, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &ip_dst, ip_dst_str, INET_ADDRSTRLEN * sizeof(char));

        printf("%-45s = %s\n", "Sender protocol address", ip_src_str);
        printf("%-45s = %s\n", "Target protocol address", ip_dst_str);
    }
}

static void arp_dump_v2(const struct ob_protocol* buffer, const struct arphdr* ah)
{
    const uint8_t* hdr = buffer->hdr;

    printf("ARP => ");
    printf("Hardware type : %s, ", arp_get_htype(be16toh(ah->ar_hrd)));
    printf("Protocol type : %s, ", network_get_name(be16toh(ah->ar_pro)));
    printf("Operation : %s, ", be16toh(ah->ar_op) == 2 ? "Reply" : "Request");

    if (be16toh(ah->ar_pro) == ARP_PROTOCOL_TYPE_IPV4)
    {
        char ip_src_str[INET_ADDRSTRLEN] = {0};
        char ip_dst_str[INET_ADDRSTRLEN] = {0};

        uint32_t ip_src;
        uint32_t ip_dst;

        if ((ssize_t) (sizeof(struct arphdr) + ah->ar_pln + 2 * ah->ar_hln + sizeof(uint32_t)) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        ip_src = read_u32_unaligned(&hdr[sizeof(struct arphdr) + ah->ar_hln]);
        ip_dst = read_u32_unaligned(&hdr[sizeof(struct arphdr) + ah->ar_pln + 2 * ah->ar_hln]);

        inet_ntop(AF_INET, &ip_src, ip_src_str, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &ip_dst, ip_dst_str, INET_ADDRSTRLEN * sizeof(char));
        
        printf("Sender IP : %s, ", ip_src_str);
        printf("Target IP : %s\n", ip_dst_str);
    }
}

void arp_dump(struct ob_protocol* buffer)
{
    struct arphdr ah;

    if ((ssize_t) sizeof(struct arphdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ah, buffer->hdr, sizeof(struct arphdr));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> ARP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            arp_dump_v2(buffer, &ah);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            arp_dump_v3(buffer, &ah);
            break;
    }
}
