#include <stdlib.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip4.h"
#include "network/ip6.h"
#include "network/arp.h"
#include "generic/binary.h"
#include "network/network.h"
#include "generic/protocol.h"

/**
 * These functions are made specifically for 802.3 Ethernet, they could easily
 * be modified to support other link types.
 */

/**
 * @brief Set the dump function on a message structure
 * @param EthType Value of the EtherType field in the Ethernet structure
 * @param buffer Pointer to the message structure
 */
void network_cast(uint16_t EthType, struct ob_protocol* buffer)
{
    switch (EthType)
    {
        case 0x800:
            buffer->dump = ipv4_dump;
            break;

        case 0x806:
            buffer->dump = arp_dump;
            break;

        case 0x86DD:
            buffer->dump = ipv6_dump;
            break;

        default:
            buffer->dump = binary_dump;
            break;
    }
}

/**
 * @brief Get the name of the transport layer
 * @param EthType Value of the EtherType field in the Ethernet structure
 * @return Constant string containing the transport name
 */
const char* network_get_name(uint16_t EthType)
{
    switch (EthType)
    {
        case 0x800:
            return "IPv4";

        case 0x806:
            return "ARP";

        case 0x842:
            return "Wake-On-Lan";

        case 0x2000:
            return "Cisco Discovery";

        case 0x22EA:
            return "Stream Reservation";

        case 0x22F0:
            return "AVTP";

        case 0x22F3:
            return "IETF TRILL";

        case 0x6002:
            return "DEC MOP RC";

        case 0x6003:
            return "DECnet Phase IV";

        case 0x6004:
            return "DEC LAT";

        case 0x8035:
            return "RARP";

        case 0x809B:
            return "Apple Talk";

        case 0x80D5:
            return "LLC PDU";

        case 0x80F3:
            return "AARP";

        case 0x8100:
            return "VLAN-tagged frame";

        case 0x8102:
            return "SLPP";

        case 0x8103:
            return "VLACP";

        case 0x8137:
            return "IPX";

        case 0x8204:
            return "QNX Qnet";

        case 0x86DD:
            return "IPv6";

        case 0x8808:
            return "Ethernet flow control";

        case 0x8809:
            return "Ethernet Slow Protocols";

        case 0x8819:
            return "CobraNet";

        case 0x8847:
            return "MPLS unicast";

        case 0x8848:
            return "MPLS multicast";

        case 0x8863:
            return "PPPoE Discovery Stage";

        case 0x8864:
            return "PPPoE Session Stage";

        case 0x887B:
            return "HomePlug 1.0 MME";

        case 0x888E:
            return "EAP over LAN";

        case 0x8892:
            return "PROFINET Protocol";

        case 0x889A:
            return "HyperSCSI";

        case 0x88A2:
            return "ATA over Ethernet";

        case 0x88A4:
            return "EtherCAT Protocol";

        case 0x88A8:
            return "Service VLAN tag identifier";

        case 0x88AB:
            return "Ethernet Powerlink";

        case 0x88B8:
            return "GOOSE";

        case 0x88B9:
            return "GSE Management Services";

        case 0x88BA:
            return "Sampled Value Transmission";

        case 0x88BF:
            return "MikroTik RoMON";

        case 0x88CC:
            return "LLDP";

        case 0x88CD:
            return "SERCOS III";

        case 0x88E1:
            return "HomePlug Green PHY";

        case 0x88E3:
            return "Media Redundancy Protocol";

        case 0x88E5:
            return "MACsec";

        case 0x88E7:
            return "PBB";

        case 0x88F7:
            return "PTP";

        case 0x88F8:
            return "NC-SI";

        case 0x88FB:
            return "PRP";

        case 0x8902:
            return "CFM";

        case 0x8906:
            return "FCoE";

        case 0x8914:
            return "FCoE Initialization Protocol";

        case 0x8915:
            return "RoCE";

        case 0x891D:
            return "TTE";

        case 0x893A:
            return "1905.1 IEEE Protocol";

        case 0x892F:
            return "HSR";

        case 0x9000:
            return "Ethernet Configuration Testing Protocol";

        case 0xF1C1:
            return "Redundancy Tag";

        default:
            return "Unknown protocol";
    }
}
