#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "network/ip.h"
#include "transport/tcp.h"
#include "transport/udp.h"
#include "generic/binary.h"
#include "transport/icmp.h"
#include "transport/igmp.h"
#include "transport/ospf.h"
#include "transport/sctp.h"
#include "transport/icmp6.h"
#include "generic/protocol.h"
#include "transport/transport.h"

void transport_cast(uint8_t type, struct ob_protocol* buffer)
{
    switch (type)
    {
        case T_IP_PROTOCOL_TCP:
            buffer->dump = tcp_dump;
            break;

        case T_IP_PROTOCOL_UDP:
            buffer->dump = udp_dump;
            break;

        case T_IP_PROTOCOL_ICMP:
            buffer->dump = icmp4_dump;
            break;

        case T_IP_PROTOCOL_IPv6_ICMP:
            buffer->dump = icmp6_dump;
            break;

        case T_IP_PROTOCOL_IGMP:
            buffer->dump = igmp_dump;
            break;

        case T_IP_PROTOCOL_OSPF:
            buffer->dump = ospf_dump;
            break;

        case T_IP_PROTOCOL_SCTP:
            buffer->dump = sctp_dump;
            break;

        default:
            buffer->dump = binary_dump;
            break;
    }
}

const char* transport_get_name(uint8_t type)
{
    switch (type)
    {
        case T_IP_PROTOCOL_TCP:
            return "TCP";

        case T_IP_PROTOCOL_UDP:
            return "UDP";

        case T_IP_PROTOCOL_ICMP:
            return "ICMP";

        case T_IP_PROTOCOL_IPv6_ICMP:
            return "ICMPv6";

        case T_IP_PROTOCOL_IGMP:
            return "IGMP";

        case T_IP_PROTOCOL_OSPF:
            return "OSPF";

        case T_IP_PROTOCOL_SCTP:
            return "SCTP";

        default:
            return "Unknown";
    }
}
