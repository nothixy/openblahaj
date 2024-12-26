#include <stdio.h>
#include <endian.h>
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
#include "network/ip6.h"
#include "generic/guid.h"
#include "generic/bytes.h"
#include "application/dhcp.h"
#include "generic/protocol.h"

/**
 * Note : there are a lot of DHCP commands, not all of them are implemented here
 */

static const char* DHCP_COMMANDS[] = {
    "PAD",
    "Subnet Mask",
    "Time Offset",
    "Router",
    "Time Server",
    "Name Server",
    "Domain Server",
    "Log Server",
    "Quotes Server",
    "LPR Server",
    "Impress Server",
    "RLP Server",
    "Hostname",
    "Boot File Size",
    "Merit Dump File",
    "Domain Name",
    "Swap Server",
    "Root Path",
    "Extension File",
    "Forward On/Off",
    "SrcRte On/Off",
    "Policy Filter",
    "Max DG Assembly",
    "Default IP TTL",
    "MTU Timeout",
    "MTU Plateau",
    "MTU Interface",
    "MTU Subnet",
    "Broadcast Address",
    "Mask Discovery",
    "Mask Supplier",
    "Router Discovery",
    "Router Request",
    "Static Route",
    "Trailers",
    "ARP Timeout",
    "Ethernet",
    "Default TCP TTL",
    "Keepalive Time",
    "Keepalive Data",
    "NIS Domain",
    "NIS Servers",
    "NTP Servers",
    "Vendor Specific",
    "NETBIOS Name Srv",
    "NETBIOS Dist Srv",
    "NETBIOS Node Type",
    "NETBIOS Scope",
    "X Window Font",
    "X Window Manager",
    "Address Request",
    "Address Time",
    "Overload",
    "DHCP Msg Type",
    "DHCP Server Id",
    "Parameter List",
    "DHCP Message",
    "DHCP Max Msg Size",
    "Renewal Time",
    "Rebinding Time",
    "Class Id",
    "Client Id",
    "NetWare/IP Domain",
    "NetWare/IP Option",
    "NIS-Domain-Name",
    "NIS-Server-Addr",
    "Server-Name",
    "Bootfile-Name",
    "Home-Agent-Addrs",
    "SMTP-Server",
    "POP3-Server",
    "NNTP-Server",
    "WWW-Server",
    "Finger-Server",
    "IRC-Server",
    "StreetTalk-Server",
    "STDA-Server",
    "User-Class",
    "Directory Agent",
    "Service Scope",
    "Rapid Commit",
    "Client FQDN",
    "Relay Agent Information",
    "iSNS",
    "REMOVED/Unassigned",
    "NDS Servers",
    "NDS Tree Name",
    "NDS Context",
    "BCMCS Controller Domain Name list",
    "BCMCS Controller IPv4 address option",
    "Authentication",
    "client-last-transaction-time option",
    "associated-ip option",
    "Client System",
    "Client NDI",
    "LDAP",
    "REMOVED/Unassigned",
    "UUID/GUID",
    "User-Auth",
    "GEOCONF_CIVIC",
    "PCode",
    "TCode",
    [102 ... 107] = "Unknown",
    "IPv6-Only Preferred",
    "OPTION_DHCP4O6_S46_SADDR",
    "REMOVED/Unassigned",
    "Unassigned",
    "Netinfo Address",
    "Netinfo Tag",
    "DHCP Captive-Portal",
    "REMOVED/Unassigned",
    "Auto-Config",
    "Name Service Search",
    "Subnet Selection Option",
    "Domain Search",
    "SIP Servers DHCP Option",
    "Classless Static Route Option",
    "CCC",
    "GeoConf Option",
    "V-I Vendor Class",
    "V-I Vendor-Specific Information",
    [126 ... 127] = "Removed/Unassigned",
    "PXE - undefined (vendor specific) | Etherboot signature. 6 bytes: E4:45:74:68:00:00 | DOCSIS \"full security\" server IP address | TFTP Server IP address (for IP Phone software load)",
    "PXE - undefined (vendor specific) | Kernel options. Variable length string | Call Server IP address",
    "PXE - undefined (vendor specific) | Ethernet interface. Variable length string. | Discrimination string (to identify vendor)",
    "PXE - undefined (vendor specific) | Remote statistics server IP address",
    "PXE - undefined (vendor specific) | IEEE 802.1Q VLAN ID",
    "PXE - undefined (vendor specific) | IEEE 802.1D/p Layer 2 Priority",
    "PXE - undefined (vendor specific) | Diffserv Code Point (DSCP) for VoIP signalling and media streams",
    "PXE - undefined (vendor specific) | HTTP Proxy for phone-specific applications",
    "OPTION_PANA_AGENT",
    "OPTION_V4_LOST",
    "OPTION_CAPWAP_AC_V4",
    "OPTION-IPv4_Address-MoS",
    "OPTION-IPv4_FQDN-MoS",
    "SIP UA Configuration Service Domains",
    "OPTION-IPv4_Address-ANDSF",
    "OPTION_V4_SZTP_REDIRECT",
    "GeoLoc",
    "FORCERENEW_NONCE_CAPABLE",
    "RDNSS Selection",
    "OPTION_V4_DOTS_RI",
    "OPTION_V4_DOTS_ADDRESS",
    "Unassigned",
    "TFTP server address | Etherboot | GRUB configuration path name",
    "status-code",
    "base-time",
    "start-time-of-state",
    "query-start-time",
    "query-end-time",
    "dhcp-state",
    "data-source",
    "OPTION_V4_PCP_SERVER",
    "OPTION_V4_PORTPARAMS",
    "Unassigned",
    "OPTION_MUD_URL_V4",
    "OPTION_V4_DNR",
    [163 ... 174] = "Unknown",
    "Etherboot (Tentatively Assigned - 2005-06-23)",
    "IP Telephone (Tentatively Assigned - 2005-06-23)",
    "Etherboot (Tentatively Assigned - 2005-06-23) | PacketCable and CableHome (replaced by 122)",
    [178 ... 207] = "Unknown",
    "PXELINUX Magic",
    "Configuration File",
    "Path Prefix",
    "Reboot Time",
    "OPTION_6RD",
    "OPTION_V4_ACCESS_DOMAIN",
    [214 ... 219] = "Unknown",
    "Subnet Allocation Option",
    "Virtual Subnet Selection (VSS) Option",
    [222 ... 254] = "Unknown",
    "End"
};

static const char* DHCP_MESSAGE_TYPE[] = {
    "UNKNOWN",
    "DISCOVER",
    "OFFER",
    "REQUEST",
    "DECLINE",
    "ACK",
    "NAK",
    "RELEASE",
    "INFORM",
    "FORCERENEW",
    "LEASEQUERY",
    "LEASEUNASSIGNED",
    "LEASEUNKNOWN",
    "LEASEACTIVE",
    "PUBLKLEASEQUERY",
    "LEASEQUERYDONE",
    "ACTIVELEASEQUERY",
    "LEASEQUERYSTATUS",
    "TLS"
};

static const char* DHCP_CABLELABS_SUBOPTIONS[] = {
    "TSP's Primary DHCP Server Address",
    "TSP's Secondary DHCP Server Address",
    "TSP's Provisioning Server Address",
    "TSP's AS-REQ/AS-REP Backoff and Retry",
    "TSP's AP-REQ/AP-REP Backoff and Retry",
    "TSP's Kerberos Realm Name",
    "TSP's Ticket Granting Server Utilization",
    "TSP's Provisioning Timer Value"
};

static const char* dhcp_get_command(uint8_t command)
{
    return DHCP_COMMANDS[command];
}

static const char* dhcp_get_message_type(uint8_t type)
{
    if (type >= sizeof(DHCP_MESSAGE_TYPE) / sizeof(const char*))
    {
        return "UNKNOWN";
    }
    return DHCP_MESSAGE_TYPE[type];
}

static const char* dhcp_get_cablelabs_suboption(uint8_t suboption)
{
    if (suboption >= sizeof(DHCP_CABLELABS_SUBOPTIONS) / sizeof(const char*))
    {
        return "Unknown";
    }
    return DHCP_CABLELABS_SUBOPTIONS[suboption];
}

static char* dhcp_get_client_id(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    static char unknown[] = "Unknown";

    if (offset >= buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    switch (hdr[offset])
    {
        case 0x1:
            return ether_ntoa((const struct ether_addr*) &hdr[offset + 1]);

        default:
            return unknown;
    }
}

static void dhcp_dump_crl(const struct ob_protocol* buffer, ssize_t offset, uint8_t crl_length)
{
    const uint8_t* hdr = buffer->hdr;
    for (int i = 0; i < crl_length; ++i)
    {
        if (offset + i >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        printf("0x%x", hdr[offset + i]);
        if (i != crl_length - 1)
        {
            printf(", ");
        }
    }
}

static void dhcp_dump_ipv4s(const struct ob_protocol* buffer, ssize_t offset, uint8_t ips_length)
{
    const uint8_t* hdr = buffer->hdr;
    char ip_addr[INET_ADDRSTRLEN] = {0};
    if (offset + ips_length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    for (uint8_t i = 0; i < ips_length; i += 4)
    {
        if (offset + i + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        inet_ntop(AF_INET, &hdr[offset + i], ip_addr, INET_ADDRSTRLEN * sizeof(char));
        printf("%s", ip_addr);
        if (i < ips_length - 4)
        {
            printf(", ");
        }
    }
}

static void dhcp_dump_relay_agent_information(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* data = buffer->hdr;
    for (int i = 0; i < command_length;)
    {
        uint8_t subopt;
        uint8_t len;

        if (offset + i + 1 >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        subopt = data[offset + i];
        len = data[offset + i + 1];

        if (offset + i + len > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        printf("%u -> ", subopt);
        for (int j = 0; j < len; ++j)
        {
            printf("%x", data[offset + i + j]);
        }

        i += len + 2;

        if (i == command_length - 1)
        {
            break;
        }

        printf(", ");
    }
}

static void dhcp_dump_client_fqdn(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* data = buffer->hdr;
    if (offset + command_length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    for (int i = 3; i < command_length; ++i)
    {
        printf("%c", data[offset + i]);
    }
    if (data[offset])
    {
        printf("\n");
        printf("%-45s = ", "Flags");
        if ((data[offset] >> 3) & 1)
        {
            printf("N");
        }
        if ((data[offset] >> 2) & 1)
        {
            printf("E");
        }
        if ((data[offset] >> 1) & 1)
        {
            printf("O");
        }
        if ((data[offset] >> 0) & 1)
        {
            printf("S");
        }
    }
}

/**
 * @note Incomplete, see https://www.rfc-editor.org/rfc/rfc4174.html for information
 */
static void dhcp_dump_iSNS(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* hdr = buffer->hdr;
    struct dhcp_isns di;

    if (offset + (ssize_t) sizeof(struct dhcp_isns) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&di, &hdr[offset], sizeof(struct dhcp_isns));

    printf("iSNS functions -> %u; ", be16toh(di.functions));
    printf("DD Access -> %u; ", be16toh(di.dd_access));
    printf("Administrative flags -> %u; ", be16toh(di.admin_flags));
    printf("Security bitmap -> %u; ", be32toh(di.sec_bitmap));

    offset += (ssize_t) sizeof(struct dhcp_isns);

    printf("Servers -> ");
    dhcp_dump_ipv4s(buffer, offset, (uint8_t) (command_length - offset));
}

static void dhcp_dump_auth(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* data = buffer->hdr;

    if (offset + (ssize_t) (3 + sizeof(uint64_t)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("Protocol -> %u; ", data[offset]);
    printf("Algorithm -> %u; ", data[offset + 1]);
    printf("RDM -> %u; ", data[offset + 2]);
    printf("Replay detection -> %lu; ", be64toh(read_u64_unaligned(&data[offset + 3])));
    printf("Authentication information -> ");
    for (uint8_t i = 7; i < command_length; ++i)
    {
        printf("%x ", data[offset + i]);
    }
}

static void dhcp_dump_client_system_arch_type(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* data = buffer->hdr;
    uint16_t type;

    if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    type = be16toh(read_u16_unaligned(&data[offset]));

    switch (type)
    {
        case 0:
            printf("Intel x86PC");
            break;

        case 1:
            printf("NEC/PC98");
            break;

        case 2:
            printf("EFI Itanium");
            break;

        case 3:
            printf("DEC Alpha");
            break;

        case 4:
            printf("Arc x86");
            break;

        case 5:
            printf("Intel Lean Client");
            break;

        case 6:
            printf("EFI IA32");
            break;

        case 7:
            printf("EFI BC");
            break;

        case 8:
            printf("EFI Xscale");
            break;

        case 9:
            printf("EFI x86-64");
            break;

        default:
            printf("Unknown");
            break;
    }

    printf("\n");
}

static void dhcp_dump_client_machine_identifier(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* data = buffer->hdr;

    char guid[37] = {0};

    if (offset + 16 >= buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("Type -> %u; ", data[offset]);
    printf("GUID -> %s", guid_get(&data[offset + 1], guid));
}

static void dhcp_dump_4o6_softwire_source(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* data = buffer->hdr;

    char ipv6_str[INET6_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) (8 * sizeof(uint16_t)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    inet_ntop(AF_INET6, &data[offset], ipv6_str, INET6_ADDRSTRLEN * sizeof(char));

    printf("%s", ipv6_str);
}

static void dhcp_dump_sip_server(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* data = buffer->hdr;

    if (offset >= buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    switch (data[offset])
    {
        case 1:
            dhcp_dump_ipv4s(buffer, offset + 1, command_length - 1);
            break;

        case 0:
        default:
            printf("Unimplemented");
            break;
    }
}

/**
 * Probably wrong but I have nothing to test, see
 * https://www.rfc-editor.org/rfc/rfc3442.html
 * for more details
 */
static void dhcp_dump_classless_route(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* data = buffer->hdr;

    for (uint8_t i = 0; i < command_length;)
    {
        uint8_t mask_length;
        uint32_t subnet;
        uint32_t netmask = (uint32_t) -1;
        uint32_t router;
        char subnet_str[INET_ADDRSTRLEN] = {0};
        char netmask_str[INET_ADDRSTRLEN] = {0};
        char router_str[INET_ADDRSTRLEN] = {0};

        if (offset + i + 1 + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        mask_length = data[offset + i];
        subnet = be32toh(read_u32_unaligned(&data[offset + i + 1]));

        for (uint8_t j = 0; j < mask_length; ++j)
        {
            netmask |= (1U << (31 - j));
        }
        for (uint8_t j = 0; j < 32 - mask_length; ++j)
        {
            subnet ^= (1U << j);
        }

        inet_ntop(AF_INET, &netmask, netmask_str, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &subnet, subnet_str, INET_ADDRSTRLEN * sizeof(char));

        if (mask_length > 24)
        {
            i += 5;
        }
        else if (mask_length > 16)
        {
            i += 4;
        }
        else if (mask_length > 8)
        {
            i += 3;
        }
        else if (mask_length > 0)
        {
            i += 2;
        }
        else
        {
            i += 1;
        }

        if (offset + i + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        router = read_u32_unaligned(&data[offset + i]);
        inet_ntop(AF_INET, &router, router_str, INET_ADDRSTRLEN * sizeof(char));

        printf("Subnet -> %s; ", subnet_str);
        printf("Netmask -> %s; ", netmask_str);
        printf("Router -> %s; ", router_str);

        i += 4;
    }
}

/**
 * I'm tired of writing things, see
 * https://www.rfc-editor.org/rfc/rfc3495.html
 */
static void dhcp_dump_cablelabs_client_configuration(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* data = buffer->hdr;

    for (uint8_t i = 0; i < command_length;)
    {
        const char* suboption;
        uint8_t option_length;

        if (offset + i + 1 >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        suboption = dhcp_get_cablelabs_suboption(data[offset + i]);
        option_length = data[offset + i + 1];

        printf("%s -> ", suboption);

        if (offset + i + 2 + option_length > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }

        for (uint8_t j = 0; j < option_length; ++j)
        {
            printf("%x ", data[offset + i + 2 + j]);
        }
        printf("; ");

        i += (uint8_t) (option_length + 2);
    }
}

static void dhcp_dump_geo(const struct ob_protocol* buffer, ssize_t offset, bool loc)
{
    const uint8_t* hdr = buffer->hdr;
    struct dhcp_geo dg;

    if (offset + (ssize_t) sizeof(struct dhcp_geo) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&dg, &hdr[offset], sizeof(struct dhcp_geo));

    printf("Latitude res -> %u; ", dg.la_res);
    printf("Latitude -> %lu; ", (uint64_t) (dg.latitude));
    printf("Longitude res -> %u; ", dg.lo_res);
    printf("Longitude -> %lu; ", (uint64_t) (dg.longitude));
    printf("Altitude type -> %u; ", dg.a_type);
    printf("Altitude res -> %u; ", dg.a_res);
    printf("Altitude -> %u; ", dg.altitude);
    if (loc)
    {
        printf("Version -> %u; ", dg.ver);
    }
    printf("Datum -> %u", dg.datum);
}

static void dhcp_dump_vendor(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    const uint8_t* hdr = buffer->hdr;
    uint8_t entreprise_data_length;
    for (ssize_t i = offset; i < offset + (ssize_t) command_length;)
    {
        printf("[");
        if (i + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        printf("Entreprise number -> %u; ", be32toh(read_u32_unaligned(&hdr[i])));

        i += (ssize_t) sizeof(uint32_t);
        if (i + (ssize_t) sizeof(uint8_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        entreprise_data_length = hdr[i];
        printf("Entreprise number -> %u; ", entreprise_data_length);
        i += (ssize_t) sizeof(uint8_t);

        printf("Vendor class data / options -> ");
        for (uint8_t j = 0; j < entreprise_data_length; ++j)
        {
            printf("%02x", hdr[i + j]);
        }
        i += (ssize_t) entreprise_data_length;
        printf("]");
    }
}

static void dhcp_dump_nss(const struct ob_protocol* buffer, ssize_t offset, uint8_t command_length)
{
    uint8_t* data = buffer->hdr;
    uint16_t ns;
    for (uint8_t i = 0; i < command_length; i += 2)
    {
        ns = be16toh(read_u16_unaligned(&data[offset + i]));
        printf("%x", ns);
        if (ns <= (uint8_t) -1)
        {
            printf(" (%s)", dhcp_get_command((uint8_t) ns));
        }
        if (i < command_length - 1)
        {
            printf(", ");
        }
    }
}

/**
 * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
 */
static void dhcp_dump_command(const struct ob_protocol* buffer, ssize_t offset, uint8_t command, uint8_t command_length)
{
    const uint8_t* data = buffer->hdr;

    if (offset + command_length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("%-45s = ", dhcp_get_command(command));
    switch (command)
    {
        case 0x1:  /* Subnet mask */
        case 0x3:  /* Router */
        case 0x4:  /* Time server */
        case 0x5:  /* Name server */
        case 0x6:  /* Domain server */
        case 0x7:  /* Log server */
        case 0x8:  /* Quotes server */
        case 0x9:  /* LPR server */
        case 0xa:  /* Impress server */
        case 0xb:  /* RLP server */
        case 0x10: /* Swap server */
        case 0x1c: /* Broadcast address */
        case 0x20: /* Router sollicitation address */
        case 0x29: /* Network information servers */
        case 0x2a: /* Network time protocol servers */
        case 0x2c: /* NetBIOS over TCP/IP name server */
        case 0x2d: /* NetBIOS over TCP/IP datagram distribution server */
        case 0x30: /* X window system font server */
        case 0x31: /* X window system display manager */
        case 0x32: /* Requested IP address */
        case 0x36: /* DHCP server ID */
        case 0x41: /* Network information service+ servers */
        case 0x44: /* Mobile IP home agent */
        case 0x45: /* SMTP server */
        case 0x46: /* POP3 server */
        case 0x47: /* NNTP server */
        case 0x48: /* WWW server */
        case 0x49: /* Finger server */
        case 0x4a: /* IRC server */
        case 0x4b: /* StreetTalk server */
        case 0x4c: /* STDA server */
        case 0x55: /* NDS servers */
        case 0x59: /* BMCS controller IP addresses */
        case 0x5c: /* Associated IPs */
        case 0x76: /* Subnet selection */
            dhcp_dump_ipv4s(buffer, offset, command_length);
            break;

        case 0xc:  /* Hostname */
        case 0xe:  /* Merit dump file */
        case 0xf:  /* Domain name */
        case 0x11: /* Root path */
        case 0x12: /* Extensions path */
        case 0x28: /* Network information service domain */
        case 0x38: /* Message */
        case 0x3e: /* Netware/IP domain name */
        case 0x40: /* Network information service+ domain */
        case 0x42: /* TFTP server name */
        case 0x43: /* Bootfile name */
        case 0x62: /* User authentication protocol */
        case 0x64: /* PCode */
        case 0x65: /* TCode */
        case 0x72: /* Captive portal */
            for (int i = 0; i < command_length; ++i)
            {
                printf("%c", data[offset + i]);
            }
            break;

        case 0x2:  /* Time offset */
        case 0xd:  /* Boot file size */
        case 0x18: /* Path MTU aging timeout option */
        case 0x23: /* ARP cache timeout */
        case 0x26: /* TCP keepalive interval */
        case 0x33: /* Address time */
        case 0x3a: /* Renewal time */
        case 0x3b: /* Rebinding time */
        case 0x5b: /* Client last transaction time */
        case 0x6c: /* IPv6-only preferred */
            if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("%u", be32toh(read_u32_unaligned(&data[offset])));
            break;

        case 0x13: /* IP forwarding */
        case 0x14: /* Non local source routing */
        case 0x17: /* Default IP TTL */
        case 0x1b: /* All subnets are local */
        case 0x1d: /* Perform mask discovery */
        case 0x1e: /* Mask supplier */
        case 0x1f: /* Perform router discovery */
        case 0x22: /* Trailer encapsulation */
        case 0x24: /* Ethernet encapsulation */
        case 0x25: /* TCP default TTL */
        case 0x27: /* TCP keepalive garbage */
        case 0x34: /* Option overload */
        case 0x50: /* Rapid commit */
        case 0x74: /* Auto configure */
            if (offset >= buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("%u", data[offset]);
            break;

        case 0x35: /* Message type */
            if (offset >= buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("%s", dhcp_get_message_type(data[offset]));
            break;

        case 0x37: /* PRL */
            dhcp_dump_crl(buffer, offset, command_length);
            break;

        case 0x4e: /* SLP directory agent */
            if (offset >= buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            dhcp_dump_ipv4s(buffer, offset + 1, command_length - 1);
            printf("\n%-45s = %u", "No multicast discovery", data[offset]);
            break;

        case 0x16: /* Maximum datagram reassembly size */
        case 0x1a: /* Interface MTU option */
        case 0x39: /* Maximum message size */
            if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("%u", be16toh(read_u16_unaligned(&data[offset])));
            break;

        case 0x3d: /* Client identifier */
            printf("%s", dhcp_get_client_id(buffer, offset));
            break;

        case 0x51: /* Client FQDN */
            dhcp_dump_client_fqdn(buffer, offset, command_length);
            break;

        case 0x52: /* Relay agent information */
            dhcp_dump_relay_agent_information(buffer, offset, command_length);
            break;

        case 0x53: /* iSNS */
            dhcp_dump_iSNS(buffer, offset, command_length);
            break;

        case 0x5a: /* Authentication */
            dhcp_dump_auth(buffer, offset, command_length);
            break;

        case 0x5d: /* Client system architecture type */
            dhcp_dump_client_system_arch_type(buffer, offset);
            break;

        case 0x5e: /* Client network interface identifier */
            if (offset + 2 >= buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("Type -> %u, Revision -> %u.%u", data[offset], data[offset + 1], data[offset + 2]);
            break;

        case 0x61: /* Client machine identifier */
            dhcp_dump_client_machine_identifier(buffer, offset);
            break;

        case 0x6d: /* 4o6 softwire source */
            dhcp_dump_4o6_softwire_source(buffer, offset);
            break;

        case 0x75: /* Name service search */
            dhcp_dump_nss(buffer, offset, command_length);
            break;

        case 0x78: /* SIP domain list */
            dhcp_dump_sip_server(buffer, offset, command_length);
            break;

        case 0x79: /* Classless route */
            dhcp_dump_classless_route(buffer, offset, command_length);
            break;

        case 0x7a: /* CableLabs client configuration */
            dhcp_dump_cablelabs_client_configuration(buffer, offset, command_length);
            break;

        case 0x7b: /* Geoconf */
            dhcp_dump_geo(buffer, offset, false);
            break;

        case 0x7c: /* Vendor identifying vendor class */
        case 0x7d: /* Vendor identifying vendor-specific information */
            dhcp_dump_vendor(buffer, offset, command_length);
            break;

        case 0x90: /* Geoconf */
            dhcp_dump_geo(buffer, offset, false);
            break;

        case 0x15: /* Policy filter */
        case 0x19: /* Path MTU plateau table option */
        case 0x21: /* Static route */
        case 0x2e: /* NetBIOS over TCP/IP node type (1Byte) */
        case 0x2f: /* NetBIOS over TCP/IP scope */
        case 0x3c: /* Class ID */
        case 0x3f: /* Netware/IP information */
        case 0x4d: /* User class */
        case 0x4f: /* SLP service scope */
        case 0x56: /* NDS tree name */
        case 0x57: /* NDS context */
        case 0x58: /* BMCS DHCPv4 / v6 domain name list */
        case 0x63: /* Civil location */
        case 0x77: /* Domain search */
            printf("Unimplemented");
            break;

        default:
            for (int i = 0; i < command_length; ++i)
            {
                printf("%x", data[offset + i]);
            }
            break;
    }

    printf("\n");
}

static void dhcp_dump_options(const struct ob_protocol* buffer)
{
    const uint8_t* hdr = buffer->hdr;

    if (buffer->verbosity_level == OB_VERBOSITY_LEVEL_HIGH)
    {
        printf("--- BEGIN DHCP MESSAGE ---\n");
    }
    else
    {
        printf("DHCP => Options : ");
    }

    for (int i = 0; i < buffer->length;)
    {
        uint8_t command = hdr[i];
        uint8_t length;

        if (buffer->verbosity_level == OB_VERBOSITY_LEVEL_MEDIUM)
        {
            printf("%u", command);
        }

        /**
         * End
         */
        if (command == 0xFF)
        {
            break;
        }

        if (buffer->verbosity_level == OB_VERBOSITY_LEVEL_MEDIUM)
        {
            printf(", ");
        }

        /**
         * Pad
         */
        if (command == 0)
        {
            i += 1;
            continue;
        }

        if (i + 1 >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        length = hdr[i + 1];

        if (buffer->verbosity_level == OB_VERBOSITY_LEVEL_HIGH)
        {
            dhcp_dump_command(buffer, i + 2, command, length);
        }

        i += length + 2;
    }

    printf("\n");
}

void dhcp_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> DHCP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            dhcp_dump_options(buffer);
            break;
    }
}
