#include <setjmp.h>
#include <stdio.h>
#include <endian.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "link/ppp.h"
#include "network/ip4.h"
#include "generic/binary.h"
#include "generic/protocol.h"

static const char* ppp_control_code[] = {
    "Unknown",
    "Configure request",
    "Configure ack",
    "Configure nak",
    "Configure reject",
    "Terminate request",
    "Terminate ack",
    "Code reject",
    "Protocol reject",
    "Echo request",
    "Echo reply",
    "Discard request"
};

static const char* ppp_link_control_option_type[] = {
    "Unknown",
    "Maximum receive unit",
    "Async control character map",
    "Authentication protocol",
    "Quality protocol",
    "Magic number",
    "Reserved",
    "Protocol field compression",
    "Address and control field compression"
};

static const char* ppp_internet_protocol_control_option_type[] = {
    "Unknown",
    "IP addresses",
    "IP compression protocol",
    "IP address",
    "Mobile IPv4",
    [129]="Primary DNS server address",
    "Primary NBNS server address",
    "Secondary DNS server address",
    "Secondary NBNS server address"
};

static const char* ppp_control_get_code(uint8_t Code)
{
    if (Code >= sizeof(ppp_control_code) / sizeof(const char*))
    {
        return "Unknown";
    }

    return ppp_control_code[Code];
}

static void ppp_encapsulation_cast(struct ob_protocol* buffer, uint16_t proto)
{
    switch (proto)
    {
        case 0x21:
            buffer->dump = ipv4_dump;
            break;

        default:
            buffer->dump = binary_dump;
            break;
    }
}

static const char* ppp_encapsulation_get_protocol(uint16_t proto)
{
    switch (proto)
    {
        case 0x21:
            return "Internet Protocol";

        case 0x23:
            return "OSI Network Layer";

        case 0x25:
            return "Xerox NS IDP";

        case 0x27:
            return "DECnet Phase IV";

        case 0x29:
            return "Appletalk";

        case 0x2B:
            return "Novell IPX";

        case 0x2D:
            return "Van Jacobson Compressed TCP/IP";

        case 0x2F:
            return "Van Jacobson Uncompressed TCP/IP";

        case 0x31:
            return "Bridging PDU";

        case 0x33:
            return "Stream Protocol (ST-II)";

        case 0x35:
            return "Banyan Vines";

        case 0x201:
            return "802.1d Hello Packets";

        case 0x231:
            return "Luxcom";

        case 0x233:
            return "Sigma Network Systems";

        case 0x8021:
            return "Internet Protocol Control Protocol";

        case 0x8023:
            return "OSI Network Layer Control Protocol";

        case 0x8025:
            return "Xerox NS IDP Control Protocol";

        case 0x8027:
            return "DECnet Phase IV Control Protocol";

        case 0x8029:
            return "Appletalk Control Protocol";

        case 0x802B:
            return "Novell IPX Control Protocol";

        case 0x8031:
            return "Bridging NCP";

        case 0x8033:
            return "Stream Protocol Control Protocol";

        case 0x8035:
            return "Banyan Vines Control Protocol";

        case 0xC021:
            return "Link Control Protocol";

        case 0xC023:
            return "Password Authentication Protocol";

        case 0xC025:
            return "Link Quality Report";

        case 0xC223:
            return "Challenge Handshake Authentication Protocol";

        default:
            return "Unknown / Reserved";
    }
}

static const char* ppp_control_get_option_type(bool lcp, uint8_t Type)
{
    if (lcp)
    {
        if (Type >= sizeof(ppp_link_control_option_type) / sizeof(const char*))
        {
            return "Unknown";
        }

        return ppp_link_control_option_type[Type];
    }
    else
    {
        if (Type >= sizeof(ppp_internet_protocol_control_option_type) / sizeof(const char*))
        {
            return "Unknown";
        }

        return ppp_internet_protocol_control_option_type[Type];
    }
}

static void ppp_encapsulation_dump_v3(const ppp_header* hdr)
{
    printf("--- BEGIN PPP MESSAGE ---\n");

    printf("%-45s = 0x%x (%s)\n", "Protocol", be16toh(*hdr), ppp_encapsulation_get_protocol(be16toh(*hdr)));
}

static void ppp_encapsulation_dump_v2(const ppp_header* hdr)
{
    printf("PPP => ");

    printf("Protocol : %s\n", ppp_encapsulation_get_protocol(be16toh(*hdr)));
}

static void ppp_control_dump_options(bool lcp, struct ppp_link_control_header* hdr, struct ob_protocol* buffer)
{
    ssize_t data_length = (ssize_t) be16toh(hdr->Length) - (ssize_t) sizeof(struct ppp_link_control_header);;
    uint8_t* bytes = &((uint8_t*) buffer->hdr)[sizeof(struct ppp_link_control_header)];

    struct ppp_link_control_option po;

    while (data_length > 0)
    {
        if (data_length < (ssize_t) sizeof(struct ppp_link_control_option))
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        memcpy(&po, bytes, sizeof(struct ppp_link_control_option));
        if (po.Length > data_length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        printf("--- BEGIN PPP LINK CONTROL OPTION ---\n");

        printf("%-45s = 0x%x (%s)\n", "Type", po.Type, ppp_control_get_option_type(lcp, po.Type));
        printf("%-45s = %u\n", "Length", po.Length);
        printf("%-45s = ", "Data");

        for (uint8_t i = 0; i < po.Length - sizeof(struct ppp_link_control_option); ++i)
        {
            printf("%x ", bytes[sizeof(struct ppp_link_control_option) + i]);
        }
        printf("\n");

        data_length -= po.Length;
        bytes = &bytes[po.Length];
    }
}

static void ppp_control_dump_v3(bool lcp, struct ppp_link_control_header* hdr, struct ob_protocol* buffer)
{
    ssize_t data_length = (ssize_t) be16toh(hdr->Length) - (ssize_t) sizeof(struct ppp_link_control_header);;
    uint8_t* bytes = &((uint8_t*) buffer->hdr)[sizeof(struct ppp_link_control_header)];

    if (lcp)
    {
        printf("--- BEGIN PPP LINK CONTROL MESSAGE ---\n");
    }
    else
    {
        printf("--- BEGIN PPP INTERNET PROTOCOL CONTROL MESSAGE ---\n");
    }

    printf("%-45s = 0x%x (%s)\n", "Code", hdr->Code, ppp_control_get_code(hdr->Code));
    printf("%-45s = 0x%x\n", "Identifier", hdr->Identifier);
    printf("%-45s = %u\n", "Length", be16toh(hdr->Length));

    switch (hdr->Code)
    {
        case 1:
        case 2:
        case 3:
        case 4:
            ppp_control_dump_options(lcp, hdr, buffer);
            return;

        // TODO: More things to dump : https://www.rfc-editor.org/rfc/rfc1548.html

        default:
            break;
    }

    printf("%-45s = ", "Data");
    for (ssize_t i = 0; i < data_length; ++i)
    {
        printf("%x ", bytes[i]);
    }
    printf("\n");
}

static void ppp_control_dump_v2(bool lcp, struct ppp_link_control_header* hdr)
{
    if (lcp)
    {
        printf("PPP Link Control => ");
    }
    else
    {
        printf("PPP Internet Protocol Control => ");
    }

    printf("Code : %s, ", ppp_control_get_code(hdr->Code));
    printf("Identifier : 0x%x\n", hdr->Identifier);
    printf("Length : %u\n", be16toh(hdr->Identifier));
}

void ppp_link_control_protocol_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct ppp_link_control_header ph;

    if ((ssize_t) sizeof(struct ppp_link_control_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ph, buffer->hdr, sizeof(struct ppp_link_control_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> PPP Link control ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ppp_control_dump_v2(true, &ph);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ppp_control_dump_v3(true, &ph, buffer);
            break;
    }

    buffer->length -= (ssize_t) sizeof(struct ppp_link_control_header);
    buffer->hdr = &hdr[sizeof(struct ppp_link_control_header)];

    buffer->dump = NULL;

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }
}

void ppp_internet_protocol_control_protocol_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct ppp_link_control_header ph;

    if ((ssize_t) sizeof(struct ppp_link_control_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ph, buffer->hdr, sizeof(struct ppp_link_control_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> PPP Internet protocol control ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ppp_control_dump_v2(false, &ph);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ppp_control_dump_v3(false, &ph, buffer);
            break;
    }

    buffer->length -= (ssize_t) sizeof(struct ppp_link_control_header);
    buffer->hdr = &hdr[sizeof(struct ppp_link_control_header)];

    buffer->dump = NULL;

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }
}

void ppp_encapsulation_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    ppp_header ph;

    if ((ssize_t) sizeof(ppp_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ph, buffer->hdr, sizeof(ppp_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> PPP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ppp_encapsulation_dump_v2(&ph);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ppp_encapsulation_dump_v3(&ph);
            break;
    }

    buffer->length -= (ssize_t) sizeof(ppp_header);
    buffer->hdr = &hdr[sizeof(ppp_header)];

    ppp_encapsulation_cast(buffer, be16toh(ph));

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }
}
