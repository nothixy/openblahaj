#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip4.h"
#include "network/ip6.h"
#include "generic/bytes.h"
#include "application/dns.h"
#include "generic/protocol.h"

static const char* dns_get_qtype(uint16_t qtype)
{
    switch (qtype)
    {
        case 1:
            return "A";

        case 2:
            return "NS";

        case 5:
            return "CNAME";

        case 6:
            return "SOA";

        case 12:
            return "PTR";

        case 13:
            return "HINFO";

        case 15:
            return "MX";

        case 16:
            return "TXT";

        case 17:
            return "RP";

        case 18:
            return "AFSDB";

        case 24:
            return "SIG";

        case 25:
            return "KEY";

        case 28:
            return "AAAA";

        case 29:
            return "LOC";

        case 33:
            return "SRV";

        case 35:
            return "NAPTR";

        case 36:
            return "KX";

        case 37:
            return "CERT";

        case 39:
            return "DNAME";

        case 41:
            return "OPT";

        case 42:
            return "APL";

        case 43:
            return "DS";

        case 44:
            return "SSHFP";

        case 45:
            return "IPSECKEY";

        case 46:
            return "RRSIG";

        case 47:
            return "NSEC";

        case 48:
            return "DNSKEY";

        case 49:
            return "DHCID";

        case 50:
            return "NSEC3";

        case 51:
            return "NSEC3PARAM";

        case 52:
            return "TLSA";

        case 53:
            return "SMIMEA";

        case 55:
            return "HIP";

        case 59:
            return "CDS";

        case 60:
            return "CDNSKEY";

        case 61:
            return "OPENPGPKEY";

        case 62:
            return "CSYNC";

        case 63:
            return "ZONEMD";

        case 64:
            return "SVCB";

        case 65:
            return "HTTPS";

        case 108:
            return "EUI48";

        case 109:
            return "EUI64";

        case 249:
            return "TKEY";

        case 250:
            return "TSIG";

        case 256:
            return "URI";

        case 257:
            return "CAA";

        case 32768:
            return "TA";

        case 32769:
            return "DLV";

        default:
            return "Unknown";
    }
}

static const char* dns_get_qclass(uint16_t qclass)
{
    switch (qclass)
    {
        case 0x1:
            return "Internet (IN)";

        case 0x3:
            return "Chaos (CH)";

        case 0x4:
            return "Hesiod (HS)";

        case 0xFE:
            return "None";

        case 0xFF:
            return "Any";

        default:
            return "Unknown";
    }
}

static const char* dns_get_rcode(uint8_t rcode)
{
    switch (rcode)
    {
        case 0:
            return "NoError";

        case 1:
            return "FormErr";

        case 2:
            return "ServFail";

        case 3:
            return "NXDomain";

        case 4:
            return "NotImp";

        case 5:
            return "Refused";

        case 6:
            return "YXDomain";

        case 7:
            return "YXRRSet";

        case 8:
            return "NXRRSet";

        case 9:
            return "NotAuth";

        case 10:
            return "NotZone";

        case 11:
            return "DSOTYPENI";

        case 16:
            return "BADVERS | BADSIG";

        case 17:
            return "BADKEY";

        case 18:
            return "BADTIME";

        case 19:
            return "BADMODE";

        case 20:
            return "BADNAME";

        case 21:
            return "BADALG";

        case 22:
            return "BADTRUNC";

        case 23:
            return "BADCOOKIE";

        default:
            return "Unknown";
    }
}

/**
 * @brief Dump a domain name in a buffer from an offset with a separator
 * @param buffer Pointer to an ob_protocol structure containing the buffer
 * @param offset Offset in the buffer
 * @param separator Separate parts of a domain with a separator
 * @param add_pad_byte Pointer to an initially true boolean that becomes false
 * @param record_length Pointer to an int that will contain the record length
 * @param disallow_ptr Pointer to a false boolean to disallow pointer compression
 * if we don't need to shift one byte from the buffer after or NULL
 * @return Offset in the buffer after the domain name
 */
static ssize_t dns_dump_name_at_offset_limited(const struct ob_protocol* buffer, ssize_t offset, char separator, bool* add_pad_byte, int* record_length, bool* disallow_ptr)
{
    const uint8_t* data = buffer->hdr;
    bool no_dot_first_run;
    uint8_t length;

    if (offset >= buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    if (data[offset] == 0)
    {
        return offset + 1;
    }
    no_dot_first_run = true;
    while ((length = data[offset]) != 0)
    {
        if (!no_dot_first_run)
        {
            printf("%c", separator);
        }
        /**
         * Label compression, as seen in RFC1035
         */
        if ((length & 0xC0) == 0xC0)
        {
            uint16_t new_offset;
            if (*disallow_ptr)
            {
                longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
            }
            *disallow_ptr = true;
            new_offset = length & (uint8_t) ~(0xC0);
            if (offset + 1 >= buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            new_offset <<= 8;
            new_offset |= data[offset + 1];
            (void) dns_dump_name_at_offset_limited(buffer, new_offset, separator, add_pad_byte, record_length, disallow_ptr);
            if (add_pad_byte != NULL)
            {
                *add_pad_byte = false;
            }
            return offset + 2;
        }

        *disallow_ptr = false;

        /**
         * DNS records are limited to 255 characters
         */
        (*record_length) += length + 1;
        if (*record_length > 0xFF)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }

        /**
         * Normally, a byte starting with 0x would be used in RFC6891 but it is
         * not yet implemented
         */
        no_dot_first_run = false;
        for (int j = 1; j <= length; ++j)
        {
            if (offset + j >= buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("%c", data[offset + j]);
        }
        offset += length + 1;
        if (offset >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
    }

    return offset;
}

static ssize_t dns_dump_name_at_offset(const struct ob_protocol* buffer, ssize_t offset, char separator, bool* add_pad_byte)
{
    int record_length = 0;
    bool disallow_ptr = false;
    return dns_dump_name_at_offset_limited(buffer, offset, separator, add_pad_byte, &record_length, &disallow_ptr);
}

static void dns_dump_ipv4hint(const struct ob_protocol* buffer, ssize_t offset, ssize_t new_offset, uint16_t https_length)
{
    const uint8_t* data = buffer->hdr;
    printf("ipv4hint=");
    for (uint16_t i = 0; i < https_length / 4; ++i)
    {
        char ipv4_addr[INET_ADDRSTRLEN] = {0};
        if (offset + new_offset + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        inet_ntop(AF_INET, &data[offset + new_offset], ipv4_addr, INET_ADDRSTRLEN * sizeof(char));
        printf("%s", ipv4_addr);
        if (i != https_length / 4 - 1)
        {
            printf(",");
        }
    }
}

static void dns_dump_ipv6hint(const struct ob_protocol* buffer, ssize_t offset, ssize_t new_offset, uint16_t https_length)
{
    const uint8_t* data = buffer->hdr;
    printf("ipv6hint=");
    for (uint16_t i = 0; i < https_length / 16; ++i)
    {
        char ipv6_addr[INET6_ADDRSTRLEN] = {0};
        if (offset + new_offset + (ssize_t) (8 * sizeof(uint16_t)) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        inet_ntop(AF_INET6, &data[offset + new_offset], ipv6_addr, INET6_ADDRSTRLEN * sizeof(char));
        printf("%s", ipv6_addr);
        if (i != https_length / 16 - 1)
        {
            printf(",");
        }
    }
}

static void dns_dump_https_by_type(const struct ob_protocol* buffer, ssize_t offset, ssize_t new_offset, uint16_t https_length, uint16_t https_type)
{
    const uint8_t* data = buffer->hdr;

    switch (https_type)
    {
        case 0: /* Mandatory */
            break;

        case 1: /* alpn */
            printf("alpn=\"");
            dns_dump_name_at_offset(buffer, offset + new_offset, '.', NULL);
            printf("\"");
            break;

        case 2: /* no-default-alpn */
            printf("no-default-alpn=\"");
            dns_dump_name_at_offset(buffer, offset + new_offset, '.', NULL);
            printf("\"");
            break;

        case 3: /* port */
            if (offset + new_offset + (ssize_t) sizeof(uint16_t) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            printf("port=\"%u\"", be16toh(read_u16_unaligned(&data[offset + new_offset])));
            break;

        case 4: /* ipv4hint */
            dns_dump_ipv4hint(buffer, offset, new_offset, https_length);
            break;

        case 6: /* ipv6hint */
            dns_dump_ipv6hint(buffer, offset, new_offset, https_length);
            break;

        default:
            break;
    }
}

/**
 * @brief Dump an HTTPS DNS record from offset in data buffer
 * @param buffer Pointer to an ob_protocol structure containing the buffer
 * @param record_length Length of the DNS record
 * @param offset Offset 
 */
static void dns_dump_https(const struct ob_protocol* buffer, uint16_t record_length, ssize_t offset)
{
    const uint8_t* data = buffer->hdr;
    uint16_t https_type;
    uint16_t https_length;
    ssize_t temp_new_offset;
    ssize_t new_offset = 0;
    uint16_t priority;

    if (offset + new_offset + (ssize_t) sizeof(uint16_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    priority = be16toh(read_u16_unaligned(&data[offset + new_offset]));
    printf("0x%x ", priority);
    new_offset += 2;
    temp_new_offset = dns_dump_name_at_offset(buffer, offset + new_offset, ',', NULL) - offset;
    if (temp_new_offset - new_offset == 1)
    {
        printf(".");
    }
    new_offset = temp_new_offset;
    printf(" ");
    while (new_offset < record_length)
    {
        if (offset + new_offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        https_type = be16toh(read_u16_unaligned(&data[offset + new_offset]));
        new_offset += 2;
        if (offset + new_offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        https_length = be16toh(read_u16_unaligned(&data[offset + new_offset]));
        new_offset += 2;

        dns_dump_https_by_type(buffer, offset, new_offset, https_length, https_type);

        new_offset += https_length;
        if (new_offset < record_length)
        {
            printf(" ");
        }
    }
    printf("\n");
}

static void dns_dump_soa(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* data = buffer->hdr;
    ssize_t new_offset = dns_dump_name_at_offset(buffer, offset, '.', NULL) - offset;
    printf(". ");
    new_offset = dns_dump_name_at_offset(buffer, offset + new_offset, '.', NULL) - offset;
    printf(". ");
    for (int i = 0; i < 5; ++i)
    {
        uint32_t value;

        if (offset + new_offset + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        value = be32toh(read_u32_unaligned(&data[offset + new_offset]));
        new_offset += 4;
        printf("%u ", value);
    }
}

static void dns_dump_rr(const struct ob_protocol* buffer, uint16_t type, uint16_t record_length, ssize_t offset)
{
    const uint8_t* data = buffer->hdr;

    char ipv4_addr[INET_ADDRSTRLEN] = {0};
    char ipv6_addr[INET6_ADDRSTRLEN] = {0};

    switch (type)
    {
        case 1: /* A */
            if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            inet_ntop(AF_INET, &data[offset], ipv4_addr, INET_ADDRSTRLEN * sizeof(char));
            printf("%s", ipv4_addr);
            break;

        case 5: /* CNAME */
            dns_dump_name_at_offset(buffer, offset, '.', NULL);
            break;

        case 6: /* SOA */
            dns_dump_soa(buffer, offset);
            break;

        case 28: /* AAAA */
            if (offset + (ssize_t) (8 * sizeof(uint16_t)) > buffer->length)
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            inet_ntop(AF_INET6, &data[offset], ipv6_addr, INET6_ADDRSTRLEN * sizeof(char));
            printf("%s", ipv6_addr);
            break;

        case 65: /* HTTPS */
            dns_dump_https(buffer, record_length, offset);
            break;

        default:
            break;
    }
}

static ssize_t dns_dump_answer(const struct ob_protocol* buffer, uint16_t i, ssize_t offset)
{
    const uint8_t* data_buffer = buffer->hdr;
    char RESPONSE[] = "Response";
    char AUTHORITY[] = "Authority";
    char ADDITIONAL[] = "Additional";

    char* type;
    const char* pad;
    uint16_t DnsQueryType;
    const char* DnsQueryTypeName;
    bool add_pad_byte = true;

    struct dns_header dh;

    memcpy(&dh, buffer->hdr, sizeof(struct dns_header));

    if (i < be16toh(dh.NumberAnswers))
    {
        printf("--- BEGIN DNS ANSWER RR ---\n");

        type = RESPONSE;
        pad = "  ";
    }
    else if (i < be16toh(dh.NumberAnswers) + be16toh(dh.NumberAuthorityRR))
    {
        printf("--- BEGIN DNS AUTHORITY RR ---\n");

        type = AUTHORITY;
        pad = " ";
    }
    else
    {
        printf("--- BEGIN DNS ADDITIONAL RR ---\n");

        type = ADDITIONAL;
        pad = "";
    }

    printf("%s%-35s%s = ", type, " Domain Name", pad);

    /**
     * If the domain name contains a reference, this reference will end with a 0 byte
     * If it is not the case, we need to take into account this 0 byte
     */
    offset = dns_dump_name_at_offset(buffer, offset, '.', &add_pad_byte);
    if (add_pad_byte)
    {
        offset += 1;
    }
    printf(".\n");

    if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    DnsQueryType = be16toh(read_u16_unaligned(&data_buffer[offset]));
    DnsQueryTypeName = dns_get_qtype(DnsQueryType);

    printf("%s%-35s%s = 0x%x (%s)\n", type, " Response Type", pad, DnsQueryType, DnsQueryTypeName);
    offset += 2;

    if (DnsQueryType != 0x29)
    {
        uint32_t DnsTTL;
        uint16_t DnsQueryClass;
        uint16_t DnsRDLength;
        const char* DnsQueryClassName;

        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        DnsQueryClass = be16toh(read_u16_unaligned(&data_buffer[offset]));
        DnsQueryClassName = dns_get_qclass(DnsQueryClass);

        printf("%s%-35s%s = 0x%x (%s)\n", type, " Response Class", pad, DnsQueryClass, DnsQueryClassName);

        offset += 2;

        if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        DnsTTL = be32toh(read_u32_unaligned(&data_buffer[offset]));

        printf("%s%-35s%s = %u\n", type, " Time To Live", pad, DnsTTL);

        offset += 4;

        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        DnsRDLength = be16toh(read_u16_unaligned(&data_buffer[offset]));

        printf("%s%-35s%s = %u\n", type, " RDATA Length", pad, DnsRDLength);

        offset += 2;

        printf("%s%-35s%s = ", type, " RDATA", pad);
        dns_dump_rr(buffer, DnsQueryType, DnsRDLength, offset);
        printf("\n");

        offset += DnsRDLength;
    }
    else
    {
        uint8_t ExtendedRCode;
        uint8_t Version;
        uint16_t PayloadSize;
        uint16_t Flags;

        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        PayloadSize = be16toh(read_u16_unaligned(&data_buffer[offset]));
        printf("%s%-35s%s = %u\n", type, " UDP Payload Size", pad, PayloadSize);

        offset += 2;

        if (offset >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        ExtendedRCode = data_buffer[offset];
        printf("%s%-35s%s = %u\n", type, " Extended RCode", pad, ExtendedRCode);
        offset += 1;

        if (offset >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        Version = data_buffer[offset];
        printf("%s%-35s%s = %u\n", type, " Version", pad, Version);
        offset += 1;

        if (offset >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        Flags = data_buffer[offset];
        printf("%s%-35s%s = %u\n", type, " DNSSEC OK", pad, (Flags >> 31) & 1);
        printf("%s%-35s%s = %u\n", type, " Z", pad, Flags ^ (1U << 31));
        offset += 2;
    }

    return offset;
}

static void dns_dump_v3(const struct ob_protocol* buffer, struct dns_header* dh, ssize_t offset)
{
    uint16_t response_count;
    const uint8_t* hdr = buffer->hdr;

    printf("--- BEGIN DNS MESSAGE ---\n");

    printf("%-45s = %u\n", "Transaction ID", be16toh(dh->TransactionID));
    printf("%-45s = %u (%s)\n", "Query / Reply", dh->QR, dh->QR ? "Reply" : "Query");
    printf("%-45s = %u (%s)\n", "OPCODE", dh->OPCODE, dh->OPCODE ? (dh->OPCODE == 2 ? "Status" : "IQuery") : "Query");
    printf("%-45s = %u\n", "Authoritative", dh->AA);
    printf("%-45s = %u\n", "Truncated", dh->TC);
    printf("%-45s = %u\n", "Recursion desired", dh->RD);
    printf("%-45s = %u\n", "Recursion available", dh->RA);
    printf("%-45s = %u\n", "Zero", dh->Z);
    printf("%-45s = %u (%s)\n", "RCODE", dh->RCODE, dns_get_rcode(dh->RCODE));
    printf("%-45s = %u\n", "Number of questions", be16toh(dh->NumberQuestions));
    printf("%-45s = %u\n", "Number of answers", be16toh(dh->NumberAnswers));
    printf("%-45s = %u\n", "Number of authority RRs", be16toh(dh->NumberAuthorityRR));
    printf("%-45s = %u\n", "Number of additional RRs", be16toh(dh->NumberAdditionalRR));

    response_count = (uint16_t) (be16toh(dh->NumberAnswers) + be16toh(dh->NumberAuthorityRR) + be16toh(dh->NumberAdditionalRR));

    for (uint16_t i = 0; i < be16toh(dh->NumberQuestions); ++i)
    {
        uint16_t DnsQueryType;
        uint16_t DnsQueryClass;
        const char* DnsQueryClassName;
        const char* DnsQueryTypeName;
        bool add_pad_byte = true;

        printf("--- BEGIN DNS QUERY ---\n");
        printf("%-45s = ", "Query Domain Name");
        offset = dns_dump_name_at_offset(buffer, offset, '.', &add_pad_byte);
        printf("\n");

        if (add_pad_byte)
        {
            offset += 1;
        }

        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        DnsQueryType = be16toh(read_u16_unaligned(&hdr[offset]));
        DnsQueryTypeName = dns_get_qtype(DnsQueryType);

        printf("%-45s = 0x%x (%s)\n", "Query Type", DnsQueryType, DnsQueryTypeName);
        offset += 2;

        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        DnsQueryClass = be16toh(read_u16_unaligned(&hdr[offset]));
        DnsQueryClassName = dns_get_qclass(DnsQueryClass);

        printf("%-45s = 0x%x (%s)\n", "Query Class", DnsQueryClass, DnsQueryClassName);
        offset += 2;
    }

    for (uint16_t i = 0; i < response_count; ++i)
    {
        offset = dns_dump_answer(buffer, i, offset);
    }
}

static void dns_dump_v2(const struct ob_protocol* buffer, struct dns_header* dh, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;

    printf("DNS => ");
    printf("Query type : %s, ", dh->QR ? "Reply" : "Query");

    printf("[");
    for (uint16_t i = 0; i < be16toh(dh->NumberQuestions); ++i)
    {
        uint16_t DnsQueryType;
        const char* DnsQueryTypeName;

        printf("Domain : ");
        offset = dns_dump_name_at_offset(buffer, offset, '.', NULL);
        printf(", ");

        offset += 1;

        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        DnsQueryType = be16toh(read_u16_unaligned(&hdr[offset]));
        DnsQueryTypeName = dns_get_qtype(DnsQueryType);

        printf("Query type : %s", DnsQueryTypeName);
        offset += 4;

        if (i != be16toh(dh->NumberQuestions) - 1)
        {
            printf("; ");
        }
    }
    printf("]\n");
}

void dns_dump(struct ob_protocol* buffer)
{
    struct dns_header dh;

    if ((ssize_t) sizeof(struct dns_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&dh, buffer->hdr, sizeof(struct dns_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> DNS ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            dns_dump_v2(buffer, &dh, (ssize_t) sizeof(struct dns_header));
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            dns_dump_v3(buffer, &dh, (ssize_t) sizeof(struct dns_header));
            break;
    }
}
