#include "generic/time.h"
#include "network/ip4.h"
#include "network/ip6.h"
#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "generic/bytes.h"
#include "application/ntp.h"

#define TIMESTAMP_UNIX_FROM_NTP_0 2208988800

static const char* leap_indicator_type[] = {
    "No warning",
    "Last minute of month has 61s",
    "Last minute of month has 59s",
    "Unsynchronized"
};

static const char* mode[] = {
    "Reserved",
    "Symmetric active",
    "Symmetric passive",
    "Client",
    "Server",
    "Broadcast",
    "NTP control",
    "Reserved"
};

static const char* autokey_code[] = {
    "NOOP",
    "ASSOC",
    "CERT",
    "COOKIE",
    "AUTO",
    "LEAP",
    "SIGN",
    "IFF",
    "GQ",
    "MV",
};

static const char* ntp_get_stratum(uint8_t stratum)
{
    if (stratum > 16)
    {
        return "Reserved";
    }

    switch (stratum)
    {
        case 0:
            return "Unspecified";
        
        case 1:
            return "Primary";

        case 16:
            return "Unsynchronized";

        default:
            return "Secondary";
    }
}

static const char* ntp_get_autokey_code(uint8_t Code)
{
    if (Code > sizeof(autokey_code) / sizeof(const char*))
    {
        return "Unknown";
    }

    return autokey_code[Code];
}

static ssize_t ntp_dump_extensions_v3(struct ob_protocol* buffer)
{
    struct ntp_autokey_header nah;
    ssize_t remaining_length = buffer->length - (ssize_t) sizeof(struct ntp_header);
    ssize_t read = 0;
    uint8_t* hdr = buffer->hdr;
    struct timeval tv = {
        .tv_sec = 0,
        .tv_usec = 0
    };
    char timestamp_buf[150] = {0};

    hdr = &hdr[sizeof(struct ntp_header)]; 
    while (remaining_length > 22)
    {
        memcpy(&nah, hdr, sizeof(struct ntp_autokey_header));
        tv.tv_sec = nah.Timestamp;

        printf("--- BEGIN NTP EXTENSION ---\n");
        printf("%-45s = %u\n", "Response", nah.Response);
        printf("%-45s = %u\n", "Error", nah.Error);
        printf("%-45s = %u (%s)\n", "Code", nah.Code, ntp_get_autokey_code(nah.Code));
        printf("%-45s = %u\n", "Field type", nah.FieldType);
        printf("%-45s = %u\n", "Length", nah.Length);
        printf("%-45s = %u\n", "Association ID", nah.AssociationID);
        printf("%-45s = %s\n", "Timestamp", get_timestamp_utc(&tv, timestamp_buf, false));

        if (nah.Code == 1)
        {

        }
        else
        {
            tv.tv_sec = nah.FileStamp;
            printf("%-45s = %s\n", "Filestamp", get_timestamp_utc(&tv, timestamp_buf, false));
        }

        break;
    }

    return read;
}

static char* ntp_fraction_get_value(uint64_t Fraction, enum FRACTION_SIZE fs, char* buf)
{
    double sum = 0;
    switch (fs)
    {
        case FRACTION_SIZE_SHORT:
            sum = (double) (uint16_t) 0xFFFF;
            break;

        case FRACTION_SIZE_TIMESTAMP:
            sum = (double) (uint32_t) 0xFFFFFFFF;
            break;

        case FRACTION_SIZE_DATE:
            sum = (double) (uint64_t) 0xFFFFFFFFFFFFFFFF;
            break;
    }
    
    double f = (double) Fraction;
    double res =  f / sum;

    sprintf(buf, "%0.09lf", res);

    return &buf[2];
}

static void ntp_dump_reference_id(struct ob_protocol* buffer, struct ntp_header* nh)
{
    uint8_t ip_version = * (uint8_t*) buffer->pseudo_header;
    char ipv4[INET_ADDRSTRLEN] = {0};
    char host[NI_MAXHOST] = {0};

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = nh->ReferenceID
    };

    if (nh->Stratum <= 1)
    {
        if (nh->ReferenceID != 0)
        {
            printf("%-45s = %.4s\n", "Reference ID", (char*) &(nh->ReferenceID));
        }
        else
        {
            printf("%-45s = %s\n", "Reference ID", "NULL");
        }
    }
    else
    {
        switch (ip_version)
        {
            case 4:
                inet_ntop(AF_INET, &(nh->ReferenceID), ipv4, INET_ADDRSTRLEN * sizeof(char));
                if (buffer->display_hostnames && getnameinfo((struct sockaddr*) &addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0)
                {
                    printf("%-45s = %s \033[1m[%s]\033[22m\n", "Reference ID", ipv4, host);
                }
                else
                {
                    printf("%-45s = %s\n", "Reference ID", ipv4);
                }
                break;

            case 6:
                printf("%-45s = %u\n", "Reference ID", nh->ReferenceID);
                break;

            default:
                break;
        }
    }
}

static void ntp_dump_v3(struct ob_protocol* buffer, struct ntp_header* nh)
{
    char buf[20];

    char timestamp[150] = {0};

    struct timeval tv;
    tv.tv_usec = 0;

    // THIS IS ONLY FOR NTP V4
    // OTHER VERSIONS MAY (AND WILL) NOT WORK

    printf("--- BEGIN NTP MESSAGE ---\n");
    printf("%-45s = %u (%s)\n", "Leap indicator", nh->LI, leap_indicator_type[nh->LI]);
    printf("%-45s = %u\n", "Version", nh->VN);
    printf("%-45s = %u (%s)\n", "Mode", nh->Mode, mode[nh->Mode]);
    printf("%-45s = %u (%s)\n", "Stratum", nh->Stratum, ntp_get_stratum(nh->Stratum));
    printf("%-45s = %d (%.9lf seconds)\n", "Poll", nh->Poll, pow(2, nh->Poll));
    printf("%-45s = %d (%.9lf seconds)\n", "Precision", nh->Precision, pow(2, nh->Precision));
    printf("%-45s = %u.%s\n", "Root delay", nh->RootDelay.Seconds, ntp_fraction_get_value(be16toh(nh->RootDelay.Fraction), FRACTION_SIZE_SHORT, buf));
    printf("%-45s = %u.%s\n", "Root dispersion", nh->RootDispersion.Seconds, ntp_fraction_get_value(be16toh(nh->RootDispersion.Fraction), FRACTION_SIZE_SHORT, buf));

    ntp_dump_reference_id(buffer, nh);

    tv.tv_sec = be32toh(nh->ReferenceTimestamp.Seconds) - TIMESTAMP_UNIX_FROM_NTP_0;
    memset(timestamp, 0, 150 * sizeof(char));
    get_timestamp_utc(&tv, timestamp, false);
    printf("%-45s = %s.%s\n", "Reference timestamp", timestamp, ntp_fraction_get_value(be32toh(nh->ReferenceTimestamp.Fraction), FRACTION_SIZE_TIMESTAMP, buf));
    tv.tv_sec = be32toh(nh->OriginTimestamp.Seconds) - TIMESTAMP_UNIX_FROM_NTP_0;
    memset(timestamp, 0, 150 * sizeof(char));
    get_timestamp_utc(&tv, timestamp, false);
    printf("%-45s = %s.%s\n", "Origin timestamp", timestamp, ntp_fraction_get_value(be32toh(nh->OriginTimestamp.Fraction), FRACTION_SIZE_TIMESTAMP, buf));
    tv.tv_sec = be32toh(nh->ReceiveTimestamp.Seconds) - TIMESTAMP_UNIX_FROM_NTP_0;
    memset(timestamp, 0, 150 * sizeof(char));
    get_timestamp_utc(&tv, timestamp, false);
    printf("%-45s = %s.%s\n", "Receive timestamp", timestamp, ntp_fraction_get_value(be32toh(nh->ReceiveTimestamp.Fraction), FRACTION_SIZE_TIMESTAMP, buf));
    tv.tv_sec = be32toh(nh->TransmitTimestamp.Seconds) - TIMESTAMP_UNIX_FROM_NTP_0;
    memset(timestamp, 0, 150 * sizeof(char));
    get_timestamp_utc(&tv, timestamp, false);
    printf("%-45s = %s.%s\n", "Transmit timestamp", timestamp, ntp_fraction_get_value(be32toh(nh->TransmitTimestamp.Fraction), FRACTION_SIZE_TIMESTAMP, buf));

    ntp_dump_extensions_v3(buffer);
}

static void ntp_dump_v2(struct ntp_header* nh)
{
    printf("NTP => ");
    printf("Leap indicator : %s, ", leap_indicator_type[nh->LI]);
    printf("Version : %u, ", nh->VN);
    printf("Mode : %s, ", mode[nh->Mode]);
    printf("Stratum : %s, ", ntp_get_stratum(nh->Stratum));
    printf("Poll : %.9lf seconds, ", pow(2, nh->Poll));
    printf("Precision : %.9lf seconds, ", pow(2, nh->Precision));
}

void ntp_dump(struct ob_protocol* buffer)
{
    struct ntp_header nh;

    if ((ssize_t) sizeof(struct ntp_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&nh, buffer->hdr, sizeof(struct ntp_header));
    // (void) mqtt_decode_number(buffer, offsetof(struct mqtt_header, length), &packet_length);

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> MQTT ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ntp_dump_v2(&nh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ntp_dump_v3(buffer, &nh);
            break;
    }
}
