#include <stdio.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/bytes.h"
#include "application/tls.h"
#include "generic/protocol.h"

/**
 * Note : it is theoretically possible to decrypt TLS traffic using session keys
 * Wireshark is able to do it, but I could not find information on how they do it
 * 
 * Get session keys using the SSLKEYLOGFILE environment variable
 */

static const char* tls_get_content_type(uint8_t ContentType)
{
    switch (ContentType)
    {
        case 0x14:
            return "Change Cipher Spec";

        case 0x15:
            return "Alert";

        case 0x16:
            return "Handshake";

        case 0x17:
            return "Application Data";

        case 0x18:
            return "Heartbeat";

        case 0x19:
            return "TLS 1.2 Cid";

        case 0x20:
            return "ACK";

        case 0x21:
            return "Return routability check";

        default:
            return "Unknown";
    }
}

static const char* tls_get_version(uint16_t Version)
{
    switch (Version)
    {
        case 0x304:
            return "TLS 1.3";

        case 0x303:
            return "TLS 1.2";

        case 0x302:
            return "TLS 1.1";

        case 0x301:
            return "TLS 1.0";

        case 0x300:
            return "SSL 3.0";

        default:
            return "Unknown";
    }
}

static void tls_dump_v3(const struct ob_protocol* buffer, const struct tls_header* th)
{
    printf("--- BEGIN TLS BUFFER ---\n");

    printf("%-45s = 0x%x (%s)\n", "Content Type", th->ContentType, tls_get_content_type(th->ContentType));
    printf("%-45s = 0x%x (%s)\n", "Version", th->LegacyVersion, tls_get_version(th->LegacyVersion));
    printf("%-45s = 0x%x\n", "Length", th->Length);

    printf("%-45s = ", "Raw data");
    for (int i = 5; i < buffer->length; ++i)
    {
        printf("%x ", ((const uint8_t*) buffer->hdr)[i]);
    }
    printf("\n");
}

static void tls_dump_v2(const struct tls_header* th)
{
    printf("TLS => ");

    printf("Content Type : %s, ", tls_get_content_type(th->ContentType));
    printf("Version : %s\n", tls_get_version(th->LegacyVersion));
}

void tls_dump(struct ob_protocol* buffer)
{
    struct tls_header th;

    if ((ssize_t) sizeof(struct tls_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&th, buffer->hdr, sizeof(struct tls_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> TLS ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            tls_dump_v2(&th);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            tls_dump_v3(buffer, &th);
            break;
    }
}
