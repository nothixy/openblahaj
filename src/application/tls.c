#include <stdio.h>
#include <endian.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/bytes.h"
#include "filetypes/ber.h"
#include "generic/binary.h"
#include "application/tls.h"
#include "generic/protocol.h"

/**
 * Note : it is theoretically possible to decrypt TLS traffic using session keys
 * Wireshark is able to do it, but I could not find information on how they do it
 * 
 * Get session keys using the SSLKEYLOGFILE environment variable
 */

static const char* tls_get_msg_type(uint8_t MessageType)
{
    switch (MessageType)
    {
        case 1:
            return "Client Hello";

        case 2:
            return "Server Hello";

        case 4:
            return "New session ticket";

        case 5:
            return "End of early data";

        case 8:
            return "Encrypted extensions";

        case 11:
            return "Certificate";

        case 13:
            return "Certificate request";

        case 15:
            return "Certificate verify";

        case 20:
            return "Finished";

        case 24:
            return "Key update";

        case 254:
            return "Message hash";

        default:
            return "Unknown";
    }
}

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

static const char* tls_get_cipher_suite_1_3(uint16_t cipher)
{
    switch (cipher)
    {
        case 0x1301:
            return "TLS_AES_128_GCM_SHA256";

        case 0x1302:
            return "TLS_AES_256_GCM_SHA384";

        case 0x1303:
            return "TLS_CHACHA20_POLY1305_SHA256";

        case 0x1304:
            return "TLS_AES_128_CCM_SHA256";

        case 0x1305:
            return "TLS_AES_128_CCM_8_SHA256";

        default:
            return "Unknown";
    }
}

static const char* tls_get_cipher_suite(uint16_t version, uint16_t cipher)
{
    switch (version)
    {
        case 0x0303:
            return tls_get_cipher_suite_1_3(cipher);

        default:
            return "Unknown";
    }
}

static const char* tls_get_extension_name(uint16_t ExtensionType)
{
    switch (ExtensionType)
    {
        case 0: /* SERVER NAME */
            return "SERVER NAME";

        case 1: /* MAX FRAGMENT LENGTH */
            return "MAX FRAGMENT LENGTH";

        case 5: /* STATUS REQUEST */
            return "STATUS REQUEST";

        case 10: /* SUPPORTED GROUPS */
            return "SUPPORTED GROUPS";

        case 13: /* SIGNATURE ALGORITHMS */
            return "SIGNATURE ALGORITHMS";

        case 14: /* USE SRTP */
            return "USE SRTP";

        case 15: /* HEARTBEAT */
            return "HEARTBEAT";

        case 16: /* APPLICATION LAYER PROTOCOL NEGOCIATION */
            return "APPLICATION LAYER PROTOCOL NEGOCIATION";

        case 18: /* SIGNED CERTIFICATE TIMESTAMP */
            return "SIGNED CERTIFICATE TIMESTAMP";

        case 19: /* CLIENT CERTIFICATE TYPE */
            return "CLIENT CERTIFICATE TYPE";

        case 20: /* SERVER CERTIFICATE TYPE */
            return "SERVER CERTIFICATE TYPE";

        case 21: /* PADDING */
            return "PADDING";

        case 40: /* RESERVED */
            return "RESERVED";

        case 41: /* PRE-SHARED KEY */
            return "PRE-SHARED KEY";

        case 42: /* EARLY DATA */
            return "EARLY DATA";

        case 43: /* SUPPORTED VERSIONS */
            return "SUPPORTED VERSIONS";

        case 44: /* COOKIE */
            return "COOKIE";

        case 45: /* PSK KEY EXCHANGE MODES */
            return "PSK KEY EXCHANGE MODES";

        case 46: /* RESERVED */
            return "RESERVED";

        case 47: /* CERTIFICATE AUTHORITIES */
            return "CERTIFICATE AUTHORITIES";

        case 48: /* OID FILTERS */
            return "OID FILTERS";

        case 49: /* POST HANDSHAKE AUTH */
            return "POST HANDSHAKE AUTH";

        case 50: /* SIGNATURE ALGORITHMS CERT */
            return "SIGNATURE ALGORITHMS CERT";

        case 51: /* KEY SHARE */
            return "KEY SHARE";

        default:
            return "UNKNOWN";
    }
}

static ssize_t tls_dump_extension(struct ob_protocol* buffer, const uint8_t* hdr)
{
    uint16_t extension_type;
    uint16_t extension_length;
    ssize_t read_bytes = 0;
    memcpy(&extension_type, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);
    memcpy(&extension_length, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);

    printf("--- BEGIN TLS EXTENSION ---\n");
    printf("%-45s = %u (%s)\n", "Name", be16toh(extension_type), tls_get_extension_name(be16toh(extension_type)));
    printf("%-45s = %u\n", "Length", be16toh(extension_length));
    printf("%-45s = ", "Value");
    for (uint16_t i = 0; i < be16toh(extension_length); ++i)
    {
        printf("%02x", hdr[read_bytes + i]);
    }
    printf("\n");

    return read_bytes + be16toh(extension_length);
}

static ssize_t tls_dump_server_hello(struct ob_protocol* buffer, uint8_t* hdr, ssize_t length)
{
    struct tls_server_hello th;
    ssize_t read_bytes = 0;
    uint8_t legacy_compression_method;
    uint16_t cipher_suite;
    uint16_t extensions_length;
    ssize_t extensions_size;
    if (length < (ssize_t) sizeof(struct tls_server_hello))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    memcpy(&th, hdr, sizeof(struct tls_server_hello));
    read_bytes += sizeof(struct tls_server_hello);

    printf("--- BEGIN TLS SERVER HELLO ---\n");
    printf("%-45s = 0x%x (%s)\n", "Version", be16toh(th.LegacyVersion), tls_get_version(be16toh(th.LegacyVersion)));
    printf("%-45s = ", "Random");
    for (uint8_t i = 0; i < 32; ++i)
    {
        printf("%02x", th.Random[i]);
    }
    printf("\n");

    if (be16toh(th.LegacyVersion) <= 0x0302)
    {
        printf("%-45s = ", "Legacy session ID echo");
        for (uint8_t i = 0; i < 32; ++i)
        {
            printf("%02x", hdr[read_bytes + i]);
        }
        printf("\n");
        read_bytes += 32;
    }
    else
    {
        printf("%-45s = %u\n", "Legacy session ID echo", hdr[read_bytes]);
        read_bytes += 1;
    }

    memcpy(&cipher_suite, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);
    printf("%-45s = 0x%x (%s)\n", "Cipher suite", be16toh(cipher_suite), tls_get_cipher_suite(be16toh(th.LegacyVersion), be16toh(cipher_suite)));
    legacy_compression_method = hdr[read_bytes];
    read_bytes += 1;
    printf("%-45s = %u\n", "Legacy compression method", legacy_compression_method);

    memcpy(&extensions_length, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);

    extensions_size = be16toh(extensions_length);

    length -= read_bytes;
    hdr = &hdr[read_bytes];

    while (extensions_size > 0)
    {
        uint8_t extension_read_bytes = tls_dump_extension(buffer, hdr);
        extensions_size -= extension_read_bytes;
        hdr = &hdr[extension_read_bytes];
    }

    return read_bytes + extensions_size;
}

static void tls_dump_certificates(struct ob_protocol* buffer, uint8_t* hdr, ssize_t length)
{
    ssize_t read_bytes = 0;
    read_bytes += 1;

    uint32_t cert_chain_length;
    memcpy(&cert_chain_length, &hdr[read_bytes], sizeof(uint32_t));
    cert_chain_length = be32toh(cert_chain_length) >> 8;

    read_bytes += 3;
    length -= 4;

    printf("--- BEGIN TLS CERTIFICATE CHAIN ---\n");
    printf("%-45s = %u\n", "Certificate chain length", cert_chain_length);

    while (length > 0)
    {
        uint8_t* buffer_saved_hdr = buffer->hdr;
        ssize_t buffer_saved_length = buffer->length;
        uint32_t cert_length;
        uint16_t cert_extensions;
        memcpy(&cert_length, &hdr[read_bytes], sizeof(uint32_t));
        cert_length = be32toh(cert_length) >> 8;

        printf("--- BEGIN TLS CERTIFICATE ---\n");
        printf("%-45s = %u\n", "Certificate length", cert_length);

        read_bytes += 3;
        length -= 3;

        buffer->hdr = &hdr[read_bytes];
        buffer->length = cert_length;
        ber_decode_v3(buffer);
        buffer->hdr = buffer_saved_hdr;
        buffer->length = buffer_saved_length;

        read_bytes += cert_length;
        length -= cert_length;

        memcpy(&cert_extensions, &hdr[read_bytes], sizeof(uint16_t));
        printf("%-45s = %u\n", "Certificate extensions", be16toh(cert_extensions));

        read_bytes += sizeof(uint16_t);
        length -= sizeof(uint16_t);
    }
}

static void tls_dump_certificate_verify(struct ob_protocol* buffer, uint8_t* hdr, ssize_t length)
{
    ssize_t read_bytes = 0;
    uint16_t signature_scheme;
    uint16_t signature_length;

    memcpy(&signature_scheme, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);
    memcpy(&signature_length, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);

    printf("--- BEGIN TLS CERTIFICATE VERIFY ---\n");
    printf("%-45s = 0x%x\n", "Signature scheme", signature_scheme);
    printf("%-45s = 0x%x\n", "Signature length", signature_length);
}

ssize_t tls_dump_handshake(struct ob_protocol* buffer)
{
    struct tls_handshake_header th;
    ssize_t read_bytes = 0;
    uint8_t* hdr = (uint8_t*) buffer->hdr;
    uint32_t handshake_length;

    if (buffer->length < (ssize_t) sizeof(struct tls_handshake_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&th, buffer->hdr, sizeof(struct tls_handshake_header));
    read_bytes += sizeof(struct tls_handshake_header);

    handshake_length = be32toh(th.Length) >> 8;

    printf("--- BEGIN TLS HANDSHAKE ---\n");
    printf("%-45s = 0x%x (%s)\n", "Message type", th.MessageType, tls_get_msg_type(th.MessageType));
    printf("%-45s = %u\n", "Length", handshake_length);

    switch (th.MessageType)
    {
        case 2:
            return tls_dump_server_hello(buffer, &hdr[sizeof(struct tls_handshake_header)], buffer->length - sizeof(struct tls_handshake_header));

        case 8:
        {
            ssize_t extensions_size;
            ssize_t extension_size_copy;
            ssize_t extension_read_bytes = 0;
            uint16_t extensions_length;
            memcpy(&extensions_length, &hdr[read_bytes], sizeof(uint16_t));
            extension_read_bytes += sizeof(uint16_t);
            printf("%-45s = %u\n", "Extensions length", be16toh(extensions_length));
            extensions_size = (ssize_t) be16toh(extensions_length);
            extension_size_copy = extensions_size;
            hdr = &hdr[read_bytes + extension_read_bytes];
            while (extensions_size > 0)
            {
                extension_read_bytes = tls_dump_extension(buffer, hdr);
                extensions_size -= extension_read_bytes;
                hdr = &hdr[extension_read_bytes];
            }
            // printf("%d\n", read_bytes + extension_size_copy);
            break;
        }

        case 0xB:
            tls_dump_certificates(buffer, &hdr[read_bytes], handshake_length);
            break;

        case 0xF:
            tls_dump_certificate_verify(buffer, &hdr[read_bytes], handshake_length);
            break;

        default:
            break;
    }

    return read_bytes + handshake_length;
}

static void tls_dump_v3(const struct ob_protocol* buffer, const struct tls_header* th)
{
    printf("--- BEGIN TLS BUFFER ---\n");

    printf("%-45s = 0x%x (%s)\n", "Content Type", th->ContentType, tls_get_content_type(th->ContentType));
    printf("%-45s = 0x%x (%s)\n", "Version", be16toh(th->LegacyVersion), tls_get_version(be16toh(th->LegacyVersion)));
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
