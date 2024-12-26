#include <stdio.h>
#include <endian.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "generic/protocol.h"
#include "application/wireguard.h"

/**
 * Note for implementation : some fields are in little-endian form
 */

static void wireguard_dump_first_message(const struct ob_protocol* buffer)
{
    struct wireguard_first_message first_message;

    if ((ssize_t) sizeof(struct wireguard_first_message) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&first_message, buffer->hdr, sizeof(struct wireguard_first_message));

    printf("%-45s = %u (%s)\n", "Message type", 1, "First message");
    printf("%-45s = 0x%x\n", "Sender index", le32toh(first_message.sender_index));
    printf("%-45s = 0x", "Unencrypted ephemeral");
    for (int i = 0; i < 32; ++i)
    {
        printf("%x", first_message.unencrypted_ephemeral[i]);
    }
    printf("\n");

    printf("%-45s = 0x", "Encrypted static");
    for (int i = 0; i < AEAD_LEN(32); ++i)
    {
        printf("%x", first_message.encrypted_static[i]);
    }
    printf("\n");

    printf("%-45s = 0x", "Encrypted timestamp");
    for (int i = 0; i < AEAD_LEN(12); ++i)
    {
        printf("%x", first_message.encrypted_timestamp[i]);
    }
    printf("\n");

    printf("%-45s = ", "MAC 1");
    for (int i = 0; i < 16; ++i)
    {
        printf("%x", first_message.mac1[i]);
    }
    printf("\n");

    printf("%-45s = ", "MAC 2");
    for (int i = 0; i < 16; ++i)
    {
        printf("%x", first_message.mac2[i]);
    }
    printf("\n");
}

static void wireguard_dump_second_message(const struct ob_protocol* buffer)
{
    struct wireguard_second_message second_message;

    if ((ssize_t) sizeof(struct wireguard_second_message) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&second_message, buffer->hdr, sizeof(struct wireguard_second_message));

    printf("%-45s = %u (%s)\n", "Message type", 2, "Second message");
    printf("%-45s = 0x%x\n", "Sender index", le32toh(second_message.sender_index));
    printf("%-45s = 0x%x\n", "Receiver index", le32toh(second_message.receiver_index));
    printf("%-45s = 0x", "Unencrypted ephemeral");
    for (int i = 0; i < 32; ++i)
    {
        printf("%u", second_message.unencrypted_ephemeral[i]);
    }
    printf("\n");

    printf("%-45s = 0x", "Encrypted nothing");
    for (int i = 0; i < AEAD_LEN(0); ++i)
    {
        printf("%u", second_message.encrypted_nothing[i]);
    }
    printf("\n");

    printf("%-45s = ", "MAC 1");
    for (int i = 0; i < 16; ++i)
    {
        printf("%x", second_message.mac1[i]);
    }
    printf("\n");

    printf("%-45s = ", "MAC 2");
    for (int i = 0; i < 16; ++i)
    {
        printf("%x", second_message.mac2[i]);
    }
    printf("\n");
}

static void wireguard_dump_data_message(const struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct wireguard_data_message data_message;

    if ((ssize_t) sizeof(struct wireguard_data_message) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&data_message, buffer->hdr, sizeof(struct wireguard_data_message));

    printf("%-45s = %u (%s)\n", "Message type", 4, "Data message");
    printf("%-45s = 0x%x\n", "Receiver index", le32toh(data_message.receiver_index));
    printf("%-45s = %lu\n", "Counter", le64toh(data_message.counter));

    printf("%-45s = ", "Raw data");
    for (ssize_t i = (ssize_t) sizeof(struct wireguard_data_message); i < buffer->length; ++i)
    {
        printf("%02x ", hdr[i]);
    }
    printf("\n");
}

static void wireguard_dump_v3(const struct ob_protocol* buffer, const struct wireguard_header* wh)
{
    printf("--- BEGIN WIREGUARD BUFFER ---\n");

    fprintf(stderr, "MESSAGE TYPE = 0x%x\n", wh->message_type);

    switch (wh->message_type)
    {
        case 1:
            wireguard_dump_first_message(buffer);
            break;

        case 2:
            wireguard_dump_second_message(buffer);
            break;

        case 4:
            wireguard_dump_data_message(buffer);
            break;

        default:
            break;
    }
}

static void wireguard_dump_v2(const struct wireguard_header* wh)
{
    printf("Wireguard => ");

    switch (wh->message_type)
    {
        case 1:
            printf("First message");
            break;

        case 2:
            printf("Second message");
            break;

        case 4:
            printf("Data message");
            break;

        default:
            break;
    }

    printf("\n");
}

void wireguard_dump(struct ob_protocol* buffer)
{
    struct wireguard_header wh;

    if ((ssize_t) sizeof(struct wireguard_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&wh, buffer->hdr, sizeof(struct wireguard_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> WireGuard ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            wireguard_dump_v2(&wh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            wireguard_dump_v3(buffer, &wh);
    }
}
