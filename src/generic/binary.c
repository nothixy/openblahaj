#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/binary.h"

/**
 * @brief Display raw bytes in a similar way to hexdump
 * @param buffer Buffer structure to dump
 */
static void binary_dump_v3(const struct ob_protocol* buffer)
{
    const uint8_t* hdr = buffer->hdr;

    printf("--- BEGIN UNKNOWN PROTOCOL MESSAGE ---\n");
    for (ssize_t i = 0; i < buffer->length; i += 16)
    {
        for (uint8_t j = 0; j < 16; ++j)
        {
            if (i + j >= buffer->length)
            {
                printf("   ");
            }
            else
            {
                printf("%02x ", hdr[i + j]);
            }
            if ((j % (1 << 3)) == (1 << 3) - 1)
            {
                printf(" ");
            }
        }
        printf("    ");
        for (uint8_t j = 0; j < 16 && i + j < buffer->length; ++j)
        {
            if (hdr[i + j] >= 32 && hdr[i + j] <= 126)
            {
                printf("%c", hdr[i + j]);
            }
            else
            {
                printf(".");
            }
            if ((j % (1 << 3)) == (1 << 3) - 1)
            {
                printf(" ");
            }
        }
        printf("\n");
    }

    printf("\n");
}

/**
 * @brief Display ascii printable raw bytes
 * @param buffer Buffer structure to dump
 */
static void binary_dump_v2(const struct ob_protocol* buffer)
{
    const uint8_t* hdr = buffer->hdr;
    ssize_t limit = buffer->length;
    if (limit > 80)
    {
        limit = 80;
    }

    printf("Unknown protocol => ");
    for (ssize_t i = 0; i < limit; ++i)
    {
        if (hdr[i] >= 32 && hdr[i] <= 126)
        {
            printf("%c", hdr[i]);
        }
        else
        {
            printf(".");
        }
    }

    printf("\n");
}

void binary_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> Unknown protocol ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            binary_dump_v2(buffer);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            binary_dump_v3(buffer);
            break;
    }
}
