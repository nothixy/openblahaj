#include <setjmp.h>
#include <stdio.h>
#include <endian.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "link/radiotap.h"
#include "generic/binary.h"
#include "network/network.h"
#include "generic/protocol.h"

static void radiotap_dump_v3(struct ob_protocol* buffer, const struct radiotap_header* hdr)
{
    uint8_t* bytes = &((uint8_t*) buffer->hdr)[sizeof(struct radiotap_header)];
    ssize_t data_left = buffer->length - (ssize_t) sizeof(struct radiotap_header);
    uint32_t present = hdr->Present;

    printf("--- BEGIN RADIOTAP MESSAGE ---\n");

    printf("%-45s = %u\n", "Version", hdr->Version);
    printf("%-45s = %u\n", "Length", le16toh(hdr->Length));
    printf("%-45s = 0b%b", "Fields present", le32toh(present));

    while (le32toh(present) & (1U << 31))
    {
        if (data_left < (ssize_t) sizeof(uint32_t))
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        memcpy(bytes, &present, sizeof(uint32_t));
        printf(" %b", le32toh(present));
        bytes = &bytes[sizeof(uint32_t)];
        data_left -= (ssize_t) data_left;
    }
    printf("\n");
}

static void radiotap_dump_v2(struct ob_protocol* buffer, const struct radiotap_header* hdr)
{
    uint8_t* bytes = &((uint8_t*) buffer->hdr)[sizeof(struct radiotap_header)];
    ssize_t data_left = buffer->length - (ssize_t) sizeof(struct radiotap_header);
    uint32_t present = hdr->Present;

    printf("RadioTap => ");

    printf("Version : %u, ", hdr->Version);
    printf("Length : %u, ", le16toh(hdr->Length));
    printf("Fields present : 0b%b", le32toh(present));

    while (le32toh(present) & (1U << 31))
    {
        if (data_left < (ssize_t) sizeof(uint32_t))
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        memcpy(bytes, &present, sizeof(uint32_t));
        printf(" %b", le32toh(present));
        bytes = &bytes[sizeof(uint32_t)];
        data_left -= (ssize_t) data_left;
    }
    printf("\n");
}

void radiotap_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct radiotap_header rh;

    if ((ssize_t) sizeof(struct radiotap_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&rh, buffer->hdr, sizeof(struct radiotap_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> RadioTap ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            radiotap_dump_v2(buffer, &rh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            radiotap_dump_v3(buffer, &rh);
            break;
    }

    buffer->length -= (ssize_t) sizeof(struct radiotap_header);
    buffer->hdr = &hdr[sizeof(struct radiotap_header)];

    buffer->dump = binary_dump;

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }
}
