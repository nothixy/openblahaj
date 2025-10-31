#include <stdio.h>
#include <endian.h>
#include <setjmp.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "generic/bytes.h"
#include "application/bgp.h"
#include "generic/protocol.h"
#include "generic/constants.h"

static const uint8_t bgp_marker[16] = {
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF, 
    0xFF
};

static const char* BGP_TYPE[] = {
    "Unknown",
    "Open",
    "Update",
    "Notification",
    "Keep-Alive",
    "Route-Refresh"
};

static const char* bgp_get_type(uint8_t Type)
{
    if (Type >= sizeof(BGP_TYPE) / sizeof(const char*))
    {
        return "Unknown";
    }

    return BGP_TYPE[Type];
}

void bgp_dump_open(const uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    struct bgp_open_message bo;
    if (length < sizeof(struct bgp_open_message))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    memcpy(&bo, hdr, sizeof(struct bgp_open_message));

    printf("--- BEGIN BGP OPEN MESSAGE ---\n");
    printf("%-45s = %u\n", "Version", bo.Version);
    printf("%-45s = %u\n", "My AS", be16toh(bo.MyAS));
    printf("%-45s = %u\n", "Hold time", be16toh(bo.HoldTime));
    printf("%-45s = %u\n", "Identifier", be32toh(bo.Identifier));
    printf("%-45s = %u\n", "Optional parameters length", bo.OptionalParametersLength);
}

void bgp_dump_update(const uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    uint16_t WithdrawRoutesLength;
    uint16_t TotalPathAttributeLength;
    ssize_t read_bytes = 0;

    memcpy(&WithdrawRoutesLength, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);

    read_bytes += be16toh(WithdrawRoutesLength);

    memcpy(&TotalPathAttributeLength, &hdr[read_bytes], sizeof(uint16_t));
    read_bytes += sizeof(uint16_t);

    read_bytes += be16toh(TotalPathAttributeLength);

    printf("--- BEGIN BGP UPDATE MESSAGE ---\n");
    printf("%-45s = %u\n", "Withdraw routes length", be16toh(WithdrawRoutesLength));
    printf("%-45s = %u\n", "Total path attribute length", be16toh(TotalPathAttributeLength));
}

void bgp_dump_notification(const uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    
}

void bgp_dump_keepalive(const uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    
}

void bgp_dump_routerefresh(const uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    
}

void bgp_dump_v3(struct bgp_header* bh, struct ob_protocol* buffer)
{
    const uint8_t* hdr = buffer->hdr;
    printf("--- BEGIN BGP MESSAGE ---\n");
    printf("%-45s = ", "Marker");
    for (uint8_t i = 0; i < 16; ++i)
    {
        printf("%02x", bh->Marker[i]);
    }
    printf("\n");
    printf("%-45s = %u\n", "Length", be16toh(bh->Length));
    printf("%-45s = %u (%s)\n", "Type", bh->Type, bgp_get_type(bh->Type));

    switch (bh->Type)
    {
        case 1:
            bgp_dump_open(&hdr[sizeof(struct bgp_header)], buffer, buffer->length - sizeof(struct bgp_header));
            break;

        case 2:
            bgp_dump_update(&hdr[sizeof(struct bgp_header)], buffer, buffer->length - sizeof(struct bgp_header));
            break;

        case 3:
            bgp_dump_notification(&hdr[sizeof(struct bgp_header)], buffer, buffer->length - sizeof(struct bgp_header));
            break;

        case 4:
            bgp_dump_keepalive(&hdr[sizeof(struct bgp_header)], buffer, buffer->length - sizeof(struct bgp_header));
            break;

        case 5:
            bgp_dump_routerefresh(&hdr[sizeof(struct bgp_header)], buffer, buffer->length - sizeof(struct bgp_header));
            break;

        default:
            break;
    }
}

void bgp_dump_v2(struct bgp_header* bh, struct ob_protocol* buffer)
{

}

void bgp_dump(struct ob_protocol *buffer)
{
    struct bgp_header bh;
    if (buffer->length < sizeof(struct bgp_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&bh, buffer->hdr, sizeof(struct bgp_header));

    if (memcmp(bh.Marker, bgp_marker, 16 * sizeof(uint8_t)))
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_HIGH:
            bgp_dump_v3(&bh, buffer);
            return;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            bgp_dump_v2(&bh, buffer);
            return;

        case OB_VERBOSITY_LEVEL_LOW:
            printf("> BGP ");
            return;
    }
}
