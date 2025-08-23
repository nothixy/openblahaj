#include <stdio.h>
#include <endian.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "link/ppp.h"
#include "link/pppoe.h"
#include "generic/binary.h"
#include "generic/protocol.h"

static const char* pppoe_get_type(uint8_t Code)
{
    switch (Code)
    {
        case 0x00:
            return "Session data";

        case 0x07:
            return "Active discovery offer";

        case 0x09:
            return "Active discovery initiation";

        case 0x19:
            return "Active discovery request";

        case 0x65:
            return "Active discovery session confirmation";

        case 0xA7:
            return "Active discovery terminate";

        default:
            return "Unknown";
    }
}

static void pppoe_dump_v3(const struct pppoe_header* hdr)
{
    printf("--- BEGIN PPPoE MESSAGE ---\n");

    printf("%-45s = %u\n", "Version", hdr->Version);
    printf("%-45s = %u\n", "Type", hdr->Type);
    printf("%-45s = %u (%s)\n", "Code", hdr->Code, pppoe_get_type(hdr->Code));
    printf("%-45s = 0x%x\n", "Session ID", be16toh(hdr->SessionID));
    printf("%-45s = %u\n", "Length", be16toh(hdr->Length));
}

static void pppoe_dump_v2(const struct pppoe_header* hdr)
{
    printf("PPPoE => ");

    printf("Version : %u, ", hdr->Version);
    printf("Type : %u, ", hdr->Type);
    printf("Code : %s, ", pppoe_get_type(hdr->Code));
    printf("Type : 0x%x\n", be16toh(hdr->SessionID));
}

void pppoe_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct pppoe_header ph;

    if ((ssize_t) sizeof(struct pppoe_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ph, buffer->hdr, sizeof(struct pppoe_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> PPPoE ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            pppoe_dump_v2(&ph);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            pppoe_dump_v3(&ph);
            break;
    }

    buffer->length -= (ssize_t) sizeof(struct pppoe_header);
    buffer->hdr = &hdr[sizeof(struct pppoe_header)];

    buffer->dump = binary_dump;

    if (ph.Code == 0x0)
    {
        buffer->dump = ppp_encapsulation_dump;
    }

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }
}
