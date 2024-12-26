#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/igmp.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "generic/bytes.h"
#include "transport/igmp.h"

static const char* igmp_get_type(uint8_t type)
{
    switch (type)
    {
        case IGMP_MEMBERSHIP_QUERY:
            return "Membership query";

        case IGMP_V1_MEMBERSHIP_REPORT:
        case IGMP_V2_MEMBERSHIP_REPORT:
            return "Membership report";

        case IGMP_V2_LEAVE_GROUP:
            return "Leave group";

        case IGMP_DVMRP:
            return "DVMRP routing";

        case IGMP_PIM:
            return "PIM routing";

        case IGMP_TRACE:
            return "Traceroute";

        case IGMP_MTRACE_RESP:
            return "Traceroute response";

        case IGMP_MTRACE:
            return "Multicast traceroute";

        case RGMP_TYPE_LEAVE_GROUP:
            return "RGMP leave group";

        case RGMP_TYPE_JOIN_GROUP:
            return "RGMP join group";

        case RGMP_TYPE_BYE:
            return "RGMP bye";

        case RGMP_TYPE_HELLO:
            return "RGMP hello";

        default:
            return "Unknown";
    }
}

static void igmp_dump_v3(const struct ob_protocol* buffer, const struct igmp* ih)
{
    char igmp_group[INET_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET, &(ih->igmp_group), igmp_group, INET_ADDRSTRLEN);

    if (ih->igmp_type >= RGMP_TYPE_LEAVE_GROUP)
    {
        printf("--- BEGIN RGMP MESSAGE ---\n");
    }
    else
    {
        printf("--- BEGIN IGMP MESSAGE ---\n");
    }
    printf("%-45s = 0x%x (%s)\n", "Type", ih->igmp_type, igmp_get_type(ih->igmp_type));
    if (ih->igmp_type < RGMP_TYPE_LEAVE_GROUP)
    {
        printf("%-45s = 0x%x\n", "Code", ih->igmp_code);
    }
    printf("%-45s = 0x%x %s\n", "Checksum", be16toh(ih->igmp_cksum), checksum_16bitonescomplement_validate(buffer, buffer->length, be16toh(ih->igmp_cksum), false));
    printf("%-45s = %s\n", "Group", igmp_group);
}

static void igmp_dump_v2(const struct igmp* ih)
{
    char igmp_group[INET_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET, &(ih->igmp_group), igmp_group, INET_ADDRSTRLEN);

    if (ih->igmp_type >= RGMP_TYPE_LEAVE_GROUP)
    {
        printf("RGMP => ");
    }
    else
    {
        printf("IGMP => ");
    }
    printf("Type : %s, ", igmp_get_type(ih->igmp_type));
    if (ih->igmp_type < RGMP_TYPE_LEAVE_GROUP)
    {
        printf("Code : 0x%x, ", ih->igmp_code);
    }
    printf("Group : %s\n", igmp_group);
}

void igmp_dump(struct ob_protocol* buffer)
{
    struct igmp ih;

    if ((ssize_t) sizeof(struct igmp) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ih, buffer->hdr, sizeof(struct igmp));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> IGMP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            igmp_dump_v2(&ih);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            igmp_dump_v3(buffer, &ih);
            break;
    }
}
