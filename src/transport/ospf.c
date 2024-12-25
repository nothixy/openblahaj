#include <stdio.h>
#include <endian.h>
#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "network/ip6.h"
#include "generic/bytes.h"
#include "transport/ospf.h"
#include "generic/protocol.h"

static const char* ospf_get_packet_type(uint8_t Type)
{
    switch (Type)
    {
        case 1:
            return "Hello";

        case 2:
            return "Database description";

        case 3:
            return "Link state request";

        case 4:
            return "Link state update";

        case 5:
            return "Link state ACK";

        default:
            return "Unknown";
    }
}

static void ospf_v3_dump_lsa_header(const struct ospf_v3_lsa_header* lsa_header)
{
    char LinkStateID[INET_ADDRSTRLEN] = {0};
    char AdvertisingRouter[INET_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET, &(lsa_header->LinkStateID), LinkStateID, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(lsa_header->AdvertisingRouter), AdvertisingRouter, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF v3 LSA HEADER ---\n");
    printf("%-45s = %u\n", "LSA age", be16toh(lsa_header->LSAAge));
    printf("%-45s = 0x%x\n", "LSA type", be16toh(lsa_header->LSType));
    printf("%-45s = %s\n", "Link state ID", LinkStateID);
    printf("%-45s = %s\n", "Advertising router", AdvertisingRouter);
    printf("%-45s = 0x%x\n", "LS sequence number", be32toh(lsa_header->LSSequenceNumber));
    printf("%-45s = 0x%x [Unchecked]\n", "LS checksum", be16toh(lsa_header->LSChecksum));
    printf("%-45s = %u\n", "Length", be16toh(lsa_header->Length));
}

static void ospf_v3_dump_hello(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ospf_v3_hello oh;
    const uint8_t* hdr = buffer->hdr;
    char DesignatedRouterID[INET_ADDRSTRLEN] = {0};
    char BackupDesignatedRouterID[INET_ADDRSTRLEN] = {0};
    char NeighborID[INET_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) sizeof(struct ospf_v3_hello) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&oh, &hdr[offset], sizeof(struct ospf_v3_hello));

    inet_ntop(AF_INET, &(oh.DesignatedRouterID), DesignatedRouterID, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(oh.BackupDesignatedRouterID), BackupDesignatedRouterID, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF v3 HELLO MESSAGE ---\n");
    printf("%-45s = %u\n", "Interface ID", be32toh(oh.InterfaceID));
    printf("%-45s = %u\n", "Router priority", oh.RouterPriority);
    printf("%-45s = %u\n", "Options", oh.Options);
    printf("%-45s = %u\n", "Hello interval", be16toh(oh.HelloInterval));
    printf("%-45s = %u\n", "Router dead interval", be16toh(oh.RouterDeadInterval));
    printf("%-45s = %s\n", "Designated router ID", DesignatedRouterID);
    printf("%-45s = %s\n", "Backup designated router ID", BackupDesignatedRouterID);

    for (ssize_t i = offset + (ssize_t) sizeof(struct ospf_v3_hello); i < buffer->length; i += 4)
    {
        if (i + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        inet_ntop(AF_INET, &(hdr[i]), NeighborID, INET_ADDRSTRLEN * sizeof(char));
        printf("%-45s = %s\n", "Neighbor ID", NeighborID);
    }
}

static void ospf_v3_dump_dd(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ospf_v3_database_description dh;
    struct ospf_v3_lsa_header lsa_header;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ospf_v3_database_description) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&dh, &hdr[offset], sizeof(struct ospf_v3_database_description));

    printf("--- BEGIN OSPF v3 DATABASE DESCRIPTION ---\n");
    printf("%-45s = %u\n", "Options", dh.Options);
    printf("%-45s = %u\n", "Interface MTU", be16toh(dh.InterfaceMTU));
    printf("%-45s = %u\n", "Flags", dh.Flags);
    printf("%-45s = %u\n", "DD sequence number", be32toh(dh.DDSequenceNumber));

    for (ssize_t i = offset + (ssize_t) sizeof(struct ospf_v3_database_description); i < buffer->length; i += (ssize_t) sizeof(struct ospf_v3_lsa_header))
    {
        if (i + (ssize_t) sizeof(struct ospf_v3_lsa_header) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&lsa_header, &hdr[i], sizeof(struct ospf_v3_lsa_header));

        ospf_v3_dump_lsa_header(&lsa_header);
    }
}

static void ospf_v3_dump_lsr(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ospf_v3_link_state_request lsrh;
    char LinkStateID[INET_ADDRSTRLEN] = {0};
    char AdvertisingRouter[INET_ADDRSTRLEN] = {0};
    const uint8_t* hdr = buffer->hdr;

    for (ssize_t i = offset; i < buffer->length; i += (ssize_t) sizeof(struct ospf_v3_link_state_request))
    {
        if (i + (ssize_t) sizeof(struct ospf_v3_link_state_request) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&lsrh, &hdr[i], sizeof(struct ospf_v2_link_state_request));
        inet_ntop(AF_INET, &(lsrh.LinkStateID), LinkStateID, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &(lsrh.AdvertisingRouter), AdvertisingRouter, INET_ADDRSTRLEN * sizeof(char));

        printf("--- BEGIN OSPF v3 LINK STATE REQUEST ---\n");
        printf("%-45s = %u\n", "LS type", be16toh(lsrh.LSType));
        printf("%-45s = %s\n", "Link state ID", LinkStateID);
        printf("%-45s = %s\n", "Advertising router", AdvertisingRouter);
    }
}

static void ospf_v3_dump_lsu(const struct ob_protocol* buffer, ssize_t offset)
{
    uint32_t LSACount;
    struct ospf_v3_lsa_header lsa_header;
    const uint8_t* hdr = buffer->hdr;
    ssize_t lsa_data_length;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&LSACount, &hdr[offset], sizeof(uint32_t));
    offset += (ssize_t) sizeof(uint32_t);
    printf("NEW OFFSET = %ld\n", offset);

    printf("--- BEGIN OSPF v3 LINK STATE UPDATE ---\n");
    printf("%-45s = %u\n", "LSA count", be32toh(LSACount));

    for (uint32_t i = 0; i < be32toh(LSACount); ++i)
    {
        if (offset + (ssize_t) sizeof(struct ospf_v3_lsa_header) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&lsa_header, &hdr[offset], sizeof(struct ospf_v3_lsa_header));

        ospf_v3_dump_lsa_header(&lsa_header);

        offset += (ssize_t) sizeof(struct ospf_v3_lsa_header);

        lsa_data_length = (ssize_t) (be16toh(lsa_header.Length)  - sizeof(struct ospf_v3_lsa_header));

        if (lsa_data_length < 0)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }

        // switch (lsa_header.LSType)
        // {
        //     case 1:
        //         ospf_v2_dump_router_lsa(buffer, offset);
        //         break;

        //     case 2:
        //         ospf_v2_dump_network_lsa(buffer, offset, (uint16_t) lsa_data_length);
        //         break;

        //     case 3:
        //     case 4:
        //         ospf_v2_dump_summary_lsa(buffer, offset, (uint16_t) lsa_data_length);
        //         break;

        //     case 5:
        //         ospf_v2_dump_as_external_lsa(buffer, offset, (uint16_t) lsa_data_length);
        //         break;

        //     default:
        //         break;
        // }

        offset += lsa_data_length;
    }
}

static void ospf_v2_dump_hello(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ospf_v2_hello oh;
    const uint8_t* hdr = buffer->hdr;
    char Netmask[INET_ADDRSTRLEN] = {0};
    char DesignatedRouterID[INET_ADDRSTRLEN] = {0};
    char BackupDesignatedRouterID[INET_ADDRSTRLEN] = {0};
    char NeighborID[INET_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) sizeof(struct ospf_v2_hello) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&oh, &hdr[offset], sizeof(struct ospf_v2_hello));

    inet_ntop(AF_INET, &(oh.Netmask), Netmask, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(oh.DesignatedRouterID), DesignatedRouterID, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(oh.BackupDesignatedRouterID), BackupDesignatedRouterID, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF v2 HELLO MESSAGE ---\n");
    printf("%-45s = %s\n", "Netmask", Netmask);
    printf("%-45s = %u\n", "Hello interval", be16toh(oh.HelloInterval));
    printf("%-45s = %u\n", "Router priority", oh.RouterPriority);
    printf("%-45s = %u\n", "Router dead interval", be32toh(oh.RouterDeadInterval));
    printf("%-45s = %s\n", "Designated router ID", DesignatedRouterID);
    printf("%-45s = %s\n", "Backup designated router ID", BackupDesignatedRouterID);

    for (ssize_t i = offset + (ssize_t) sizeof(struct ospf_v2_hello); i < buffer->length; i += (ssize_t) sizeof(uint32_t))
    {
        if (i + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        inet_ntop(AF_INET, &(hdr[i]), NeighborID, INET_ADDRSTRLEN * sizeof(char));
        printf("%-45s = %s\n", "Neighbor ID", NeighborID);
    }
}

static void ospf_v2_dump_lsa_header(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    struct ospf_v2_lsa_header lsa_header;

    char LinkStateID[INET_ADDRSTRLEN] = {0};
    char AdvertisingRouter[INET_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) sizeof(struct ospf_v2_lsa_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&lsa_header, &hdr[offset], sizeof(struct ospf_v2_lsa_header));

    inet_ntop(AF_INET, &(lsa_header.LinkStateID), LinkStateID, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(lsa_header.AdvertisingRouter), AdvertisingRouter, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF v2 LSA HEADER ---\n");
    printf("%-45s = %u\n", "LSA age", be16toh(lsa_header.LSAAge));
    printf("%-45s = %u\n", "Options", lsa_header.Options);
    printf("%-45s = 0x%x\n", "LSA type", lsa_header.LSType);
    printf("%-45s = %s\n", "Link state ID", LinkStateID);
    printf("%-45s = %s\n", "Advertising router", AdvertisingRouter);
    printf("%-45s = 0x%x\n", "LS sequence number", be32toh(lsa_header.LSSequenceNumber));
    printf("%-45s = 0x%x [Unchecked]\n", "LS checksum", be16toh(lsa_header.LSChecksum));
    printf("%-45s = %u\n", "Length", be16toh(lsa_header.Length));
}

static void ospf_v2_dump_router_lsa(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ospf_v2_router_lsa router_lsa;
    struct ospf_v2_router_lsa_link lsa_link;
    char LinkID[INET_ADDRSTRLEN] = {0};
    char LinkData[INET_ADDRSTRLEN] = {0};
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ospf_v2_router_lsa) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&router_lsa, &hdr[offset], sizeof(struct ospf_v2_router_lsa));
    offset += (ssize_t) sizeof(struct ospf_v2_router_lsa);

    printf("--- BEGIN OSPF v2 ROUTER LSA ---\n");
    printf("%-45s = %u\n", "Flags", be16toh(router_lsa.Flags));
    printf("%-45s = %u\n", "Link count", be16toh(router_lsa.LinkCount));

    if (offset + (ssize_t) (be16toh(router_lsa.LinkCount) * sizeof(struct ospf_v2_router_lsa_link)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    for (uint16_t i = 0; i < be16toh(router_lsa.LinkCount); ++i)
    {
        if (offset + (ssize_t) sizeof(struct ospf_v2_router_lsa_link) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&lsa_link, &hdr[offset], sizeof(struct ospf_v2_router_lsa_link));

        offset += (ssize_t) (i * sizeof(struct ospf_v2_router_lsa_link));

        inet_ntop(AF_INET, &(lsa_link.LinkID), LinkID, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &(lsa_link.LinkData), LinkData, INET_ADDRSTRLEN * sizeof(char));

        printf("--- BEGIN OSPF v2 LSA LINK ---\n");
        printf("%-45s = %s\n", "Link ID", LinkID);
        printf("%-45s = %s\n", "Link data", LinkData);
        printf("%-45s = %u\n", "Type", lsa_link.Type);
        printf("%-45s = %u\n", "Tos count", lsa_link.TOSCount);
        printf("%-45s = %u\n", "Metric", be16toh(lsa_link.Metric));
    }
}

static void ospf_v2_dump_network_lsa(const struct ob_protocol* buffer, ssize_t offset, uint16_t length)
{
    struct ospf_v2_network_lsa network_lsa;
    char AttachedRouterStr[INET_ADDRSTRLEN] = {0};
    char NetworkMask[INET_ADDRSTRLEN] = {0};
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ospf_v2_network_lsa) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&network_lsa, &hdr[offset], sizeof(struct ospf_v2_network_lsa));
    offset += (ssize_t) sizeof(struct ospf_v2_network_lsa);

    inet_ntop(AF_INET, &(network_lsa.NetworkMask), NetworkMask, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF v2 NETWORK LSA ---\n");
    printf("%-45s = %s\n", "Network mask", NetworkMask);

    for (uint32_t i = 0; i < length / sizeof(uint32_t) - 1; ++i)
    {
        if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        inet_ntop(AF_INET, &hdr[offset], AttachedRouterStr, INET_ADDRSTRLEN * sizeof(char));
        
        printf("%-45s = %s\n", "Attached router", AttachedRouterStr);

        offset += (ssize_t) sizeof(uint32_t);
    }
}

static void ospf_v2_dump_summary_lsa(const struct ob_protocol* buffer, ssize_t offset, uint16_t length)
{
    struct ospf_v2_summary_lsa summary_lsa;
    struct ospf_v2_summary_lsa_metric lsa_metric;
    char NetworkMask[INET_ADDRSTRLEN] = {0};
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(sizeof(struct ospf_v2_summary_lsa)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&summary_lsa, &hdr[offset], sizeof(struct ospf_v2_summary_lsa));
    offset += (ssize_t) sizeof(struct ospf_v2_summary_lsa);

    inet_ntop(AF_INET, &(summary_lsa.NetworkMask), NetworkMask, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF v2 SUMMARY LSA ---\n");
    printf("%-45s = %s\n", "Network mask", NetworkMask);

    for (uint32_t i = 0; i < (length - sizeof(struct ospf_v2_summary_lsa)) / sizeof(struct ospf_v2_summary_lsa_metric); ++i)
    {
        if (offset + (ssize_t) sizeof(sizeof(struct ospf_v2_summary_lsa_metric)) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&lsa_metric, &hdr[offset], sizeof(struct ospf_v2_summary_lsa_metric));

        printf("--- BEGIN OSPF v2 SUMMARY LSA METRIC ---\n");
        printf("%-45s = %u\n", "TOS", lsa_metric.TOS);
        printf("%-45s = %u\n", "Metric", lsa_metric.Metric);

        offset += (ssize_t) sizeof(struct ospf_v2_summary_lsa_metric);
    }
}

static void ospf_v2_dump_as_external_lsa(const struct ob_protocol* buffer, ssize_t offset, uint16_t length)
{
    struct ospf_v2_as_external_lsa as_external_lsa;
    struct ospf_v2_as_external_lsa_route lsa_route;
    char NetworkMask[INET_ADDRSTRLEN] = {0};
    char ForwardingAddressStr[INET_ADDRSTRLEN] = {0};
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ospf_v2_as_external_lsa) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    memcpy(&as_external_lsa, &hdr[offset], sizeof(struct ospf_v2_as_external_lsa));
    offset += (ssize_t) sizeof(struct ospf_v2_as_external_lsa);

    inet_ntop(AF_INET, &(as_external_lsa.NetworkMask), NetworkMask, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF v2 AS EXTERNAL LSA ---\n");
    printf("%-45s = %s\n", "Network mask", NetworkMask);

    for (uint32_t i = 0; i < (length - sizeof(struct ospf_v2_as_external_lsa)) / sizeof(struct ospf_v2_as_external_lsa_route); ++i)
    {
        if (offset + (ssize_t) sizeof(struct ospf_v2_as_external_lsa_route) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }

        memcpy(&lsa_route, &hdr[offset], sizeof(struct ospf_v2_as_external_lsa_route));

        inet_ntop(AF_INET, &(lsa_route.ForwardingAddress), ForwardingAddressStr, INET_ADDRSTRLEN * sizeof(char));
        
        printf("--- BEGIN OSPF v2 EXTERNAL LSA ROUTE ---\n");
        printf("%-45s = %u\n", "External", lsa_route.External);
        printf("%-45s = %u\n", "TOS", lsa_route.TOS);
        printf("%-45s = %u\n", "Metric", lsa_route.Metric);
        printf("%-45s = %s\n", "Forwarding address", ForwardingAddressStr);
        printf("%-45s = %u\n", "External route tag", lsa_route.ExternalRouteTag);

        offset += (ssize_t) sizeof(struct ospf_v2_as_external_lsa_route);
    }
}

static void ospf_v2_dump_dd(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ospf_v2_database_description dh;
    // struct ospf_v2_lsa_header lsa_header;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ospf_v2_database_description) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&dh, &hdr[offset], sizeof(struct ospf_v2_database_description));

    printf("--- BEGIN OSPF v2 DATABASE DESCRIPTION ---\n");
    printf("%-45s = %u\n", "Interface MTU", be16toh(dh.InterfaceMTU));
    printf("%-45s = %u\n", "Options", dh.Options);
    printf("%-45s = %u\n", "Flags", dh.Flags);
    printf("%-45s = %u\n", "DD sequence number", be32toh(dh.DDSequenceNumber));

    for (ssize_t i = offset + (ssize_t) sizeof(struct ospf_v2_database_description); i < buffer->length; i += (ssize_t) sizeof(struct ospf_v2_lsa_header))
    {
        ospf_v2_dump_lsa_header(buffer, i);
    }
}

static void ospf_v2_dump_lsr(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ospf_v2_link_state_request lsrh;
    char LinkStateID[INET_ADDRSTRLEN] = {0};
    char AdvertisingRouter[INET_ADDRSTRLEN] = {0};
    const uint8_t* hdr = buffer->hdr;

    for (ssize_t i = offset; i < buffer->length; i += (ssize_t) sizeof(struct ospf_v2_link_state_request))
    {
        if (i + (ssize_t) sizeof(struct ospf_v2_link_state_request) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&lsrh, &hdr[i], sizeof(struct ospf_v2_link_state_request));
        inet_ntop(AF_INET, &(lsrh.LinkStateID), LinkStateID, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &(lsrh.AdvertisingRouter), AdvertisingRouter, INET_ADDRSTRLEN * sizeof(char));

        printf("--- BEGIN OSPF v2 LINK STATE REQUEST ---\n");
        printf("%-45s = %u\n", "LS type", be32toh(lsrh.LSType));
        printf("%-45s = %s\n", "Link state ID", LinkStateID);
        printf("%-45s = %s\n", "Advertising router", AdvertisingRouter);
    }
}

static void ospf_v2_dump_lsu(const struct ob_protocol* buffer, ssize_t offset)
{
    uint32_t LSACount;
    struct ospf_v2_lsa_header lsa_header;
    const uint8_t* hdr = buffer->hdr;
    ssize_t lsa_data_length;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&LSACount, &hdr[offset], sizeof(uint32_t));
    offset += (ssize_t) sizeof(uint32_t);
    printf("NEW OFFSET = %ld\n", offset);

    printf("--- BEGIN OSPF v2 LINK STATE UPDATE ---\n");
    printf("%-45s = %u\n", "LSA count", be32toh(LSACount));

    for (uint32_t i = 0; i < be32toh(LSACount); ++i)
    {
        if (offset + (ssize_t) sizeof(struct ospf_v2_lsa_header) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&lsa_header, &hdr[offset], sizeof(struct ospf_v2_lsa_header));

        ospf_v2_dump_lsa_header(buffer, offset);

        offset += (ssize_t) sizeof(struct ospf_v2_lsa_header);

        lsa_data_length = (ssize_t) (be16toh(lsa_header.Length) - sizeof(struct ospf_v2_lsa_header));

        if (lsa_data_length < 0)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }

        switch (lsa_header.LSType)
        {
            case 1:
                ospf_v2_dump_router_lsa(buffer, offset);
                break;

            case 2:
                ospf_v2_dump_network_lsa(buffer, offset, (uint16_t) lsa_data_length);
                break;

            case 3:
            case 4:
                ospf_v2_dump_summary_lsa(buffer, offset, (uint16_t) lsa_data_length);
                break;

            case 5:
                ospf_v2_dump_as_external_lsa(buffer, offset, (uint16_t) lsa_data_length);
                break;

            default:
                break;
        }

        offset += lsa_data_length;
    }
}

static void ospf_v2_dump_lsack(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    struct ospf_v2_lsa_header lsa_header;
    char LinkStateID[INET_ADDRSTRLEN] = {0};
    char AdvertisingRouter[INET_ADDRSTRLEN] = {0};

    for (ssize_t i = offset; i < buffer->length; i += (ssize_t) sizeof(struct ospf_v2_lsa_header))
    {
        if (i + (ssize_t) sizeof(struct ospf_v2_lsa_header) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        printf("--- BEGIN OSPF v2 LSA HEADER ---\n");
        memcpy(&lsa_header, &hdr[i], sizeof(struct ospf_v2_lsa_header));

        inet_ntop(AF_INET, &(lsa_header.LinkStateID), LinkStateID, INET_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET, &(lsa_header.AdvertisingRouter), AdvertisingRouter, INET_ADDRSTRLEN * sizeof(char));

        printf("%-45s = %u\n", "LSA age", be16toh(lsa_header.LSAAge));
        printf("%-45s = %u\n", "Options", lsa_header.Options);
        printf("%-45s = 0x%x\n", "LSA type", lsa_header.LSType);
        printf("%-45s = %s\n", "Link state ID", LinkStateID);
        printf("%-45s = %s\n", "Advertising router", AdvertisingRouter);
        printf("%-45s = 0x%x\n", "LS sequence number", be32toh(lsa_header.LSSequenceNumber));
        printf("%-45s = 0x%x [Unchecked]\n", "LS checksum", be16toh(lsa_header.LSChecksum));
        printf("%-45s = %u\n", "Length", be16toh(lsa_header.Length));
    }
}

static void ospf_v3_dump(const struct ob_protocol* buffer, uint8_t Type, ssize_t offset)
{
    switch (Type)
    {
        case 1:
            ospf_v3_dump_hello(buffer, offset);
            break;

        case 2:
            ospf_v3_dump_dd(buffer, offset);
            break;

        case 3:
            ospf_v3_dump_lsr(buffer, offset);
            break;

        case 4:
            ospf_v3_dump_lsu(buffer, offset);
            break;

        default:
            break;
    }
}

static void ospf_v2_dump(const struct ob_protocol* buffer, uint8_t Type, ssize_t offset)
{
    switch (Type)
    {
        case 1:
            ospf_v2_dump_hello(buffer, offset);
            break;

        case 2:
            ospf_v2_dump_dd(buffer, offset);
            break;

        case 3:
            ospf_v2_dump_lsr(buffer, offset);
            break;

        case 4:
            ospf_v2_dump_lsu(buffer, offset);
            break;

        case 5:
            ospf_v2_dump_lsack(buffer, offset);
            break;

        default:
            break;
    }
}

static void ospf_dump_v3(const struct ob_protocol* buffer, struct ospf_header* oh)
{
    ssize_t offset;
    uint64_t Auth;
    char RouterID[INET_ADDRSTRLEN] = {0};
    char AreaID[INET_ADDRSTRLEN] = {0};

    uint8_t* hdr = buffer->hdr;
    struct ip6_pseudo_header ip6h;
    ssize_t checksum_offset = offsetof(struct ospf_header, Checksum);
    uint32_t checksum;

    inet_ntop(AF_INET, &(oh->RouterID), RouterID, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(oh->AreaID), AreaID, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN OSPF MESSAGE ---\n");
    printf("%-45s = %u\n", "Version", oh->Version);
    printf("%-45s = %u (%s)\n", "Type", oh->Type, ospf_get_packet_type(oh->Type));
    printf("%-45s = %u\n", "Packet length", be16toh(oh->PacketLength));
    printf("%-45s = %s\n", "Router ID", RouterID);
    printf("%-45s = %s\n", "Area ID", AreaID);

    switch (oh->Version)
    {
        case 3:
            memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
            printf("%-45s = 0x%x", "Checksum", be16toh(oh->Checksum));
            checksum = be16toh(oh->Checksum);
            checksum += ip6h.ip6_len;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            for (uint8_t i = 0; i < 8; ++i)
            {
                checksum += be16toh(ip6h.ip6_src.s6_addr16[i]);
                checksum += (checksum >> 16);
                checksum = (uint16_t) checksum;
                checksum += be16toh(ip6h.ip6_dst.s6_addr16[i]);
                checksum += (checksum >> 16);
                checksum = (uint16_t) checksum;
            }
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += ip6h.ip6_next_header;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            hdr[checksum_offset] = (uint8_t) (checksum >> 8);
            hdr[checksum_offset + 1] = (uint8_t) (checksum);
            printf(" %s\n", checksum_16bitonescomplement_validate(buffer, buffer->length, 0, false));
            printf("%-45s = %u\n", "Instance ID", oh->Rest.v3.InstanceID);
            offset = sizeof(struct ospf_header) - sizeof(oh->Rest.v2) + (ssize_t) sizeof(oh->Rest.v3);
            ospf_v3_dump(buffer, oh->Type, offset);
            break;

        case 2:
            Auth = oh->Rest.v2.Authentication;
            oh->Rest.v2.Authentication = 0;
            printf("%-45s = 0x%x %s\n", "Checksum", be16toh(oh->Checksum), checksum_16bitonescomplement_validate(buffer, buffer->length, 0, false));
            printf("%-45s = %u\n", "AuType", be16toh(oh->Rest.v2.AuType));
            oh->Rest.v2.Authentication = Auth;
            printf("%-45s = %lu\n", "Authentication", be64toh(Auth));
            offset = sizeof(struct ospf_header);
            ospf_v2_dump(buffer, oh->Type, offset);
            break;

        default:
            printf("Unhandled OSPF version\n");
            break;
    }
}

static void ospf_dump_v2(const struct ospf_header* oh)
{
    char RouterID[INET_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET, &(oh->RouterID), RouterID, INET_ADDRSTRLEN * sizeof(char));

    printf("OSPF => ");
    printf("Version : %u, ", oh->Version);
    printf("Type : %s, ", ospf_get_packet_type(oh->Type));
    printf("Router ID : %s\n", RouterID);
}

void ospf_dump(struct ob_protocol* buffer)
{
    struct ospf_header oh;

    if ((ssize_t) sizeof(struct ospf_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&oh, buffer->hdr, sizeof(struct ospf_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> OSPF ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ospf_dump_v2(&oh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ospf_dump_v3(buffer, &oh);
            break;
    }
}
