#ifndef OB_OSPF_H
#define OB_OSPF_H

#include "generic/protocol.h"

struct ospf_header {
    uint8_t Version;
    uint8_t Type;
    uint16_t PacketLength;
    uint32_t RouterID;
    uint32_t AreaID;
    uint16_t Checksum;
    union {
        struct {
            uint16_t AuType;
            uint64_t Authentication;
        } __attribute__((packed)) v2;
        struct {
            uint8_t InstanceID;
            uint8_t Reserved;
        } v3;
    } Rest;
};

struct ospf_v2_hello {
    uint32_t Netmask;
    uint16_t HelloInterval;
    uint8_t Options;
    uint8_t RouterPriority;
    uint32_t RouterDeadInterval;
    uint32_t DesignatedRouterID;
    uint32_t BackupDesignatedRouterID;
};

struct ospf_v2_database_description {
    uint16_t InterfaceMTU;
    uint8_t Options;
    uint8_t Flags;
    uint32_t DDSequenceNumber;
};

struct ospf_v2_link_state_request {
    uint32_t LSType;
    uint32_t LinkStateID;
    uint32_t AdvertisingRouter;
};

struct ospf_v2_link_state_update {
    uint32_t LSACount;
};

struct ospf_v2_lsa_header {
    uint16_t LSAAge;
    uint8_t Options;
    uint8_t LSType;
    uint32_t LinkStateID;
    uint32_t AdvertisingRouter;
    uint32_t LSSequenceNumber;
    uint16_t LSChecksum;
    uint16_t Length;
};

struct ospf_v2_router_lsa {
    uint16_t Flags;
    uint16_t LinkCount;
};

struct ospf_v2_router_lsa_link {
    uint32_t LinkID;
    uint32_t LinkData;
    uint8_t Type;
    uint8_t TOSCount;
    uint16_t Metric;
    /**
     * In OSPF v1, TOS metrics are used but not after that
     */
};

struct ospf_v2_network_lsa {
    uint32_t NetworkMask;
};

struct ospf_v2_summary_lsa {
    uint32_t NetworkMask;
};

struct ospf_v2_summary_lsa_metric {
    uint8_t TOS;
    uint32_t Metric : 24;
};

struct ospf_v2_as_external_lsa {
    uint32_t NetworkMask;
};

struct ospf_v2_as_external_lsa_route {
    uint8_t External : 1;
    uint8_t TOS : 7;
    uint32_t Metric : 24;
    uint32_t ForwardingAddress;
    uint32_t ExternalRouteTag;
};

struct ospf_v3_hello {
    uint32_t InterfaceID;
    uint8_t RouterPriority;
    uint32_t Options : 24;
    uint16_t HelloInterval;
    uint16_t RouterDeadInterval;
    uint32_t DesignatedRouterID;
    uint32_t BackupDesignatedRouterID;
    uint32_t NeighborID;
};

struct ospf_v3_database_description {
    uint8_t Reserved;
    uint32_t Options : 24;
    uint16_t InterfaceMTU;
    uint8_t Reserved2;
    uint8_t Flags;
    uint32_t DDSequenceNumber;
} __attribute__((packed));


struct ospf_v3_lsa_header {
    uint16_t LSAAge;
    uint16_t LSType;
    uint32_t LinkStateID;
    uint32_t AdvertisingRouter;
    uint32_t LSSequenceNumber;
    uint16_t LSChecksum;
    uint16_t Length;
};

struct ospf_v3_link_state_request {
    uint16_t Reserved;
    uint16_t LSType;
    uint32_t LinkStateID;
    uint32_t AdvertisingRouter;
};

struct ospf_v3_link_state_update {
    uint32_t LSACount;
};

/*
OSPF header (common between v2 and v3)

+----------+----------+---------------------+
|  Version |   Type   |    Packet length    |
+----------+----------+---------------------+
|                 Router ID                 |
+---------------------+---------------------+
|                  Area ID                  |
+---------------------+---------------------+
|       Checksum      |
+---------------------+

Rest of OSPF v2 header

                      +---------------------+
                      |        AuType       |
+---------------------+---------------------+
|              Authentication               |
|                                           |
+-------------------------------------------+
*/

void ospf_dump(struct ob_protocol* buffer);

#endif
