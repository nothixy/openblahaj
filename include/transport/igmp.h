#ifndef OB_IGMP_H
#define OB_IGMP_H

#include <arpa/inet.h>
#include "generic/protocol.h"

struct igmp {
  uint8_t Type;
  uint8_t Code;
  uint16_t Checksum;
  struct in_addr Group;
};

enum RGMP_TYPE {
    IGMP_MEMBERSHIP_QUERY = 0x11,
    IGMP_V1_MEMBERSHIP_REPORT = 0x12,
    IGMP_DVMRP = 0x13,
    IGMP_PIM = 0x14,
    IGMP_TRACE = 0x15,
    IGMP_V2_MEMBERSHIP_REPORT = 0x16,
    IGMP_V2_LEAVE_GROUP = 0x17,
    IGMP_MTRACE_RESP = 0x1E,
    IGMP_MTRACE = 0x1F,
    RGMP_TYPE_LEAVE_GROUP = 0xFC,
    RGMP_TYPE_JOIN_GROUP,
    RGMP_TYPE_BYE,
    RGMP_TYPE_HELLO
};

void igmp_dump(struct ob_protocol* buffer);

#endif
