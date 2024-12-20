#ifndef OB_IGMP_H
#define OB_IGMP_H

#include "generic/protocol.h"

enum RGMP_TYPE {
    RGMP_TYPE_LEAVE_GROUP = 0xFC,
    RGMP_TYPE_JOIN_GROUP,
    RGMP_TYPE_BYE,
    RGMP_TYPE_HELLO
};

void igmp_dump(struct ob_protocol* buffer);

#endif
