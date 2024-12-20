#ifndef OB_ICMP6_H
#define OB_ICMP6_H

#include "generic/protocol.h"

#define ICMP_OFFSET_TYPE 0
#define ICMP_OFFSET_CODE 1
#define ICMP_OFFSET_CHECKSUM 2
#define ICMP_OFFSET_REST_HEADER 4
#define ICMP_OFFSET_DATA 8

void icmp6_dump(struct ob_protocol* buffer);

#endif
