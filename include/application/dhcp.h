#ifndef OB_DHCP_H
#define OB_DHCP_H

#include "generic/protocol.h"

struct dhcp_isns {
    uint16_t functions;
    uint16_t dd_access;
    uint16_t admin_flags;
    uint32_t sec_bitmap;
} __attribute__((packed));

struct dhcp_geo {
    uint8_t la_res : 6;
    uint64_t latitude : 34;
    uint8_t lo_res : 6;
    uint64_t longitude : 34;
    uint8_t a_type : 4;
    uint16_t a_res : 6;
    uint32_t altitude : 30;
    uint8_t ver : 2;
    uint8_t res : 3;
    uint8_t datum : 3;
} __attribute__((packed));

void dhcp_dump(struct ob_protocol* buffer);

/**
 * https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
 */

#endif
