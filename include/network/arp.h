#ifndef OB_ARP_H
#define OB_ARP_H

#include "generic/protocol.h"

#define ARP_HARDWARE_TYPE_ETHERNET 1
#define ARP_PROTOCOL_TYPE_IPV4 0x800

const char* arp_get_htype(uint16_t Htype);
void arp_dump(struct ob_protocol* buffer);

#endif
