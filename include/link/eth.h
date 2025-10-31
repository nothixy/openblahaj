#ifndef OB_ETH_H
#define OB_ETH_H

#include "generic/protocol.h"

#define ETH_HEADER_LENGTH 14

struct ether_addr {
    uint8_t Addr[6];
};

struct ether_header
{
  uint8_t  Dst[6];	/* destination eth addr	*/
  uint8_t  Src[6];	/* source ether addr	*/
  uint16_t EtherType;		        /* packet type ID field	*/
};

char* ether_ntoa(const struct ether_addr* addr);
void eth_dump(struct ob_protocol* buffer);

#endif
