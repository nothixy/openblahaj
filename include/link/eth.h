#ifndef OB_ETH_H
#define OB_ETH_H

#include "generic/protocol.h"

#define ETH_HEADER_LENGTH 14

struct ether_addr {
    uint8_t addr[6];
};

struct ether_header
{
  uint8_t  ether_dhost[6];	/* destination eth addr	*/
  uint8_t  ether_shost[6];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
};

char* ether_ntoa(const struct ether_addr* addr);
void eth_dump(struct ob_protocol* buffer);

#endif
