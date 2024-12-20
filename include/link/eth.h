#ifndef OB_ETH_H
#define OB_ETH_H

#include "generic/protocol.h"

#define ETH_HEADER_LENGTH 14

void eth_dump(struct ob_protocol* buffer);

#endif
