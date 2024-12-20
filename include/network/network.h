#ifndef OB_NETWORK_H
#define OB_NETWORK_H

#include "generic/protocol.h"

void network_cast(uint16_t EthType, struct ob_protocol* buffer);
const char* network_get_name(uint16_t EthType);

#endif
