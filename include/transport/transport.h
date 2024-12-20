#ifndef OB_TRANSPORT_H
#define OB_TRANSPORT_H

#include "generic/protocol.h"

void transport_cast(uint8_t type, struct ob_protocol* buffer);
const char* transport_get_name(uint8_t type);

#endif
