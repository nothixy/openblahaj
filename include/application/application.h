#ifndef OB_APPLICATION_H
#define OB_APPLICATION_H

#include <stdbool.h>

#include "generic/protocol.h"

enum T_TRANSPORT {
    T_TRANSPORT_SCTP,
    T_TRANSPORT_TCP,
    T_TRANSPORT_UDP,
};

bool application_cast(enum T_TRANSPORT transport, uint16_t port, struct ob_protocol* buffer);
const char* application_get_name(enum T_TRANSPORT transport, uint16_t port);

#endif
