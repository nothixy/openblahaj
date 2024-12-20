#ifndef OB_DBUS_H
#define OB_DBUS_H

#include "generic/protocol.h"

struct dbus_header {
    uint8_t Endianness;
    uint8_t MessageType;
    uint8_t Flags;
    uint8_t Major;
    uint32_t Length;
    uint32_t Serial;
};

void dbus_dump(struct ob_protocol* buffer);

#endif
