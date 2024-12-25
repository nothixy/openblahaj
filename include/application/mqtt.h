#ifndef OB_MQTT_H
#define OB_MQTT_H

#include "generic/protocol.h"

struct mqtt_header {
    uint8_t flags : 4;
    uint8_t type : 4;
    uint8_t length;
};

void mqtt_dump(struct ob_protocol* buffer);

#endif
