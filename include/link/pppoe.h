#ifndef OB_PPPOE_H
#define OB_PPPOE_H

#include "generic/protocol.h"

struct pppoe_header {
    uint8_t Version : 4;
    uint8_t Type : 4;
    uint8_t Code;
    uint16_t SessionID;
    uint16_t Length;
};

void pppoe_dump(struct ob_protocol* buffer);

#endif
