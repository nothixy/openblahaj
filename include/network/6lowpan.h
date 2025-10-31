#ifndef OB_6LOWPAN_H
#define OB_6LOWPAN_H

#include "generic/protocol.h"

struct sixlowpan_header {
    uint8_t DispatchType : 2;
    uint8_t Dispatch : 6;
};



void sixlowpan_dump(struct ob_protocol* buffer);

#endif
