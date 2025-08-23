#ifndef OB_RADIOTAP_H
#define OB_RADIOTAP_H

#include "generic/protocol.h"

struct radiotap_header {
    uint8_t Version;
    uint8_t Pad;
    uint16_t Length;
    uint32_t Present;
};

void radiotap_dump(struct ob_protocol* buffer);

#endif
