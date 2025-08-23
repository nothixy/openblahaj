#ifndef OB_PPP_H
#define OB_PPP_H

#include "generic/protocol.h"

typedef uint16_t ppp_header;

struct ppp_link_control_header {
    uint8_t Code;
    uint8_t Identifier;
    uint16_t Length;
};

struct ppp_link_control_option {
    uint8_t Type;
    uint8_t Length;
};

void ppp_encapsulation_dump(struct ob_protocol* buffer);
void ppp_link_control_protocol_dump(struct ob_protocol* buffer);
void ppp_internet_protocol_control_protocol_dump(struct ob_protocol* buffer);

#endif
