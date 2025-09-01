#ifndef OB_FILE_BER_H
#define OB_FILE_BER_H

#include "generic/protocol.h"

struct ber_type_byte1 {
    uint8_t tag_class : 2;
    uint8_t constructed : 1;
    uint8_t tag_type_long_form : 5;
};

void ber_decode_v3(struct ob_protocol* buffer);

#endif
