#ifndef OB_DNS_H
#define OB_DNS_H

#include <endian.h>

#include "generic/protocol.h"

struct dns_header {
    uint16_t TransactionID;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t RD : 1;
    uint8_t TC : 1;
    uint8_t AA : 1;
    uint8_t OPCODE : 4;
    uint8_t QR : 1;
    uint8_t RCODE : 4;
    uint8_t Z : 3;
    uint8_t RA : 1;
#else
    uint8_t QR : 1;
    uint8_t OPCODE : 4;
    uint8_t AA : 1;
    uint8_t TC : 1;
    uint8_t RD : 1;
    uint8_t RA : 1;
    uint8_t Z : 3;
    uint8_t RCODE : 4;
#endif
    uint16_t NumberQuestions;
    uint16_t NumberAnswers;
    uint16_t NumberAuthorityRR;
    uint16_t NumberAdditionalRR;
};

void dns_dump(struct ob_protocol* buffer);

// DNS HTTPS record : https://datatracker.ietf.org/doc/rfc9460/?include_text=1
//                    https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml

#endif
