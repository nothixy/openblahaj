#ifndef OB_TCP_H
#define OB_TCP_H

#include "network/ip4.h"
#include "network/ip6.h"
#include "generic/protocol.h"

extern struct tcp_reassembly_htable_element* tcp_htable[(1 << 16)];

struct tcp_reassembly {
    unsigned long buffer_length;
    long long index;
    uint32_t Seq;
    uint8_t SYN : 1;
    uint8_t PSH : 1;
    uint8_t* buffer;
    struct tcp_reassembly* next;
} __attribute__((packed));

struct tcp_reassembly_htable_element {
    uint16_t source_port;
    uint16_t destination_port;
    struct tcp_reassembly_htable_element* next;
    struct tcp_reassembly* buffers;
    union {
        struct {
            struct in_addr source_ip;
            struct in_addr destination_ip;
        } ipv4;
        struct {
            struct in6_addr source_ip;
            struct in6_addr destination_ip;
        } ipv6;
    };
};

struct tcp_quickstart {
    uint8_t function : 4;
    uint8_t rate_request : 4;
    uint8_t QS_ttl;
    uint32_t QS_nonce : 31;
    uint8_t R : 1;
} __attribute__((packed));

struct tcp_usertimeout {
    uint8_t G : 1;
    uint32_t user_timeout : 31;
} __attribute__((packed));

void tcp_dump(struct ob_protocol* buffer);

#endif
