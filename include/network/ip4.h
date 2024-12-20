#ifndef OB_IP4_H
#define OB_IP4_H

#include <netinet/ip.h>

#include "generic/protocol.h"

#define IP_HEADER_LENGTH 20

struct ipv4_reassembly {
    unsigned long buffer_length;
    unsigned long frag_offset;
    long long index;
    bool more_fragment;
    uint8_t* buffer;
    struct ipv4_reassembly* next;
};

struct ip_pseudo_header {
    uint8_t ip_version;
    uint16_t ip_len;
    uint16_t ip_proto;
    struct in_addr ip_dst;
    struct in_addr ip_src;
} __attribute__((packed));

struct ip_option_header {
    uint8_t Copied : 1;
    uint8_t Class : 2;
    uint8_t Number : 5;
    uint8_t Length;
};

void ipv4_dump(struct ob_protocol* buffer);

#endif
