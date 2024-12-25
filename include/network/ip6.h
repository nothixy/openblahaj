#ifndef OB_IP6_H
#define OB_IP6_H

#include <netinet/ip6.h>

#include "generic/protocol.h"

struct ip6_pseudo_header {
    uint8_t ip6_version;
    uint8_t ip6_next_header;
    uint16_t ip6_len;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

struct ip6_auth {
    uint8_t  ip6a_nxt;
    uint8_t  ip6a_len;
    uint16_t ip6a_rsv;
    uint32_t ip6a_spi;
    uint32_t ip6a_seq;
};

struct ip6_hip {
    uint8_t ip6h_nxt;
    uint8_t ip6h_len;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6h_zro : 1;
    uint8_t ip6h_pkt : 7;
    uint8_t ip6h_ver : 4;
    uint8_t ip6h_rsv : 3;
    uint8_t ip6h_one : 1;
#else
    uint8_t ip6h_pkt : 7;
    uint8_t ip6h_zro : 1;
    uint8_t ip6h_one : 1;
    uint8_t ip6h_rsv : 3;
    uint8_t ip6h_ver : 4;
#endif
    uint16_t ip6h_chk;
    uint16_t ip6h_ctr;
    uint8_t ip6h_shi[16];
    uint8_t ip6h_rhi[16];
    // Parameters
};

struct ip6_shim {
    uint8_t ip6s_nxt;
    uint8_t ip6s_len;
    union {
        struct {
            uint8_t ip6s_p0 : 1;
            uint64_t ip6s_rct : 47;
        } __attribute__((packed));
        struct {
            uint8_t ip6s_p1 : 1;
            uint8_t ip6s_typ : 7;
            uint8_t ip6s_tys : 7;
            uint8_t ip6s_s : 1;
            uint16_t ip6s_chk;
            uint64_t ip6s_tsf : 48;
        } __attribute__((packed));
    } ip6s_flw;
};

struct ip6_secu {
    uint32_t ip6s_spi;
    uint32_t ip6s_seq;

    // Other things
};

struct ip6_mobi {
    uint8_t  ip6m_nxt;
    uint8_t  ip6m_len;
    uint8_t ip6m_mht;
    uint8_t ip6m_rsv;
    uint16_t ip6m_chk;
};

struct ip6_mobi_hti {
    uint16_t ip6m_rsv;
    uint64_t ip6m_hic;
};

struct ip6_mobi_coti {
    uint16_t ip6m_rsv;
    uint64_t ip6m_cic;
};

struct ip6_mobi_hts {
    uint16_t ip6m_hni;
    uint64_t ip6m_hic;
    uint64_t ip6m_hkt;
};

struct ip6_mobi_cot {
    uint16_t ip6m_cni;
    uint64_t ip6m_cic;
    uint64_t ip6m_ckt;
};

struct ip6_mobi_bum {
    uint16_t ip6m_seq;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_a : 1;
    uint8_t ip6m_h : 1;
    uint8_t ip6m_l : 1;
    uint8_t ip6m_k : 1;
    uint16_t ip6m_rsv : 12;
#else
    uint16_t ip6m_rsv : 12;
    uint8_t ip6m_k : 1;
    uint8_t ip6m_l : 1;
    uint8_t ip6m_h : 1;
    uint8_t ip6m_a : 1;
#endif
    uint16_t ip6m_lft;
};

struct ip6_mobi_bak {
    uint8_t ip6m_sts;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_k : 1;
    uint8_t ip6m_rsv : 7;
#else
    uint8_t ip6m_rsv : 7;
    uint8_t ip6m_k : 1;
#endif
    uint16_t ip6m_seq;
    uint16_t ip6m_lft;
};

struct ip6_mobi_ber {
    uint8_t ip6m_sts;
    uint8_t ip6m_rsv;
    uint8_t ip6m_had[16];
};

struct ip6_mobi_hoi {
    uint16_t ip6m_seq;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_s : 1;
    uint8_t ip6m_u : 1;
    uint8_t ip6m_rsv : 6;
#else
    uint8_t ip6m_rsv : 6;
    uint8_t ip6m_u : 1;
    uint8_t ip6m_s : 1;
#endif
    uint8_t ip6m_cod;
};

struct ip6_mobi_hoa {
    uint16_t ip6m_seq;
    uint8_t ip6m_rsv;
    uint8_t ip6m_cod;
};

struct ip6_mobi_fbu {
    uint16_t ip6m_seq;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_a : 1;
    uint8_t ip6m_h : 1;
    uint8_t ip6m_l : 1;
    uint8_t ip6m_k : 1;
    uint16_t ip6m_rsv : 12;
#else
    uint16_t ip6m_rsv : 12;
    uint8_t ip6m_k : 1;
    uint8_t ip6m_l : 1;
    uint8_t ip6m_h : 1;
    uint8_t ip6m_a : 1;
#endif
    uint16_t ip6m_lft;
};

struct ip6_mobi_fba {
    uint8_t ip6m_sts;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_k : 1;
    uint8_t ip6m_rsv : 7;
#else
    uint8_t ip6m_rsv : 7;
    uint8_t ip6m_k : 1;
#endif
    uint16_t ip6m_seq;
    uint16_t ip6m_lft;
};

struct ip6_mobi_has {
    uint8_t ip6m_adc;
    uint8_t ip6m_rsv;
};

struct ip6_mobi_hbt {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t ip6m_rsv : 14;
    uint8_t ip6m_u : 1;
    uint8_t ip6m_r : 1;
#else
    uint8_t ip6m_r : 1;
    uint8_t ip6m_u : 1;
    uint16_t ip6m_rsv : 14;
#endif
    uint32_t ip6m_seq;
};

struct ip6_mobi_bri {
    uint8_t ip6m_brt;
    uint8_t ip6m_rtr;
    uint16_t ip6m_seq;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_p : 1;
    uint8_t ip6m_v : 1;
    uint8_t ip6m_g : 1;
    uint16_t ip6m_rsv : 13;
#else
    uint16_t ip6m_rsv : 13;
    uint8_t ip6m_g : 1;
    uint8_t ip6m_v : 1;
    uint8_t ip6m_p : 1;
#endif
};

struct ip6_mobi_lri {
    uint16_t ip6m_seq;
    uint16_t ip6m_rsv;
    uint16_t ip6m_lft;
};

struct ip6_mobi_lra {
    uint16_t ip6m_seq;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_u : 1;
    uint8_t ip6m_rsv : 7;
#else
    uint8_t ip6m_rsv : 7;
    uint8_t ip6m_u : 1;
#endif
    uint8_t ip6m_sts;
    uint16_t ip6m_lft;
};

struct ip6_mobi_upn {
    uint16_t ip6m_seq;
    uint16_t ip6m_rsn;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_a : 1;
    uint8_t ip6m_d : 1;
    uint16_t ip6m_rsv : 14;
#else
    uint16_t ip6m_rsv : 14;
    uint8_t ip6m_d : 1;
    uint8_t ip6m_a : 1;
#endif
};

struct ip6_mobi_upa {
    uint16_t ip6m_seq;
    uint8_t ip6m_sts;
    uint32_t ip6m_rsv : 24;
};

struct ip6_mobi_flb {
    uint16_t ip6m_fbt;
    uint16_t ip6m_seq;
    uint8_t ip6m_trs;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_a : 1;
    uint8_t ip6m_rsv : 7;
#else
    uint8_t ip6m_rsv : 7;
    uint8_t ip6m_a : 1;
#endif
};

struct ip6_mobi_squ {
    uint8_t ip6m_seq;
    uint8_t ip6m_rsv;
};

struct ip6_mobi_srs {
    uint8_t ip6m_seq;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t ip6m_i : 1;
    uint8_t ip6m_rsv : 7;
#else
    uint8_t ip6m_rsv : 7;
    uint8_t ip6m_i : 1;
#endif
};

void ipv6_dump(struct ob_protocol* buffer);

#endif
