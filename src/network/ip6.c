#include <stdio.h>
#include <endian.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip.h"
#include "network/ip6.h"
#include "generic/bytes.h"
#include "transport/ospf.h"
#include "generic/protocol.h"
#include "transport/transport.h"

static const char* ipv6_get_protocol(uint8_t protocol)
{
    if (protocol >= 146)
    {
        return "Unknown";
    }
    return IP_PROTOCOLS[protocol];
}

static uint8_t ipv6_dump_extension_hop_by_hop(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_hbh hbh;
    const uint8_t* hdr = buffer->hdr;
    bool requires_length;

    if (offset + (ssize_t) sizeof(struct ip6_hbh) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hbh, &hdr[offset], sizeof(struct ip6_hbh));

    if (nodisp)
    {
        return hbh.ip6h_nxt;
    }

    if (offset + (hbh.ip6h_len + 1) * 8 > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    printf("%-45s\n", "Hop by Hop");
    for (ssize_t i = offset + (ssize_t) sizeof(struct ip6_hbh); i < offset + (hbh.ip6h_len + 1) * 8;)
    {
        requires_length = (hdr[i] != 0);
        if (requires_length && i + 1 >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        switch (hdr[i])
        {
            case 0:
                printf("Pad1");
                i += 1;
                continue;

            case 1:
                printf("PadN (%u)", hdr[i + 1]);
                i += hdr[i + 1] + 2;
                continue;

            default:
                printf("Unknown");
                i += hdr[i + 1] + 2;
                break;
        }
        if (i < offset + (hbh.ip6h_len + 1) * 8)
        {
            printf(", ");
        }
    }
    printf("\n");

    return hbh.ip6h_nxt;
}

static uint8_t ipv6_dump_extension_routing(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_rthdr routing;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_rthdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&routing, &hdr[offset], sizeof(struct ip6_rthdr));

    if (nodisp)
    {
        return routing.ip6r_nxt;
    }

    if (offset + (routing.ip6r_len + 1) * 8 > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("%-45s = ", "Routing");
    printf("Routing type : %u, ", routing.ip6r_type);
    printf("Segments left : %u, ", routing.ip6r_segleft);

    printf("Type specific data : ");
    for (ssize_t i = offset + (ssize_t) sizeof(struct ip6_rthdr); i < offset + (routing.ip6r_len + 1) * 8; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");

    return routing.ip6r_nxt;
}

static uint8_t ipv6_dump_extension_fragment(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_frag frag;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_frag) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&frag, &hdr[offset], sizeof(struct ip6_frag));

    if (nodisp)
    {
        return frag.ip6f_nxt;
    }

    printf("%-45s = ", "Fragment");
    printf("Fragment offset : %u, ", frag.ip6f_offlg & IP6F_OFF_MASK);
    printf("M : %u, ", frag.ip6f_offlg & IP6F_MORE_FRAG);
    printf("Identification : %u", be32toh(frag.ip6f_ident));

    return frag.ip6f_nxt;
}

static uint8_t ipv6_dump_extension_encapsulating_security(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    (void) buffer;
    (void) offset;
    (void) nodisp;

    printf("%-45s = NOT IMPLEMENTED", "Fragment");

    return 0;
}

static uint8_t ipv6_dump_extension_authentication(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_auth auth;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_auth) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&auth, &hdr[offset], sizeof(struct ip6_auth));

    if (nodisp)
    {
        return auth.ip6a_nxt;
    }

    if (offset + (auth.ip6a_len + 2) * 4 > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    printf("%-45s = ", "Auth");
    printf("Security parameters index : 0x%x, ", be32toh(auth.ip6a_spi));
    printf("Sequence number : %u, ", be32toh(auth.ip6a_seq));
    printf("Integrity sequence value : ");
    for (ssize_t i = offset + (ssize_t) sizeof(struct ip6_auth); i < offset + (auth.ip6a_len + 2) * 4; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");

    return auth.ip6a_nxt;
}

static uint8_t ipv6_dump_extension_destination(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_dest dest;
    const uint8_t* hdr = buffer->hdr;
    bool requires_length;

    if (offset + (ssize_t) sizeof(struct ip6_dest) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&dest, &hdr[offset], sizeof(struct ip6_dest));

    if (nodisp)
    {
        return dest.ip6d_nxt;
    }

    if (offset + (dest.ip6d_len + 1) * 8 > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("%-45s = ", "Destination");
    for (ssize_t i = offset + (ssize_t) sizeof(struct ip6_dest); i < offset + (dest.ip6d_len + 1) * 8;)
    {
        requires_length = (hdr[i] != 0);
        if (requires_length && i + 1 >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        switch (hdr[i])
        {
            case 0:
                printf("Pad1");
                i += 1;
                continue;

            case 1:
                printf("PadN (%u)", hdr[i + 1]);
                i += hdr[i + 1] + 2;
                continue;

            default:
                printf("Unknown");
                i += hdr[i + 1] + 2;
                break;
        }
        if (i < offset + (dest.ip6d_len + 1) * 8)
        {
            printf(", ");
        }
    }
    printf("\n");

    return dest.ip6d_nxt;
}

static ssize_t ipv6_dump_extension_mobility_noop(const struct ob_protocol* buffer, ssize_t offset)
{
    /**
     * NOOP
     */

    (void) buffer;
    (void) offset;

    offset += (ssize_t) sizeof(uint16_t);
    return offset;
}

static ssize_t ipv6_dump_extension_mobility_home_test_init(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_hti hti;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_hti) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hti, &hdr[offset], sizeof(struct ip6_mobi_hti));

    printf("Home init cookie : %lu", be64toh(hti.ip6m_hic));

    return sizeof(struct ip6_mobi_hti);
}

static ssize_t ipv6_dump_extension_mobility_care_of_init_test(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_coti coti;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_coti) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&coti, &hdr[offset], sizeof(struct ip6_mobi_coti));

    printf("Care of init cookie : %lu", be64toh(coti.ip6m_cic));

    return sizeof(struct ip6_mobi_coti);
}

static ssize_t ipv6_dump_extension_mobility_home_test(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_hts hts;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_hts) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hts, &hdr[offset], sizeof(struct ip6_mobi_hts));

    printf("Home nonce index : %u, ", be16toh(hts.ip6m_hni));
    printf("Home init cookie : %lu, ", be64toh(hts.ip6m_hic));
    printf("Home keygen token : %lu", be64toh(hts.ip6m_hkt));

    return sizeof(struct ip6_mobi_hts);
}

static ssize_t ipv6_dump_extension_mobility_care_of_test(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_cot cot;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_cot) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&cot, &hdr[offset], sizeof(struct ip6_mobi_cot));

    printf("Care of nonce index : %u, ", be16toh(cot.ip6m_cni));
    printf("Care of init cookie : %lu, ", be64toh(cot.ip6m_cic));
    printf("Care of keygen token : %lu", be64toh(cot.ip6m_ckt));

    return sizeof(struct ip6_mobi_cot);
}

static ssize_t ipv6_dump_extension_mobility_binding_update(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_bum bum;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_bum) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&bum, &hdr[offset], sizeof(struct ip6_mobi_bum));

    printf("Sequence number : %u, ", be16toh(bum.ip6m_seq));
    printf("A : %u, ", bum.ip6m_a);
    printf("H : %u, ", bum.ip6m_h);
    printf("L : %u, ", bum.ip6m_l);
    printf("K : %u, ", bum.ip6m_k);
    printf("Lifetime : %u", be16toh(bum.ip6m_lft));

    return sizeof(struct ip6_mobi_bum);
}

static ssize_t ipv6_dump_extension_mobility_binding_acknowledgement(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_bak bak;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_bak) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&bak, &hdr[offset], sizeof(struct ip6_mobi_bak));

    printf("Status : %u, ", bak.ip6m_sts);
    printf("K : %u, ", bak.ip6m_k);
    printf("Sequence : %u, ", be16toh(bak.ip6m_seq));
    printf("Lifetime : %u", be16toh(bak.ip6m_lft));

    return sizeof(struct ip6_mobi_bak);
}

static ssize_t ipv6_dump_extension_mobility_binding_error(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_ber ber;
    const uint8_t* hdr = buffer->hdr;
    char home_address[INET6_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) sizeof(struct ip6_mobi_ber) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ber, &hdr[offset], sizeof(struct ip6_mobi_ber));

    inet_ntop(AF_INET6, ber.ip6m_had, home_address, INET6_ADDRSTRLEN);

    printf("Status : %u, ", ber.ip6m_sts);
    printf("Home address : %s", home_address);

    return sizeof(struct ip6_mobi_ber);
}

static ssize_t ipv6_dump_extension_mobility_handover_initiate(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_hoi hak;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_hoi) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hak, &hdr[offset], sizeof(struct ip6_mobi_hoi));

    printf("Sequence number : %u, ", be16toh(hak.ip6m_seq));
    printf("S : %u, ", hak.ip6m_s);
    printf("U : %u, ", hak.ip6m_u);
    printf("Code : %u", hak.ip6m_cod);

    return sizeof(struct ip6_mobi_hoi);
}

static ssize_t ipv6_dump_extension_mobility_handover_acknowledge(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_hoa hak;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_hoa) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hak, &hdr[offset], sizeof(struct ip6_mobi_hoa));

    printf("Sequence number : %u, ", be16toh(hak.ip6m_seq));
    printf("Code : %u", hak.ip6m_cod);

    return sizeof(struct ip6_mobi_hoa);
}

static ssize_t ipv6_dump_extension_mobility_fast_binding_update(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_fbu fbu;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_fbu) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&fbu, &hdr[offset], sizeof(struct ip6_mobi_fbu));

    printf("Sequence number : %u, ", be16toh(fbu.ip6m_seq));
    printf("A : %u, ", fbu.ip6m_a);
    printf("H : %u, ", fbu.ip6m_h);
    printf("L : %u, ", fbu.ip6m_l);
    printf("K : %u, ", fbu.ip6m_k);
    printf("Lifetime : %u", be16toh(fbu.ip6m_lft));

    return sizeof(struct ip6_mobi_fbu);
}

static ssize_t ipv6_dump_extension_mobility_fast_binding_acknowledge(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_fba fba;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_fba) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&fba, &hdr[offset], sizeof(struct ip6_mobi_fba));

    printf("Status : %u, ", fba.ip6m_sts);
    printf("K : %u, ", fba.ip6m_k);
    printf("Sequence number : %u, ", be16toh(fba.ip6m_seq));
    printf("Lifetime : %u", be16toh(fba.ip6m_lft));

    return sizeof(struct ip6_mobi_fba);
}

static ssize_t ipv6_dump_extension_mobility_home_agent_switch(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_has has;
    const uint8_t* hdr = buffer->hdr;
    char HomeAgentAddress[INET6_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) sizeof(struct ip6_mobi_has) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&has, &hdr[offset], sizeof(struct ip6_mobi_has));

    printf("Number of addresses : %u, ", has.ip6m_adc);

    offset += (ssize_t) sizeof(uint16_t);

    printf("Home agent addresses : ");
    for (uint8_t i = 0; i < has.ip6m_adc; ++i)
    {
        if (offset + (ssize_t) (8 * sizeof(uint16_t)) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        inet_ntop(AF_INET6, &hdr[offset], HomeAgentAddress, INET6_ADDRSTRLEN);
        offset += 16;
        printf("%s", HomeAgentAddress);
        if (i != has.ip6m_adc - 1)
        {
            printf(", ");
        }
    }

    return sizeof(struct ip6_mobi_has) + has.ip6m_adc * 16;
}

static ssize_t ipv6_dump_extension_mobility_heartbeat(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_hbt hbt;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_hbt) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hbt, &hdr[offset], sizeof(struct ip6_mobi_hbt));

    printf("U : %u, ", hbt.ip6m_u);
    printf("R : %u, ", hbt.ip6m_r);
    printf("Sequence number : %u", be32toh(hbt.ip6m_seq));

    return sizeof(struct ip6_mobi_hbt);
}

static ssize_t ipv6_dump_extension_mobility_binding_revocation_indication(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_bri bri;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_bri) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&bri, &hdr[offset], sizeof(struct ip6_mobi_bri));

    printf("Binding revocation type : %u, ", bri.ip6m_brt);
    printf("Revocation trigger : %u, ", bri.ip6m_rtr);
    printf("Sequence number : %u, ", be16toh(bri.ip6m_seq));
    printf("P : %u, ", bri.ip6m_p);
    printf("V : %u, ", bri.ip6m_v);
    printf("G : %u", bri.ip6m_g);

    return sizeof(struct ip6_mobi_bri);
}

static ssize_t ipv6_dump_extension_mobility_localized_routing_initiation(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_lri lri;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_lri) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&lri, &hdr[offset], sizeof(struct ip6_mobi_lri));

    printf("Sequence number : %u, ", be16toh(lri.ip6m_seq));
    printf("Lifetime : %u", be16toh(lri.ip6m_lft));

    return sizeof(struct ip6_mobi_lri);
}

static ssize_t ipv6_dump_extension_mobility_localized_routing_acknowledgement(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_lra lra;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_lra) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&lra, &hdr[offset], sizeof(struct ip6_mobi_lra));

    printf("Sequence number : %u, ", be16toh(lra.ip6m_seq));
    printf("U : %u, ", lra.ip6m_u);
    printf("Status : %u, ", lra.ip6m_sts);
    printf("Lifetime : %u", be16toh(lra.ip6m_lft));

    return sizeof(struct ip6_mobi_lra);
}

static ssize_t ipv6_dump_extension_mobility_update_notification(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_upn upn;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_upn) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&upn, &hdr[offset], sizeof(struct ip6_mobi_upn));

    printf("Sequence number : %u, ", be16toh(upn.ip6m_seq));
    printf("Reason : %u, ", be16toh(upn.ip6m_rsn));
    printf("A : %u, ", upn.ip6m_a);
    printf("D : %u", upn.ip6m_d);

    return sizeof(struct ip6_mobi_upn);
}

static ssize_t ipv6_dump_extension_mobility_update_notification_acknowledgement(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_upa upa;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_upa) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&upa, &hdr[offset], sizeof(struct ip6_mobi_upa));

    printf("Sequence number : %u, ", be16toh(upa.ip6m_seq));
    printf("Status : %u, ", upa.ip6m_sts);

    return sizeof(struct ip6_mobi_upa);
}

static ssize_t ipv6_dump_extension_mobility_flow_binding(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_flb flb;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_flb) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&flb, &hdr[offset], sizeof(struct ip6_mobi_flb));

    printf("Flow binding type : %u, ", be16toh(flb.ip6m_fbt));
    printf("Sequence number : %u, ", be16toh(flb.ip6m_seq));
    switch (be16toh(flb.ip6m_fbt))
    {
        case 1:
            printf("Trigger : %u, ", flb.ip6m_trs);
            printf("A : %u", flb.ip6m_a);
            break;

        case 2:
            printf("Status : %u", flb.ip6m_trs);
            break;

        default:
            break;
    }

    return sizeof(struct ip6_mobi_flb);
}

static ssize_t ipv6_dump_extension_mobility_subscription_query(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_squ squ;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_squ) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&squ, &hdr[offset], sizeof(struct ip6_mobi_squ));

    printf("Sequence number : %u", squ.ip6m_seq);

    return sizeof(struct ip6_mobi_squ);
}

static ssize_t ipv6_dump_extension_mobility_subscription_response(const struct ob_protocol* buffer, ssize_t offset)
{
    struct ip6_mobi_srs srs;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_mobi_srs) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&srs, &hdr[offset], sizeof(struct ip6_mobi_srs));

    printf("Sequence number : %u, ", srs.ip6m_seq);
    printf("I : %u", srs.ip6m_i);

    return sizeof(struct ip6_mobi_srs);
}

static uint8_t ipv6_dump_extension_mobility(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_mobi mobi;
    const uint8_t* hdr = buffer->hdr;
    ssize_t end;

    if (offset + (ssize_t) sizeof(struct ip6_mobi) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&mobi, &hdr[offset], sizeof(struct ip6_mobi));

    if (nodisp)
    {
        return mobi.ip6m_nxt;
    }

    end = offset + (mobi.ip6m_len + 1) * 8;

    if (end > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    printf("%-45s = ", "Mobility");
    printf("MH type : %u, ", mobi.ip6m_mht);
    printf("Checksum : 0x%x, ", be16toh(mobi.ip6m_chk));
    printf("Message data : [");

    offset += (ssize_t) sizeof(struct ip6_mobi);

    switch (mobi.ip6m_mht)
    {
        case 0: /* Binding refresh */
            offset += ipv6_dump_extension_mobility_noop(buffer, offset);
            break;

        case 1: /* Home test init */
            offset += ipv6_dump_extension_mobility_home_test_init(buffer, offset);
            break;

        case 2: /* Care of test init */
            offset += ipv6_dump_extension_mobility_care_of_init_test(buffer, offset);
            break;

        case 3: /* Home test */
            offset += ipv6_dump_extension_mobility_home_test(buffer, offset);
            break;

        case 4: /* Care of test */
            offset += ipv6_dump_extension_mobility_care_of_test(buffer, offset);
            break;

        case 5: /* Binding update */
            offset += ipv6_dump_extension_mobility_binding_update(buffer, offset);
            break;

        case 6: /* Binding acknowledgement */
            offset += ipv6_dump_extension_mobility_binding_acknowledgement(buffer, offset);
            break;

        case 7: /* Binding error */
            offset += ipv6_dump_extension_mobility_binding_error(buffer, offset);
            break;

        case 8: /* Fast binding update */
            offset += ipv6_dump_extension_mobility_fast_binding_update(buffer, offset);
            break;

        case 9: /* Fast binding acknowledgement */
            offset += ipv6_dump_extension_mobility_fast_binding_acknowledge(buffer, offset);
            break;

        case 10: /* Fast neighbor advertisement */
            offset += ipv6_dump_extension_mobility_noop(buffer, offset);
            break;

        case 11: /* Experimental mobility header */
            /**
             * There is nothing here, it is only options
             */
            break;

        case 12: /* Home agent switch message */
            offset += ipv6_dump_extension_mobility_home_agent_switch(buffer, offset);
            break;

        case 13: /* Heartbeat message */
            offset += ipv6_dump_extension_mobility_heartbeat(buffer, offset);
            break;

        case 14: /* Handover initiate message */
            offset += ipv6_dump_extension_mobility_handover_initiate(buffer, offset);
            break;

        case 15: /* Handover acknowledge message */
            offset += ipv6_dump_extension_mobility_handover_acknowledge(buffer, offset);
            break;

        case 16: /* Binding revocation message */
            offset += ipv6_dump_extension_mobility_binding_revocation_indication(buffer, offset);
            break;

        case 17: /* Localized routing information */
            offset += ipv6_dump_extension_mobility_localized_routing_initiation(buffer, offset);
            break;

        case 18: /* Localized routing acknowledgement */
            offset += ipv6_dump_extension_mobility_localized_routing_acknowledgement(buffer, offset);
            break;

        case 19: /* Update notification */
            offset += ipv6_dump_extension_mobility_update_notification(buffer, offset);
            break;

        case 20: /* Update notification acknowledgement */
            offset += ipv6_dump_extension_mobility_update_notification_acknowledgement(buffer, offset);
            break;

        case 21: /* Flow binding message */
            offset += ipv6_dump_extension_mobility_flow_binding(buffer, offset);
            break;

        case 22: /* Subscription query */
            offset += ipv6_dump_extension_mobility_subscription_query(buffer, offset);
            break;

        case 23: /* Subscription response */
            offset += ipv6_dump_extension_mobility_subscription_response(buffer, offset);
            break;

        default:
            printf("UNKNOWN %d", mobi.ip6m_mht);
            break;
    }
    printf("]\n");

    printf("%-45s = ", "Mobility options");
    for (ssize_t i = offset; i < end; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");

    return mobi.ip6m_nxt;
}

static uint8_t ipv6_dump_extension_host_identity(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_hip hip;
    const uint8_t* hdr = buffer->hdr;
    char SenderHostIdentity[INET6_ADDRSTRLEN] = {0};
    char ReceiverHostIdentity[INET6_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) sizeof(struct ip6_hip))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hip, &hdr[offset], sizeof(struct ip6_hip));

    if (nodisp)
    {
        return hip.ip6h_nxt;
    }

    inet_ntop(AF_INET6, hip.ip6h_shi, SenderHostIdentity, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, hip.ip6h_rhi, ReceiverHostIdentity, INET6_ADDRSTRLEN);

    printf("%-45s = ", "Host identity");
    printf("Packet type : %u, ", hip.ip6h_pkt);
    printf("Version : %u, ", hip.ip6h_ver);
    printf("Checksum : %u, ", be16toh(hip.ip6h_chk));
    printf("Controls : %u, ", be16toh(hip.ip6h_ctr));
    printf("Sender host identity tag : %s, ", SenderHostIdentity);
    printf("Receiver host identity tag : %s", ReceiverHostIdentity);

    // Parameters https://www.rfc-editor.org/rfc/rfc7401.html#section-5

    return hip.ip6h_nxt;
}

static uint8_t ipv6_dump_extension_shim6(const struct ob_protocol* buffer, ssize_t offset, bool nodisp)
{
    struct ip6_shim shm;
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(struct ip6_shim) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&shm, &hdr[offset], sizeof(struct ip6_shim));

    if (nodisp)
    {
        return shm.ip6s_nxt;
    }

    printf("%-45s = ", "Shim6");
    printf("P : %u, ", shm.ip6s_flw.ip6s_p0);

    if (shm.ip6s_flw.ip6s_p0 == 1)
    {
        uint64_t rct = shm.ip6s_flw.ip6s_rct;
        printf("Receiver context tag : %lu\n", rct);
    }
    else
    {
        uint64_t tsf = shm.ip6s_flw.ip6s_tsf;
        printf("Type : %u, ", shm.ip6s_flw.ip6s_typ);
        printf("Type specific : %u, ", shm.ip6s_flw.ip6s_tys);
        printf("S : %u, ", shm.ip6s_flw.ip6s_s);
        printf("Checksum : %u, ", be16toh(shm.ip6s_flw.ip6s_chk));
        printf("Type specific format : %lu\n", tsf);
    }

    return shm.ip6s_nxt;
}

static ssize_t ipv6_dump_extension_header(const struct ob_protocol* buffer, ssize_t offset, uint8_t* NextHeader, bool nonverbose)
{
    const uint8_t* hdr = buffer->hdr;
    ssize_t HeaderExtensionLength = 0;
    bool nodisp = false;

    if (nonverbose)
    {
        nodisp = true;
    }

    while (1)
    {
        if (offset + 1 >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        HeaderExtensionLength = hdr[offset + 1];

        switch (*NextHeader)
        {
            case 0: /* Hop-by-hop */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_hop_by_hop(buffer, offset, nonverbose);
                HeaderExtensionLength = (hdr[offset + 1] + 1) * 8;
                nodisp = true;
                break;

            case 43: /* Routing */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_routing(buffer, offset, nonverbose);
                HeaderExtensionLength = (hdr[offset + 1] + 1) * 8;
                nodisp = true;
                break;

            case 44: /* Fragment */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_fragment(buffer, offset, nonverbose);
                nodisp = true;
                break;

            case 50: /* Encapsulating security payload */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_encapsulating_security(buffer, offset, nonverbose);
                nodisp = true;
                /**
                 * Not implemented
                 */
                return buffer->length;

            case 51: /* Authentication header */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_authentication(buffer, offset, nonverbose);
                HeaderExtensionLength = ((hdr[offset + 1] + 2) * 4);
                nodisp = true;
                break;

            case 60: /* Destination options */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_destination(buffer, offset, nonverbose);
                nodisp = true;
                break;

            case 135: /* Mobility */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_mobility(buffer, offset, nonverbose);
                HeaderExtensionLength = (hdr[offset + 1] + 1) * 8;
                nodisp = true;
                break;

            case 139: /* Host identity protocol */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_host_identity(buffer, offset, nonverbose);
                nodisp = true;
                break;

            case 140: /* Shim6 protocol */
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = ipv6_dump_extension_shim6(buffer, offset, nonverbose);
                nodisp = true;
                break;

            case 253: /* Reserved */
            case 254:
                if (!nodisp)
                {
                    printf("--- BEGIN IPv6 OPTIONS ---\n");
                }
                *NextHeader = hdr[offset];
                nodisp = true;
                break;

            default:
                return offset;
        }

        if (HeaderExtensionLength <= 0)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }

        offset += HeaderExtensionLength;
    }
}

static void ipv6_dump_v3(const struct ip6_hdr* ipv6)
{
    uint8_t Version;
    uint8_t TrafficClass;
    uint32_t FlowLabel;
    uint32_t Flow;

    char ip_source[INET6_ADDRSTRLEN] = {0};
    char ip_dest[INET6_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET6, &(ipv6->ip6_src), ip_source, INET6_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), ip_dest, INET6_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN IPv6 MESSAGE ---\n");

    Flow = be32toh(ipv6->ip6_flow);

    Version = (uint8_t) (Flow >> 28);
    TrafficClass = (Flow >> 20) & 0xFF;
    FlowLabel = (Flow) & ((1UL << 20) - 1);

    printf("%-45s = 0x%x\n", "Version", Version);
    printf("%-45s = 0x%x\n", "Traffic Class", TrafficClass);
    printf("%-45s = 0x%x\n", "Flow Label", FlowLabel);
    printf("%-45s = %u\n", "Length", be16toh(ipv6->ip6_plen));
    printf("%-45s = %u\n", "Hop Limit", ipv6->ip6_hlim);
    printf("%-45s = %s\n", "Source", ip_source);
    printf("%-45s = %s\n", "Destination", ip_dest);
}

static void ipv6_dump_v2(const struct ip6_hdr* ipv6)
{
    char ip_source[INET6_ADDRSTRLEN] = {0};
    char ip_dest[INET6_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET6, &(ipv6->ip6_src), ip_source, INET6_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET6, &(ipv6->ip6_dst), ip_dest, INET6_ADDRSTRLEN * sizeof(char));

    printf("IPv6 => ");
    printf("Next Header : %s, ", ipv6_get_protocol(ipv6->ip6_nxt));
    printf("Source : %s, ", ip_source);
    printf("Destination : %s\n", ip_dest);
}

void ipv6_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct ip6_hdr ipv6;
    ssize_t offset;
    struct ip6_pseudo_header pseudo_header;

    if ((ssize_t) sizeof(struct ip6_hdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ipv6, buffer->hdr, sizeof(struct ip6_hdr));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> IPv6 ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ipv6_dump_v2(&ipv6);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ipv6_dump_v3(&ipv6);
            break;
    }

    offset = ipv6_dump_extension_header(buffer, sizeof(struct ip6_hdr), &(ipv6.ip6_nxt), false);

    transport_cast(ipv6.ip6_nxt, buffer);

    buffer->length -= offset;
    buffer->hdr = &hdr[offset];

    /**
     * Save values of IP version, addresses, length and next header for TCP and UDP
     * checksum calculation and segment reassembly
     */
    pseudo_header.ip6_version = (uint8_t) (be32toh(ipv6.ip6_flow) >> 28);
    pseudo_header.ip6_dst = ipv6.ip6_dst;
    pseudo_header.ip6_src = ipv6.ip6_src;
    pseudo_header.ip6_len = be16toh(ipv6.ip6_plen) - (uint16_t) ((uint16_t) (offset) - sizeof(struct ip6_hdr));
    pseudo_header.ip6_next_header = ipv6.ip6_nxt;

    buffer->pseudo_header = &pseudo_header;
    buffer->pseudo_header_length = sizeof(struct ip6_pseudo_header);

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }

    buffer->pseudo_header = NULL;
}
