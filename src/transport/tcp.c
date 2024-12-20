#include <stdio.h>
#include <endian.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/tcp.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/time.h"
#include "generic/bytes.h"
#include "transport/tcp.h"
#include "generic/protocol.h"
#include "application/application.h"

struct tcp_reassembly_htable_element* tcp_htable[1 << 16] = {NULL};

static const char* tcp_get_option(uint8_t Option)
{
    switch (Option)
    {
        case 0:
            return "End of options";

        case 1:
            return "NOOP";
        
        case 2:
            return "Maximum segment size";

        case 3:
            return "Window scale";

        case 4:
            return "Selective acknowledgement OK";

        case 5:
            return "Selective acknowledgement";

        case 8:
            return "Timestamp / echo";

        case 27:
            return "Quick-start response";

        case 28:
            return "User timeout";

        case 29:
            return "TCP authentication option";

        case 30:
            return "Multipath TCP";

        case 34:
            return "TCP fast-open cookie";

        case 69:
            return "Encryption negociation";

        default:
            return "Unknown";
    }
}

/**
 * @brief Hash a TCP buffer for insertion in a hashtable
 * @param buffer The buffer to hash
 * @param source_port Source port of the TCP buffer
 * @param destination_port Destination port of the TCP buffer
 * @return XORd value of all hashed fields
 */
static uint16_t tcp_hash_element(const struct ob_protocol* buffer, uint16_t source_port, uint16_t destination_port)
{
    uint16_t hash = 0;
    uint8_t ip_version;
    struct ip_pseudo_header iph;
    struct ip6_pseudo_header ip6h;

    ip_version = * (uint8_t*) buffer->pseudo_header;

    switch (ip_version)
    {
        case 4:
            memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
            hash ^= (uint16_t) (iph.ip_dst.s_addr);
            hash ^= (uint16_t) (iph.ip_dst.s_addr >> 16);
            hash ^= (uint16_t) (iph.ip_src.s_addr);
            hash ^= (uint16_t) (iph.ip_src.s_addr >> 16);
            break;

        case 6:
            memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
            for (uint8_t i = 0; i < 8; ++i)
            {
                hash ^= ip6h.ip6_dst.s6_addr16[i];
                hash ^= ip6h.ip6_src.s6_addr16[i];
            }
            break;
    }

    hash ^= source_port;
    hash ^= destination_port;

    return hash;
}

/**
 * @brief Find or insert a new packet linked list in a hashtable
 * @param buffer The buffer to hash
 * @param source_port Source port of the TCP buffer
 * @param destination_port Destination port of the TCP buffer
 * @return Pointer to the existing or newly inserted element
 */
static struct tcp_reassembly_htable_element* tcp_find_hashtable(const struct ob_protocol* buffer, uint16_t source_port, uint16_t destination_port)
{
    uint16_t hash = tcp_hash_element(buffer, source_port, destination_port);
    struct tcp_reassembly_htable_element* begin = tcp_htable[hash];
    struct tcp_reassembly_htable_element* previous;

    struct ip_pseudo_header iph;
    struct ip6_pseudo_header ip6h;
    uint8_t ip_version;

    ip_version = * (uint8_t*) buffer->pseudo_header;

    /**
     * If the list is empty at this index, create the first element
     */
    if (begin == NULL)
    {
        tcp_htable[hash] = malloc(sizeof(struct tcp_reassembly_htable_element));
        if (tcp_htable[hash] == NULL)
        {
            longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
        }
        tcp_htable[hash]->source_port = source_port;
        tcp_htable[hash]->destination_port = destination_port;
        tcp_htable[hash]->buffers = NULL;
        tcp_htable[hash]->next = NULL;

        switch (ip_version)
        {
            case 4:
                memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
                tcp_htable[hash]->ipv4.destination_ip.s_addr = iph.ip_dst.s_addr;
                tcp_htable[hash]->ipv4.source_ip.s_addr = iph.ip_src.s_addr;
                break;

            case 6:
                memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
                tcp_htable[hash]->ipv6.destination_ip = ip6h.ip6_dst;
                tcp_htable[hash]->ipv6.source_ip = ip6h.ip6_src;
                break;
        }

        return tcp_htable[hash];
    }

    previous = begin;

    /**
     * Compare with every element already in the list
     */
    while (begin != NULL)
    {
        switch (ip_version)
        {
            case 4:
                memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
                if (begin->source_port == source_port &&
                begin->destination_port == destination_port &&
                begin->ipv4.destination_ip.s_addr == iph.ip_dst.s_addr &&
                begin->ipv4.source_ip.s_addr == iph.ip_src.s_addr)
                {
                    return begin;
                }
                break;

            case 6:
                memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
                if (begin->source_port == source_port &&
                begin->destination_port == destination_port &&
                memcmp(begin->ipv6.destination_ip.s6_addr16, ip6h.ip6_dst.s6_addr16, sizeof(struct in6_addr)) == 0 &&
                memcmp(begin->ipv6.source_ip.s6_addr16, ip6h.ip6_src.s6_addr16, sizeof(struct in6_addr)) == 0)
                {
                    return begin;
                }
                break;
        }
        previous = begin;
        begin = begin->next;
    }

    /**
     * We reached the end of the list without matching, create a new element
     */
    previous->next = malloc(sizeof(struct tcp_reassembly_htable_element));
    if (previous->next == NULL)
    {
        longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
    }
    previous->next->source_port = source_port;
    previous->next->destination_port = destination_port;
    previous->next->buffers = NULL;
    previous->next->next = NULL;

    switch (ip_version)
    {
        case 4:
            memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
            previous->next->ipv4.destination_ip.s_addr = iph.ip_dst.s_addr;
            previous->next->ipv4.source_ip.s_addr = iph.ip_src.s_addr;
            break;

        case 6:
            memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
            previous->next->ipv6.destination_ip = ip6h.ip6_dst;
            previous->next->ipv6.source_ip = ip6h.ip6_src;
            break;
    }

    return previous->next;
}

/**
 * @brief Insert a fragment inside a packet linked list
 * @param buffer The buffer to insert
 * @param offset Offset of the packet inside the buffer
 * @param length Length of the underlying buffer
 * @param Seq Sequence number
 * @param SYN SYN flag of the buffer
 * @param PSH PSH flag of the buffer
 * @param htable_element Pointer to the beginning of the linked list, obtained with tcp_find_hashtable()
 */
static void tcp_insert_fragment(const struct ob_protocol* buffer, ssize_t offset, unsigned long length, uint32_t Seq, uint8_t SYN, uint8_t PSH, struct tcp_reassembly_htable_element* htable_element)
{
    const uint8_t* hdr = buffer->hdr;
    if (offset + (ssize_t) length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    if (length == 0 && !SYN)
    {
        return;
    }

    if (htable_element->buffers == NULL)
    {
        htable_element->buffers = malloc(sizeof(struct tcp_reassembly));
        if (htable_element->buffers == NULL)
        {
            longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
        }
        htable_element->buffers->buffer_length = length;
        htable_element->buffers->PSH = PSH ? 1 : 0;
        htable_element->buffers->SYN = SYN ? 1 : 0;
        htable_element->buffers->Seq = Seq;
        htable_element->buffers->index = buffer->packet_index;
        htable_element->buffers->next = NULL;
        htable_element->buffers->buffer = malloc(length * sizeof(uint8_t));
        if (htable_element->buffers->buffer == NULL)
        {
            free(htable_element->buffers);
            htable_element->buffers = NULL;
            longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
        }
        memcpy(htable_element->buffers->buffer, &hdr[offset], length);
        return;
    }
    struct tcp_reassembly* identified = htable_element->buffers;
    struct tcp_reassembly* previous = htable_element->buffers;
    while (identified->Seq <= Seq)
    {
        previous = identified;
        identified = identified->next;
        if (identified == NULL)
        {
            break;
        }
    }
    struct tcp_reassembly* current = malloc(sizeof(struct tcp_reassembly));
    if (current == NULL)
    {
        longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
    }
    current->buffer_length = length;
    current->Seq = Seq;
    current->next = identified;
    current->index = buffer->packet_index;
    current->SYN = SYN ? 1 : 0;
    current->PSH = PSH ? 1 : 0;
    current->buffer = malloc(length * sizeof(uint8_t));
    if (current->buffer == NULL)
    {
        free(current);
        previous->next = identified;
        longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
    }
    /**
     * This probably means `Insert at begin`
     */
    if (previous == identified)
    {
        htable_element->buffers = current;
    }
    else
    {
        previous->next = current;
    }
    memcpy(current->buffer, &hdr[offset], length);
    return;
}

/**
 * @brief Check if there is a list of segments that can be reassembled
 * @param htable_element Pointer to the beginning of the linked list, obtained with tcp_find_hashtable()
 * @return - -1 if there is no segments that can be reassembled
 * @return - `index` of the first segment that can be reassembled
 */
static int tcp_is_complete(const struct tcp_reassembly_htable_element* htable_element)
{
    struct tcp_reassembly* current = htable_element->buffers;
    bool found = true;
    int index = 0;
    int saved_index = 0;
    if (current == NULL)
    {
        return -1;
    }
    while (current->next != NULL)
    {
        if (current->SYN == 1)
        {
            saved_index = index;
            found = true;
        }
        if (current->PSH == 1 && found)
        {
            return saved_index;
        }
        if (current->Seq + current->buffer_length + (current->SYN == 0 ? 0 : 1) != current->next->Seq)
        {
            found = false;
        }
        current = current->next;
        ++index;
    }
    return (current->PSH == 1 && found) ? saved_index : -1;
}

/**
 * @brief Reassemble a list of TCP segments into one that will be set in a buffer
 * @param buffer Pointer to an ob_protocol structure that will contain the reassembled buffer after this call
 * @param htable_element Pointer to the beginning of the linked list, obtained with tcp_find_hashtable()
 * @param from Index of the first segment to reassemble
 */
static void tcp_reassemble(struct ob_protocol* buffer, struct tcp_reassembly_htable_element* htable_element, int from)
{
    unsigned long total_buffer_length = 0;
    unsigned long current_offset = 0;
    uint8_t* total_buffer = NULL;
    struct tcp_reassembly** previous_packet;
    struct tcp_reassembly* from_packet;
    struct tcp_reassembly* to_delete;
    struct tcp_reassembly* to_move_after;
    struct tcp_reassembly* current = htable_element->buffers;
    int packet_count = 0;
    int index = 0;

    /**
     * Find region
     */
    if (current == NULL)
    {
        longjmp(*(buffer->catcher), OB_ERROR_DATA_UNAVAILABLE);
    }

    previous_packet = &current;

    /**
     * Find initial packet
     */
    while (current->next != NULL && index != from)
    {
        ++index;
        previous_packet = &current;
        current = current->next;
    }

    if (index != from)
    {
        longjmp(*(buffer->catcher), OB_ERROR_DATA_UNAVAILABLE);
    }

    from_packet = current;

    /**
     * Calculate buffer length and allocate
     */
    while (current->next != NULL && current->PSH == 0)
    {
        ++packet_count;
        total_buffer_length += current->buffer_length;
        current = current->next;
    }
    total_buffer_length += current->buffer_length;
    total_buffer = malloc(total_buffer_length * sizeof(uint8_t));

    if (total_buffer == NULL)
    {
        longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
    }
    
    /**
     * Go back to initial packet
     */
    current = from_packet;

    /** 
     * Copy data
     */
    if (packet_count > 1)
    {
        printf("\033[1m[Reassembly of packets ");
    }
    while (current->next != NULL && current->PSH == 0)
    {
        if (packet_count > 1)
        {
            printf("%lld, ", current->index);
        }
        memcpy(&total_buffer[current_offset], current->buffer, current->buffer_length);
        current_offset += current->buffer_length;
        to_delete = current->next;
        free(current->buffer);
        free(current);
        current = to_delete;
    }
    if (packet_count > 1)
    {
        printf("%lld]\033[22m", current->index);
        if (buffer->verbosity_level != OB_VERBOSITY_LEVEL_LOW)
        {
            printf("\n");
        }
        else
        {
            printf(" ");
        }
    }

    memcpy(&total_buffer[current_offset], current->buffer, current->buffer_length);
    to_move_after = current->next;
    free(current->buffer);
    free(current);
    current = NULL;

    from_packet = NULL;

    /**
     * Restore linked list
     */
    if ((*previous_packet) != NULL)
    {
        (*previous_packet)->next = to_move_after;
    }
    else
    {
        htable_element->buffers = to_move_after;
    }

    free(buffer->orig);
    buffer->orig = NULL;

    buffer->orig = total_buffer;
    buffer->hdr = total_buffer;
    buffer->length = (ssize_t) total_buffer_length;
    buffer->reassembled = true;
}

static void tcp_options_dump_default(const struct ob_protocol* buffer, ssize_t offset, uint8_t Length)
{
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) Length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    if (Length > 2)
    {
        printf(" = 0x");
        for (uint8_t j = 2; j < Length; ++j)
        {
            printf("%x", hdr[offset + j]);
        }
    }
    printf("\n");
}

static void tcp_options_dump_sack(const struct ob_protocol* buffer, ssize_t offset, uint8_t Length)
{
    const uint8_t* hdr = buffer->hdr;
    uint32_t LeftEdge;
    uint32_t RightEdge;
    uint8_t count = 0;

    if (offset + Length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    printf(" = [");
    for (uint8_t j = 2; j < Length; j += 2 * sizeof(uint32_t))
    {
        ++count;
        LeftEdge = read_u32_unaligned(&hdr[offset + j]);
        RightEdge = read_u32_unaligned(&hdr[offset + (ssize_t) (j + sizeof(uint32_t))]);

        printf("Left edge of block %u : %u, ", count, be32toh(LeftEdge));
        printf("Right edge of block %u : %u", count, be32toh(RightEdge));

        if (j < Length - 2 * sizeof(uint32_t))
        {
            printf(", ");
        }
    }
    printf("]\n");
}

static void tcp_options_dump_timestamp(const struct ob_protocol* buffer, ssize_t offset, uint8_t Length)
{
    const uint8_t* hdr = buffer->hdr;
    uint32_t timestamp_sec, echo_sec;
    struct timeval timestamp, echo;
    char timestamp_str[150];
    char echo_str[150];

    if (offset + (ssize_t) (2 + 2 * sizeof(uint32_t)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    if (Length != 2 * sizeof(uint32_t) + 2 * sizeof(uint8_t))
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }
    memcpy(&timestamp_sec, &hdr[offset + 2], sizeof(uint32_t));
    memcpy(&echo_sec, &hdr[offset + 6], sizeof(uint32_t));
    timestamp.tv_sec = timestamp_sec;
    timestamp.tv_usec = 0;
    echo.tv_sec = echo_sec;
    echo.tv_usec = 0;
    printf(" = %s / %s\n", get_timestamp_utc(&timestamp, timestamp_str), get_timestamp_utc(&echo, echo_str));
}

static void tcp_options_dump_quickstart(const struct ob_protocol* buffer, ssize_t offset, uint8_t Length)
{
    const uint8_t* hdr = buffer->hdr;
    struct tcp_quickstart tq;

    if (Length != sizeof(struct tcp_quickstart) + 2 * sizeof(uint8_t))
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }
    if (offset + (ssize_t) Length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&tq, &hdr[offset + 2], sizeof(struct tcp_quickstart));

    printf(" = Func : %u, Rate request : %u, QS ttl : %u, QS Nonce : %u, R : %u\n", tq.function, tq.rate_request, tq.QS_ttl, tq.QS_nonce, tq.R);
}

static void tcp_options_dump_usertimeout(const struct ob_protocol* buffer, ssize_t offset, uint8_t Length)
{
    const uint8_t* hdr = buffer->hdr;
    struct tcp_usertimeout tu;

    if (Length != sizeof(struct tcp_usertimeout) + 2 * sizeof(uint8_t))
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }
    if (offset + (ssize_t) Length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&tu, &hdr[offset + 2], sizeof(struct tcp_usertimeout));

    printf(" = G : %u, User timeout : %u\n", tu.G, tu.user_timeout);
}

static void tcp_options_dump_authentication(const struct ob_protocol* buffer, ssize_t offset, ssize_t Length)
{
    const uint8_t* hdr = buffer->hdr;
    if (Length < (ssize_t) (4 * sizeof(uint8_t)))
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }
    if (offset + (ssize_t) Length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf(" = Key ID : %u, R next key ID : %u, ", hdr[offset + 2], hdr[offset + 3]);
    printf("MAC = ");
    for (ssize_t i = offset + 4; i < Length; ++i)
    {
        printf("%02x", hdr[i]);
    }
}

static void tcp_options_dump(const struct ob_protocol* buffer, ssize_t offset, ssize_t max_length)
{
    const uint8_t* hdr = buffer->hdr;

    uint8_t Option;
    uint8_t Length;

    printf("--- BEGIN TCP OPTIONS ---\n");

    for (ssize_t i = offset; i < max_length;)
    {
        if (i + 1 >= buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        Option = hdr[i];
        Length = hdr[i + 1];

        printf("%-45s", tcp_get_option(Option));

        switch (Option)
        {
            case 0: /* End of options */
                printf("\n");
                return;

            case 1: /* NOOP */
                printf("\n");
                ++i;
                continue;

            case 2: /* Maximum segment size */
                printf(" = %u\n", be32toh(read_u32_unaligned(&hdr[i + 2])));
                break;

            case 3: /* Window scale */
                printf(" = %u\n", hdr[i + 2]);
                break;

            case 4: /* SACK permitted */
                /**
                 * NOOP
                 */
                printf("\n");
                break;

            case 5: /* SACK */
                tcp_options_dump_sack(buffer, i, Length);
                break;

            case 8: /* Timestamps */
                tcp_options_dump_timestamp(buffer, i, Length);
                break;

            case 27: /* QuickStart */
                tcp_options_dump_quickstart(buffer, i,  Length);
                break;

            case 28: /* User timeout */
                tcp_options_dump_usertimeout(buffer, i, Length);
                break;

            case 29: /* Authentication */
                tcp_options_dump_authentication(buffer, i, Length);
                break;

            case 30: /* Multipath */
                /**
                 * Not implemented
                 */
                break;

            case 69: /* Encryption negociation */
                /**
                 * Not implemented
                 */
                break;

            case 34: /* Fast open cookie */
            default:
                tcp_options_dump_default(buffer, i, Length);
                break;
        }
        i += Length;
    }
}

static void tcp_dump_v3(const struct ob_protocol* buffer, struct tcphdr* th)
{
    uint8_t ip_version;
    uint8_t* hdr = buffer->hdr;
    struct ip_pseudo_header iph;
    struct ip6_pseudo_header ip6h;
    ssize_t checksum_offset = offsetof(struct tcphdr, th_sum);
    uint32_t checksum;

    ip_version = * (uint8_t*) buffer->pseudo_header;
    
    printf("--- BEGIN TCP MESSAGE ---\n");

    printf("%-45s = %u (%s)\n", "Source Port", be16toh(th->th_sport), application_get_name(T_TRANSPORT_TCP, be16toh(th->th_sport)));
    printf("%-45s = %u (%s)\n", "Destination Port", be16toh(th->th_dport), application_get_name(T_TRANSPORT_TCP, be16toh(th->th_dport)));
    printf("%-45s = %u\n", "Sequence Number", be32toh(th->th_seq));
    printf("%-45s = %u\n", "ACK", be32toh(th->th_ack));
    printf("%-45s = %u\n", "Data Offset", th->th_off);
    printf("%-45s = %u\n", "URG", (th->th_flags & TH_URG) ? 1 : 0);
    printf("%-45s = %u\n", "ACK", (th->th_flags & TH_ACK) ? 1 : 0);
    printf("%-45s = %u\n", "PSH", (th->th_flags & TH_PUSH) ? 1 : 0);
    printf("%-45s = %u\n", "RST", (th->th_flags & TH_RST) ? 1 : 0);
    printf("%-45s = %u\n", "SYN", (th->th_flags & TH_SYN) ? 1 : 0);
    printf("%-45s = %u\n", "FIN", (th->th_flags & TH_FIN) ? 1 : 0);
    printf("%-45s = %u\n", "Window Size", be16toh(th->th_win));
    printf("%-45s = 0x%x", "Checksum", be16toh(th->th_sum));

    switch (ip_version)
    {
        case 4:
            memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
            checksum = be16toh(th->th_sum);
            checksum += iph.ip_len;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_dst.s_addr));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_dst.s_addr >> 16));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_src.s_addr));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += be16toh((uint16_t) (iph.ip_src.s_addr >> 16));
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += iph.ip_proto;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            hdr[checksum_offset] = (uint8_t) (checksum >> 8);
            hdr[checksum_offset + 1] = (uint8_t) (checksum);
            break;

        case 6:
            memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
            checksum = be16toh(th->th_sum);
            checksum += ip6h.ip6_len;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            for (uint8_t i = 0; i < 8; ++i)
            {
                checksum += be16toh(ip6h.ip6_src.s6_addr16[i]);
                checksum += (checksum >> 16);
                checksum = (uint16_t) checksum;
                checksum += be16toh(ip6h.ip6_dst.s6_addr16[i]);
                checksum += (checksum >> 16);
                checksum = (uint16_t) checksum;
            }
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            checksum += ip6h.ip6_next_header;
            checksum += (checksum >> 16);
            checksum = (uint16_t) checksum;
            hdr[checksum_offset] = (uint8_t) (checksum >> 8);
            hdr[checksum_offset + 1] = (uint8_t) (checksum);
            break;
    }
    
    printf(" %s\n", checksum_16bitonescomplement_validate(buffer, buffer->length, be16toh(th->th_sum), true));
    printf("%-45s = %u\n", "Urgent Pointer", be16toh(th->th_urp));
}

static void tcp_dump_v2(const struct tcphdr* th)
{
    printf("TCP => ");
    printf("Source Port : %u, ", be16toh(th->th_sport));
    printf("Destination Port : %u\n", be16toh(th->th_dport));
}

void tcp_dump(struct ob_protocol* buffer)
{
    ssize_t header_size;
    struct tcphdr th;
    int tcp_complete_value;
    struct tcp_reassembly_htable_element* htable_element;

    if ((ssize_t) sizeof(struct tcphdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    
    memcpy(&th, buffer->hdr, sizeof(struct tcphdr));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> TCP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            tcp_dump_v2(&th);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            tcp_dump_v3(buffer, &th);
            break;
    }

    header_size = th.th_off * sizeof(uint32_t);

    if (header_size > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    if (buffer->verbosity_level == OB_VERBOSITY_LEVEL_HIGH && (unsigned long) header_size > 5L * sizeof(uint32_t))
    {
        tcp_options_dump(buffer, sizeof(struct tcphdr), header_size);
    }
    
    if (header_size == buffer->length)
    {
        return;
    }

    htable_element = tcp_find_hashtable(buffer, be16toh(th.th_sport), be16toh(th.th_dport));

    tcp_insert_fragment(buffer, header_size, (unsigned long) (buffer->length - header_size), be32toh(th.th_seq), th.th_flags & TH_SYN, th.th_flags & TH_PUSH, htable_element);
    
    tcp_complete_value = tcp_is_complete(htable_element);

    if (tcp_complete_value == -1)
    {
        printf("\033[1m[Received partial packet, saved for later]\033[22m\n");
        return;
    }

    tcp_reassemble(buffer, htable_element, tcp_complete_value);

    if (!application_cast(T_TRANSPORT_TCP, be16toh(th.th_sport), buffer))
    {
        application_cast(T_TRANSPORT_TCP, be16toh(th.th_dport), buffer);
    }

    buffer->dump(buffer);
}
