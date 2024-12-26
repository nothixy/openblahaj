#include <stdio.h>
#include <endian.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip4.h"
#include "network/ip6.h"
#include "generic/bytes.h"
#include "transport/sctp.h"
#include "generic/protocol.h"
#include "generic/terminal.h"
#include "application/application.h"

struct sctp_reassembly_htable_element* sctp_htable[1 << 16] = {NULL};

static const char* sctp_get_parameter_type(uint16_t Type)
{
    switch (Type)
    {
        case 0x1:
            return "Heartbeat info";

        case 0x5:
            return "IPv4 address";

        case 0x6:
            return "IPv6 address";

        case 0x7:
            return "State cookie";

        case 0x8:
            return "Unrecognized parameter";

        case 0x9:
            return "Cookie preservative";

        case 0xb:
            return "Host name address";

        case 0xc:
            return "Supported address types";

        case 0xd:
            return "Outgoing SSN reset request parameter";

        case 0xe:
            return "Incoming SSN reset request parameter";

        case 0xf:
            return "SSN / TSN reset request parameter";

        case 0x10:
            return "Re-configuration response parameter";

        case 0x11:
            return "Add outgoing streams request parameter";

        case 0x12:
            return "Add incoming streams request parameter";

        case 0x8000:
            return "Reserved for ECN capable";

        case 0x8001:
            return "Zero checksum acceptable";

        case 0x8002:
            return "Random";

        case 0x8003:
            return "Chunk list";

        case 0x8004:
            return "Requested HMAC algorithm parameter";

        case 0x8005:
            return "Padding";

        case 0x8008:
            return "Supported extensions";

        case 0xC000:
            return "Forward TSN supported";

        case 0xC001:
            return "Add IP address";

        case 0xC002:
            return "Delete IP address";

        case 0xC003:
            return "Error cause indication";

        case 0xC004:
            return "Set primary address";

        case 0xC005:
            return "Success indication";

        case 0xC006:
            return "Adaptation layer indication";

        default:
            return "Unknown";
    }
}

static const char* sctp_get_chunk_type(uint8_t Type)
{
    switch (Type)
    {
        case 0:
            return "Data";

        case 1:
            return "Init";

        case 2:
            return "Init ACK";

        case 3:
            return "SACK";

        case 4:
            return "Heartbeat";

        case 5:
            return "Heartbeat ACK";

        case 6:
            return "Abort";

        case 7:
            return "Shutdown";

        case 8:
            return "Shutdown ACK";

        case 9:
            return "Error";

        case 10:
            return "Cookie echo";

        case 11:
            return "Cookie ACK";

        case 12:
            return "ECNE";

        case 13:
            return "CWR";

        case 14:
            return "Shutdown complete";

        case 15:
            return "Auth";

        case 64:
            return "I-Data";

        case 128:
            return "ASCONF-ACK";

        case 130:
            return "RE-Config";

        case 132:
            return "Pad";

        case 192:
            return "Forward-TSN";

        case 193:
            return "ASCONF";

        case 194:
            return "I-Forward-TSN";

        default:
            return "Unknown";
    }
}

/**
 * @brief Hash a SCTP buffer for insertion in a hashtable
 * @param buffer The buffer to hash
 * @param source_port Source port of the SCTP buffer
 * @param destination_port Destination port of the SCTP buffer
 * @return XORd value of all hashed fields
 */
static uint16_t sctp_hash_element(const struct ob_protocol* buffer, uint16_t source_port, uint16_t destination_port, uint16_t StreamID)
{
    uint16_t hash = 0;
    uint8_t ip_version;
    struct ip_pseudo_header iph;
    struct ip6_pseudo_header ip6h;

    ip_version = *(uint8_t*) buffer->pseudo_header;

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

        default:
            break;
    }

    hash ^= source_port;
    hash ^= destination_port;
    hash ^= StreamID;

    return hash;
}

/**
 * @brief Find or insert a new packet linked list in a hashtable
 * @param buffer The buffer to hash
 * @param source_port Source port of the SCTP buffer
 * @param destination_port Destination port of the SCTP buffer
 * @param create If the function should create the element if it is missing
 * @return Pointer to the existing or newly inserted element
 */
static struct sctp_reassembly_htable_element* sctp_find_hashtable(const struct ob_protocol* buffer, uint16_t source_port, uint16_t destination_port, uint16_t StreamID, bool create)
{
    uint16_t hash = sctp_hash_element(buffer, source_port, destination_port, StreamID);
    struct sctp_reassembly_htable_element* begin = sctp_htable[hash];
    struct sctp_reassembly_htable_element* previous;

    struct ip_pseudo_header iph;
    struct ip6_pseudo_header ip6h;
    uint8_t ip_version;

    ip_version = *(uint8_t*) buffer->pseudo_header;

    /**
     * If the list is empty at this index, create the first element
     */
    if (begin == NULL)
    {
        if (!create)
        {
            return NULL;
        }
        sctp_htable[hash] = malloc(sizeof(struct sctp_reassembly_htable_element));
        if (sctp_htable[hash] == NULL)
        {
            longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
        }
        sctp_htable[hash]->source_port = source_port;
        sctp_htable[hash]->destination_port = destination_port;
        sctp_htable[hash]->StreamID = StreamID;
        sctp_htable[hash]->buffers = NULL;
        sctp_htable[hash]->next = NULL;

        switch (ip_version)
        {
            case 4:
                memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
                sctp_htable[hash]->ipv4.destination_ip = iph.ip_dst;
                sctp_htable[hash]->ipv4.source_ip = iph.ip_src;
                break;

            case 6:
                memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
                sctp_htable[hash]->ipv6.destination_ip = ip6h.ip6_dst;
                sctp_htable[hash]->ipv6.source_ip = ip6h.ip6_src;
                break;

            default:
                break;
        }

        return sctp_htable[hash];
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
                begin->ipv4.source_ip.s_addr == iph.ip_src.s_addr &&
                begin->StreamID == StreamID)
                {
                    return begin;
                }
                break;

            case 6:
                memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
                if (begin->source_port == source_port &&
                begin->destination_port == destination_port &&
                memcmp(begin->ipv6.destination_ip.s6_addr16, ip6h.ip6_dst.s6_addr16, sizeof(struct in6_addr)) == 0 &&
                memcmp(begin->ipv6.source_ip.s6_addr16, ip6h.ip6_src.s6_addr16, sizeof(struct in6_addr)) == 0 &&
                begin->StreamID == StreamID)
                {
                    return begin;
                }
                break;

            default:
                break;
        }
        previous = begin;
        begin = begin->next;
    }

    /**
     * We reached the end of the list without matching, create a new element
     */
    if (!create)
    {
        return NULL;
    }

    previous->next = malloc(sizeof(struct sctp_reassembly_htable_element));
    if (previous->next == NULL)
    {
        longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
    }
    previous->next->source_port = source_port;
    previous->next->destination_port = destination_port;
    previous->next->StreamID = StreamID;
    previous->next->buffers = NULL;
    previous->next->next = NULL;

    switch (ip_version)
    {
        case 4:
            memcpy(&iph, buffer->pseudo_header, sizeof(struct ip_pseudo_header));
            previous->next->ipv4.destination_ip = iph.ip_dst;
            previous->next->ipv4.source_ip = iph.ip_src;
            break;

        case 6:
            memcpy(&ip6h, buffer->pseudo_header, sizeof(struct ip6_pseudo_header));
            previous->next->ipv6.destination_ip = ip6h.ip6_dst;
            previous->next->ipv6.source_ip = ip6h.ip6_src;
            break;

        default:
            break;
    }

    return previous->next;
}

/**
 * @brief Insert a fragment inside a packet linked list
 * @param buffer The buffer to insert
 * @param offset Offset of the packet inside the buffer
 * @param length Length of the underlying buffer
 * @param TSN Sequence number
 * @param Flag_E E flag of the buffer
 * @param Flag_B B flag of the buffer
 * @param Flag_U U flag of the buffer
 * @param htable_element Pointer to the beginning of the linked list, obtained with sctp_find_hashtable()
 */
static void sctp_insert_fragment(const struct ob_protocol* buffer, ssize_t offset, unsigned long length, uint32_t TSN, uint8_t Flag_E, uint8_t Flag_B, uint8_t Flag_U, struct sctp_reassembly_htable_element* htable_element)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_reassembly* identified;
    struct sctp_reassembly* previous;
    struct sctp_reassembly* current;
    if (offset + (ssize_t) length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    if (htable_element->buffers == NULL)
    {
        htable_element->buffers = calloc(1, sizeof(struct sctp_reassembly));
        if (htable_element->buffers == NULL)
        {
            longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
        }
        htable_element->buffers->buffer_length = length;
        htable_element->buffers->TSN = TSN;
        htable_element->buffers->index = buffer->packet_index;
        htable_element->buffers->next = NULL;
        htable_element->buffers->Flag_E = Flag_E ? 1 : 0;
        htable_element->buffers->Flag_B = Flag_B ? 1 : 0;
        htable_element->buffers->Flag_U = Flag_U ? 1 : 0;
        htable_element->buffers->buffer = malloc(length * sizeof(uint8_t));
        if (htable_element->buffers->buffer == NULL)
        {
            free(htable_element->buffers);
            htable_element->buffers = NULL;
            longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
        }
        memcpy(htable_element->buffers->buffer, &hdr[offset], length * sizeof(uint8_t));
        return;
    }
    identified = htable_element->buffers;
    previous = htable_element->buffers;
    while (identified->TSN < TSN)
    {
        previous = identified;
        identified = identified->next;
        if (identified == NULL)
        {
            break;
        }
    }
    current = malloc(sizeof(struct sctp_reassembly));
    if (current == NULL)
    {
        longjmp(*(buffer->catcher), OB_ERROR_MEMORY_ALLOCATION);
    }
    current->buffer_length = length;
    current->TSN = TSN;
    current->next = identified;
    current->index = buffer->packet_index;
    current->Flag_E = Flag_E ? 1 : 0;
    current->Flag_B = Flag_B ? 1 : 0;
    current->Flag_U = Flag_U ? 1 : 0;
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
 * @param htable_element Pointer to the beginning of the linked list, obtained with sctp_find_hashtable()
 * @return - -1 if there is no segments that can be reassembled
 * @return - `index` of the first segment that can be reassembled
 */
static int sctp_complete(const struct sctp_reassembly_htable_element* htable_element)
{
    struct sctp_reassembly* current = htable_element->buffers;
    bool found = true;
    int index = 0;
    int saved_index = 0;
    if (current == NULL)
    {
        return -1;
    }
    if (current->Flag_U == 1)
    {
        return 0;
    }
    while (current->next != NULL)
    {
        if (current->Flag_U)
        {
            return index;
        }
        if (current->Flag_B)
        {
            saved_index = index;
            found = true;
        }
        if (current->Flag_E && found)
        {
            return saved_index;
        }
        if (current->TSN + 1 != current->next->TSN)
        {
            found = false;
        }
        current = current->next;
        ++index;
    }
    return (current->Flag_E == 1 || current->Flag_U == 1) ? saved_index : -1;
}

/**
 * @brief Reassemble a list of SCTP segments into one that will be set in a buffer
 * @param buffer Pointer to an ob_protocol structure that will NOT contain the reassembled buffer after this call
 * @param htable_element Pointer to the beginning of the linked list, obtained with sctp_find_hashtable()
 * @param grouped_data_length Pointer to the
 * @param from Index of the first segment to reassemble
 */
static uint8_t* sctp_reassemble(const struct ob_protocol* buffer, struct sctp_reassembly_htable_element* htable_element, unsigned long* grouped_data_length, int from)
{
    unsigned long total_buffer_length = 0;
    unsigned long current_offset = 0;
    uint8_t* total_buffer = NULL;
    struct sctp_reassembly** previous_packet;
    struct sctp_reassembly* from_packet;
    struct sctp_reassembly* to_delete;
    struct sctp_reassembly* to_move_after;
    struct sctp_reassembly* current = htable_element->buffers;
    int packet_count = 0;
    int index = 0;

    /**
     * Find region
     */
    if (current == NULL)
    {
        *grouped_data_length = 0;
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
    while (current->next != NULL && (current->Flag_E == 0 && current->Flag_U == 0))
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
    while (current->next != NULL && (current->Flag_E == 0 && current->Flag_U == 0))
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

    *grouped_data_length = total_buffer_length;
    return total_buffer;
}

/**
 * Forward declaration for mutual calls
 */
static ssize_t sctp_dump_parameter(const struct ob_protocol* buffer, ssize_t offset, bool header);

static void sctp_dump_parameter_hex(const struct ob_protocol* buffer, ssize_t offset, ssize_t length, const char* name)
{
    const uint8_t* hdr = buffer->hdr;

    printf("%-45s = ", name);

    for (ssize_t i = offset; i < offset + length; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");
}

static void sctp_dump_parameter_ipv4(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    char ipv4[INET_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    inet_ntop(AF_INET, &hdr[offset], ipv4, INET_ADDRSTRLEN);

    printf("%-45s = %s\n", "IPv4 address", ipv4);
}

static void sctp_dump_parameter_ipv6(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    char ipv6[INET6_ADDRSTRLEN] = {0};

    if (offset + (ssize_t) (8 * sizeof(uint16_t)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    inet_ntop(AF_INET6, &hdr[offset], ipv6, INET6_ADDRSTRLEN);

    printf("%-45s = %s\n", "IPv6 address", ipv6);
}

static void sctp_dump_parameter_supported_address_type(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    uint16_t addr_type;

    printf("%-45s = ", "Supported address types");

    for (ssize_t i = offset; i < offset + length; i += 2)
    {
        if (i + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        addr_type = be16toh(read_u16_unaligned(&hdr[i]));

        printf("%u (%s)", addr_type, sctp_get_parameter_type(addr_type));

        if (i < offset + length - 2)
        {
            printf(", ");
        }
    }

    printf("\n");
}

static void sctp_dump_parameter_list(const struct ob_protocol* buffer, ssize_t offset, ssize_t length, const char* name)
{
    const uint8_t* hdr = buffer->hdr;

    printf("%-45s = ", name);

    for (ssize_t i = offset; i < offset + length; ++i)
    {
        printf("%02x", hdr[i]);
        if (i < offset + length - 1)
        {
            printf(", ");
        }
    }
    printf("\n");
}

static void sctp_dump_parameter_u32(const struct ob_protocol* buffer, ssize_t offset, const char* name)
{
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("%-45s = 0x%x\n", name, be32toh(read_u32_unaligned(&hdr[offset])));
}

static void sctp_dump_parameter_outgoing_ssn_reset_request(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_parameter_outgoing_ssn_reset_request ss;
    ssize_t StreamCount = (length - 16) / 2;

    if (offset + (ssize_t) sizeof(struct sctp_parameter_outgoing_ssn_reset_request) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ss, &hdr[offset], sizeof(struct sctp_parameter_outgoing_ssn_reset_request));

    offset += (ssize_t) sizeof(struct sctp_parameter_outgoing_ssn_reset_request);

    printf("%-45s = %u\n", "Re-configuration request sequence number", be32toh(ss.RequestSequence));
    printf("%-45s = %u\n", "Re-configuration response sequence number", be32toh(ss.ResponseSequence));
    printf("%-45s = %u\n", "Sender last TSN", be32toh(ss.SenderLastTSN));

    for (ssize_t i = 0; i < StreamCount; ++i)
    {
        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }
        printf("%-45s = %u\n", "Stream", be16toh(read_u16_unaligned(&hdr[offset])));
        offset += (ssize_t) sizeof(uint16_t);
    }
}

static void sctp_dump_parameter_incoming_ssn_reset_request(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    ssize_t StreamCount = (length - 8) / 2;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("%-45s = %u\n", "Re-configuration request sequence number", be32toh(read_u32_unaligned(&hdr[offset])));

    offset += (ssize_t) sizeof(uint32_t);

    for (ssize_t i = 0; i < StreamCount; ++i)
    {
        if (offset + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        printf("%-45s = %u\n", "Stream", be16toh(read_u16_unaligned(&hdr[offset])));
        offset += (ssize_t) sizeof(uint16_t);
    }
}

static void sctp_dump_parameter_reconfiguration_response(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_parameter_reconfiguration_response sr;

    if (offset + (ssize_t) sizeof(struct sctp_parameter_reconfiguration_response) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&sr, &hdr[offset], sizeof(struct sctp_parameter_reconfiguration_response));

    printf("%-45s = %u\n", "Re-configuration response sequence number", be32toh(sr.ResponseSequence));
    printf("%-45s = %u\n", "Result", be32toh(sr.Result));
    printf("%-45s = %u\n", "Sender next TSN", be32toh(sr.SenderNextTSN));
    printf("%-45s = %u\n", "Receiver next TSN", be32toh(sr.ReceiverNextTSN));
}

static void sctp_dump_parameter_add_stream(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_parameter_add_stream sa;

    if (offset + (ssize_t) sizeof(struct sctp_parameter_add_stream) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&sa, &hdr[offset], sizeof(struct sctp_parameter_add_stream));

    printf("%-45s = %u\n", "Re-configuration request sequence number", be32toh(sa.RequestSequence));
    printf("%-45s = %u\n", "Number of new streams", be32toh(sa.NewStreamCount));
}

static void sctp_dump_parameter_requested_hmac_parameters(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;

    printf("%-45s = ", "HMAC identifiers");

    for (ssize_t i = offset; i < offset + length; i += 2)
    {
        if (i + (ssize_t) sizeof(uint16_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        printf("%u", be16toh(read_u16_unaligned(&hdr[i])));

        if (i < offset + length - 2)
        {
            printf(", ");
        }
    }
    printf("\n");
}

static void sctp_dump_parameter_add_delete_set_ip_error_cause(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    ssize_t max_length = offset + length;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("%-45s = 0x%x\n", "ASCONF request correlation ID", be32toh(read_u32_unaligned(&hdr[offset])));

    offset += (ssize_t) sizeof(uint32_t);

    for (ssize_t i = offset; i < max_length;)
    {
        i += sctp_dump_parameter(buffer, i, false);
    }
}

static ssize_t sctp_dump_parameter(const struct ob_protocol* buffer, ssize_t offset, bool header)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_parameter sp;
    ssize_t parameter_data_length;

    if (offset + (ssize_t) sizeof(struct sctp_parameter) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&sp, &hdr[offset], sizeof(struct sctp_parameter));

    offset += (ssize_t) sizeof(struct sctp_parameter);

    if (header)
    {
        printf("--- BEGIN SCTP PARAMETER ---\n");
    }
    printf("%-45s = %u (%s)\n", "Type", be16toh(sp.ParameterType), sctp_get_parameter_type(be16toh(sp.ParameterType)));
    printf("%-45s = %u\n", "Length", be16toh(sp.ParameterLength));

    if (be16toh(sp.ParameterLength) == 0)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    parameter_data_length = be16toh(sp.ParameterLength) - (ssize_t) sizeof(struct sctp_parameter);

    if (offset + parameter_data_length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    switch (be16toh(sp.ParameterType))
    {
        case 1: /* Heartbeat info */
            sctp_dump_parameter_hex(buffer, offset, parameter_data_length, "Heartbeat info");
            break;

        case 5: /* IPv4 address */
            sctp_dump_parameter_ipv4(buffer, offset);
            break;

        case 6: /* IPv6 address */
            sctp_dump_parameter_ipv6(buffer, offset);
            break;

        case 7: /* State cookie */
            sctp_dump_parameter_hex(buffer, offset, parameter_data_length, "State cookie");
            break;

        case 8: /* Unrecognized parameter */
            sctp_dump_parameter_list(buffer, offset, parameter_data_length, "Unrecognized Parameters");
            break;

        case 9: /* Cookie preservative */
            sctp_dump_parameter_u32(buffer, offset, "Cookie preservative");
            break;

        case 0xB: /* Host name address */
            /**
             * Not implemented
             */
            break;

        case 0xC: /* Supported address types */
            sctp_dump_parameter_supported_address_type(buffer, offset, parameter_data_length);
            break;

        case 0xD: /* Outgoing SSN reset request parameter */
            sctp_dump_parameter_outgoing_ssn_reset_request(buffer, offset, parameter_data_length);
            break;

        case 0xE: /* Incoming SSN reset request parameter */
            sctp_dump_parameter_incoming_ssn_reset_request(buffer, offset, parameter_data_length);
            break;

        case 0xF: /* SSN/TSN reset request parameter */
            sctp_dump_parameter_u32(buffer, offset, "Re-configuration request sequence number");
            break;

        case 0x10: /* Re-configuration response parameter */
            sctp_dump_parameter_reconfiguration_response(buffer, offset);
            break;

        case 0x11: /* Add outgoing streams request parameter */
        case 0x12: /* Add incoming streams request parameter */
            sctp_dump_parameter_add_stream(buffer, offset);
            break;

        case 0x8001: /* Zero checksum acceptable */
            sctp_dump_parameter_u32(buffer, offset, "Error detection method identifier");
            break;

        case 0x8002: /* Random */
            sctp_dump_parameter_hex(buffer, offset, parameter_data_length, "Random number");
            break;

        case 0x8003: /* Chunk list */
        case 0x8008: /* Supported extensions */
            sctp_dump_parameter_list(buffer, offset, parameter_data_length, "Chunk types");
            break;

        case 0x8004: /* Requested HMAC algorithm parameter */
            sctp_dump_parameter_requested_hmac_parameters(buffer, offset, parameter_data_length);
            break;

        case 0xC000: /* Forward TSN supported */
            /**
             * NOOP
             */
            break;

        case 0xC001: /* Add IP address */
        case 0xC002: /* Delete IP address */
        case 0xC003: /* Error cause indication */
        case 0xC004: /* Set primary address */
            sctp_dump_parameter_add_delete_set_ip_error_cause(buffer, offset, parameter_data_length);
            break;

        case 0xC005: /* Success indication */
            sctp_dump_parameter_u32(buffer, offset, "ASCONF request correlation ID");
            break;

        case 0xC006: /* Adaptation layer indication */
            sctp_dump_parameter_u32(buffer, offset, "Adaptation code point");
            break;

        default:
            break;
    }

    /**
     * SCTP parameters are padded to 4 byte aligned words
     */
    if (be16toh(sp.ParameterLength) % 4 != 0)
    {
        uint16_t PRL = be16toh(sp.ParameterLength);
        PRL += (1 << 2);
        PRL &= (uint16_t) -4;
        sp.ParameterLength = htobe16(PRL);
    }

    return be16toh(sp.ParameterLength);
}

static void sctp_dump_chunk_data(const struct ob_protocol* buffer, ssize_t offset, ssize_t length, uint8_t Flags, uint16_t source_port, uint16_t dest_port)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_chunk_data sd;
    struct sctp_reassembly_htable_element* hash_element;

    if (offset + (ssize_t) sizeof(struct sctp_chunk_data) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&sd, &hdr[offset], sizeof(struct sctp_chunk_data));

    length -= (ssize_t) sizeof(struct sctp_chunk_data);

    offset += (ssize_t) sizeof(struct sctp_chunk_data);

    printf("--- BEGIN SCTP DATA ---\n");
    printf("%-45s = %u\n", "TSN", be32toh(sd.TSN));
    printf("%-45s = %u\n", "Stream identifier", be16toh(sd.StreamID));
    printf("%-45s = %u\n", "Stream sequence number", be16toh(sd.StreamSequenceNumber));
    printf("%-45s = %u\n", "Payload protocol identifier", be32toh(sd.PayloadID));

    if (offset + length > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    hash_element = sctp_find_hashtable(buffer, source_port, dest_port, be16toh(sd.StreamID), true);

    sctp_insert_fragment(buffer, offset, (unsigned long) length, be32toh(sd.TSN), Flags & (1 << 0), Flags & (1 << 1), Flags & (1 << 2), hash_element);
}

static void sctp_dump_chunk_init(const struct ob_protocol* buffer, ssize_t offset, ssize_t length, bool ack)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_chunk_init si;
    ssize_t max_length = offset + length;

    if (offset + (ssize_t) sizeof(struct sctp_chunk_init) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&si, &hdr[offset], sizeof(struct sctp_chunk_init));

    printf("--- BEGIN SCTP INIT");
    if (ack)
    {
        printf(" ACK");
    }
    printf(" ---\n");
    printf("%-45s = 0x%x\n", "Initiate tag", be32toh(si.InitiateTag));
    printf("%-45s = %u\n", "Advertized receiver window credit", be32toh(si.AdvertizedReceiverWindowCredit));
    printf("%-45s = %u\n", "Outbound stream count", be16toh(si.OutboundStreamCount));
    printf("%-45s = %u\n", "Inbount stream count", be16toh(si.InboundStreamCount));
    printf("%-45s = %u\n", "Initial TSN", be32toh(si.InitialTSN));

    offset += (ssize_t) sizeof(struct sctp_chunk_init);

    while (offset < max_length)
    {
        offset += sctp_dump_parameter(buffer, offset, true);
    }
}

static void sctp_dump_chunk_sack(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_chunk_sack sa;
    struct sctp_gap_ack_block sgab;

    if (offset + (ssize_t) sizeof(struct sctp_chunk_sack) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&sa, &hdr[offset], sizeof(struct sctp_chunk_sack));

    printf("--- BEGIN SCTP SACK ---\n");
    printf("%-45s = %u\n", "Cumulative TSN ack", be32toh(sa.CumulativeTSNAck));
    printf("%-45s = %u\n", "Advertized receiver window credit", be32toh(sa.AdvertizedReceiverWindowCredit));
    printf("%-45s = %u\n", "Number of Gap ACK blocks", be16toh(sa.GapAckBlockCount));
    printf("%-45s = %u\n", "Number of duplicate TSNs", be16toh(sa.DuplicateTSNCount));

    offset += (ssize_t) sizeof(struct sctp_chunk_sack);

    for (uint16_t i = 0; i < be16toh(sa.GapAckBlockCount); ++i)
    {
        if (offset + (ssize_t) sizeof(struct sctp_gap_ack_block) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&sgab, &hdr[offset], sizeof(struct sctp_gap_ack_block));

        printf("--- BEGIN SCTP GAP ACK BLOCK ---\n");
        printf("%-45s = %u\n", "Start", be16toh(sgab.Start));
        printf("%-45s = %u\n", "End", be16toh(sgab.End));

        offset += (ssize_t) sizeof(struct sctp_gap_ack_block);
    }

    for (uint16_t i = 0; i < be16toh(sa.GapAckBlockCount); ++i)
    {
        if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        printf("--- BEGIN SCTP DUPLICATE TSN ---\n");
        printf("%-45s = %u\n", "Duplicate TSN", be32toh(read_u32_unaligned(&hdr[offset])));

        offset += (ssize_t) sizeof(uint32_t);
    }
}

static void sctp_dump_chunk_heartbeat(const struct ob_protocol* buffer, ssize_t offset, ssize_t length, bool ack)
{
    ssize_t max_length = offset + length;

    printf("--- BEGIN SCTP HEARTBEAT");
    if (ack)
    {
        printf(" ACK");
    }
    printf(" ---\n");
    while (offset < max_length)
    {
        offset += sctp_dump_parameter(buffer, offset, true);
    }
}

static void sctp_dump_chunk_shutdown(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("--- BEGIN SCTP SHUTDOWN ---\n");
    printf("%-45s = %u\n", "Cumulative TSN ack", be32toh(read_u32_unaligned(&hdr[offset])));
}

static void sctp_dump_chunk_cookie_echo(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;

    printf("--- BEGIN SCTP COOKIE ECHO ---\n");
    printf("%-45s = ", "Cookie");
    for (ssize_t i = offset; i < offset + length; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");
}

static void sctp_dump_chunk_auth(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_chunk_auth sa;
    ssize_t max_length = offset + length;

    if (offset + (ssize_t) sizeof(struct sctp_chunk_auth) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&sa, &hdr[offset], sizeof(struct sctp_chunk_auth));

    offset += (ssize_t) sizeof(struct sctp_chunk_auth);

    printf("--- BEGIN SCTP AUTH ---\n");
    printf("%-45s = %u\n", "Shared key identifier", be16toh(sa.SharedKeyIdentifier));
    printf("%-45s = %u\n", "HMAC identifier", be16toh(sa.HMACIdentifier));
    printf("%-45s = ", "HMAC");
    for (ssize_t i = offset; i < max_length; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");
}

static void sctp_dump_chunk_idata(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_chunk_idata si;
    ssize_t max_length = offset + length;

    if (offset + (ssize_t) sizeof(struct sctp_chunk_idata) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&si, &hdr[offset], sizeof(struct sctp_chunk_idata));

    offset += (ssize_t) sizeof(struct sctp_chunk_idata);

    printf("--- BEGIN SCTP I-Data ---\n");
    printf("%-45s = %u\n", "TSN", be32toh(si.TSN));
    printf("%-45s = %u\n", "Stream identifier", be16toh(si.StreamID));
    printf("%-45s = %u\n", "Message identifier", be32toh(si.MessageID));
    printf("%-45s = %u\n", "Payload protocol identifier / Fragment sequence number", be32toh(si.PayloadID_FragmentSequence));
    printf("%-45s = ", "User data");

    for (ssize_t i = offset; i < max_length; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");
}

static void sctp_dump_chunk_reconfig(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    ssize_t max_length = offset + length;

    printf("--- BEGIN SCTP RE-CONFIG ---\n");
    while (offset < max_length)
    {
        offset += sctp_dump_parameter(buffer, offset, true);
    }
}

static void sctp_dump_chunk_forward_tsn(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_forward_tsn_stream stream;
    ssize_t max_length = offset + length;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("--- BEGIN SCTP FORWARD TSN ---\n");
    printf("%-45s = %u\n", "New cumulative TSN", be32toh(read_u32_unaligned(&hdr[offset])));

    offset += (ssize_t) sizeof(uint32_t);

    while (offset < max_length)
    {
        memcpy(&stream, &hdr[offset], sizeof(struct sctp_forward_tsn_stream));

        printf("%-45s = %u\n", "Stream", be16toh(stream.Stream));
        printf("%-45s = %u\n", "Stream sequence", be16toh(stream.StreamSequence));

        offset += (ssize_t) sizeof(struct sctp_forward_tsn_stream);
    }
}

static void sctp_dump_chunk_iforward_tsn(const struct ob_protocol* buffer, ssize_t offset, ssize_t length)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_iforward_tsn_stream stream;
    ssize_t max_length = offset + length;

    if (offset + (ssize_t) sizeof(uint32_t) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("--- BEGIN SCTP I-FORWARD TSN ---\n");
    printf("%-45s = %u\n", "New cumulative TSN", be32toh(read_u32_unaligned(&hdr[offset])));

    offset += (ssize_t) sizeof(uint32_t);

    while (offset < max_length)
    {
        memcpy(&stream, &hdr[offset], sizeof(struct sctp_iforward_tsn_stream));

        printf("%-45s = %u\n", "Stream identifier", be16toh(stream.StreamID));
        printf("%-45s = %u\n", "U", stream.U);
        printf("%-45s = %u\n", "Message identifier", be32toh(stream.MessageID));

        offset += (ssize_t) sizeof(struct sctp_iforward_tsn_stream);
    }
}

static void sctp_dump_chunks(const struct ob_protocol* buffer, ssize_t offset, uint16_t source_port, uint16_t dest_port)
{
    const uint8_t* hdr = buffer->hdr;
    struct sctp_chunk sc;
    ssize_t chunk_length;
    ssize_t chunk_length_wo_pad;

    for (ssize_t i = offset; i < buffer->length;)
    {
        if (i + (ssize_t) sizeof(struct sctp_chunk) > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&sc, &hdr[i], sizeof(struct sctp_chunk));

        printf("--- BEGIN SCTP CHUNK ---\n");
        printf("%-45s = 0x%x (%s)\n", "Type", sc.Type, sctp_get_chunk_type(sc.Type));
        printf("%-45s = %u\n", "Flags", sc.Flags);
        printf("%-45s = %u\n", "Length", be16toh(sc.Length));

        if (be16toh(sc.Length) == 0)
        {
            longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
        }

        i += (ssize_t) sizeof(struct sctp_chunk);

        chunk_length = chunk_length_wo_pad = be16toh(sc.Length) - (ssize_t) sizeof(struct sctp_chunk);

        if (chunk_length % 4 != 0)
        {
            chunk_length += (1 << 2);
            chunk_length &= (uint16_t) -4;
        }

        if (i + chunk_length > buffer->length)
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        switch (sc.Type)
        {
            case 0: /* Payload data */
                sctp_dump_chunk_data(buffer, i, chunk_length_wo_pad, sc.Flags, source_port, dest_port);
                break;

            case 1: /* Initiation */
                sctp_dump_chunk_init(buffer, i, chunk_length_wo_pad, false);
                break;

            case 2: /* Initiation acknowledgement */
                sctp_dump_chunk_init(buffer, i, chunk_length_wo_pad, true);
                break;

            case 3: /* Selective acknowledgement */
                sctp_dump_chunk_sack(buffer, i);
                break;

            case 4: /* Heartbeat request */
                sctp_dump_chunk_heartbeat(buffer, i, chunk_length_wo_pad, false);
                break;

            case 5: /* Heartbeat acknowledgement */
                sctp_dump_chunk_heartbeat(buffer, i, chunk_length_wo_pad, true);
                break;

            case 6: /* Abort */
                /**
                 * Not implemented
                 */
                break;

            case 7: /* Shutdown */
                sctp_dump_chunk_shutdown(buffer, i);
                break;

            case 8: /* Shutdown acknowledgement */
                /**
                 * NOOP
                 */
                break;

            case 9: /* Operation error */
                /**
                 * Not implemented
                 */
                break;

            case 10: /* State cookie */
                sctp_dump_chunk_cookie_echo(buffer, i, chunk_length_wo_pad);
                break;

            case 11: /* Cookie acknowledgement */
                /**
                 * NOOP
                 */
                break;

            case 14: /* Shutdown comlete */
                /**
                 * NOOP
                 */
                break;

            case 15: /* Authentication */
                sctp_dump_chunk_auth(buffer, i, chunk_length_wo_pad);
                break;

            case 64: /* Payload data supporting interleaving */
                /**
                 * Not completely implemented
                 */
                sctp_dump_chunk_idata(buffer, i, chunk_length_wo_pad);
                break;

            case 128: /* Address configuration acknowledgement */
            case 193: /* Address configuration change */
                /**
                 * Not implemented
                 */
                break;

            case 130: /* Re-configuration */
                sctp_dump_chunk_reconfig(buffer, i, chunk_length_wo_pad);
                break;

            case 132: /* Padding */
                /**
                 * NOOP
                 */
                break;

            case 192: /* Forward TSN */
                sctp_dump_chunk_forward_tsn(buffer, i, chunk_length_wo_pad);
                break;

            case 194: /* I-Forward TSN */
                sctp_dump_chunk_iforward_tsn(buffer, i, chunk_length_wo_pad);
                break;

            default:
                return;
        }

        i += chunk_length;
    }
}

static void sctp_dump_v3(const struct sctp_header* sh)
{
    printf("--- BEGIN SCTP MESSAGE ---\n");
    printf("%-45s = %u\n", "Source port", be16toh(sh->SourcePort));
    printf("%-45s = %u\n", "Destination port", be16toh(sh->DestPort));
    printf("%-45s = 0x%x\n", "Verification tag", be32toh(sh->VerificationTag));
    printf("%-45s = 0x%x\n", "Checksum", be32toh(sh->Checksum));
}

static void sctp_dump_v2(const struct sctp_header* sh)
{
    printf("SCTP => ");
    printf("Source port : %u, ", be16toh(sh->SourcePort));
    printf("Destination port : %u, ", be16toh(sh->DestPort));
    printf("Verification tag : 0x%x, ", be32toh(sh->VerificationTag));
    printf("Checksum : 0x%x\n", be32toh(sh->Checksum));
}

void sctp_dump(struct ob_protocol* buffer)
{
    struct sctp_header sh;
    uint8_t* buffer_orig_save = buffer->orig;
    uint8_t* buffer_ptr_save = buffer->hdr;
    ssize_t buffer_length_save = buffer->length;

    jmp_buf multiple_return;
    jmp_buf* default_catcher = buffer->catcher;

    if ((ssize_t) sizeof(struct sctp_header) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&sh, buffer->hdr, sizeof(struct sctp_header));

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> SCTP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            sctp_dump_v2(&sh);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            sctp_dump_v3(&sh);
            break;
    }

    sctp_dump_chunks(buffer, (ssize_t) sizeof(struct sctp_header), be16toh(sh.SourcePort), be16toh(sh.SourcePort));

    if (!application_cast(T_TRANSPORT_SCTP, be16toh(sh.SourcePort), buffer))
    {
        application_cast(T_TRANSPORT_SCTP, be16toh(sh.DestPort), buffer);
    }

    for (uint32_t i = 0; i < (1 << 16); ++i)
    {
        int dump_return;
        int sctp_complete_value;
        uint8_t* data_buffer;
        unsigned long grouped_data_length;
        struct sctp_reassembly_htable_element* elt = sctp_find_hashtable(buffer, be16toh(sh.SourcePort), be16toh(sh.SourcePort), (uint16_t) i, false);
        if (elt == NULL)
        {
            continue;
        }

        if (elt->buffers == NULL)
        {
            continue;
        }

        if ((sctp_complete_value = sctp_complete(elt)) == -1)
        {
            printf("\033[1m[Received partial packet, saved for later]\033[22m\n");
            continue;
        }

        data_buffer = sctp_reassemble(buffer, elt, &grouped_data_length, sctp_complete_value);

        buffer->hdr = buffer->orig = data_buffer;
        buffer->length = (ssize_t) grouped_data_length;

        /**
         * Change catcher buffer, if only one of the data chunks fails, we don't
         * want to skip the others
         */
        buffer->catcher = &multiple_return;
        if ((dump_return = setjmp(*(buffer->catcher))) == 0)
        {
            buffer->dump(buffer);
        }
        else
        {
            display_error(dump_return);
        }
        buffer->catcher = default_catcher;

        free(buffer->orig);
    }

    buffer->hdr = buffer_ptr_save;
    buffer->orig = buffer_orig_save;
    buffer->length = buffer_length_save;
}
