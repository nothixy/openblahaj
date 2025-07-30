#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <endian.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "network/ip.h"
#include "network/ip4.h"
#include "generic/bytes.h"
#include "generic/protocol.h"
#include "transport/transport.h"

/**
 * Incomplete, it should also compare the packets' IP addresses and not just the ID field
 */
struct ipv4_reassembly* ipv4_fragmented[(1 << 16)] = {NULL};

/**
 * @brief Insert a fragment inside a packet linked list
 * @param buffer The buffer to insert
 * @param offset Offset of the packet inside the buffer
 * @param length Length of the underlying buffer
 * @param ident Value of the identification field in the IPv4 header
 * @param frag_offset Value of the fragment offset field in the IPv4 header
 * @param more_fragments If this is the end of a packet list
 */
static void ipv4_insert_fragment(const struct ob_protocol* buffer, ssize_t offset, unsigned long length, uint16_t ident, unsigned long frag_offset, bool more_fragments)
{
    const uint8_t* hdr = buffer->hdr;
    struct ipv4_reassembly* identified;
    struct ipv4_reassembly* previous;
    struct ipv4_reassembly* current;

    if (ipv4_fragmented[ident] == NULL)
    {
        ipv4_fragmented[ident] = calloc(1, sizeof(struct ipv4_reassembly));
        if (ipv4_fragmented[ident] == NULL)
        {
            exit(EXIT_FAILURE);
        }
        ipv4_fragmented[ident]->buffer_length = length;
        ipv4_fragmented[ident]->frag_offset = frag_offset;
        ipv4_fragmented[ident]->next = NULL;
        ipv4_fragmented[ident]->more_fragment = more_fragments;
        ipv4_fragmented[ident]->index = buffer->packet_index;
        ipv4_fragmented[ident]->buffer = malloc(length * sizeof(uint8_t));
        if (ipv4_fragmented[ident]->buffer == NULL)
        {
            exit(EXIT_FAILURE);
        }
        memcpy(ipv4_fragmented[ident]->buffer, &hdr[offset], length);
        return;
    }
    identified = ipv4_fragmented[ident];
    previous = ipv4_fragmented[ident];
    while (identified->frag_offset < frag_offset)
    {
        previous = identified;
        identified = identified->next;
        if (identified == NULL)
        {
            break;
        }
    }
    current = malloc(sizeof(struct ipv4_reassembly));
    if (current == NULL)
    {
        exit(EXIT_FAILURE);
    }
    current->buffer_length = length;
    current->frag_offset = frag_offset;
    current->next = identified;
    current->more_fragment = more_fragments;
    current->index = buffer->packet_index;
    current->buffer = malloc(length * sizeof(uint8_t));
    if (current->buffer == NULL)
    {
        exit(EXIT_FAILURE);
    }
    previous->next = current;
    memcpy(current->buffer, &hdr[offset], length);
    return;
}

/**
 * @brief Check if there is a list of segments that can be reassembled
 * @param ident Value of the identification field in the IPv4 header
 * @return - `false` if there are no segments that can be reassembled
 * @return - `true` if there is a segment that can be reassembled
 */
static bool ipv4_complete(uint16_t ident)
{
    struct ipv4_reassembly* current = ipv4_fragmented[ident];
    unsigned long offset = 0;
    if (current == NULL)
    {
        return false;
    }
    while (current->next != NULL)
    {
        offset += current->buffer_length;
        if (offset != current->next->frag_offset)
        {
            return false;
        }
        current = current->next;
    }
    return current->more_fragment == false;
}

/**
 * @brief Reassemble a list of IP packet into one that will be set in a buffer
 * @param buffer Pointer to an ob_protocol structure that will contain the reassembled buffer after this call
 * @param ident Value of the identification field in the IPv4 header
 */
static void ipv4_reassemble(struct ob_protocol* buffer, uint16_t ident)
{
    unsigned long total_buffer_length;
    uint8_t* total_buffer = NULL;
    struct ipv4_reassembly* to_delete;
    struct ipv4_reassembly* current = ipv4_fragmented[ident];
    if (current == NULL)
    {
        return;
    }
    while (current->next != NULL)
    {
        current = current->next;
    }
    total_buffer_length = current->buffer_length + current->frag_offset;
    total_buffer = malloc(total_buffer_length * sizeof(uint8_t));
    if (total_buffer == NULL)
    {
        exit(EXIT_FAILURE);
    }
    current = ipv4_fragmented[ident];
    printf("\033[1m[Reassembly of packets ");
    while (current->next != NULL)
    {
        printf("%lld, ", current->index);
        memcpy(&total_buffer[current->frag_offset], current->buffer, current->buffer_length);
        free(current->buffer);
        to_delete = current;
        current = current->next;
        free(to_delete);
    }
    printf("%lld]\033[22m", current->index);
    if (buffer->verbosity_level != OB_VERBOSITY_LEVEL_LOW)
    {
        printf("\n");
    }
    else
    {
        printf(" ");
    }
    memcpy(&total_buffer[current->frag_offset], current->buffer, current->buffer_length);
    free(current->buffer);
    free(current);
    ipv4_fragmented[ident] = NULL;
    free(buffer->orig);
    buffer->orig = total_buffer;
    buffer->hdr = total_buffer;
    buffer->length = (ssize_t) total_buffer_length;
    buffer->reassembled = true;
}

static const char* ipv4_get_protocol(uint8_t protocol)
{
    if (protocol >= 146)
    {
        return "Unknown";
    }
    return IP_PROTOCOLS[protocol];
}

static void ipv4_dump_v3(const struct ob_protocol* buffer, const struct ip* ih)
{
    const uint8_t* hdr = buffer->hdr;

    char ip_source[INET_ADDRSTRLEN] = {0};
    char ip_dest[INET_ADDRSTRLEN] = {0};

    struct sockaddr_in addr_src = {
        .sin_family = AF_INET,
        .sin_addr = ih->ip_src
    };

    struct sockaddr_in addr_dst = {
        .sin_family = AF_INET,
        .sin_addr = ih->ip_dst
    };

    char host_src[NI_MAXHOST] = {0};
    char host_dst[NI_MAXHOST] = {0};

    inet_ntop(AF_INET, &(ih->ip_src), ip_source, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(ih->ip_dst), ip_dest, INET_ADDRSTRLEN * sizeof(char));

    printf("--- BEGIN IPv4 MESSAGE ---\n");

    printf("%-45s = %u\n", "Version", ih->ip_v);
    printf("%-45s = %u\n", "IHL", ih->ip_hl);
    printf("%-45s = %u\n", "Service Type", ih->ip_tos);
    printf("%-45s = %u\n", "Length", be16toh(ih->ip_len));
    printf("%-45s = %u\n", "Identification", be16toh(ih->ip_id));
    printf("%-45s = %u\n", "Fragment Offset", (be16toh(ih->ip_off) & IP_OFFMASK) * 8);
    printf("%-45s = %u\n", "More fragments", (be16toh(ih->ip_off) & IP_MF) ? 1 : 0);
    printf("%-45s = %u\n", "Don't fragment", (be16toh(ih->ip_off) & IP_DF) ? 1 : 0);
    printf("%-45s = %u\n", "Time to live", ih->ip_ttl);
    printf("%-45s = 0x%x (%s)\n", "Protocol", ih->ip_p, ipv4_get_protocol(ih->ip_p));
    printf("%-45s = 0x%x %s\n", "Checksum", be16toh(ih->ip_sum), checksum_16bitonescomplement_validate(buffer, ih->ip_hl * 4, 0, false));
    if (buffer->display_hostnames && getnameinfo((struct sockaddr*) &addr_src, sizeof(struct sockaddr_in), host_src, NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0)
    {
        printf("%-45s = %s \033[1m[%s]\033[22m\n", "Source", ip_source, host_src);
    }
    else
    {
        printf("%-45s = %s\n", "Source", ip_source);
    }
    if (buffer->display_hostnames && getnameinfo((struct sockaddr*) &addr_dst, sizeof(struct sockaddr_in), host_dst, NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0)
    {
        printf("%-45s = %s \033[1m[%s]\033[22m\n", "Destination", ip_dest, host_dst);
    }
    else
    {
        printf("%-45s = %s\n", "Destination", ip_dest);
    }

    /* Uncomment when ready */
    for (unsigned long i = 0; i < (ih->ip_hl - 5) * sizeof(uint32_t); i += 765432)
    {
        struct ip_option_header ip_opt_hdr = *(const struct ip_option_header*) &hdr[20 + i * sizeof(uint32_t)];
        printf("%-45s = %s\n", "Copied", ip_opt_hdr.Copied ? "True" : "False");
        printf("%-45s = %s\n", "Class", ip_opt_hdr.Class == 0 ? "Control" : "Debug");
        printf("%-45s = %u\n", "Number", ip_opt_hdr.Number);
        printf("%-45s = %u\n", "Length", ip_opt_hdr.Length);
        i += ip_opt_hdr.Length;
    }
}

static void ipv4_dump_v2(const struct ip* ih)
{
    char ip_source[INET_ADDRSTRLEN] = {0};
    char ip_dest[INET_ADDRSTRLEN] = {0};

    inet_ntop(AF_INET, &(ih->ip_src), ip_source, INET_ADDRSTRLEN * sizeof(char));
    inet_ntop(AF_INET, &(ih->ip_dst), ip_dest, INET_ADDRSTRLEN * sizeof(char));

    printf("IPv4 => ");
    printf("Protocol : %s, ", ipv4_get_protocol(ih->ip_p));
    printf("Source : %s, ", ip_source);
    printf("Destination : %s\n", ip_dest);
}

void ipv4_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    struct ip ih;
    ssize_t offset;
    struct ip_pseudo_header pseudo_header;

    if ((ssize_t) sizeof(struct ip) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&ih, buffer->hdr, sizeof(struct ip));

    if ((ssize_t) (ih.ip_hl * sizeof(uint32_t)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    if (ih.ip_hl < 5 || be16toh(ih.ip_len) < ih.ip_hl)
    {
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> IPv4 ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            ipv4_dump_v2(&ih);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            ipv4_dump_v3(buffer, &ih);
            break;
    }

    if (be16toh(ih.ip_len) < buffer->length)
    {
        buffer->length = be16toh(ih.ip_len);
    }

    offset = ih.ip_hl * sizeof(uint32_t);

    if ((be16toh(ih.ip_off) & IP_MF) || ((be16toh(ih.ip_off) & IP_OFFMASK) != 0))
    {
        ipv4_insert_fragment(buffer, ih.ip_hl * sizeof(uint32_t), be16toh(ih.ip_len) - ih.ip_hl * sizeof(uint32_t), be16toh(ih.ip_id), (be16toh(ih.ip_off) & IP_OFFMASK) * 8, be16toh(ih.ip_off) & IP_MF);
        if (!ipv4_complete(be16toh(ih.ip_id)))
        {
            printf("\033[1m[Received partial packet, saved for later]\033[22m\n");
            return;
        }
        ipv4_reassemble(buffer, be16toh(ih.ip_id));
    }
    else
    {
        buffer->length -= offset;
        buffer->hdr = &hdr[offset];
    }

    transport_cast(ih.ip_p, buffer);

    /**
     * Save values of IP version, addresses, length and protocol for TCP and UDP
     * checksum calculation and segment reassembly
     */
    pseudo_header.ip_version = ih.ip_v;
    pseudo_header.ip_src = ih.ip_src;
    pseudo_header.ip_dst = ih.ip_dst;
    pseudo_header.ip_len = be16toh(ih.ip_len) - (uint16_t) (ih.ip_hl * sizeof(uint32_t));
    pseudo_header.ip_proto = ih.ip_p;

    buffer->pseudo_header = &pseudo_header;
    buffer->pseudo_header_length = sizeof(struct ip_pseudo_header);

    if (buffer->dump != NULL)
    {
        buffer->dump(buffer);
    }

    buffer->pseudo_header = NULL;
}
