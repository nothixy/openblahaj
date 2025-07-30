#ifndef OB_PROTOCOL_H
#define OB_PROTOCOL_H

#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#include "generic/constants.h"

enum OB_ERROR {
    OB_ERROR_MEMORY_ALLOCATION = 1,
    OB_ERROR_BUFFER_OVERFLOW,
    OB_ERROR_INVALID_VALUES,
    OB_ERROR_NOT_SUPPORTED,
    OB_ERROR_DATA_UNAVAILABLE
};

extern const char* OB_ERROR_STR[6];

struct ob_protocol {
    /**
     * @brief Dump the data from a buffer
     * @param buffer Pointer to an ob_protocol structure containing a byte array
     * @return Number of bytes read on this layer
     * @note Calling dump() on a buffer may modify its dump() attribute
     */
    void (*dump)(struct ob_protocol* buffer);

    /**
     * Pointer to the buffer
     */
    void* hdr;

    /**
     * Pointer to a free()-able origin of a buffer
     */
    void* orig;

    /**
     * Size of the buffer in bytes
     */
    ssize_t length;

    /**
     * Verbosity level to use in the dump command
     */
    enum OB_VERBOSITY_LEVEL verbosity_level;

    /**
     * Indicate that this packet has been reassembled and the cursor and length
     * should not be modified after dumping
     */
    bool reassembled;

    /**
     * Display hostnames associated to IP addresses
     */
    bool display_hostnames;

    /**
     * Index of this packet
     */
    long long packet_index;

    /**
     * Error catcher
     */
    jmp_buf* catcher;

    /**
     * Useful data from the encapsulating layer that the upper layer might find useful
     */
    void* pseudo_header;

    /**
     * Length (in bytes) of the previous field
     */
    size_t pseudo_header_length;

    /**
     * Link type as returned by pcap_
     */
    int link_type;
};

#endif
