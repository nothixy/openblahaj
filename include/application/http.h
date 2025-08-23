#ifndef OB_HTTP_H
#define OB_HTTP_H

#include "generic/protocol.h"

enum HTTP_VERSION {
    HTTP_VERSION_1_0,
    HTTP_VERSION_1_1,
    HTTP_VERSION_2,
    HTTP_VERSION_3
};

struct http_2_data_frame_flags {
    uint8_t Unused : 4;
    uint8_t Padded : 1;
    uint8_t Unused2 : 2;
    uint8_t EndStream : 1;
};

// Reordered
struct http_2_headers_frame_flags {
    uint8_t EndStream : 1;
    uint8_t Unused3 : 1;
    uint8_t EndHeaders : 1;
    uint8_t Padded : 1;
    uint8_t Unused2 : 1;
    uint8_t Priority : 1;
    uint8_t Unused : 2;
};

struct http_2_priority_frame_header {
    uint8_t Exclusive : 1;
    uint32_t StreamDependency : 31;
    uint8_t Weight;
} __attribute__((packed));

struct http_2_rst_frame_header {
    uint32_t ErrorCode;
};

struct http_2_setting {
    uint16_t Identifier;
    uint32_t Value;
} __attribute__((packed));

struct http_2_push_promise_flags {
    uint8_t Unused : 4;
    uint8_t Padded : 1;
    uint8_t EndHeaders : 1;
    uint8_t Unused2 : 2;
};

struct http_2_push_promise_header {
    uint8_t Reserved : 1;
    uint32_t PromisedStreamID : 31;
};

struct http_2_ping_flags {
    uint8_t Unused : 7;
    uint8_t Ack : 1;
};

struct http_2_ping_header {
    uint64_t Data;
};

struct http_2_goaway_header {
    uint8_t Reserved : 1;
    uint32_t LastStreamID : 31;
    uint32_t ErrorCode;
};

struct http_2_window_update_header {
    uint8_t Reserved : 1;
    uint32_t WindowSizeIncrement : 31;
};

struct http_2_continuation_flags {
    uint8_t Unused : 5;
    uint8_t EndHeaders : 1;
    uint8_t Unused2 : 2;
};

struct http_2_frame_header {
    uint32_t Length : 24;
    uint8_t Type;
    uint8_t Flags;
    uint32_t StreamID;
} __attribute__((packed));

struct http_2_huffman {
    uint64_t bits;
    uint8_t length;
} __attribute__((packed));

void http_dump(struct ob_protocol* buffer);
void http_dump_text(const unsigned char* hdr, ssize_t length);

#endif
