#ifndef OB_WIREGUARD_H
#define OB_WIREGUARD_H

#include "generic/protocol.h"

#define AEAD_LEN(X) (X + 16)

/* https://www.wireguard.com/protocol/#first-message-initiator-to-responder */

struct wireguard_first_message {
    uint8_t message_type;
    uint8_t reserved_zero[3];
    uint32_t sender_index;
    uint8_t unencrypted_ephemeral[32];
    uint8_t encrypted_static[AEAD_LEN(32)];
    uint8_t encrypted_timestamp[AEAD_LEN(12)];
    uint8_t mac1[16];
    uint8_t mac2[16];
};

struct wireguard_second_message {
    uint8_t message_type;
    uint8_t reserved_zero[3];
    uint32_t sender_index;
    uint32_t receiver_index;
    uint8_t unencrypted_ephemeral[32];
    uint8_t encrypted_nothing[16];
    uint8_t mac1[16];
    uint8_t mac2[16];
};

struct wireguard_data_message {
    uint8_t message_type;
    uint8_t reserved_zero[3];
    uint32_t receiver_index;
    uint64_t counter;
} __attribute__((packed));

/**
 * The previous structures cannot fit inside the wireguard_header
 * structure because in an union the compiler would align them
 * and leave blank space in between
 */

struct wireguard_header {
    uint8_t message_type;
    uint8_t reserved_zero[3];
};

void wireguard_dump(struct ob_protocol* buffer);

#endif
