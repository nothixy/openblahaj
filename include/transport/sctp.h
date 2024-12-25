#ifndef OB_SCTP_H
#define OB_SCTP_H

#include "generic/protocol.h"

extern struct sctp_reassembly_htable_element* sctp_htable[1 << 16];

struct sctp_reassembly {
    unsigned long buffer_length;
    long long index;
    uint32_t TSN;
    uint8_t Flag_B : 1;
    uint8_t Flag_E : 1;
    uint8_t Flag_U : 1;
    uint8_t Pad : 5;
    uint8_t* buffer;
    struct sctp_reassembly* next;
} __attribute__((packed));

struct sctp_reassembly_htable_element {
    uint16_t source_port;
    uint16_t destination_port;
    struct sctp_reassembly_htable_element* next;
    struct sctp_reassembly* buffers;
    uint16_t StreamID;
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

struct sctp_header {
    uint16_t SourcePort;
    uint16_t DestPort;
    uint32_t VerificationTag;
    uint32_t Checksum;
};

struct sctp_chunk {
    uint8_t Type;
    uint8_t Flags;
    uint16_t Length;
};

struct sctp_parameter {
    uint16_t ParameterType;
    uint16_t ParameterLength;
};

struct sctp_parameter_outgoing_ssn_reset_request {
    uint32_t RequestSequence;
    uint32_t ResponseSequence;
    uint32_t SenderLastTSN;
};

struct sctp_parameter_reconfiguration_response {
    uint32_t ResponseSequence;
    uint32_t Result;
    uint32_t SenderNextTSN;
    uint32_t ReceiverNextTSN;
};

struct sctp_parameter_add_stream {
    uint32_t RequestSequence;
    uint16_t NewStreamCount;
    uint16_t Reserved;
};

struct sctp_chunk_init {
    uint32_t InitiateTag;
    uint32_t AdvertizedReceiverWindowCredit;
    uint16_t OutboundStreamCount;
    uint16_t InboundStreamCount;
    uint32_t InitialTSN;
};

struct sctp_chunk_sack {
    uint32_t CumulativeTSNAck;
    uint32_t AdvertizedReceiverWindowCredit;
    uint16_t GapAckBlockCount;
    uint16_t DuplicateTSNCount;
};

struct sctp_chunk_auth {
    uint16_t SharedKeyIdentifier;
    uint16_t HMACIdentifier;
};

struct sctp_chunk_idata {
    uint32_t TSN;
    uint16_t StreamID;
    uint16_t Reserved;
    uint32_t MessageID;
    uint32_t PayloadID_FragmentSequence;
};

struct sctp_chunk_data {
    uint32_t TSN;
    uint16_t StreamID;
    uint16_t StreamSequenceNumber;
    uint32_t PayloadID;
};

struct sctp_gap_ack_block {
    uint16_t Start;
    uint16_t End;
};

struct sctp_forward_tsn_stream {
    uint16_t Stream;
    uint16_t StreamSequence;
};

struct sctp_iforward_tsn_stream {
    uint16_t StreamID;
    uint16_t Reserved : 15;
    uint8_t U : 1;
    uint32_t MessageID;
} __attribute__((packed));

void sctp_dump(struct ob_protocol* buffer);

#endif
