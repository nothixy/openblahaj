#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>

#include "generic/binary.h"
#include "application/quic.h"
#include "application/http3.h"
#include "generic/protocol.h"

static uint8_t stream_data[1<<16] = {0};

static uint8_t done = 0;
static uint64_t max_length;

ssize_t quic_read_variable_number(const uint8_t* hdr, uint64_t* number)
{
    uint8_t byte = hdr[0];
    *number = byte & 0b00111111;
    uint8_t length;
    switch (byte >> 6)
    {
        case 0b00:
            length = 1;
            break;

        case 0b01:
            length = 2;
            break;

        case 0b10:
            length = 4;
            break;

        case 0b11:
            length = 8;
            break;
    }
    for (int i = 1; i < length; ++i)
    {
        *number <<= 8;
        *number |= hdr[i];
    }
    return length;
}

static ssize_t quic_dump_frame_ack(const uint8_t* hdr, struct ob_protocol* buffer)
{
    // TODO: Write 
    (void) hdr;
    (void) buffer;
    return 5;
}

// static ssize_t quic_dump_stream_data(const uint8_t* hdr, struct ob_protocol* buffer)
// {
//     // TODO: Write
//     (void) hdr;
//     (void) buffer;
//     return 0;
// }

static ssize_t quic_dump_frames(const uint8_t* hdr, struct ob_protocol* buffer)
{
    ssize_t original_length = buffer->length;
    bool stop = false;

    while (buffer->length > 0 && !stop)
    {
        ssize_t read_bytes;
        uint8_t frame_type = hdr[0];
        switch (frame_type)
        {
            case 0x0: /* PADDING */
                printf("--- BEGIN QUIC PADDING FRAME ---\n");
                buffer->length -= 1;
                hdr = &hdr[1];
                break;

            case 0x1: /* PING */
                printf("--- BEGIN QUIC PING FRAME ---\n");
                buffer->length -= 1;
                hdr = &hdr[1];
                break;

            case 0x2:
            case 0x3: /* ACK */
                printf("--- BEGIN QUIC ACK FRAME ---\n");
                read_bytes = quic_dump_frame_ack(hdr, buffer);
                buffer->length -= read_bytes;
                hdr = &hdr[read_bytes];
                break;

            case 0x4: /* RESET STREAM */
                printf("--- BEGIN QUIC RESET STREAM FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x5: /* STOP SENDING */
            {
                ssize_t off = 1;
                uint64_t stream_id;
                uint64_t application_protocol_error_code;
                off += quic_read_variable_number(&hdr[off], &stream_id);
                off += quic_read_variable_number(&hdr[off], &application_protocol_error_code);
                printf("--- BEGIN QUIC STOP SENDING FRAME ---\n");
                // NOT IMPLEMENTED
                printf("%-45s = %lu\n", "Stream ID", stream_id);
                printf("%-45s = %lu\n", "Application protocol error code", application_protocol_error_code);
                hdr = &hdr[off];
                buffer->length -= off;
                break;
            }

            case 0x6: /* CRYPTO */
            {
                ssize_t off = 1;
                uint64_t offset;
                uint64_t length;
                off += quic_read_variable_number(&hdr[off], &offset);
                off += quic_read_variable_number(&hdr[off], &length);
                printf("--- BEGIN QUIC CRYPTO FRAME ---\n");
                printf("%-45s = %lu\n", "Offset", offset);
                printf("%-45s = %lu\n", "Length", length);
                off += (ssize_t) length;
                // NOT IMPLEMENTED
                hdr = &hdr[off];
                buffer->length -= off;
                break;
            }

            case 0x7: /* NEW TOKEN */
                printf("--- BEGIN QUIC NEW TOKEN FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x8:
            case 0x9:
            case 0xA:
            case 0xB:
            case 0xC:
            case 0xD:
            case 0xE:
            case 0xF: /* STREAM */
            {
                uint8_t flags = hdr[0] - 8;
                uint8_t has_offset = flags & 0x4;
                uint8_t has_len = flags & 0x2;
                uint8_t fin = flags & 0x1;
                ssize_t off = 1;
                uint64_t length = 0;
                uint64_t offset = 0;
                uint64_t stream_id;


                printf("--- BEGIN STREAM FRAME ---\n");
                off += quic_read_variable_number(&hdr[off], &stream_id);
                if (has_offset)
                {
                    off += quic_read_variable_number(&hdr[off], &offset);
                }
                if (has_len)
                {
                    off += quic_read_variable_number(&hdr[off], &length);
                }
                printf("%-45s = %lu\n", "Stream ID", stream_id);
                printf("%-45s = %lu\n", "Offset", offset);
                printf("%-45s = %lu\n", "Length", length);
                printf("%-45s = %u\n", "Final", fin);

                if (stream_id == 0)
                {
                    done += 1;
                    if (length + offset > max_length)
                    {
                        max_length = length + offset;
                    }
                    memcpy(&stream_data[offset], &hdr[off], length);
                }


                off += (ssize_t) length;
                hdr = &hdr[off];
                buffer->length -= off;
                break;
            }

            case 0x10: /* MAX DATA */
                printf("--- BEGIN QUIC MAX DATA FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x11: /* MAX STREAM DATA */
                printf("--- BEGIN QUIC MAX STREAM DATA FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x12:
            case 0x13: /* MAX STREAMS */
                printf("--- BEGIN QUIC MAX STREAMS FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x14: /* DATA BLOCKED */
                printf("--- BEGIN QUIC DATA BLOCKED FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x15: /* STREAM DATA BLOCKED */
                printf("--- BEGIN QUIC STREAM DATA BLOCKED FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x16:
            case 0x17: /* STREAMS BLOCKED */
                printf("--- BEGIN QUIC STREAMS BLOCKED FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x18: /* NEW CONNECTION ID */
            {
                ssize_t off = 1;
                uint64_t sequence_number;
                uint64_t retire_prior_to;
                uint8_t length;
                printf("--- BEGIN QUIC NEW CONNECTION ID FRAME ---\n");
                off += quic_read_variable_number(&hdr[off], &sequence_number);
                off += quic_read_variable_number(&hdr[off], &retire_prior_to);
                length = hdr[off];
                off += 1;
                printf("%-45s = %lu\n", "Sequence number", sequence_number);
                printf("%-45s = %lu\n", "Retire prior to", retire_prior_to);
                printf("%-45s = %u\n", "Length", length);
                off += length;
                off += (128 / 8);
                hdr = &hdr[off];
                buffer->length -= off;
                break;
            }

            case 0x19: /* RETIRE CONNECTION ID */
                printf("--- BEGIN QUIC RETIRE CONNECTION ID FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x1A: /* PATH CHALLENGE */
                printf("--- BEGIN QUIC PATH CHALLENGE FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x1B: /* PATH RESPONSE */
                printf("--- BEGIN QUIC PATH RESPONSE FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x1C:
            case 0x1D: /* CONNECTION CLOSE */
                printf("--- BEGIN QUIC CONNECTION CLOSE FRAME ---\n");
                // NOT IMPLEMENTED
                buffer->length = 0;
                break;

            case 0x1E: /* HANDSHAKE DONE */
                printf("--- BEGIN QUIC HANDSHAKE DONE FRAME ---\n");
                hdr = &hdr[1];
                buffer->length -= 1;
                break;

            default:
                stop = true;
                buffer->length = 0;
                break;
        }
    }

    // printf("HAS DATA LEFT = %d\n", buffer->length);
    return original_length - buffer->length;
}

static ssize_t quic_dump_long_packet(const uint8_t* hdr, struct ob_protocol* buffer)
{
    ssize_t read_length = 0;
    uint8_t dcid_length;
    uint8_t scid_length;
    uint8_t packet_number_length;
    uint32_t packet_number;
    uint64_t data_length;
    uint64_t token_length;
    struct quic_header_long qh;
    if (buffer->length < (ssize_t) sizeof(struct quic_header_long))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    memcpy(&qh, hdr, sizeof(struct quic_header_long));

    read_length += (ssize_t) sizeof(struct quic_header_long);

    packet_number_length = qh.TypeSpecificBits & 0b11;

    printf("%-45s = %u\n", "Header form", qh.HeaderForm);
    printf("%-45s = %u\n", "Fixed bit", qh.FixedBit);
    printf("%-45s = %u\n", "Long packet type", qh.LongPacketType);
    printf("%-45s = %u\n", "Type specific bits", qh.TypeSpecificBits);
    printf("%-45s = %u\n", "Version", be32toh(qh.VersionID));
    
    dcid_length = hdr[read_length];
    printf("%-45s = %u\n", "DCID length", dcid_length);
    read_length += dcid_length + 1;
    scid_length = hdr[read_length];
    printf("%-45s = %u\n", "SCID length", scid_length);
    read_length += scid_length + 1;

    switch (qh.LongPacketType)
    {
        case 0: /* INITIAL PACKET */
            read_length += quic_read_variable_number(&hdr[read_length], &token_length);
            read_length += (ssize_t) token_length;

            printf("%-45s = %lu\n", "Token length", token_length);

            read_length += quic_read_variable_number(&hdr[read_length], &data_length);
            printf("%-45s = %lu\n", "Data length", data_length);

            packet_number = hdr[read_length];
            if (packet_number_length >= 1)
            {
                packet_number <<= 8;
                packet_number |= hdr[read_length + 1];
            }
            if (packet_number_length >= 2)
            {
                packet_number <<= 8;
                packet_number |= hdr[read_length + 2];
            }
            if (packet_number_length >= 3)
            {
                packet_number <<= 8;
                packet_number |= hdr[read_length + 3];
            }

            printf("%-45s = %u\n", "Packet number", packet_number);

            read_length += (ssize_t) data_length;
            printf("%-45s = %ld\n", "Read length", read_length);
            break;

        case 1: /* 0-RTT */
            // NOT IMPLEMENTED
            break;

        case 2: /* HANDSHAKE PACKET */
            read_length += quic_read_variable_number(&hdr[read_length], &data_length);
            printf("%-45s = %lu\n", "Data length", data_length);

            read_length += (ssize_t) data_length;
            printf("%-45s = %ld\n", "Read length", read_length);
            break;

        case 3: /* RETRY PACKET */
            // NOT IMPLEMENTED
            break;

        default:
            break;
    }

    return read_length;
}

static void quic_dump_v3(struct ob_protocol* buffer)
{
    const uint8_t* hdr = buffer->hdr;
    ssize_t read_length = 0;

    // binary_dump(buffer);
    // return;

    while (buffer->length > 0)
    {
        uint8_t first_byte = hdr[0];
        if (first_byte == 0)
        {
            return;
        }
        printf("--- BEGIN QUIC MESSAGE ---\n");

        if (first_byte & (1 << 7))
        {
            read_length = quic_dump_long_packet(hdr, buffer);

            hdr = &hdr[read_length];
            buffer->length -= read_length;

            continue;
        }
        else
        {
            uint32_t packet_number;
            struct quic_header_short qh;
            if (buffer->length < (ssize_t) sizeof(struct quic_header_short))
            {
                longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
            }
            memcpy(&qh, buffer->hdr, sizeof(struct quic_header_short));

            read_length += (ssize_t) sizeof(struct quic_header_short);

            printf("%-45s = %u\n", "Header form", qh.HeaderForm);
            printf("%-45s = %u\n", "Fixed bit", qh.FixedBit);
            printf("%-45s = %u\n", "Spin bits", qh.SpinBits);
            printf("%-45s = %u\n", "Reserved", qh.Reserved);
            printf("%-45s = %u\n", "Key phase", qh.KeyPhase);
            printf("%-45s = %u\n", "P", qh.P);

            packet_number = hdr[read_length];
            if (qh.P >= 1)
            {
                packet_number <<= 8;
                packet_number |= hdr[read_length + 1];
            }
            if (qh.P >= 2)
            {
                packet_number <<= 8;
                packet_number |= hdr[read_length + 2];
            }
            if (qh.P >= 3)
            {
                packet_number <<= 8;
                packet_number |= hdr[read_length + 3];
            }
            read_length += qh.P + 1;

            printf("%-45s = %u\n", "Packet number", packet_number);

            hdr = &hdr[read_length];
            buffer->length -= read_length;

            // printf("BUFFER LENGTH IS %d\n", buffer->length);
            // printf("BYTES ARE %d %d %d\n", hdr[-1], hdr[0], hdr[1]);

            read_length = quic_dump_frames(hdr, buffer);
            // return;
            hdr = &hdr[read_length];
        }

        // binary_dump(buffer);
    }

    // printf("HAS REMAINING DATA = %d\n", buffer->length);

    // printf("LESS GOOO\n");

    
    if (done == 3)
    {
        buffer->length = (ssize_t) max_length;
        buffer->hdr = stream_data;
        http3_dump(buffer);
        done = 0;
        // for (uint64_t i = 0; i < max_length; ++i)
        // {
        //     putc(stream_data[i], stdout);
        // }
        // printf("%s\n", stream_data);
    }
}

static void quic_dump_v2(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;
    if (buffer->length == 0)
    {
        return;
    }

    printf("QUIC => ");
    for (ssize_t i = 0; i < buffer->length; ++i)
    {
        if (hdr[i] == '\n' || hdr[i] == '\r')
        {
            if (i < buffer->length - 2)
            {
                printf("\033[1m[Output truncated]\033[22m");
            }
            printf("\n");
            return;
        }
        if (hdr[i] >= 32 && hdr[i] <= 126)
        {
            printf("%c", hdr[i]);
        }
        else
        {
            printf(".");
        }
    }
    printf("\n");
}

void quic_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> QUIC ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            quic_dump_v2(buffer);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            quic_dump_v3(buffer);
            break;
    }
}
