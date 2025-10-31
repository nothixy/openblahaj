#include <stdio.h>
#include <endian.h>
#include <setjmp.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "application/tls.h"
#include "generic/binary.h"
#include "application/quic.h"
#include "application/http3.h"
#include "generic/protocol.h"

static uint8_t stream_data[1<<16] = {0};
static uint8_t crypto_data[1<<16] = {0};
static ssize_t crypto_length = 0;
static bool has_dumped_once = false;

static uint8_t stream_done = 0;
static bool stream_fin = false;
static uint64_t max_length;

void quic_dump_remaining_crypto_data()
{
    struct ob_protocol buffer;
    ssize_t read_tls;
    buffer.hdr = (void*) crypto_data;
    buffer.length = crypto_length;
    // binary_dump(&buffer);
    while (buffer.length > 0)
    {
        uint8_t* hdr = (uint8_t*) buffer.hdr;
        // binary_dump(buffer);
        read_tls = tls_dump_handshake(&buffer);
        buffer.length -= read_tls;
        buffer.hdr = &hdr[read_tls];
    }
}

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

static ssize_t quic_dump_frame_ack(const uint8_t* hdr, ssize_t length)
{
    // TODO: Write
    ssize_t read_bytes = 1;
    uint64_t largest_acknowledged;
    uint64_t ack_delay;
    uint64_t ack_range_count;
    uint64_t first_ack_range;
    read_bytes += quic_read_variable_number(&hdr[read_bytes], &largest_acknowledged);
    read_bytes += quic_read_variable_number(&hdr[read_bytes], &ack_delay);
    read_bytes += quic_read_variable_number(&hdr[read_bytes], &ack_range_count);
    read_bytes += quic_read_variable_number(&hdr[read_bytes], &first_ack_range);

    printf("%-45s = %lu\n", "Largest acknowledged", largest_acknowledged);
    printf("%-45s = %lu\n", "ACK delay", ack_delay);
    printf("%-45s = %lu\n", "ACK range count", ack_range_count);
    printf("%-45s = %lu\n", "First ACK range", first_ack_range);

    return read_bytes;
}

// static ssize_t quic_dump_stream_data(const uint8_t* hdr, struct ob_protocol* buffer)
// {
//     // TODO: Write
//     (void) hdr;
//     (void) buffer;
//     return 0;
// }

static bool has_only_0_remaining(const uint8_t* hdr, ssize_t length)
{
    for (ssize_t i = 0; i < length; ++i)
    {
        if (hdr[i])
        {
            return false;
        }
    }
    return true;
}

static ssize_t quic_dump_frames(const uint8_t* hdr, ssize_t length, struct ob_protocol* buffer)
{
    ssize_t original_length = length;
    bool stop = false;
    // printf("RUN LENGTH %d\n", length);

    while (length > 0 && !stop)
    {
        ssize_t read_bytes;
        uint8_t frame_type = hdr[0];
        switch (frame_type)
        {
            case 0x0: /* PADDING */
                if (has_only_0_remaining(hdr, length))
                {
                    return length;
                }
                printf("--- BEGIN QUIC PADDING FRAME ---\n");
                length -= 1;
                hdr = &hdr[1];
                break;

            case 0x1: /* PING */
                printf("--- BEGIN QUIC PING FRAME ---\n");
                length -= 1;
                hdr = &hdr[1];
                break;

            case 0x2:
            case 0x3: /* ACK */
                printf("--- BEGIN QUIC ACK FRAME ---\n");
                read_bytes = quic_dump_frame_ack(hdr, length);
                length -= read_bytes;
                hdr = &hdr[read_bytes];
                break;

            case 0x4: /* RESET STREAM */
                printf("--- BEGIN QUIC RESET STREAM FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
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
                length -= off;
                break;
            }

            case 0x6: /* CRYPTO */
            {
                void* hdr_save = buffer->hdr;
                ssize_t length_save = buffer->length;
                ssize_t off = 1;
                uint64_t offset;
                uint64_t length;
                off += quic_read_variable_number(&hdr[off], &offset);
                off += quic_read_variable_number(&hdr[off], &length);
                printf("--- BEGIN QUIC CRYPTO FRAME ---\n");
                printf("%-45s = %lu\n", "Offset", offset);
                printf("%-45s = %lu\n", "Length", length);
                // printf("Offset = %lu, crypto_data_has_0_byte = %d\n", offset, crypto_data_has_0_byte);
                if (offset == 0)
                {
                    printf("Crypto length = %ld\n", crypto_length);
                    if (!has_dumped_once)
                    {
                        printf("\033[1m[SAVED FOR LATER]\033[22m\n");
                        memcpy(&crypto_data[offset], &hdr[off], length);
                        if (length + offset >= crypto_length)
                        {
                            crypto_length = length + offset;
                        }
                        has_dumped_once = true;
                    }
                    else
                    {
                        printf("\033[1m[SAVED FOR LATER]\033[22m\n");
                        printf("\033[1m[REASSEMBLY OF PREVIOUS CRYPTO, LENGTH = %ld]\033[22m\n", crypto_length);
                        ssize_t read_tls;
                        buffer->hdr = (void*) crypto_data;
                        buffer->length = crypto_length;
                        // binary_dump(buffer);
                        while (buffer->length > 0)
                        {
                            uint8_t* hdr = (uint8_t*) buffer->hdr;
                            // binary_dump(buffer);
                            read_tls = tls_dump_handshake(buffer);
                            printf("READ TLS = %ld\n", read_tls);
                            buffer->length -= read_tls;
                            buffer->hdr = &hdr[read_tls];
                        }
                        buffer->hdr = hdr_save;
                        buffer->length = length_save;
                        has_dumped_once = true;
                        crypto_length = length;
                        memset(crypto_data, 0, sizeof(crypto_data));
                        memcpy(&crypto_data[offset], &hdr[off], length);
                        if (length + offset >= crypto_length)
                        {
                            crypto_length = length + offset;
                        }
                    }
                }
                else
                {
                    printf("\033[1m[SAVED FOR LATER]\033[22m\n");
                    memcpy(&crypto_data[offset], &hdr[off], length);
                    if (length + offset >= crypto_length)
                    {
                        crypto_length = length + offset;
                    }
                }
                off += (ssize_t) length;
                // NOT IMPLEMENTED
                hdr = &hdr[off];
                length -= off;
                break;
            }

            case 0x7: /* NEW TOKEN */
                printf("--- BEGIN QUIC NEW TOKEN FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
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
                    if (fin)
                    {
                        stream_fin = true;
                    }
                    stream_done += 1;
                    if (length + offset > max_length)
                    {
                        max_length = length + offset;
                    }
                    memcpy(&stream_data[offset], &hdr[off], length);
                }

                off += (ssize_t) length;
                hdr = &hdr[off];
                length -= off;
                break;
            }

            case 0x10: /* MAX DATA */
                printf("--- BEGIN QUIC MAX DATA FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x11: /* MAX STREAM DATA */
                printf("--- BEGIN QUIC MAX STREAM DATA FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x12:
            case 0x13: /* MAX STREAMS */
                printf("--- BEGIN QUIC MAX STREAMS FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x14: /* DATA BLOCKED */
                printf("--- BEGIN QUIC DATA BLOCKED FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x15: /* STREAM DATA BLOCKED */
                printf("--- BEGIN QUIC STREAM DATA BLOCKED FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x16:
            case 0x17: /* STREAMS BLOCKED */
                printf("--- BEGIN QUIC STREAMS BLOCKED FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
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
                printf("%-45s = ", "Connection ID");
                for (uint8_t i = 0; i < length; ++i)
                {
                    printf("%02x", hdr[off + i]);
                }
                printf("\n");
                off += length;
                printf("%-45s = ", "Stateless reset token");
                for (uint8_t i = 0; i < 128 / 8; ++i)
                {
                    printf("%02x", hdr[off + i]);
                }
                printf("\n");
                off += (128 / 8);
                hdr = &hdr[off];
                length -= off;
                break;
            }

            case 0x19: /* RETIRE CONNECTION ID */
                printf("--- BEGIN QUIC RETIRE CONNECTION ID FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x1A: /* PATH CHALLENGE */
                printf("--- BEGIN QUIC PATH CHALLENGE FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x1B: /* PATH RESPONSE */
                printf("--- BEGIN QUIC PATH RESPONSE FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x1C:
            case 0x1D: /* CONNECTION CLOSE */
                printf("--- BEGIN QUIC CONNECTION CLOSE FRAME ---\n");
                // NOT IMPLEMENTED
                length = 0;
                break;

            case 0x1E: /* HANDSHAKE DONE */
                printf("--- BEGIN QUIC HANDSHAKE DONE FRAME ---\n");
                hdr = &hdr[1];
                length -= 1;
                break;

            default:
                stop = true;
                length = 0;
                break;
        }
    }

    // printf("HAS DATA LEFT = %d\n", buffer->length);
    return original_length - length;
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

            read_length += (ssize_t) packet_number_length + 1;

            printf("%-45s = %u\n", "Packet number", packet_number);

            quic_dump_frames(&hdr[read_length], (ssize_t) data_length, buffer);

            read_length += (ssize_t) (data_length - packet_number_length - 1);

            // printf("%-45s = %ld\n", "Read length", read_length);
            break;

        case 1: /* 0-RTT */
            // NOT IMPLEMENTED
            break;

        case 2: /* HANDSHAKE PACKET */
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

            read_length += (ssize_t) packet_number_length + 1;

            quic_dump_frames(&hdr[read_length], (ssize_t) data_length, buffer);

            read_length += (ssize_t) (data_length - packet_number_length - 1);
            // printf("%-45s = %ld\n", "Read length", read_length);
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

            read_length = quic_dump_frames(hdr, buffer->length, buffer);
            // return;
            hdr = &hdr[read_length];
            buffer->length -= read_length;
        }

        // binary_dump(buffer);
    }

    // printf("HAS REMAINING DATA = %d\n", buffer->length);

    // printf("LESS GOOO\n");

    // printf("FIN = %d\n", stream_fin);

    if (stream_done >= 3 && stream_fin)
    {
        buffer->length = (ssize_t) max_length;
        buffer->hdr = stream_data;
        http3_dump(buffer);
        stream_done = 0;
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
