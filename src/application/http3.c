#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "generic/binary.h"
#include "application/http.h"
#include "application/quic.h"
#include "application/http3.h"

static ssize_t http3_qpack_dump(uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    void* saved_hdr = buffer->hdr;
    ssize_t saved_length = buffer->length;
    buffer->hdr = hdr;
    buffer->length = length;
    binary_dump(buffer);
    buffer->length = saved_length;
    buffer->hdr = saved_hdr;

    return -1;
}

static ssize_t http3_dump_headers(uint8_t* hdr, struct ob_protocol* buffer)
{
    ssize_t off = 1;
    uint64_t length;
    off += quic_read_variable_number(&hdr[off], &length);
    http3_qpack_dump(&hdr[off], buffer, (ssize_t) length);
    return off + (ssize_t) length;
}

static ssize_t http3_dump_data(const uint8_t* hdr)
{
    ssize_t off = 1;
    uint64_t length;
    off += quic_read_variable_number(&hdr[off], &length);
    http_dump_text(&hdr[off], (ssize_t) length);
    return off + (ssize_t) length;
}

void http3_dump(struct ob_protocol* buffer)
{
    uint8_t* hdr = buffer->hdr;
    ssize_t read_bytes;
    while (buffer->length > 0)
    {
        switch (hdr[0])
        {
            case 0x0: /* DATA */
                printf("--- BEGIN HTTP/3 DATA ---\n");
                read_bytes = http3_dump_data(hdr);
                hdr = &hdr[read_bytes];
                buffer->length -= read_bytes;
                break;

            case 0x1: /* HEADERS */
                printf("--- BEGIN HTTP/3 HEADERS ---\n");
                read_bytes = http3_dump_headers(hdr, buffer);
                hdr = &hdr[read_bytes];
                buffer->length -= read_bytes;
                break;

            case 0x3: /* CANCEL PUSH */
                printf("--- BEGIN HTTP/3 CANCEL PUSH ---\n");
                buffer->length = 0;
                break;

            case 0x4: /* SETTINGS */
                printf("--- BEGIN HTTP/3 SETTINGS ---\n");
                buffer->length = 0;
                break;

            case 0x5: /* PUSH PROMISE */
                printf("--- BEGIN HTTP/3 PUSH PROMISE ---\n");
                buffer->length = 0;
                break;

            case 0x7: /* GOAWAY */
                printf("--- BEGIN HTTP/3 GOAWAY ---\n");
                buffer->length = 0;
                break;

            case 0xd: /* MAX PUSH ID */
                printf("--- BEGIN HTTP/3 MAX PUSH ID ---\n");
                buffer->length = 0;
                break;

            default:
                printf("--- BEGIN HTTP/3 UNKNOWN ---\n");
                buffer->length = 0;
                break;
        }
    }
}
