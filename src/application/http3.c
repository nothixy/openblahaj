#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "generic/binary.h"
#include "application/http.h"
#include "application/quic.h"
#include "application/http3.h"

static const char* HTTP_3_QPACK_STATIC_TABLE[] = {
    "0Authority: ",
    "1Path: /",
    "1Age: 0",
    "0Content-Disposition: ",
    "1Content-Length: 0",
    "0Cookie: ",
    "0Date: ",
    "0Etag: ",
    "8If-Modified-Since: ",
    "0If-None-Match: ",
    "0Last-Modified: ",
    "0Link: ",
    "0Location: ",
    "0Referer: ",
    "0Set-Cookie: ",
    "1Method: CONNECT",
    "1Method: DELETE",
    "1Method: GET",
    "1Method: HEAD",
    "1Method: OPTIONS",
    "1Method: POST",
    "1Method: PUT",
    "1Scheme: http",
    "1Scheme: https",
    "1Status: 103",
    "1Status: 200",
    "1Status: 304",
    "1Status: 404",
    "1Status: 503",
    "1Accept: */*",
    "1Accept: application/dns-message",
    "1Accept-Encoding: gzip, deflate, br",
    "1Accept-Ranges: bytes",
    "1Access-Control-Allow-Headers: cache-control",
    "1Access-Control-Allow-Headers: content-type",
    "1Access-Control-Allow-Origin: *",
    "1Cache-Control: max-age=0",
    "1Cache-Control: max-age=2592000",
    "1Cache-Control: max-age=604800",
    "1Cache-Control: no-cache",
    "1Cache-Control: no-store",
    "1Cache-Control: public, max-age=31536000",
    "1Content-Encoding: br",
    "1Content-Encoding: gzip",
    "1Content-Type: application/dns-message",
    "1Content-Type: application/javascript",
    "1Content-Type: application/json",
    "1Content-Type: application/x-www-form-urlencoded",
    "1Content-Type: image/gif",
    "1Content-Type: image/jpeg",
    "1Content-Type: image/png",
    "1Content-Type: text/css",
    "1Content-Type: text/html; charset=utf-8",
    "1Content-Type: text/plain",
    "1Content-Type: text/plain; charset=utf-8",
    "1Range: bytes=0-",
    "1Strict-Transport-Security: max-age=31536000",
    "1Strict-Transport-Security: max-age=31536000; includeSubdomains",
    "1Strict-Transport-Security: max-age=31536000; includeSubdomains; preload",
    "1Vary: accept-encoding",
    "1Vary: origin",
    "1X-Content-Type-Options: nosniff",
    "1X-XSS-Protection: 1; mode=block",
    "1Status: 100",
    "1Status: 204",
    "1Status: 206",
    "1Status: 302",
    "1Status: 400",
    "1Status: 403",
    "1Status: 421",
    "1Status: 425",
    "1Status: 500",
    "0Accept-Language: ",
    "1Access-Control-Allow-Credentials: FALSE",
    "1Access-Control-Allow-Credentials: TRUE",
    "1Access-Control-Allow-Headers: *",
    "1Access-Control-Allow-Methods: get",
    "1Access-Control-Allow-Methods: get, post, options",
    "1Access-Control-Allow-Methods: options",
    "1Access-Control-Expose-Headers: content-length",
    "1Access-Control-Request-Headers: content-type",
    "1Access-Control-Request-Method: get",
    "1Access-Control-Request-Method: post",
    "1Alt-Svc: clear",
    "0Authorization: ",
    "1Content-Security-Policy: script-src 'none'; object-src 'none'; base-uri 'none'",
    "1Early-Data: 1",
    "0Expect-CT: ",
    "0Forwarded: ",
    "0If-Range: ",
    "0Origin: ",
    "1Purpose: prefetch",
    "0Server: ",
    "1Timing-Allow-Origin: *",
    "1Upgrade-Insecure-Requests: 1",
    "0User-Agent: ",
    "0X-Forwarded-For: ",
    "1X-Frame-Options: deny",
    "1X-Frame-Options: sameorigin"
};

static ssize_t http3_read_integer(uint8_t* hdr, ssize_t length, uint64_t* value, uint8_t bit_start)
{
    ssize_t index = 1;
    uint64_t multi = 1;
    *value = hdr[0] & ((1 << (8 - bit_start)) - 1);
    if (*value + 1 != (1 << (8 - bit_start)))
    {
        return 1;
    }
    do
    {
        uint8_t byte_value = (hdr[index] & (1 << (8 - bit_start)) - 1);
        *value += (hdr[index] & 0b01111111) * multi;
        multi *= 128;
    }
    while (hdr[index++] & (1 << 7));
    return index;
}

static ssize_t http3_qpack_read_header(uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    ssize_t read_bytes = 0;
    uint8_t line_type = hdr[0];

    if (line_type & (1 << 7))
    {
        if (line_type & (1 << 6))
        {
            uint64_t table_index;
            read_bytes += http3_read_integer(hdr, length, &table_index, 2);
            printf("%s\n", &HTTP_3_QPACK_STATIC_TABLE[line_type & 0b00111111][1]);
            return 1;
        }
        else
        {
            return length;
        }
    }
    if (line_type & (1 << 6))
    {
        bool add_to_dynamic = (bool) (1 << 5);
        if (line_type & (1 << 4))
        {
            bool huffman;
            uint64_t table_index;
            uint64_t value_length;
            read_bytes += http3_read_integer(hdr, length, &table_index, 4);
            char* name = &HTTP_3_QPACK_STATIC_TABLE[table_index][1];
            while (*name != ':' && *name != '\0')
            {
                printf("%c", *name);
                ++name;
            }
            printf(": ");
            huffman = hdr[read_bytes] & (1 << 7);
            read_bytes += http3_read_integer(&hdr[read_bytes], length - read_bytes, &value_length, 1);
            if (huffman)
            {
                http_2_huffman_decode(&hdr[read_bytes], value_length);
            }
            else
            {
                for (uint64_t i = 0; i < value_length; ++i)
                {
                    printf("%c", hdr[read_bytes + i]);
                }
            }
            printf("\n");
            return read_bytes + value_length;
        }
    }
    if (line_type & (1 << 5))
    {
        bool value_huffman;
        bool name_huffman = (bool) (line_type & (1 << 3));
        uint64_t name_length;
        uint64_t value_length;
        read_bytes += http3_read_integer(hdr, length, &name_length, 5);
        if (name_huffman)
        {
            http_2_huffman_decode(&hdr[read_bytes], name_length);
        }
        else
        {
            for (uint64_t i = 0; i < name_length; ++i)
            {
                printf("%c", hdr[read_bytes + i]);
            }
        }
        printf(": ");
        read_bytes += (ssize_t) name_length;
        value_huffman = hdr[read_bytes] & (1 << 7);
        read_bytes += http3_read_integer(&hdr[read_bytes], length - read_bytes, &value_length, 1);
        if (value_huffman)
        {
            http_2_huffman_decode(&hdr[read_bytes], value_length);
        }
        else
        {
            for (uint64_t i = 0; i < value_length; ++i)
            {
                printf("%c", hdr[read_bytes + i]);
            }
        }
        printf("\n");
        return read_bytes + value_length;
    }

    buffer->hdr = hdr;
    buffer->length = length;
    
    binary_dump(buffer);

    return length;
}

static ssize_t http3_qpack_dump(uint8_t* hdr, struct ob_protocol* buffer, ssize_t length)
{
    void* saved_hdr = buffer->hdr;
    ssize_t saved_length = buffer->length;

    uint8_t required_insert_count = hdr[0];
    uint8_t delta_base = hdr[1] & 0b01111111;

    printf("%-45s = %u\n", "Required insert count", required_insert_count);
    printf("%-45s = %u\n", "Base", hdr[1] & (1 << 7) ? required_insert_count - delta_base - 1 : required_insert_count + delta_base);

    length -= 2;
    hdr = &hdr[2];

    while (length > 0)
    {
        ssize_t read_bytes = http3_qpack_read_header(hdr, buffer, length);
        length -= read_bytes;
        hdr = &hdr[read_bytes];
        // uint8_t line_type = hdr[0];
        // if (line_type & (1 << 7))
        // {
        //     if (line_type & (1 << 6))
        //     {
        //         // Static table
        //         printf("%s\n", &HTTP_3_QPACK_STATIC_TABLE[line_type & 0b00111111][1]);
        //     }
        //     else
        //     {

        //     }
        //     length -= 1;
        //     hdr = &hdr[1];
        //     continue;
        // }
        // if (line_type & (1 << 6))
        // {
        //     if (line_type & (1 << 4))
        //     {

        //     }
        // }
        // length = 0;
    }

    buffer->length = saved_length;
    buffer->hdr = saved_hdr;
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
