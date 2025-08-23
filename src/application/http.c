#include "generic/binary.h"
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "application/http.h"
#include "generic/protocol.h"
#include "application/quic.h"

const char HTTP_PRISM_INIT[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const char* HTTP_2_FRAME_TYPE[] = {
    "DATA",
    "HEADERS",
    "PRIORITY",
    "RST_STREAM",
    "SETTINGS",
    "PUSH_PROMISE",
    "PING",
    "GOAWAY",
    "WINDOW_UPDATE",
    "CONTINUATION",
};

const char* HTTP_2_SETTING_NAME[] = {
    "UNKNOWN",
    "HEADER TABLE SIZE",
    "ENABLE PUSH",
    "MAX CONCURRENT STREAMS",
    "INITIAL WINDOW SIZE",
    "MAX FRAME SIZE",
    "MAX HEADER LIST SIZE",
};

const char* HTTP_2_HPACK_STATIC_TABLE[] = {
    "0" "Unknown: ",
    "0" "Authority: ",
    "1" "Method: GET",
    "1" "Method: POST",
    "1" "Path: /",
    "1" "Path: /index.html",
    "1" "Scheme: http",
    "1" "Scheme: https",
    "1" "Status: 200",
    "1" "Status: 204",
    "1" "Status: 206",
    "1" "Status: 304",
    "1" "Status: 400",
    "1" "Status: 404",
    "1" "Status: 500",
    "0" "Accept-Charset: ",
    "1" "Accept-Encoding: gzip, deflate",
    "0" "Accept-Language: ",
    "0" "Accept-Ranges: ",
    "0" "Accept: ",
    "0" "Access-Control-Allow-Origin: ",
    "0" "Age: ",
    "0" "Allow: ",
    "0" "Authorization: ",
    "0" "Cache-Control: ",
    "0" "Content-Disposition: ",
    "0" "Content-Encoding: ",
    "0" "Content-Language: ",
    "0" "Content-Length: ",
    "0" "Content-Location: ",
    "0" "Content-Range: ",
    "0" "Content-Type: ",
    "0" "Cookie: ",
    "0" "Date: ",
    "0" "Etag: ",
    "0" "Expect: ",
    "0" "Expires: ",
    "0" "From: ",
    "0" "Host: ",
    "0" "If-Match: ",
    "0" "If-Modified-Since: ",
    "0" "If-None-Match: ",
    "0" "If-Range: ",
    "0" "If-Unmodified-Since: ",
    "0" "Last-Modified: ",
    "0" "Link: ",
    "0" "Location: ",
    "0" "Max-Forwards: ",
    "0" "Proxy-Authenticate: ",
    "0" "Proxy-Authorization: ",
    "0" "Range: ",
    "0" "Referer: ",
    "0" "Refresh: ",
    "0" "Retry-After: ",
    "0" "Server: ",
    "0" "Set-Cookie: ",
    "0" "Strict-Transport-Security: ",
    "0" "Transfer-Encoding: ",
    "0" "User-Agent: ",
    "0" "Vary: ",
    "0" "Via: ",
    "0" "WWW-Authenticate: "
};

struct http_2_huffman codes[] = {
    {0b1111111111000, 13},
    {0b11111111111111111011000, 23},
    {0b1111111111111111111111100010, 28},
    {0b1111111111111111111111100011, 28},
    {0b1111111111111111111111100100, 28},
    {0b1111111111111111111111100101, 28},
    {0b1111111111111111111111100110, 28},
    {0b1111111111111111111111100111, 28},
    {0b1111111111111111111111101000, 28},
    {0b111111111111111111101010, 24},
    {0b111111111111111111111111111100, 30},
    {0b1111111111111111111111101001, 28},
    {0b1111111111111111111111101010, 28},
    {0b111111111111111111111111111101, 30},
    {0b1111111111111111111111101011, 28},
    {0b1111111111111111111111101100, 28},
    {0b1111111111111111111111101101, 28},
    {0b1111111111111111111111101110, 28},
    {0b1111111111111111111111101111, 28},
    {0b1111111111111111111111110000, 28},
    {0b1111111111111111111111110001, 28},
    {0b1111111111111111111111110010, 28},
    {0b111111111111111111111111111110, 30},
    {0b1111111111111111111111110011, 28},
    {0b1111111111111111111111110100, 28},
    {0b1111111111111111111111110101, 28},
    {0b1111111111111111111111110110, 28},
    {0b1111111111111111111111110111, 28},
    {0b1111111111111111111111111000, 28},
    {0b1111111111111111111111111001, 28},
    {0b1111111111111111111111111010, 28},
    {0b1111111111111111111111111011, 28},
    {0b010100, 6},
    {0b1111111000, 10},
    {0b1111111001, 10},
    {0b111111111010, 12},
    {0b1111111111001, 13},
    {0b010101, 6},
    {0b11111000, 8},
    {0b11111111010, 11},
    {0b1111111010, 10},
    {0b1111111011, 10},
    {0b11111001, 8},
    {0b11111111011, 11},
    {0b11111010, 8},
    {0b010110, 6},
    {0b010111, 6},
    {0b011000, 6},
    {0b00000, 5},
    {0b00001, 5},
    {0b00010, 5},
    {0b011001, 6},
    {0b011010, 6},
    {0b011011, 6},
    {0b011100, 6},
    {0b011101, 6},
    {0b011110, 6},
    {0b011111, 6},
    {0b1011100, 7},
    {0b11111011, 8},
    {0b111111111111100, 15},
    {0b100000, 6},
    {0b111111111011, 12},
    {0b1111111100, 10},
    {0b1111111111010, 13},
    {0b100001, 6},
    {0b1011101, 7},
    {0b1011110, 7},
    {0b1011111, 7},
    {0b1100000, 7},
    {0b1100001, 7},
    {0b1100010, 7},
    {0b1100011, 7},
    {0b1100100, 7},
    {0b1100101, 7},
    {0b1100110, 7},
    {0b1100111, 7},
    {0b1101000, 7},
    {0b1101001, 7},
    {0b1101010, 7},
    {0b1101011, 7},
    {0b1101100, 7},
    {0b1101101, 7},
    {0b1101110, 7},
    {0b1101111, 7},
    {0b1110000, 7},
    {0b1110001, 7},
    {0b1110010, 7},
    {0b11111100, 8},
    {0b1110011, 7},
    {0b11111101, 8},
    {0b1111111111011, 13},
    {0b1111111111111110000, 19},
    {0b1111111111100, 13},
    {0b11111111111100, 14},
    {0b100010, 6},
    {0b111111111111101, 15},
    {0b00011, 5},
    {0b100011, 6},
    {0b00100, 5},
    {0b100100, 6},
    {0b00101, 5},
    {0b100101, 6},
    {0b100110, 6},
    {0b100111, 6},
    {0b00110, 5},
    {0b1110100, 7},
    {0b1110101, 7},
    {0b101000, 6},
    {0b101001, 6},
    {0b101010, 6},
    {0b00111, 5},
    {0b101011, 6},
    {0b1110110, 7},
    {0b101100, 6},
    {0b01000, 5},
    {0b01001, 5},
    {0b101101, 6},
    {0b1110111, 7},
    {0b1111000, 7},
    {0b1111001, 7},
    {0b1111010, 7},
    {0b1111011, 7},
    {0b111111111111110, 15},
    {0b11111111100, 11},
    {0b11111111111101, 14},
    {0b1111111111101, 13},
    {0b1111111111111111111111111100, 28},
    {0b11111111111111100110, 20},
    {0b1111111111111111010010, 22},
    {0b11111111111111100111, 20},
    {0b11111111111111101000, 20},
    {0b1111111111111111010011, 22},
    {0b1111111111111111010100, 22},
    {0b1111111111111111010101, 22},
    {0b11111111111111111011001, 23},
    {0b1111111111111111010110, 22},
    {0b11111111111111111011010, 23},
    {0b11111111111111111011011, 23},
    {0b11111111111111111011100, 23},
    {0b11111111111111111011101, 23},
    {0b11111111111111111011110, 23},
    {0b111111111111111111101011, 24},
    {0b11111111111111111011111, 23},
    {0b111111111111111111101100, 24},
    {0b111111111111111111101101, 24},
    {0b1111111111111111010111, 22},
    {0b11111111111111111100000, 23},
    {0b111111111111111111101110, 24},
    {0b11111111111111111100001, 23},
    {0b11111111111111111100010, 23},
    {0b11111111111111111100011, 23},
    {0b11111111111111111100100, 23},
    {0b111111111111111011100, 21},
    {0b1111111111111111011000, 22},
    {0b11111111111111111100101, 23},
    {0b1111111111111111011001, 22},
    {0b11111111111111111100110, 23},
    {0b11111111111111111100111, 23},
    {0b111111111111111111101111, 24},
    {0b1111111111111111011010, 22},
    {0b111111111111111011101, 21},
    {0b11111111111111101001, 20},
    {0b1111111111111111011011, 22},
    {0b1111111111111111011100, 22},
    {0b11111111111111111101000, 23},
    {0b11111111111111111101001, 23},
    {0b111111111111111011110, 21},
    {0b11111111111111111101010, 23},
    {0b1111111111111111011101, 22},
    {0b1111111111111111011110, 22},
    {0b111111111111111111110000, 24},
    {0b111111111111111011111, 21},
    {0b1111111111111111011111, 22},
    {0b11111111111111111101011, 23},
    {0b11111111111111111101100, 23},
    {0b111111111111111100000, 21},
    {0b111111111111111100001, 21},
    {0b1111111111111111100000, 22},
    {0b111111111111111100010, 21},
    {0b11111111111111111101101, 23},
    {0b1111111111111111100001, 22},
    {0b11111111111111111101110, 23},
    {0b11111111111111111101111, 23},
    {0b11111111111111101010, 20},
    {0b1111111111111111100010, 22},
    {0b1111111111111111100011, 22},
    {0b1111111111111111100100, 22},
    {0b11111111111111111110000, 23},
    {0b1111111111111111100101, 22},
    {0b1111111111111111100110, 22},
    {0b11111111111111111110001, 23},
    {0b11111111111111111111100000, 26},
    {0b11111111111111111111100001, 26},
    {0b11111111111111101011, 20},
    {0b1111111111111110001, 19},
    {0b1111111111111111100111, 22},
    {0b11111111111111111110010, 23},
    {0b1111111111111111101000, 22},
    {0b1111111111111111111101100, 25},
    {0b11111111111111111111100010, 26},
    {0b11111111111111111111100011, 26},
    {0b11111111111111111111100100, 26},
    {0b111111111111111111111011110, 27},
    {0b111111111111111111111011111, 27},
    {0b11111111111111111111100101, 26},
    {0b111111111111111111110001, 24},
    {0b1111111111111111111101101, 25},
    {0b1111111111111110010, 19},
    {0b111111111111111100011, 21},
    {0b11111111111111111111100110, 26},
    {0b111111111111111111111100000, 27},
    {0b111111111111111111111100001, 27},
    {0b11111111111111111111100111, 26},
    {0b111111111111111111111100010, 27},
    {0b111111111111111111110010, 24},
    {0b111111111111111100100, 21},
    {0b111111111111111100101, 21},
    {0b11111111111111111111101000, 26},
    {0b11111111111111111111101001, 26},
    {0b1111111111111111111111111101, 28},
    {0b111111111111111111111100011, 27},
    {0b111111111111111111111100100, 27},
    {0b111111111111111111111100101, 27},
    {0b11111111111111101100, 20},
    {0b111111111111111111110011, 24},
    {0b11111111111111101101, 20},
    {0b111111111111111100110, 21},
    {0b1111111111111111101001, 22},
    {0b111111111111111100111, 21},
    {0b111111111111111101000, 21},
    {0b11111111111111111110011, 23},
    {0b1111111111111111101010, 22},
    {0b1111111111111111101011, 22},
    {0b1111111111111111111101110, 25},
    {0b1111111111111111111101111, 25},
    {0b111111111111111111110100, 24},
    {0b111111111111111111110101, 24},
    {0b11111111111111111111101010, 26},
    {0b11111111111111111110100, 23},
    {0b11111111111111111111101011, 26},
    {0b111111111111111111111100110, 27},
    {0b11111111111111111111101100, 26},
    {0b11111111111111111111101101, 26},
    {0b111111111111111111111100111, 27},
    {0b111111111111111111111101000, 27},
    {0b111111111111111111111101001, 27},
    {0b111111111111111111111101010, 27},
    {0b111111111111111111111101011, 27},
    {0b1111111111111111111111111110, 28},
    {0b111111111111111111111101100, 27},
    {0b111111111111111111111101101, 27},
    {0b111111111111111111111101110, 27},
    {0b111111111111111111111101111, 27},
    {0b111111111111111111111110000, 27},
    {0b11111111111111111111101110, 26},
    {0b111111111111111111111111111111, 30}
};

// TODO: set for each connection
static bool connection_http2 = false;

static uint8_t get_bit_at_array(const uint8_t* bytes, ssize_t index)
{
    ssize_t byte = index / 8;
    ssize_t bit = 7 - (index % 8);
    return (bytes[byte] >> bit) & 1;
}

static uint8_t get_bit_at_u64(uint64_t nbr, ssize_t index)
{
    return (nbr >> index) & 1;
}

static void http_2_huffman_decode(const uint8_t* bytes, ssize_t length_bytes)
{
    ssize_t read_bits_begin = 0;
    bool done = false;
    while (read_bits_begin < length_bytes * 8)
    {
        for (ssize_t i = read_bits_begin; i >= (length_bytes - 1) * 8 && i % 8 != 0; ++i)
        {
            if (get_bit_at_array(bytes, i) != 1)
            {
                done = false;
                break;
            }
            done = true;
        }
        if (done)
        {
            return;
        }

        bool letter_found = false;
        for (uint16_t i = 0; i < 256; ++i)
        {
            bool match_found = true;
            uint8_t length = codes[i].length;
            for (ssize_t j = 0; j < length; ++j)
            {
                uint8_t bit_in_array = get_bit_at_array(bytes, j + read_bits_begin);
                uint8_t bit_in_table = get_bit_at_u64(codes[i].bits, codes[i].length - j - 1);
                if (bit_in_array != bit_in_table)
                {
                    match_found = false;
                    break;
                }
            }
            if (match_found)
            {
                letter_found = true;
                printf("%c", i);
                read_bits_begin += length;
                break;
            }
        }
        if (!letter_found)
        {
            return;
        }
    }
}

static const char* http_2_get_frame_type(uint8_t Type)
{
    if (Type >= sizeof(HTTP_2_FRAME_TYPE) / sizeof(const char*))
    {
        return "UNKNOWN";
    }

    return HTTP_2_FRAME_TYPE[Type];
}

static const char* http_2_get_setting_name(uint16_t SettingName)
{
    if (SettingName >= sizeof(HTTP_2_SETTING_NAME) / sizeof(const char*))
    {
        return "UNKNOWN";
    }

    return HTTP_2_SETTING_NAME[SettingName];
}

void http_dump_text(const unsigned char* hdr, ssize_t length)
{
    for (ssize_t i = 0; i < length; ++i)
    {
        if ((hdr[i] >= 32 && hdr[i] <= 126) || hdr[i] == '\r' || hdr[i] == '\n' || hdr[i] == '\t')
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

static void http_dump_data_frame(const unsigned char* hdr, ssize_t length, struct http_2_frame_header* hh)
{
    struct http_2_data_frame_flags hf;
    hf = *(struct http_2_data_frame_flags*) &(hh->Flags);

    ssize_t data_begin = 0;
    if (hf.Padded)
    {
        data_begin = 1;
        length -= hdr[0];
    }

    // printf("DATA BEGIN = %ld, LENGTH = %d, DIFF = %d\n", data_begin, length, length - data_begin);

    for (ssize_t i = data_begin; i < length; ++i)
    {
        if ((hdr[i] >= 32 && hdr[i] <= 126) || hdr[i] == '\r' || hdr[i] == '\n' || hdr[i] == '\t')
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

static void print_until_delim(char delim, const char* str)
{
    if (str == NULL)
    {
        printf("(nil)\n");
    }
    while (*str != 0)
    {
        putc(*str, stdout);
        if (*str == delim)
        {
            putc(' ', stdout);
            break;
        }
        str++;
    }
}

static ssize_t http_hpack_read_header(const unsigned char* hdr)
{
    uint8_t begin_byte = hdr[0];

    if (begin_byte & (1 << 7))
    {
        uint8_t index = begin_byte & 0b01111111;
        bool has_value = HTTP_2_HPACK_STATIC_TABLE[index][0] == '1';
        // printf("6.1\n");
        if (has_value)
        {
            // From static / dynamic table, has value
            printf("%s\n", &HTTP_2_HPACK_STATIC_TABLE[index][1]);
            return 1;
        }
        else
        {
            // From static / dynamic table, does not have value
            printf("%s", &HTTP_2_HPACK_STATIC_TABLE[index][1]);
            printf("[PLACEHOLDER]\n");
            return 0;
        }
    }
    else if (begin_byte & (1 << 6))
    {
        // Literal header field, incremental indexing (6.2.1)
        ssize_t total_length = 1;
        uint8_t index = begin_byte & 0b00111111;
        uint8_t next_byte = hdr[1];
        // printf("Next byte = %x\n", next_byte);
        bool huffman = next_byte & (1 << 7);
        uint8_t name_length = next_byte & 0b01111111;
        // printf("Name length = %x\n", name_length);
        total_length += name_length + 1;
        if (index == 0)
        {
            uint8_t follow_byte = hdr[total_length];
            // printf("Follow byte = %x\n", follow_byte);
            bool huffman2 = follow_byte & (1 << 7);
            uint8_t value_length = follow_byte & 0b01111111;
            // printf("Value length = %x\n", value_length);
            total_length += value_length + 1;

            if (!huffman)
            {
                for (int i = 0; i < name_length; ++i)
                {
                    printf("%c", hdr[1 + i]);
                }
                printf(": ");
            }
            else
            {
                http_2_huffman_decode(&hdr[1], name_length);
                printf(": ");
            }
            if (!huffman2)
            {
                for (int i = 0; i < value_length; ++i)
                {
                    printf("%c", hdr[name_length + 1 + i]);
                }
                printf("\n");
            }
            else
            {
                http_2_huffman_decode(&hdr[name_length + 1], value_length);
                printf("\n");
            }
        }
        else
        {
            print_until_delim(':', &HTTP_2_HPACK_STATIC_TABLE[index][1]);
            if (!huffman)
            {
                for (int i = 0; i < name_length; ++i)
                {
                    printf("%c", hdr[2 + i]);
                }
                printf("\n");
            }
            else
            {
                http_2_huffman_decode(&hdr[2], name_length);
                printf("\n");
            }
        }
        // printf("Total length = %d\n", total_length);
        return total_length;
    }
    else if (begin_byte & (1 << 5))
    {
        // Dynamic table size update (6.3)
        // printf("6.3\n");
        return 0;
    }
    else if (begin_byte & (1 << 4))
    {
        // Literal header field never indexed (6.2.3)
        // printf("6.2.3\n");
        return 0;
    }
    else
    {
        // Literal header field without indexing (6.2.2)
        ssize_t total_length = 1;
        uint8_t index = begin_byte & 0b00001111;
        uint8_t next_byte = hdr[1];
        // printf("Next byte = %x\n", next_byte);
        bool huffman = next_byte & (1 << 7);
        uint8_t name_length = next_byte & 0b01111111;
        // printf("Name length = %x\n", name_length);
        total_length += name_length + 1;
        if (index == 0)
        {
            uint8_t follow_byte = hdr[total_length];
            // printf("Follow byte = %x\n", follow_byte);
            bool huffman2 = follow_byte & (1 << 7);
            uint8_t value_length = follow_byte & 0b01111111;
            // printf("Value length = %x\n", value_length);
            total_length += value_length + 1;

            if (!huffman)
            {
                for (int i = 0; i < name_length; ++i)
                {
                    printf("%c", hdr[1 + i]);
                }
                printf(": ");
            }
            else
            {
                http_2_huffman_decode(&hdr[2], name_length);
                printf(": ");
            }
            if (!huffman2)
            {
                for (int i = 0; i < value_length; ++i)
                {
                    printf("%c", hdr[name_length + 1 + i]);
                }
                printf("\n");
            }
            else
            {
                http_2_huffman_decode(&hdr[name_length + 3], value_length);
                printf("\n");
            }
        }
        else
        {
            print_until_delim(':', &HTTP_2_HPACK_STATIC_TABLE[index][1]);
            if (!huffman)
            {
                for (int i = 0; i < name_length; ++i)
                {
                    printf("%c", hdr[2 + i]);
                }
                printf("\n");
            }
            else
            {
                http_2_huffman_decode(&hdr[2], name_length);
                printf("\n");
            }
        }
        return total_length;
    }
}

static void http_2_dump_headers_frame(const unsigned char* hdr, ssize_t length, struct http_2_frame_header* hh)
{
    struct http_2_headers_frame_flags hf;
    hf = *(struct http_2_headers_frame_flags*) &(hh->Flags);

    ssize_t data_begin = 0;
    if (hf.Priority)
    {
        data_begin += 5;
    }
    if (hf.Padded)
    {
        data_begin += 1;
        length -= hdr[0];
    }

    // ssize_t saved_length = buffer->length;
    // void* saved_hdr = buffer->hdr;

    // buffer->hdr = &hdr[data_begin];
    // buffer->length = length - data_begin;

    // binary_dump(buffer);

    // buffer->hdr = saved_hdr;
    // buffer->length = saved_length;

    // printf("ID = %d\n", hdr[data_begin] & 0b01111111);
    // printf("Huffman = %d\n", hdr[data_begin + 1] >> 7);
    // printf("Length = %d\n", hdr[data_begin + 1] & 0b01111111);

    while (length > 0)
    {
        ssize_t bytes_read = http_hpack_read_header(&hdr[data_begin]);
        if (bytes_read == 0)
        {
            break;
        }
        length -= bytes_read;
        data_begin += bytes_read;
    }

    for (ssize_t i = data_begin; i < length; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");
}

static void http_dump_priority_frame(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length)
{
    struct http_2_priority_frame_header hd;
    if (length < (ssize_t) sizeof(struct http_2_priority_frame_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hd, hdr, sizeof(struct http_2_priority_frame_header));

    printf("%-45s = %u\n", "Exclusive", hd.Exclusive);
    printf("%-45s = %u\n", "Stream dependency", hd.StreamDependency);
    printf("%-45s = %u\n", "Weight", hd.Weight);
}

static void http_dump_rst_frame(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length)
{
    struct http_2_rst_frame_header hd;
    if (length < (ssize_t) sizeof(struct http_2_rst_frame_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hd, hdr, sizeof(struct http_2_rst_frame_header));
    printf("%-45s = %u\n", "Error code", hd.ErrorCode);
}

static void http_dump_settings_frame(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length)
{
    while (length > 0)
    {
        struct http_2_setting hs;

        if (length < (ssize_t) sizeof(struct http_2_setting))
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&hs, hdr, sizeof(struct http_2_setting));

        printf("--- BEGIN HTTP/2.0 SETTINGS ---\n");
        printf("%-45s = 0x%x (%s)\n", "Setting ID", be16toh(hs.Identifier), http_2_get_setting_name(be16toh(hs.Identifier)));
        printf("%-45s = 0x%x\n", "Value", be32toh(hs.Value));
        length -= (ssize_t) sizeof(struct http_2_setting);
        hdr = &hdr[sizeof(struct http_2_setting)];
    }
}

static void http_dump_push_promise_frame(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length, struct http_2_frame_header* hh)
{
    struct http_2_push_promise_flags hf;
    struct http_2_push_promise_header hd;
    hf = *(struct http_2_push_promise_flags*) &(hh->Flags);

    ssize_t data_begin = 0;
    if (hf.Padded)
    {
        data_begin += 1;
        length -= hdr[0];
    }


    if (length < (ssize_t) sizeof(struct http_2_push_promise_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hd, &hdr[data_begin], sizeof(struct http_2_push_promise_header));
    data_begin += (ssize_t) sizeof(struct http_2_push_promise_header);

    printf("%-45s = %u\n", "Promised stream ID", hd.PromisedStreamID);

    for (ssize_t i = data_begin; i < length; ++i)
    {
        printf("%02x", hdr[i]);
    }
    printf("\n");
}

static void http_dump_ping_frame(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length)
{
    struct http_2_ping_header hd;
    if (length < (ssize_t) sizeof(struct http_2_ping_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hd, hdr, sizeof(struct http_2_ping_header));
    printf("%-45s = %lu\n", "Data", hd.Data);
}

static void http_dump_goaway_frame(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length)
{
    struct http_2_goaway_header hd;
    if (length < (ssize_t) sizeof(struct http_2_goaway_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hd, hdr, sizeof(struct http_2_goaway_header));
    printf("%-45s = %u\n", "Last stream ID", hd.LastStreamID);
    printf("%-45s = %u\n", "Error code", hd.ErrorCode);
    printf("%-45s = ", "Additional data");

    for (ssize_t i = sizeof(struct http_2_goaway_header); i < length; ++i)
    {
        printf("%c", hdr[i]);
    }
    printf("\n");
}

static void http_dump_window_update_frame(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length)
{
    struct http_2_window_update_header hd;
    if (length < (ssize_t) sizeof(struct http_2_window_update_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hd, hdr, sizeof(struct http_2_window_update_header));
    printf("%-45s = %u\n", "Window size increment", hd.WindowSizeIncrement);
}

static void http_v2_dump(const struct ob_protocol* buffer, const unsigned char* hdr, ssize_t length)
{
    struct http_2_frame_header hh;
    if (length == 0)
    {
        return;
    }
    ssize_t struct_length = (ssize_t) (sizeof(struct http_2_frame_header));
    if (length < struct_length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&hh, hdr, (size_t) struct_length);

    uint32_t header_length = be32toh(hh.Length) >> 8;

    printf("--- BEGIN HTTP/2.0 MESSAGE ---\n");
    printf("%-45s = %u\n", "Length", header_length);
    printf("%-45s = 0x%x (%s)\n", "Type", hh.Type, http_2_get_frame_type(hh.Type));
    printf("%-45s = %u\n", "Flags", hh.Flags);
    printf("%-45s = %u\n", "Stream ID", be32toh(hh.StreamID));

    if (header_length != 0)
    {
        switch (hh.Type)
        {
            case 0x0:
                printf("--- BEGIN HTTP/2.0 DATA FRAME ---\n");
                http_dump_data_frame(&hdr[struct_length], header_length, &hh);
                break;

            case 0x1:
                printf("--- BEGIN HTTP/2.0 HEADERS FRAME ---\n");
                http_2_dump_headers_frame(&hdr[struct_length], header_length, &hh);
                break;

            case 0x2:
                printf("--- BEGIN HTTP/2.0 PRIORITY FRAME ---\n");
                http_dump_priority_frame(buffer, &hdr[struct_length], header_length);
                break;

            case 0x3:
                printf("--- BEGIN HTTP/2.0 RESET STREAM FRAME ---\n");
                http_dump_rst_frame(buffer, &hdr[struct_length], header_length);
                break;

            case 0x4:
                // printf("--- BEGIN HTTP/2.0 SETTINGS FRAME ---\n");
                http_dump_settings_frame(buffer, &hdr[struct_length], header_length);
                break;

            case 0x5:
                printf("--- BEGIN HTTP/2.0 PUSH PROMISE FRAME ---\n");
                http_dump_push_promise_frame(buffer, &hdr[struct_length], header_length, &hh);
                break;

            case 0x6:
                printf("--- BEGIN HTTP/2.0 PING FRAME ---\n");
                http_dump_ping_frame(buffer, &hdr[struct_length], header_length);
                break;

            case 0x7:
                printf("--- BEGIN HTTP/2.0 GOAWAY FRAME ---\n");
                http_dump_goaway_frame(buffer, &hdr[struct_length], header_length);
                break;

            case 0x8:
                printf("--- BEGIN HTTP/2.0 WINDOW UPDATE FRAME ---\n");
                http_dump_window_update_frame(buffer, &hdr[struct_length], header_length);
                break;

            case 0x9:
                printf("--- BEGIN HTTP/2.0 CONTINUATION FRAME ---\n");
                http_dump_text(&hdr[struct_length], header_length);
                break;

            default:
                longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
                break;
        }
    }

    http_v2_dump(buffer, &hdr[header_length + struct_length], length - header_length - struct_length);
}

static void http_dump_v3(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;

    if (buffer->length < (ssize_t) (sizeof(HTTP_PRISM_INIT) / sizeof(char) - 1) && !connection_http2)
    {
        http_dump_text(hdr, buffer->length);
        return;
    }

    if (strcmp(hdr, HTTP_PRISM_INIT) == 0)
    {
        connection_http2 = true;
        // binary_dump(buffer);
        http_v2_dump(buffer, &hdr[sizeof(HTTP_PRISM_INIT) / sizeof(char) - 1], buffer->length - (ssize_t) (sizeof(HTTP_PRISM_INIT) / sizeof(char) + 1));
        return;
    }

    if (connection_http2)
    {
        // binary_dump(buffer);
        http_v2_dump(buffer, hdr, buffer->length);
        return;
    }
    else
    {
        http_dump_text(hdr, buffer->length);
        return;
    }
}

// static void http_dump_v3(const struct ob_protocol* buffer)
// {
//     const unsigned char* hdr = buffer->hdr;
//     if (buffer->length == 0)
//     {
//         return;
//     }

//     printf("--- BEGIN HTTP MESSAGE ---\n");
//     for (ssize_t i = 0; i < buffer->length; ++i)
//     {
//         if ((hdr[i] >= 32 && hdr[i] <= 126) || hdr[i] == '\r' || hdr[i] == '\n')
//         {
//             printf("%c", hdr[i]);
//         }
//         else
//         {
//             printf(".");
//         }
//     }
//     printf("\n");
// }

static void http_dump_v2(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;
    if (buffer->length == 0)
    {
        return;
    }

    printf("HTTP => ");
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

void http_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> HTTP ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            http_dump_v2(buffer);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            http_dump_v3(buffer);
            break;
    }
}
