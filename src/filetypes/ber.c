#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filetypes/ber.h"
#include "filetypes/oid.h"
#include "generic/binary.h"

static const uint8_t nonest1[] = {0x55, 0x1d, 0x0e};
static const uint8_t nonest2[] = {0x55, 0x1d, 0x23};
static const uint8_t nonest3[] = {0x2b, 0x6, 0x1, 0x4, 0x1, 0xd6, 0x79, 0x2, 0x4, 0x2};
static bool do_not_nest = false;

ssize_t ber_read_type(uint8_t* hdr, uint64_t* value)
{
    ssize_t read_bytes = 1;
    *value = hdr[0];
    if ((*value & 0b00011111) == 0b00011111)
    {
        uint8_t next_byte;
        do
        {
            next_byte = hdr[read_bytes];
            *value *= 128;
            *value += next_byte & 0b01111111;
            ++read_bytes;
        }
        while (next_byte & 0b10000000);
    }
    return read_bytes;
}

ssize_t ber_read_length(uint8_t* hdr, uint64_t* length, bool* indefinite)
{
    ssize_t length_of_length;
    ssize_t read_bytes = 1;
    *indefinite = false;
    *length = hdr[0];
    if (!(*length & 0b10000000))
    {
        return read_bytes;
    }
    *length = *length & 0b01111111;
    if (*length == 0)
    {
        *indefinite = true;
        return read_bytes;
    }
    length_of_length = *length;
    *length = 0;
    for (ssize_t i = 0; i < length_of_length; ++i)
    {
        *length *= 256;
        *length += hdr[read_bytes];
        read_bytes += 1;
    }
    return read_bytes;
}

void print_tabs(ssize_t tab_length)
{
    for (ssize_t i = 0; i < tab_length; ++i)
    {
        printf("    ");
    }
}

ssize_t ber_decode_with_length(uint8_t* hdr, struct ob_protocol* buffer, ssize_t length, ssize_t tab_length);

void ber_print_with_type(uint8_t* hdr, struct ob_protocol* buffer, uint64_t length, uint64_t type, ssize_t tab_length)
{
    print_tabs(tab_length);

    switch (type)
    {
        // case 0x0: /* END OF CONTENT, TO HANDLE SEPARATELY */
        //     print_tabs(tab_length);
        //     // printf()
        //     break;

        case 0x1: /* BOOLEAN */
            printf("(BOOLEAN) %s\n", hdr[0] ? "True" : "False");
            break;

        case 0x2: /* INTEGER */
            printf("(INTEGER) ");
            for (uint64_t i = 0; i < length - 1; ++i)
            {
                printf("%02x:", hdr[i]);
            }
            printf("%02x", hdr[length - 1]);
            printf("\n");
            break;

        case 0x6: /* OBJECT IDENTIFIER, SHOULD BE DIFFERENT BUT TOO LAZY */
            uint8_t oid1 = hdr[0] / 40;
            uint8_t oid2 = hdr[0] % 40;
            struct oid_node* base = oid_root;
            printf("(OBJECT IDENTIFIER) ");
            do_not_nest = ! (bool) memcmp(hdr, nonest1, 3 * sizeof(uint8_t));
            if (!do_not_nest)
            {
                do_not_nest = ! (bool) memcmp(hdr, nonest2, 3 * sizeof(uint8_t));
            }
            if (!do_not_nest)
            {
                do_not_nest = ! (bool) memcmp(hdr, nonest3, 10 * sizeof(uint8_t));
            }
            printf("%d.%d.", oid1, oid2);
            if (base != NULL)
            {
                base = get_oid_node(base, oid1);
            }
            if (base != NULL)
            {
                base = base->node;
                base = get_oid_node(base, oid2);
            }
            for (uint64_t i = 1; i < length; ++i)
            {
                uint16_t byte;
                if (base != NULL)
                {
                    base = base->node;
                }
                byte = hdr[i];
                if (byte >= 128)
                {
                    byte &= 0b01111111;
                    byte *= 128;
                    byte += (hdr[i + 1] & 0b01111111);
                    ++i;
                    // printf("%u.", byte);
                }
                printf("%u.", byte);
                if (base != NULL)
                {
                    base = get_oid_node(base, byte);
                }
            }
            if (base != NULL)
            {
                printf(" (%s)", base->name);
            }
            // if (do_not_nest)
            // {
            //     printf(" (DO NEST)");
            // }
            printf("\n");
            break;

        case 0x13: /* PRINTABLE STRING */
            printf("(STRING) ");
            for (uint64_t i = 0; i < length; ++i)
            {
                printf("%c", hdr[i]);
            }
            printf("\n");
            break;

        case 0x17: /* UTCTime */
            printf("(DATE) ");
            for (uint64_t i = 0; i < length; ++i)
            {
                printf("%c", hdr[i]);
            }
            printf("\n");
            break;

        case 0x3: /* BIT STRING */
            printf("(BIT STRING) ");
            printf("(Pad %d bits) ", hdr[0]);
            uint8_t remain = 0;
            for (uint64_t i = 1; i < length - 1; ++i)
            {
                // uint16_t v = hdr[i];
                // uint16_t byte = hdr[i] >> 
                printf("%02x:", hdr[i]);
            }
            printf("%02x", hdr[length - 1]);
            printf("\n");
            break;

        case 0x4: /* OCTET STRING */
        {
            // ssize_t read_bytes = 0;
            // uint64_t ber_type;
            // uint64_t ber_length;
            // bool ber_length_indefinite;
            if (!do_not_nest)
            {
                printf("(OCTET STRING)\n");
                ber_decode_with_length(hdr, buffer, length, tab_length);
            }
            else
            {
                // printf("(OCTET STRING) ");
                // read_bytes += ber_read_type(&hdr[read_bytes], &ber_type);
                // read_bytes += ber_read_length(&hdr[read_bytes], &ber_length, &ber_length_indefinite);
                // if (ber_type & 0x20)
                // {
                //     print_tabs(tab_length);
                //     printf("[\n");
                //     ber_decode_with_length(hdr, buffer, (ssize_t) length, tab_length + 1);
                //     print_tabs(tab_length);
                //     printf("]\n");
                //     break;
                // }
                // else
                printf("(OCTET STRING) ");
                for (uint64_t i = 0; i < length; ++i)
                {
                    printf("%02x", hdr[i]);
                }
                printf("\n");
            }
            break;
        }

        case 0x5: /* NULL */
            // ber_decode_with_length(hdr, buffer, (ssize_t) length, tab_length);
            printf("(NULL) ");
            for (uint64_t i = 0; i < length; ++i)
            {
                printf("%02x", hdr[i]);
            }
            printf("\n");
            break;

        case 0xc: /* UTF8 STRING */
            printf("(UTF8 STRING) ");
            for (uint64_t i = 0; i < length; ++i)
            {
                printf("%c", hdr[i]);
            }
            printf("\n");
            break;

        default:
            printf("UNSUPPOERTED 0x%x\n", type);
            for (uint64_t i = 0; i < length; ++i)
            {
                printf("%02x", hdr[i]);
            }
            printf("\n");
            exit(0);
            break;
    }

    return;
}

ssize_t ber_decode_with_length(uint8_t* hdr, struct ob_protocol* buffer, ssize_t length, ssize_t tab_length)
{
    ssize_t read_bytes = 0;
    ssize_t read_bytes_save;
    while (read_bytes < length)
    {
        read_bytes_save = read_bytes;
        bool ber_length_indefinite;
        uint64_t ber_length;
        uint64_t ber_type;
        read_bytes += ber_read_type(&hdr[read_bytes], &ber_type);
        read_bytes += ber_read_length(&hdr[read_bytes], &ber_length, &ber_length_indefinite);

        if (ber_type & 0x20)
        {
            print_tabs(tab_length);
            printf("[L = 0x%lx\n", ber_length);
            read_bytes += ber_decode_with_length(&hdr[read_bytes], buffer, ber_length, tab_length + 1);
            print_tabs(tab_length);
            printf("]\n");
        }
        // else if (ber_type > 0x80)
        // {
        //     ber_print_with_type(&hdr[read_bytes_save], )
        // }
        else
        {
            ber_print_with_type(&hdr[read_bytes], buffer, ber_length, ber_type & 0b00011111, tab_length);
            read_bytes += ber_length;
        }
        // else
        // {
        //     print_tabs(tab_length);
        //     read_bytes = length;
        //     printf("(UNKNOWN TYPE) ");
        //     for (ssize_t i = read_bytes_save; i < length; ++i)
        //     {
        //         printf("%02x", hdr[i]);
        //     }
        //     printf("\n");
        // }
    }
}

void ber_decode_v3(struct ob_protocol* buffer)
{
    binary_dump(buffer);

    printf("--- BEGIN BER FILE ---\n");
    ber_decode_with_length(buffer->hdr, buffer, buffer->length, 0);
}
