#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "generic/binary.h"
#include "generic/protocol.h"
#include "generic/terminal.h"
#include "generic/constants.h"
#include "application/application.h"

// NOTE: This should instead send a pacp-formatted packet to a socket to the main program
// The main program should open a pcap connection from this socket and keep reading incoming
// packets with pcap_dispatch()

void printbuf(void* buf, ssize_t size, uint16_t src_port, uint16_t dst_port, bool tcp)
{
    static int idx = 0;
    static int modulo = -1;
    struct ob_protocol buffer;
    int jump_error;
    jmp_buf b;
    buffer.hdr = buf;
    buffer.length = size;
    buffer.display_hostnames = false;
    buffer.orig = NULL;
    buffer.verbosity_level = OB_VERBOSITY_LEVEL_HIGH;
    buffer.reassembled = false;
    buffer.display_hostnames = true;
    buffer.packet_index = idx++;
    buffer.catcher = &b;
    buffer.pseudo_header = NULL;
    buffer.pseudo_header_length = 0;
    buffer.link_type = 0;
    buffer.dump = binary_dump;

    if (buffer.length <= 0)
    {
        return;
    }

    if (modulo == -1)
    {
        modulo = rand() % 5;
    }

    if (true)
    {
        switch (modulo)
        {
            case 0:
                printf("\033[31m");
                break;

            case 1:
                printf("\033[32m");
                break;

            case 2:
                printf("\033[33m");
                break;

            case 3:
                printf("\033[34m");
                break;

            case 4:
            default:
                printf("\033[35m");
                break;
        }
    }

    modulo = (modulo + 1) % 5;

    if (!application_cast(tcp ? T_TRANSPORT_TCP : T_TRANSPORT_UDP, src_port, &buffer))
    {
        application_cast(tcp ? T_TRANSPORT_TCP : T_TRANSPORT_UDP, dst_port, &buffer);
    }

    if ((jump_error = setjmp(*(buffer.catcher))) == 0)
    {
        buffer.dump(&buffer);
    }
    else
    {
        display_error(jump_error);
        printf("\n");
    }

    printf("\033[0m\033(B\033)0\017\033[?5l\0337\033[0;0r\0338");
}
