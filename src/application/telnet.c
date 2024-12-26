#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "generic/protocol.h"
#include "application/telnet.h"

static void telnet_display_option(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;

    if (offset >= buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf(" ");
    switch (hdr[offset])
    {
        case 0:
            printf("Binary transmission");
            break;

        case 1:
            printf("Echo");
            break;

        case 2:
            printf("Reconnection");
            break;

        case 3:
            printf("Suppress go ahead");
            break;

        case 4:
            printf("Approximative message size notification");
            break;

        case 5:
            printf("Status");
            break;

        case 6:
            printf("Timing mark");
            break;

        case 7:
            printf("Remote controlled trans and echo");
            break;

        case 8:
            printf("Output line width");
            break;

        case 9:
            printf("Output page size");
            break;

        case 10:
            printf("Output carriage-return disposition");
            break;

        case 11:
            printf("Output horizontal tab stops");
            break;

        case 12:
            printf("Output horizontal tab disposition");
            break;

        case 13:
            printf("Output formfeed disposition");
            break;

        case 14:
            printf("Output vertical tabstops");
            break;

        case 15:
            printf("Output vertical tab disposition");
            break;

        case 16:
            printf("Output linefeed disposition");
            break;

        case 17:
            printf("Extended ASCII");
            break;

        case 18:
            printf("Logout");
            break;

        case 19:
            printf("Byte macro");
            break;

        case 20:
            printf("Data entry terminal");
            break;

        case 21:
            printf("Supdup");
            break;

        case 22:
            printf("Supdup output");
            break;

        case 23:
            printf("Send location");
            break;

        case 24:
            printf("Terminal type");
            break;

        case 25:
            printf("End of record");
            break;

        case 26:
            printf("TACACS user identification");
            break;

        case 27:
            printf("Output marking");
            break;

        case 28:
            printf("Terminal location number");
            break;

        case 29:
            printf("Telnet 3270 regime");
            break;

        case 30:
            printf("X.3 pad");
            break;

        case 31:
            printf("Negociate about window size");
            break;

        case 32:
            printf("Terminal speed");
            break;

        case 33:
            printf("Remote flow control");
            break;

        case 34:
            printf("Linemode");
            break;

        case 35:
            printf("X display location");
            break;

        case 36:
            printf("Environment option");
            break;

        case 37:
            printf("Authentication option");
            break;

        case 38:
            printf("Encryption option");
            break;

        case 39:
            printf("New environment option");
            break;

        case 40:
            printf("TN3270E");
            break;

        case 41:
            printf("XAUTH");
            break;

        case 42:
            printf("Charset");
            break;

        case 43:
            printf("Telnet remote serial port");
            break;

        case 44:
            printf("Com port control option");
            break;

        case 45:
            printf("Telnet suppress local echo");
            break;

        case 46:
            printf("Telnet start TLS");
            break;

        case 47:
            printf("Kermit");
            break;

        case 48:
            printf("Send URL");
            break;

        case 49:
            printf("Forward-X");
            break;

        case 138:
            printf("Telopt pragma logon");
            break;

        case 139:
            printf("Telopt sspi logon");
            break;

        case 140:
            printf("Telopt pragma heartbeat");
            break;

        default:
            printf("Unknown");
            break;
    }
}

static ssize_t telnet_display_special(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    ssize_t length = 1;

    if (offset >= buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    printf("\033[1m[");
    switch (hdr[offset])
    {
        case 240:
            printf("End of subnegocation parameters");
            break;

        case 241:
            printf("NOP");
            break;

        case 242:
            printf("Data mark");
            break;

        case 243:
            printf("Break");
            break;

        case 244:
            printf("Interrupt process");
            break;

        case 245:
            printf("Abort output");
            break;

        case 246:
            printf("Are you there ?");
            break;

        case 247:
            printf("Erase character");
            break;

        case 248:
            printf("Erase line");
            break;

        case 249:
            printf("Go ahead");
            break;

        case 250:
            printf("Subnegociation");
            break;

        case 251:
            printf("Will");
            telnet_display_option(buffer, offset + 1);
            length = 2;
            break;

        case 252:
            printf("Won't");
            telnet_display_option(buffer, offset + 1);
            length = 2;
            break;

        case 253:
            printf("Do");
            telnet_display_option(buffer, offset + 1);
            length = 2;
            break;

        case 254:
            printf("Don't");
            telnet_display_option(buffer, offset + 1);
            length = 2;
            break;

        case 255:
            printf("IAC");
            break;

        default:
            printf("Unknown");
            break;
    }
    printf("]\033[22m");
    return length;
}

static void telnet_dump_v3(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;
    if (buffer->length == 0)
    {
        return;
    }

    printf("--- BEGIN TELNET MESSAGE ---\n");
    for (ssize_t i = 0; i < buffer->length; ++i)
    {
        if (hdr[i] == 0xFF)
        {
            i += telnet_display_special(buffer, i + 1);
            continue;
        }
        printf("%c", hdr[i]);
    }
    printf("\n");

    return;
}

static void telnet_dump_v2(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;
    if (buffer->length == 0)
    {
        return;
    }

    printf("TELNET => ");
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
        if (hdr[i] == 0xFF)
        {
            i += telnet_display_special(buffer, i + 1);
            continue;
        }
        printf("%c", hdr[i]);
    }
    printf("\n");
}

void telnet_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> TELNET ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            telnet_dump_v2(buffer);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            telnet_dump_v3(buffer);
            break;
    }
}
