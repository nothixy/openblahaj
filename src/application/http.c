#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "application/http.h"
#include "generic/protocol.h"

static void http_dump_v3(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;
    if (buffer->length == 0)
    {
        return;
    }

    printf("--- BEGIN HTTP MESSAGE ---\n");
    for (ssize_t i = 0; i < buffer->length; ++i)
    {
        if ((hdr[i] >= 32 && hdr[i] <= 126) || hdr[i] == '\r' || hdr[i] == '\n')
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
