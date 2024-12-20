#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "application/pop.h"
#include "generic/protocol.h"

static void pop_dump_v3(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;
    if (buffer->length == 0)
    {
        return;
    }

    printf("--- BEGIN POP3 BUFFER ---\n");
    for (ssize_t i = 0; i < buffer->length; ++i)
    {
        printf("%c", hdr[i]);
    }
    printf("\n");

    return;
}

static void pop_dump_v2(const struct ob_protocol* buffer)
{
    const unsigned char* hdr = buffer->hdr;
    if (buffer->length == 0)
    {
        return;
    }

    printf("POP3 => ");
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
        printf("%c", hdr[i]);
    }
    printf("\n");
}

void pop_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> POP3 ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            pop_dump_v2(buffer);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            pop_dump_v3(buffer);
            break;
    }
}
