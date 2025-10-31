#include "network/6lowpan.h"
#include "generic/protocol.h"
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

static const char* SIXLOWPAN_DISPATCH_TYPE[] = {
    "NALP",
    "LOWPAN",
    "MESH",
    "FRAGMENTATION"
};

void sixlowpan_dump(struct ob_protocol* buffer)
{
    struct sixlowpan_header sh;
    if (buffer->length < sizeof(struct sixlowpan_header))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    memcpy(&sh, buffer->hdr, sizeof(struct sixlowpan_header));

    printf("--- BEGIN 6LOWPAN MESSAGE ---\n");

    printf("%-45s = %u (%s)\n", "Dispatch type", sh.DispatchType, SIXLOWPAN_DISPATCH_TYPE[sh.DispatchType]);
    printf("%-45s = %u\n", "Dispatch", sh.Dispatch);
    
    // if (sh.DispatchType == 0)
    // {
        // longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    // }

    
}
