#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/guid.h"

/**
 * @brief Get a GUID in the form of XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 * @param buffer Char array of at least 37 bytes
 * @param guid Buffer containing the GUID in binary format
 */
char* guid_get(const uint8_t buffer[16], char* guid)
{
    if (guid == NULL)
    {
        return guid;
    }

    sprintf(&guid[0], "%02x", buffer[0]);
    sprintf(&guid[2], "%02x", buffer[1]);
    sprintf(&guid[4], "%02x", buffer[2]);
    sprintf(&guid[6], "%02x", buffer[3]);
    guid[8] = '-';
    sprintf(&guid[9], "%02x", buffer[4]);
    sprintf(&guid[11], "%02x", buffer[5]);
    guid[13] = '-';
    sprintf(&guid[14], "%02x", buffer[6]);
    sprintf(&guid[16], "%02x", buffer[7]);
    guid[18] = '-';
    sprintf(&guid[19], "%02x", buffer[8]);
    sprintf(&guid[21], "%02x", buffer[9]);
    guid[23] = '-';
    sprintf(&guid[24], "%02x", buffer[10]);
    sprintf(&guid[26], "%02x", buffer[11]);
    sprintf(&guid[28], "%02x", buffer[12]);
    sprintf(&guid[30], "%02x", buffer[13]);
    sprintf(&guid[32], "%02x", buffer[14]);
    sprintf(&guid[34], "%02x", buffer[15]);
    guid[36] = '\0';

    return guid;
}
