#include <time.h>
#include <stdio.h>
#include <stddef.h>

#include "generic/time.h"

/**
 * @brief Get the current timestamp in UTC timezone
 * @param ts Pointer to the timeval passed by pcap_dispatch()
 * @param buf Char array of at least 111 characters
 */
char* get_timestamp_utc(const struct timeval* tv, char* buf)
{
    struct tm* tm;
    size_t written;

    tm = gmtime(&tv->tv_sec);
    written = strftime(buf, 100, "%Y-%m-%dT%H:%M:%S.", tm);
    sprintf(&buf[written], "%09luZ", tv->tv_usec);

    return buf;
}
