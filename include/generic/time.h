#ifndef OB_TIME_H
#define OB_TIME_H

#include <stdbool.h>
#include <sys/time.h>

char* get_timestamp_utc(const struct timeval* tv, char* buf, bool usec);

#endif
