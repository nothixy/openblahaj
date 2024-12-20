#ifndef OB_TIME_H
#define OB_TIME_H

#include <sys/time.h>

char* get_timestamp_utc(const struct timeval* tv, char* buf);

#endif
