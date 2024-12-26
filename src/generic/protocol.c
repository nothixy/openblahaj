#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "generic/protocol.h"

const char* OB_ERROR_STR[6] = {
    [OB_ERROR_MEMORY_ALLOCATION] = "Memory allocation error",
    [OB_ERROR_BUFFER_OVERFLOW] = "Buffer overflow prevented",
    [OB_ERROR_INVALID_VALUES] = "Invalid values",
    [OB_ERROR_NOT_SUPPORTED] = "Protocol or option not supported",
    [OB_ERROR_DATA_UNAVAILABLE] = "No data to process"
};
