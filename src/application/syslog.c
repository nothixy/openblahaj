#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif
#include "generic/protocol.h"
#include "application/syslog.h"

static const char* SYSLOG_FACILITY[] = {
    "KERNEL",
    "USER",
    "MAIL",
    "SYSTEM DAEMONS",
    "SECURITY",
    "SYSLOGD",
    "LINE PRINTER",
    "NETWORK NEWS",
    "UUCP",
    "CLOCK",
    "SECURITY",
    "FTP",
    "NTP",
    "LOG AUDIT",
    "LOG ALERT",
    "CLOCK (note 2)",
    "LOCAL0",
    "LOCAL1",
    "LOCAL2",
    "LOCAL3",
    "LOCAL4",
    "LOCAL5",
    "LOCAL6",
    "LOCAL7"
};

static const char* SYSLOG_SEVERITY[] = {
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG"
};

static const char* syslog_get_facility(uint8_t Facility)
{
    if (Facility > sizeof(SYSLOG_FACILITY) / sizeof(char*))
    {
        return "UNKNOWN";
    }
    return SYSLOG_FACILITY[Facility];
}

static const char* syslog_get_severity(uint8_t Severity)
{
    if (Severity > sizeof(SYSLOG_SEVERITY) / sizeof(char*))
    {
        return "UNKNOWN";
    }
    return SYSLOG_SEVERITY[Severity];
}

static void syslog_dump_v3(const struct ob_protocol* buffer)
{
    uint8_t Severity;
    uint8_t Facility;
    uint8_t PRI = 0;
    bool PRI_valid = false;
    int i;
    char PRI_str[4] = {0};
    const unsigned char* hdr = buffer->hdr;

    printf("--- BEGIN SYSLOG MESSAGE ---\n");

    if ((ssize_t) (4 * sizeof(char)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    for (i = 1; i <= 4; ++i)
    {
        if (hdr[i] < '0' || hdr[i] > '9')
        {
            break;
        }
        PRI_valid = true;
        PRI_str[i - 1] = (char) hdr[i];
    }

    /**
     * atoi() does not do any kind of verification on the string passed to it
     * This is okay here because on error it will return 0
     */
    PRI = (uint8_t) atoi(PRI_str);

    Severity = PRI & 0x7;
    Facility = PRI >> 3;

    i += 1;

    if (!PRI_valid)
    {
        printf("%-45s = Invalid\n", "PRI");
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    printf("%-45s = %u (%s)\n", "Facility", Facility, syslog_get_facility(Facility));
    printf("%-45s = %u (%s)\n", "Severity", Severity, syslog_get_severity(Severity));
    printf("%-45s = ", "Message");
    while (i < buffer->length)
    {
        printf("%c", hdr[i]);
        ++i;
    }

    printf("\n");
}

static void syslog_dump_v2(const struct ob_protocol* buffer)
{
    uint8_t Severity;
    uint8_t Facility;
    uint8_t PRI = 0;
    bool PRI_valid = false;
    char PRI_str[4] = {0};
    const unsigned char* hdr = buffer->hdr;

    printf("Syslog => ");

    if ((ssize_t) (4 * sizeof(char)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    for (int i = 1; i <= 4; ++i)
    {
        if (hdr[i] < '0' || hdr[i] > '9')
        {
            break;
        }
        PRI_valid = true;
        PRI_str[i - 1] = (char) hdr[i];
    }

    /**
     * atoi() does not do any kind of verification on the string passed to it
     * This is okay here because on error it will return 0
     */
    PRI = (uint8_t) atoi(PRI_str);

    Severity = PRI & 0x7;
    Facility = PRI >> 3;

    if (!PRI_valid)
    {
        printf("Invalid PRI\n");
        longjmp(*(buffer->catcher), OB_ERROR_INVALID_VALUES);
    }

    printf("Facility : %s, ", syslog_get_facility(Facility));
    printf("Severity : %s\n", syslog_get_severity(Severity));
}

void syslog_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> SysLog ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            syslog_dump_v2(buffer);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            syslog_dump_v3(buffer);
            break;
    }
}
