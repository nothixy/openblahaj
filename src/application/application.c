#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/binary.h"
#include "application/dns.h"
#include "application/ftp.h"
#include "application/pop.h"
#include "application/rip.h"
#include "application/tls.h"
#include "application/http.h"
#include "application/imap.h"
#include "application/smtp.h"
#include "application/ssdp.h"
#include "generic/protocol.h"
#include "application/bootp.h"
#include "application/ripng.h"
#include "application/whois.h"
#include "application/syslog.h"
#include "application/telnet.h"
#include "application/wireguard.h"
#include "application/application.h"

bool application_udp_cast(uint16_t port, struct ob_protocol* buffer)
{
    switch (port)
    {
        case 53: /* DNS */
            buffer->dump = dns_dump;
            break;

        case 67:
        case 68: /* BOOTP */
            buffer->dump = bootp_dump;
            break;

        case 514: /* Syslog */
            buffer->dump = syslog_dump;
            break;

        case 520: /* RIP */
            buffer->dump = rip_dump;
            break;

        case 521: /* RIPng */
            buffer->dump = ripng_dump;
            break;

        case 1900: /* SSDP */
            buffer->dump = ssdp_dump;
            break;

        case 5353: /* mDNS */
            buffer->dump = dns_dump;
            break;

        case 51000: /* Wireguard */
            buffer->dump = wireguard_dump;
            break;

        default:
            buffer->dump = binary_dump;
            return false;
    }

    return true;
}

bool application_tcp_cast(uint16_t port, struct ob_protocol* buffer)
{
    switch (port)
    {
        case 21: /* FTP */
            buffer->dump = ftp_dump;
            break;

        case 23: /* Telnet */
            buffer->dump = telnet_dump;
            break;

        case 25: /* SMTP */
            buffer->dump = smtp_dump;
            break;

        case 43: /* WHOIS */
            buffer->dump = whois_dump;
            break;

        case 80: /* HTTP */
            buffer->dump = http_dump;
            break;

        case 110: /* POP3 */
            buffer->dump = pop_dump;
            break;

        case 143: /* IMAP */
            buffer->dump = imap_dump;
            break;

        case 443: /* HTTPS */
            buffer->dump = tls_dump;
            break;

        default:
            buffer->dump = binary_dump;
            return false;
    }

    return true;
}

bool application_sctp_cast(uint16_t port, struct ob_protocol* buffer)
{
    switch (port)
    {
        case 80:
            buffer->dump = http_dump;
            break;

        default:
            buffer->dump = binary_dump;
            return false;
    }

    return true;
}

/**
 * @brief Set the dump function on a message structure
 * @param trasport One of UDP, TCP, SCTP
 * @param port Port number from the transport layer
 * @param buffer Pointer to the message structure
 */
bool application_cast(enum T_TRANSPORT transport, uint16_t port, struct ob_protocol* buffer)
{
    switch (transport)
    {
        case T_TRANSPORT_UDP:
            return application_udp_cast(port, buffer);

        case T_TRANSPORT_TCP:
            return application_tcp_cast(port, buffer);

        case T_TRANSPORT_SCTP:
            return application_sctp_cast(port, buffer);

        default:
            buffer->dump = binary_dump;
            return false;
    }
}

const char* application_udp_get_name(uint16_t port)
{
    switch (port)
    {
        case 53:
            return "DNS";

        case 67:
        case 68:
            return "Bootp";

        case 443:
            return "QUIC HTTP/3";

        case 514:
            return "Syslog";

        case 520:
            return "RIP";

        case 521:
            return "RIPng";

        case 51000:
            return "Wireguard";

        default:
            return "Unknown";
    }
}

const char* application_tcp_get_name(uint16_t port)
{
    switch (port)
    {
        case 21:
            return "FTP";

        case 23:
            return "Telnet";

        case 25:
            return "SMTP";

        case 43:
            return "WHOIS";

        case 80:
            return "HTTP";

        case 110:
            return "POP3";

        case 143:
            return "IMAP";

        case 443:
            return "HTTPS";

        default:
            return "Unknown";
    }
}

const char* application_sctp_get_name(uint16_t port)
{
    switch (port)
    {
        case 80:
            return "HTTP";

        default:
            return "Unknown";
    }
}

/**
 * @brief Get the name of the application layer
 * @param trasport One of UDP, TCP, SCTP
 * @param port Port number from the transport layer
 * @return Constant string containing the application name
 */
const char* application_get_name(enum T_TRANSPORT transport, uint16_t port)
{
    switch (transport)
    {
        case T_TRANSPORT_UDP:
            return application_udp_get_name(port);

        case T_TRANSPORT_TCP:
            return application_tcp_get_name(port);

        case T_TRANSPORT_SCTP:
            return application_sctp_get_name(port);

        default:
            return "Unknown";
    }
}
