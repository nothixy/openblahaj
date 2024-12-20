#include <stdio.h>
#include <stdlib.h>
#include <pcap/dlt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "link/eth.h"
#include "link/dbus.h"
#include "link/link.h"
#include "link/cooked.h"
#include "network/ip4.h"
#include "network/ip6.h"
#include "generic/binary.h"
#include "link/bluetooth.h"
#include "generic/protocol.h"

/**
 * @brief Set the dump function on a message structure
 * @param buffer Pointer to the message structure
 */
void link_cast(struct ob_protocol* buffer)
{
    buffer->dump = NULL;

    switch (buffer->link_type)
    {
        case DLT_EN10MB: /* Ethernet */
            buffer->dump = eth_dump;
            break;

        case DLT_RAW:
            buffer->dump = ipv6_dump;
            break;

        case DLT_LINUX_SLL: /* Cooked */
            buffer->dump = cooked_dump;
            break;

#ifdef OB_BUILD_BLUETOOTH
        case DLT_BLUETOOTH_HCI_H4_WITH_PHDR: /* Bluetooth HCI with PHDR */
            buffer->dump = bt_dump;
            break;
#endif

#ifdef OB_BUILD_DBUS
        case DLT_DBUS: /* DBus */
            buffer->dump = dbus_dump;
            break;
#endif

        default:
            buffer->dump = binary_dump;
            break;
    }
}

/**
 * @brief Get the name of the link layer
 * @param LinkType Link type returned by pcap_datalink()
 * @return Constant string containing the link name
 */
const char* link_get_name(int LinkType)
{
    switch (LinkType)
    {
        case DLT_EN10MB:
            return "Ethernet";

        case DLT_LINUX_SLL:
            return "Linux cooked capture";

        case DLT_BLUETOOTH_HCI_H4_WITH_PHDR:
            return "Bluetooth HCI with PHDR";

        case DLT_DBUS:
            return "DBus";

        case DLT_NFLOG:
            return "NFLog";

        default:
            return "Unknown";
    }
}
