#include <stdio.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "link/bluetooth.h"
#include "generic/protocol.h"

#define MASK_OCF(Opcode) (Opcode & ~(0x3F << 10))
#define MASK_OGF(Opcode) ((Opcode >> 10) & 0x3F)

#define MASK_Handle(Handle) (Handle & ~(0xF << 12))
#define MASK_PB(Handle) ((Handle >> 12) & 0x3)
#define MASK_BC(Handle) ((Handle >> 14) & 0x3)

#define MASK_ConnectionHandle(Handle) (Handle & ~(0xF << 12))
#define MASK_PacketStatus(Handle) ((Handle >> 12) & 0x3)
#define MASK_RFU(Handle) ((Handle >> 14) & 0x3)

#define MASK_TS(Handle) ((Handle >> 14) & 0x1)
#define MASK_RFU1(Handle) ((Handle >> 15) & 0x1)
#define MASK_DataTotalLength(Length) (Length & ~(0x3 << 14))
#define MASK_RFU2(Length) ((Length >> 14) & 0x3)

/**
 * This implementation of the Bluetooth HCI dump is specific to bluez
 */

static const char* bt_hci_get_packet_type(uint8_t Indicator)
{
    switch (Indicator)
    {
        case 0x1:
            return "HCI Command";

        case 0x2:
            return "HCI ACL Data";

        case 0x3:
            return "HCI Synchronous Data";

        case 0x4:
            return "HCI Event";

        case 0x5:
            return "HCI ISO Data";

        default:
            return "Unknown";
    }
}

static void bt_hci_command_dump(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    hci_command_hdr data;

    uint16_t Opcode;

    if (offset + (ssize_t) sizeof(hci_command_hdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&data, &hdr[offset], sizeof(hci_command_hdr));

    Opcode = le16toh(data.opcode);

    printf("--- BEGIN HCI COMMAND MESSAGE ---\n");
    printf("%-45s = %u\n", "OCF", MASK_OCF(Opcode));
    printf("%-45s = %u\n", "OGF", MASK_OGF(Opcode));
    printf("%-45s = %u\n", "Parameter Total Length", data.plen);
}

static void bt_hci_acl_data_dump(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    hci_acl_hdr data;

    uint16_t Handle;

    if (offset + (ssize_t) sizeof(hci_acl_hdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&data, &hdr[offset], sizeof(hci_acl_hdr));

    Handle = le16toh(data.handle);

    printf("--- BEGIN HCI ACL DATA MESSAGE ---\n");

    printf("%-45s = 0x%x\n", "Handle", MASK_Handle(Handle));
    printf("%-45s = %u\n", "PB", MASK_PB(Handle));
    printf("%-45s = %u\n", "BC", MASK_BC(Handle));
    printf("%-45s = %u\n", "Data Total Length", le16toh(data.dlen));
}

static void bt_hci_sync_data_dump(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    hci_sco_hdr data;

    uint16_t Handle;

    if (offset + (ssize_t) sizeof(hci_sco_hdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&data, &hdr[offset], sizeof(hci_sco_hdr));

    Handle = le16toh(data.handle);

    printf("--- BEGIN HCI SYNCHRONOUS DATA MESSAGE ---\n");

    printf("%-45s = %u\n", "Connection Handle", MASK_ConnectionHandle(Handle));
    printf("%-45s = %u\n", "Packet Status", MASK_PacketStatus(Handle));
    printf("%-45s = %u\n", "RFU", MASK_RFU(Handle));
    printf("%-45s = %u\n", "Data Total Length", data.dlen);
}

static void bt_hci_event_dump(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    hci_event_hdr data;

    if (offset + (ssize_t) sizeof(hci_event_hdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&data, &hdr[offset], sizeof(hci_event_hdr));

    printf("--- BEGIN HCI EVENT MESSAGE ---\n");

    printf("%-45s = 0x%x\n", "Event Code", data.evt);
    printf("%-45s = %u\n", "Paramater Total Length", data.plen);
}

static void bt_hci_iso_data_dump(const struct ob_protocol* buffer, ssize_t offset)
{
    const uint8_t* hdr = buffer->hdr;
    hci_msg_hdr data;

    uint16_t Handle;
    uint16_t Length;

    if (offset + (ssize_t) sizeof(hci_msg_hdr) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&data, &hdr[offset], sizeof(hci_msg_hdr));

    Handle = le16toh(data.device);
    Length = le16toh(data.plen);

    printf("--- BEGIN HCI ISO DATA MESSAGE ---\n");

    printf("%-45s = 0x%x\n", "Handle", MASK_ConnectionHandle(Handle));
    printf("%-45s = %u\n", "PB", MASK_PB(Handle));
    printf("%-45s = %u\n", "TS", MASK_TS(Handle));
    printf("%-45s = %u\n", "RFU1", MASK_RFU1(Handle));
    printf("%-45s = %u\n", "Data Total Length", MASK_DataTotalLength(Length));
    printf("%-45s = %u\n", "RFU2", MASK_RFU2(Length));
}

static void bt_dump_v3(const struct ob_protocol* buffer)
{
    const uint8_t* hdr = buffer->hdr;
    
    printf("--- BEGIN BLUETOOTH MESSAGE ---\n");

    printf("%-45s = %u (%s)\n", "HCI Packet Indicator", hdr[4], bt_hci_get_packet_type(hdr[4]));

    switch (hdr[4])
    {
        case 0x1:
            bt_hci_command_dump(buffer, 5);
            break;

        case 0x2:
            bt_hci_acl_data_dump(buffer, 5);
            break;

        case 0x3:
            bt_hci_sync_data_dump(buffer, 5);
            break;

        case 0x4:
            bt_hci_event_dump(buffer, 5);
            break;

        case 0x5:
            bt_hci_iso_data_dump(buffer, 5);
            break;

        default:
            break;
    }
}

static void bt_dump_v2(const struct ob_protocol* buffer)
{
    const uint8_t* hdr = buffer->hdr;

    printf("Bluetooth => ");
    printf("HCI Packet Indicator : %s\n", bt_hci_get_packet_type(hdr[4]));
}

void bt_dump(struct ob_protocol* buffer)
{
    if ((ssize_t) (5 * sizeof(uint8_t)) > buffer->length)
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_LOW:
            printf("> Bluetooth ");
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            bt_dump_v2(buffer);
            break;

        case OB_VERBOSITY_LEVEL_HIGH:
        default:
            bt_dump_v3(buffer);
            break;
    }
}
