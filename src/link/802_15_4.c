#include <endian.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "link/802_15_4.h"
#include "generic/binary.h"
#include "generic/constants.h"
#include "generic/protocol.h"

static const char* IEEE802154_FRAME_TYPES[] = {
    "Beacon",
    "Data",
    "Acknowledgement",
    "MAC command",
    "Reserved",
    "Multipurpose",
    "Fragment or Frak",
    "Extended"
};

static const char* IEEE802154_MAC_COMMANDS[] = {
    "Unknown",
    "Association request",
    "Association response",
    "Disassociation notification",
    "Data request",
    "PAN ID conflict notification",
    "Orphan notification",
    "Beacon request",
    "Coordinator realignment",
    "GTS request",
    "TRLE management request",
    "TRLE management response",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "DSME association request",
    "DSME association response",
    "DSME GTS request",
    "DSME GTS response",
    "DSME GST notify",
    "DSME information request",
    "DSME information response",
    "DSME beacon allocation notification",
    "DSME beacon collision notification",
    "DSME link report",
    "Reserved",
    "Reserved",
    "Reserved",
    "RIT data request",
    "DBS request",
    "DBS response",
    "RIT data response",
    "Vendor specific"
};

static const char* lrwpan_get_mac_command(uint8_t MacCommand)
{
    if (MacCommand >= sizeof(IEEE802154_MAC_COMMANDS) / sizeof(const char*))
    {
        return "Reserved";
    }
    return IEEE802154_MAC_COMMANDS[MacCommand];
}

static void lrwpan_dump_mac_association_request(struct ob_protocol* buffer, const uint8_t* hdr, ssize_t length)
{
    struct lrwpan_mac_association_request ci;
    ssize_t read_bytes = 0;
    if (length - read_bytes < sizeof(struct lrwpan_mac_association_request))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    memcpy(&ci, &hdr[read_bytes], sizeof(struct lrwpan_mac_association_request));
    read_bytes += sizeof(struct lrwpan_mac_association_request);

    printf("%-45s = 0x%x\n", "Device type is FFD", ci.DeviceTypeFFD);
    printf("%-45s = 0x%x\n", "Power source", ci.PowerSource);
    printf("%-45s = 0x%x\n", "Receiver on while IDLE", ci.ReceiverOnWhileIDLE);
    printf("%-45s = 0x%x\n", "Association type is fast", ci.AssociationTypeFast);
    printf("%-45s = 0x%x\n", "Security capability", ci.SecurityCapability);
    printf("%-45s = 0x%x\n", "Allocate address", ci.AllocateAddress);
}

static void lrwpan_dump_mac_command(struct ob_protocol* buffer, const uint8_t* hdr, ssize_t length)
{
    ssize_t read_bytes = 0;
    uint8_t MacCommand;
    if (length - read_bytes < sizeof(uint8_t))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }
    memcpy(&MacCommand, &hdr[read_bytes], sizeof(uint8_t));
    read_bytes += sizeof(uint8_t);

    printf("--- BEGIN IEEE 802.15.4 MAC COMMAND ---\n");

    printf("%-45s = 0x%x (%s)\n", "Mac command", MacCommand, lrwpan_get_mac_command(MacCommand));

    switch (MacCommand)
    {
        case 0x1:
            lrwpan_dump_mac_association_request(buffer, &hdr[read_bytes], length - read_bytes);
            break;

        default:
            break;
    }
}

static void lrwpan_dump_v3(struct ob_protocol* buffer)
{
    ssize_t bytes_read = 0;
    void* saved_hdr = buffer->hdr;
    ssize_t saved_length = buffer->length;
    const uint8_t* hdr = buffer->hdr;
    struct lrwpan_frame_control lc;

    bool has_pan_id_src = true;
    bool has_pan_id_dst = true;

    uint16_t FCS = 0;

    if (buffer->length - bytes_read < sizeof(struct lrwpan_frame_control))
    {
        longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
    }

    memcpy(&lc, &hdr[bytes_read], sizeof(struct lrwpan_frame_control));
    bytes_read += sizeof(struct lrwpan_frame_control);

    printf("--- BEGIN 802.15.4 MESSAGE ---\n");
    printf("%-45s = 0x%x (%s)\n", "Frame type", lc.FrameType, IEEE802154_FRAME_TYPES[lc.FrameType]);
    printf("%-45s = %u\n", "Security enabled", lc.SecurityEnabled);
    printf("%-45s = %u\n", "Frame pending", lc.FramePending);
    printf("%-45s = %u\n", "Acknowledgement required", lc.AcknowledgementRequired);
    printf("%-45s = %u\n", "PAN ID compression", lc.PANIDCompression);
    printf("%-45s = %u\n", "Sequence number compression", lc.SequenceNumberCompression);
    printf("%-45s = %u\n", "IE present", lc.IEPresent);
    printf("%-45s = %u\n", "Destination addressing mode", lc.DestinationAddressingMode);
    printf("%-45s = %u\n", "Frame version", lc.FrameVersion);
    printf("%-45s = %u\n", "Source addressing mode", lc.SourceAddressingMode);

    if (lc.SequenceNumberCompression == 0)
    {
        uint8_t SequenceNumber;
        if (buffer->length - bytes_read < sizeof(uint8_t))
        {
            longjmp(*(buffer->catcher), OB_ERROR_BUFFER_OVERFLOW);
        }

        memcpy(&SequenceNumber, &hdr[bytes_read], sizeof(uint8_t));
        bytes_read += sizeof(uint8_t);

        printf("%-45s = %u\n", "Sequence number", SequenceNumber);
    }

    switch (lc.DestinationAddressingMode)
    {
        case 0b00:
            break;

        case 0b01:
            break;

        case 0b10:
            {
                uint16_t PanID;
                uint16_t DestAddr;
                memcpy(&PanID, &hdr[bytes_read], sizeof(uint16_t));
                bytes_read += sizeof(uint16_t);
                printf("%-45s = %04x\n", "Destination PAN ID", PanID);
                memcpy(&DestAddr, &hdr[bytes_read], sizeof(uint16_t));
                bytes_read += sizeof(uint16_t);
                printf("%-45s = %04x\n", "Destination address", DestAddr);
                break;
            }

        case 0b11:
            {
                uint16_t PanID;
                uint64_t DestAddr;
                memcpy(&PanID, &hdr[bytes_read], sizeof(uint16_t));
                bytes_read += sizeof(uint16_t);
                printf("%-45s = %04x\n", "Destination PAN ID", PanID);
                memcpy(&DestAddr, &hdr[bytes_read], sizeof(uint64_t));
                bytes_read += sizeof(uint64_t);
                printf("%-45s = %016lx\n", "Destination address", DestAddr);
            }
            break;
    }

    switch (lc.SourceAddressingMode)
    {
        case 0b00:
            break;

        case 0b01:
            break;

        case 0b10:
            {
                if (lc.PANIDCompression == 0)
                {
                    uint16_t PanID;
                    memcpy(&PanID, &hdr[bytes_read], sizeof(uint16_t));
                    bytes_read += sizeof(uint16_t);
                    printf("%-45s = %04x\n", "Source PAN ID", PanID);
                }
                uint16_t SrcAddr;
                memcpy(&SrcAddr, &hdr[bytes_read], sizeof(uint16_t));
                bytes_read += sizeof(uint16_t);
                printf("%-45s = %04x\n", "Source address", SrcAddr);
                break;
            }

        case 0b11:
            {
                if (lc.PANIDCompression == 0)
                {
                    uint16_t PanID;
                    memcpy(&PanID, &hdr[bytes_read], sizeof(uint16_t));
                    bytes_read += sizeof(uint16_t);
                    printf("%-45s = %04x\n", "Source PAN ID", PanID);
                }
                uint64_t SrcAddr;
                memcpy(&SrcAddr, &hdr[bytes_read], sizeof(uint64_t));
                bytes_read += sizeof(uint64_t);
                printf("%-45s = %016lx\n", "Source address", SrcAddr);
            }
            break;
    }

    if (lc.SecurityEnabled == 1)
    {
        // NOT IMPLEMENTED
        longjmp(*(buffer->catcher), OB_ERROR_NOT_SUPPORTED);
    }

    if (lc.IEPresent)
    {
        // NOT IMPLEMENTED
        longjmp(*(buffer->catcher), OB_ERROR_NOT_SUPPORTED);
    }

    switch (lc.FrameType)
    {
        case 0x3:
            lrwpan_dump_mac_command(buffer, &hdr[bytes_read], buffer->length - bytes_read);
            break;

        default:
            break;
    }

    memcpy(&FCS, &hdr[saved_length - 2], sizeof(uint16_t));
    saved_length -= sizeof(uint16_t);

    printf("%-45s = 0x%04x\n", "FCS", FCS);

    buffer->hdr = &hdr[bytes_read];
    buffer->length = saved_length - bytes_read;

    binary_dump(buffer);

    buffer->length = saved_length;
    buffer->hdr = saved_hdr;
}

void lrwpan_dump(struct ob_protocol* buffer)
{
    switch (buffer->verbosity_level)
    {
        case OB_VERBOSITY_LEVEL_HIGH:
            lrwpan_dump_v3(buffer);
            break;

        case OB_VERBOSITY_LEVEL_MEDIUM:
            break;

        case OB_VERBOSITY_LEVEL_LOW:
            printf("> IEEE 802.15.4 ");
            break;
    }

    return;
}
