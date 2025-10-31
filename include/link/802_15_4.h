#ifndef OB_802154_H
#define OB_802154_H

#include "generic/protocol.h"

struct lrwpan_frame_control {
    uint8_t FrameType : 3;
    uint8_t SecurityEnabled : 1;
    uint8_t FramePending : 1;
    uint8_t AcknowledgementRequired : 1;
    uint8_t PANIDCompression : 1;
    uint8_t Reserved : 1;
    uint8_t SequenceNumberCompression : 1;
    uint8_t IEPresent : 1;
    uint8_t DestinationAddressingMode : 2;
    uint8_t FrameVersion : 2;
    uint8_t SourceAddressingMode : 2;
};

struct lrwpan_mac_association_request {
    uint8_t Reserved : 1;
    uint8_t DeviceTypeFFD : 1;
    uint8_t PowerSource : 1;
    uint8_t ReceiverOnWhileIDLE : 1;
    uint8_t AssociationTypeFast : 1;
    uint8_t Reserved2 : 1;
    uint8_t SecurityCapability : 1;
    uint8_t AllocateAddress : 1;
};

void lrwpan_dump(struct ob_protocol* buffer);

#endif
