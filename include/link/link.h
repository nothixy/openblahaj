#ifndef OB_LINK_H
#define OB_LINK_H

#include "generic/protocol.h"

void link_cast(struct ob_protocol* buffer);
const char* link_get_name(int LinkType);

#endif
