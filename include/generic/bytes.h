#ifndef OB_BYTES_H
#define OB_BYTES_H

#include <stdint.h>
#include <stdbool.h>

#include "generic/protocol.h"

uint16_t read_u16_unaligned(const uint8_t buffer[2]);
uint32_t read_u32_unaligned(const uint8_t buffer[4]);
uint64_t read_u64_unaligned(const uint8_t buffer[8]);

const char* checksum_16bitonescomplement_validate(const struct ob_protocol* buffer, ssize_t length, uint16_t chksum, bool allow_disable);

#endif
