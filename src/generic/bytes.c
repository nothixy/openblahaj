#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "generic/bytes.h"

/**
 * @brief Read 2 bytes as an uint16_t without caring about the alignment or endianness
 * @note Caller is responsible for checking array bounds
 * @param buffer Buffer containing at least 2 bytes
 * @return uint16_t containing read value
 */
uint16_t read_u16_unaligned(const uint8_t buffer[2])
{
    uint16_t l1 = (uint16_t) buffer[0];
    uint16_t l2 = (uint16_t) buffer[1];
    return l1 | (uint16_t) (l2 << 8);
}

/**
 * @brief Read 4 bytes as an uint32_t without caring about the alignment or endianness
 * @note Caller is responsible for checking array bounds
 * @param buffer Buffer containing at least 4 bytes
 * @return uint32_t containing read value
 */
uint32_t read_u32_unaligned(const uint8_t buffer[4])
{
    uint32_t l1 = (uint32_t) buffer[0];
    uint32_t l2 = (uint32_t) buffer[1];
    uint32_t l3 = (uint32_t) buffer[2];
    uint32_t l4 = (uint32_t) buffer[3];
    return l1 | (l2 << 8) | (l3 << 16) | (l4 << 24);
}

/**
 * @brief Read 8 bytes as an uint64_t without caring about the alignment or endianness
 * @note Caller is responsible for checking array bounds
 * @param buffer Buffer containing at least 8 bytes
 * @return uint64_t containing read value
 */
uint64_t read_u64_unaligned(const uint8_t buffer[8])
{
    uint64_t l1 = (uint64_t) buffer[0];
    uint64_t l2 = (uint64_t) buffer[1];
    uint64_t l3 = (uint64_t) buffer[2];
    uint64_t l4 = (uint64_t) buffer[3];
    uint64_t l5 = (uint64_t) buffer[4];
    uint64_t l6 = (uint64_t) buffer[5];
    uint64_t l7 = (uint64_t) buffer[6];
    uint64_t l8 = (uint64_t) buffer[7];
    return l1 | (l2 << 8) | (l3 << 16) | (l4 << 24) | (l5 << 32) | (l6 << 40) | (l7 << 48) | (l8 << 56);
}

/**
 * @brief Validate a 16bit one's complement checksum
 * @param buffer Array of bytes to check
 * @param length Length of the array in bytes
 * @param chksum Value of the checksum field
 * @param allow_disable If a 0 checksum field means no checksum
 * @return Constant string containing the status of this check
 */
const char* checksum_16bitonescomplement_validate(const struct ob_protocol* buffer, ssize_t length, uint16_t chksum, bool allow_disable)
{
    const uint8_t* hdr = buffer->hdr;
    uint32_t sum = 0;

    if (allow_disable && chksum == 0)
    {
        return "\033[1m[Disabled]\033[22m";
    }

    for (ssize_t i = 0; i < length - 1; i += 2)
    {
        sum += be16toh(read_u16_unaligned(&hdr[i]));
        sum += (sum >> 16);
        sum = (uint16_t) sum;
    }

    if ((length & 1) != 0)
    {
        sum += be16toh(hdr[length - 1]);
        sum += (sum >> 16);
        sum = (uint16_t) sum;
    }
    
    sum = (uint16_t) (~sum);

    return sum == 0 ? "\033[1m[Valid]\033[22m" : "\033[1m[Invalid (this might indicate that hardware offloading was used)]\033[22m";
}
