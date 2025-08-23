#ifndef OB_HOOKS_PRINTBUF_H
#define OB_HOOKS_PRINTBUF_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

void printbuf(void* buf, ssize_t size, uint16_t src_port, uint16_t dst_port, bool tcp);

#endif
