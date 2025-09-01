#ifndef OB_FILE_OID_H
#define OB_FILE_OID_H

#include <stdint.h>

struct oid_node {
    const char* name;
    struct oid_node* node;
};

extern struct oid_node oid_root[];

struct oid_node* get_oid_node(struct oid_node* base, uint64_t value);

#endif
