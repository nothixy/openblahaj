#include <stdio.h>
#include <stdlib.h>

#include "filetypes/oid.h"

#define SET(id, name, ptr) [id + 1]={name, ptr}

struct oid_node iso_standard[] = {

};

struct oid_node iso_registration_authority[] = {

};

// 1.2.840.10045.4.3.
struct oid_node iso_member_body_us_ansi_x962_signatures_ecdsa_with_sha2[] = {
    {"4", NULL},
    SET(1, "ecdsa-with-SHA224", NULL),
    SET(2, "ecdsa-with-SHA256", NULL),
    SET(3, "ecdsa-with-SHA384", NULL),
    SET(4, "ecdsa-with-SHA512", NULL),
};

// 1.2.840.10045.4.
struct oid_node iso_member_body_us_ansi_x962_signatures[] = {
    {"3", NULL},
    SET(1, "ecdsa-with-SHA1", NULL),
    SET(2, "ecdsa-with-Recommended", NULL),
    SET(3, "ecdsa-with-SHA2", iso_member_body_us_ansi_x962_signatures_ecdsa_with_sha2),
};

// 1.2.840.10045.2.
struct oid_node iso_member_body_us_ansi_x962_keytype[] = {
    {"1", NULL},
    SET(1, "ecPublicKey", NULL),
};

// 1.2.840.10045.3.1.
struct oid_node iso_member_body_us_ansi_x962_curves_prime[] = {
    {"7", NULL},
    SET(1, "prime192v1", NULL),
    SET(2, "prime192v2", NULL),
    SET(3, "prime192v3", NULL),
    SET(4, "prime239v1", NULL),
    SET(5, "prime239v2", NULL),
    SET(6, "prime239v3", NULL),
    SET(7, "prime256v1", NULL),
};

// 1.2.840.10045.3.
struct oid_node iso_member_body_us_ansi_x962_curves[] = {
    {"1", NULL},
    SET(0, "characteristicTwo", NULL),
    SET(1, "prime", iso_member_body_us_ansi_x962_curves_prime),
};

// 1.2.840.10045.
struct oid_node iso_member_body_us_ansi_x962[] = {
    {"5", NULL},
    SET(0, "modules", NULL),
    SET(1, "fieldType", NULL),
    SET(2, "keyType", iso_member_body_us_ansi_x962_keytype),
    SET(3, "curves", iso_member_body_us_ansi_x962_curves),
    SET(4, "signatures", iso_member_body_us_ansi_x962_signatures),
    SET(5, "module", NULL),
};

// 1.2.840.
struct oid_node iso_member_body_us[] = {
    {"912006", NULL},
    //
    // SET(1, "organization", NULL),
    // SET(101, "gov", NULL),
    // SET(10003, "z39-50", NULL),
    // SET(10004, "ieee11073", NULL),
    // SET(10006, "ieee802dot3", NULL),
    // SET(10007, "ieee802-1B", NULL),
    // SET(10008, "dicom", NULL),
    SET(10045, "ansi-x962", iso_member_body_us_ansi_x962),
    SET(912006, "[INTERNAL]", NULL),
};

// 1.2.
struct oid_node iso_member_body[] = {
    {"840", NULL},
    SET(36, "au", NULL),
    SET(40, "at", NULL),
    SET(56, "be", NULL),
    SET(124, "ca", NULL),
    SET(156, "cn", NULL),
    SET(203, "cz", NULL),
    SET(208, "dk", NULL),
    SET(246, "fi", NULL),
    SET(250, "fr", NULL),
    SET(276, "de", NULL),
    SET(280, "280", NULL),
    SET(300, "gr", NULL),
    SET(344, "hk", NULL),
    SET(372, "ie", NULL),
    SET(392, "jp", NULL),
    SET(398, "kz", NULL),
    SET(410, "kr", NULL),
    SET(498, "md", NULL),
    SET(504, "ma", NULL),
    SET(528, "nl", NULL),
    SET(566, "ng", NULL),
    SET(578, "no", NULL),
    SET(616, "pl", NULL),
    SET(643, "ru", NULL),
    SET(702, "sg", NULL),
    SET(752, "se", NULL),
    SET(804, "ua", NULL),
    SET(826, "gb", NULL),
    SET(840, "us", iso_member_body_us),
};

// 1.3.132.
struct oid_node iso_identified_organization_certicom[] = {
    {"1", NULL},
    SET(0, "curve", NULL),
    SET(1, "schemes", NULL)
};

// 1.3.
struct oid_node iso_identified_organization[] = {
    {"9999", NULL},
    //
    SET(132, "certicom", iso_identified_organization_certicom),
    SET(9999, "[INTERNAL]", NULL),
};

// 0.
struct oid_node itu[] = {

};

// 1.
struct oid_node iso[] = {
    {"3", NULL},
    SET(0, "standard", iso_standard),
    SET(1, "registration-authority", iso_registration_authority),
    SET(2, "member-body", iso_member_body),
    SET(3, "identified-organization", iso_identified_organization),
};

// 2.5.4.
struct oid_node joint_ds_attributetype[] = {
    {"106", NULL},
    //
    SET(3, "commonName", NULL),
    SET(6, "countryName", NULL),
    SET(10, "organizationName", NULL),
    SET(106, "[INTERNAL]", NULL),
};

// 2.5.29.
struct oid_node joint_ds_certificateextension[] = {
    {"75", NULL},
    //
    SET(14, "subjectKeyIdentifier", NULL),
    SET(15, "keyUsage", NULL),
    SET(19, "basicConstraints", NULL),
    SET(35, "authorityKeyIdentifier", NULL),
    SET(37, "extKeyUsage", NULL),
    SET(75, "[INTERNAL]", NULL),
};

// 2.5.
struct oid_node joint_ds[] = {
    {"44", NULL},
    //
    SET(4, "attributeType", joint_ds_attributetype),
    SET(29, "certificateExtension", joint_ds_certificateextension),
    SET(44, "[INTERNAL]", NULL),
};

// 2.
struct oid_node joint[] = {
    {"999", NULL},
    // 
    SET(5, "ds", joint_ds),
    SET(999, "[INTERNAL]", NULL),
};

struct oid_node oid_root[] = {
    {"2", NULL},
    SET(0, "itu-t", NULL),
    SET(1, "iso", iso),
    SET(2, "joint-iso-itu-t", joint),
};

struct oid_node* get_oid_node(struct oid_node* base, uint64_t value)
{
    uint64_t len;
    // printf("ASKED FOR %d\n", value);
    // printf("BASE = %p\n", base);
    if (base == NULL)
    {
        return NULL;
    }
    // printf("LEN = %s\n", base[0].name);
    len = atoll(base[0].name) + 1;
    if (value >= len)
    {
        return NULL;
    }
    return &base[value + 1];
}
