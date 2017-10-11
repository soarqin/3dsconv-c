#ifndef __TICKET_H_
#define __TICKET_H_

#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
    uint32_t enable_timelimit;
    uint32_t timelimit_seconds;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
TimeLimitEntry;

typedef struct {
    uint8_t sig_type[4];
    uint8_t signature[0x100];
    uint8_t padding1[0x3c];
    uint8_t issuer[0x40];
    uint8_t ecdsa[0x3c];
    uint8_t padding2[0x03];
    uint8_t encrypted_title_key[0x10];
    uint8_t unknown;
    uint8_t ticket_id[8];
    uint8_t console_id[4];
    uint8_t title_id[8];
    uint16_t sys_access;
    uint16_t ticket_version;
    uint32_t time_mask;
    uint32_t permit_mask;
    uint8_t title_export;
    uint8_t commonkey_idx;
    uint8_t unknown_buf[0x30];
    uint8_t content_permissions[0x40];
    uint8_t padding0[2];

    TimeLimitEntry timelimits[8];  
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ETicket;

#pragma pack(pop)

#endif // __TICKET_H_
