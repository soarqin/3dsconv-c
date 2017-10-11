#ifndef __CIA_H_
#define __CIA_H_

#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
    uint32_t header_size;
    uint16_t type;
    uint16_t version;
    uint32_t cert_size;
    uint32_t ticket_size;
    uint32_t tmd_size;
    uint32_t meta_size;
    uint64_t content_size;
    uint8_t content_index[0x2000];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
CIAHeader;

#pragma pack(pop)

#endif // __CIA_H_
