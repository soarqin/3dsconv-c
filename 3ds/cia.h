#ifndef __CIA_H_
#define __CIA_H_

#include "ticket.h"
#include "tmd.h"

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

typedef struct {
    CIAHeader header;
    ETicket ticket;
    uint8_t cert_chain[0xA00];
    union {
        uint32_t sig_type;
        TMDSig2048 tmd_sig2048;
        TMDSig4096 tmd_sig4096;
    };
    TMDBody tmd_body;
    TMDContentChunk tmd_chunks[3];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
CIAContext;

#pragma pack(pop)

#endif // __CIA_H_
