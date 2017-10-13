#ifndef __CIA_H_
#define __CIA_H_

#include "ticket.h"
#include "tmd.h"
#include "ncch.h"
#include "ncsd.h"

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
    ExHeaderDependencyList dep_list;
    uint8_t reserved[0x180];
    uint32_t core_version;
    uint8_t reserved2[0xFC];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
CIAMeta;

typedef struct {
    CIAHeader header;
    uint8_t *cert_chain;
    size_t cert_chain_size;
    ETicket ticket;
    union {
        uint32_t tmd_sig_type;
        TMDSig2048 tmd_sig2048;
        TMDSig4096 tmd_sig4096;
    };
    size_t tmd_sig_size;
    TMDBody tmd_body;
    TMDContentChunk tmd_chunks[3];
    size_t chunk_count;
    NCCHHeader ncch;
    ExHeader exheader;
    CIAMeta meta;
    uint8_t *smdh_icon;
    size_t smdh_icon_size;
    void *fd;
    int writable;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
CIAContext;

#pragma pack(pop)

void cia_new(CIAContext *context);
void cia_close(CIAContext *context);
void cia_set_certchain(CIAContext *context, const uint8_t *data, size_t size);
void cia_set_ticket(CIAContext *context, const uint8_t *data, size_t size);
void cia_copy_tmd_part(CIAContext *context, const uint8_t *data, size_t size);
void cia_copy_ncch_from_ncsd(CIAContext *context, NCSDContext *ncsd);
void cia_set_smdh(CIAContext *context, const uint8_t *data, size_t size);
int cia_create_file(CIAContext *context, const char *ciafile);
int cia_write_headers(CIAContext *context);
int cia_write_from_ncsd(CIAContext *context, NCSDContext *ncsd, void(*on_progress)(uint32_t part, uint64_t prog, uint64_t total));

#endif // __CIA_H_
