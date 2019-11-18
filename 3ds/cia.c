#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "cia.h"
#include "bn.h"

#include "mbedtls/sha256.h"

#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
#define fseeko _fseeki64
#define ftello _ftelli64
#endif

void cia_new(CIAContext *context) {
    memset(context, 0, sizeof(CIAContext));
}

void cia_close(CIAContext *context) {
    if (context->cert_chain)
        free(context->cert_chain);
    if (context->smdh_icon != NULL)
        free(context->smdh_icon);
    if (context->fd != NULL)
        fclose((FILE*)context->fd);
    memset(context, 0, sizeof(CIAContext));
}

void cia_set_certchain(CIAContext *context, const uint8_t *data, size_t size) {
    context->cert_chain = (uint8_t*)malloc(size);
    context->cert_chain_size = size;
    memcpy(context->cert_chain, data, size);
}

void cia_set_ticket(CIAContext *context, const uint8_t *data, size_t size) {
    if (size > sizeof(ETicket)) size = sizeof(ETicket);
    memcpy(&context->ticket, data, size);
}

void cia_copy_tmd_part(CIAContext *context, const uint8_t *data, size_t size) {
    switch (BE32(*(uint32_t*)data)) {
        case 0x10000:
        case 0x10003:
            context->tmd_sig_size = sizeof(TMDSig4096);
            memcpy(&context->tmd_sig4096, data, context->tmd_sig_size);
            break;
        case 0x10001:
        case 0x10004:
            context->tmd_sig_size = sizeof(TMDSig2048);
            memcpy(&context->tmd_sig2048, data, context->tmd_sig_size);
            break;
        default:
            break;
    }
    data += context->tmd_sig_size;
    size -= context->tmd_sig_size;
    if (size > sizeof(TMDBody)) size = sizeof(TMDBody);
    memcpy(&context->tmd_body, data, size);
}

void cia_copy_ncch_from_ncsd(CIAContext *context, NCSDContext *ncsd) {
    uint8_t i;
    uint64_t manual_cfa_size = (uint64_t)ncsd->header.partition_geometry[1].size * MEDIA_UNIT_SIZE;
    uint64_t dlpchild_cfa_size = (uint64_t)ncsd->header.partition_geometry[2].size * MEDIA_UNIT_SIZE;
    context->ncch = ncsd->ncch;
    context->exheader = ncsd->exheader;
    context->chunk_count = 0;
    context->header.header_size = sizeof(CIAHeader);
    context->header.type = 0;
    context->header.version = 0;
    context->header.cert_size = (uint32_t)context->cert_chain_size;
    context->header.ticket_size = (uint32_t)sizeof(ETicket);
    context->header.content_size = 0;
    for (i = 0; i < 3; ++i) {
        uint64_t csize = (uint64_t)ncsd->header.partition_geometry[i].size * MEDIA_UNIT_SIZE;
        if (csize == 0) continue;
        context->tmd_chunks[context->chunk_count].id = BE32(i);
        context->tmd_chunks[context->chunk_count].index = BE16(i);
        context->tmd_chunks[context->chunk_count].type = BE16(0);
        context->tmd_chunks[context->chunk_count].size = BE64(csize);
        context->header.content_size += csize;
        context->header.content_index[0] |= 0x80 >> i;
        ++context->chunk_count;
    }
    context->header.tmd_size = (uint32_t)(sizeof(TMDContentChunk) * context->chunk_count + context->tmd_sig_size + sizeof(TMDBody));
    context->ticket.title_id = BE64(ncsd->header.media_id);
    context->tmd_body.content_count = BE16((uint16_t)context->chunk_count);
    context->tmd_body.content_info[0].command_count = BE16((uint16_t)context->chunk_count);
    context->tmd_body.title_id = BE64(ncsd->header.media_id);
    context->tmd_body.savedata_size = (uint32_t)ncsd->exheader.system_info.savedata_size;
    context->meta.dep_list = ncsd->exheader.dep_list;
    context->meta.core_version = ncsd->exheader.arm11_system_local_caps.core_version;
    ncsd_crypt_exheader(ncsd, &context->exheader);
}

void cia_set_smdh(CIAContext *context, const uint8_t *data, size_t size) {
    context->smdh_icon = (uint8_t*)malloc(size);
    context->smdh_icon_size = size;
    context->header.meta_size = (uint32_t)(sizeof(CIAMeta) + context->smdh_icon_size);
    memcpy(context->smdh_icon, data, size);
}

int cia_create_file(CIAContext *context, const char *ciafile) {
    FILE *fd = fopen(ciafile, "wb");
    if (fd == NULL) {
        return -1;
    }
    context->fd = fd;
    context->writable = 1;
    return 0;
}

static void write_struct_with_padding(FILE *fd, const void *data, size_t sz) {
    size_t pad_size = (size_t)(((sz + 0x3F) & ~0x3FULL) - sz);
    fwrite(data, sz, 1, fd);
    if (pad_size > 0) {
        uint8_t zero[0x40];
        memset(zero, 0, pad_size);
        fwrite(zero, 1, pad_size, fd);
    }
}

int cia_write_from_ncsd(CIAContext *context, NCSDContext *ncsd, void (*on_progress)(uint32_t part, uint64_t prog, uint64_t total)) {
    const uint64_t read_size = 0x800000;
    mbedtls_sha256_context ctx;
    FILE *fd = (FILE*)context->fd;
    uint64_t save_off;
    uint64_t left, total_size;
    uint8_t* dataread;
    if (fd == NULL || !context->writable) return -1;
    write_struct_with_padding(fd, &context->header, sizeof(CIAHeader));
    write_struct_with_padding(fd, context->cert_chain, context->cert_chain_size);
    write_struct_with_padding(fd, &context->ticket, sizeof(ETicket));
    write_struct_with_padding(fd, &context->tmd_sig4096, context->tmd_sig_size);
    save_off = ftello(fd);
    write_struct_with_padding(fd, &context->tmd_body, sizeof(TMDBody) + sizeof(TMDContentChunk) * context->chunk_count);

    dataread = (uint8_t*)malloc(read_size);

    fwrite(&context->ncch, sizeof(NCCHHeader), 1, fd);
    fwrite(&context->exheader, sizeof(ExHeader), 1, fd);
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, (const uint8_t*)&context->ncch, sizeof(NCCHHeader));
    mbedtls_sha256_update(&ctx, (const uint8_t*)&context->exheader, sizeof(ExHeader));
    total_size = left = ncsd_read_part_start(ncsd, 0, sizeof(NCCHHeader) + sizeof(ExHeader));
    on_progress(0, 0, total_size);
    while (left > 0) {
        size_t to_read = (size_t)(read_size < left ? read_size : left);
        size_t readbytes = ncsd_read_part(ncsd, dataread, to_read);
        mbedtls_sha256_update(&ctx, dataread, readbytes);
        fwrite(dataread, 1, readbytes, fd);
        left -= readbytes;
        on_progress(0, total_size - left, total_size);
    }
    mbedtls_sha256_finish(&ctx, context->tmd_chunks[0].hash);
    mbedtls_sha256_free(&ctx);

    // Manual CFA
    if (ncsd->header.partition_geometry[1].size != 0) {
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        total_size = left = ncsd_read_part_start(ncsd, 1, 0);
        on_progress(1, 0, total_size);
        while (left > 0) {
            size_t to_read = (size_t)(read_size < left ? read_size : left);
            size_t readbytes = ncsd_read_part(ncsd, dataread, to_read);
            mbedtls_sha256_update(&ctx, dataread, readbytes);
            fwrite(dataread, 1, readbytes, fd);
            left -= readbytes;
            on_progress(1, total_size - left, total_size);
        }
        mbedtls_sha256_finish(&ctx, context->tmd_chunks[1].hash);
        mbedtls_sha256_free(&ctx);
    }

    // Download Play child container CFA
    if (ncsd->header.partition_geometry[2].size != 0) {
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        total_size = left = ncsd_read_part_start(ncsd, 2, 0);
        on_progress(2, 0, total_size);
        while (left > 0) {
            size_t to_read = (size_t)(read_size < left ? read_size : left);
            size_t readbytes = ncsd_read_part(ncsd, dataread, to_read);
            mbedtls_sha256_update(&ctx, dataread, readbytes);
            fwrite(dataread, 1, readbytes, fd);
            left -= readbytes;
            on_progress(2, total_size - left, total_size);
        }
        mbedtls_sha256_finish(&ctx, context->tmd_chunks[2].hash);
        mbedtls_sha256_free(&ctx);
    }
    free(dataread);
    
    fwrite(&context->meta, sizeof(CIAMeta), 1, fd);
    fwrite(context->smdh_icon, 1, context->smdh_icon_size, fd);

    // update final hashes
    mbedtls_sha256((const uint8_t*)&context->tmd_chunks[0], sizeof(TMDContentChunk) * context->chunk_count, context->tmd_body.content_info[0].hash, 0);
    mbedtls_sha256((const uint8_t*)&context->tmd_body.content_info[0], sizeof(TMDContentInfo) * 64, context->tmd_body.hash, 0);
    fseeko(fd, save_off, SEEK_SET);
    write_struct_with_padding(fd, &context->tmd_body, sizeof(TMDBody) + sizeof(TMDContentChunk) * context->chunk_count);
    return 0;
}
