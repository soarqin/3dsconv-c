#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "ncsd.h"

#include "bn.h"

#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#define fseeko64 _fseeki64
#define ftello64 _ftelli64
#endif

const uint128 slot_0x2C_key = {0x1F76A94DE934C053ULL, 0xB98E95CECA3E4D17ULL};

static void int128_to_key(uint128 *n, uint8_t *key) {
    int i;
    for (i = 56; i >= 0; i -= 8)
        *key++ = (uint8_t)(n->highpart >> i);
    for (i = 56; i >= 0; i -= 8)
        *key++ = (uint8_t)(n->lowpart >> i);
}

static void setup_key(NCSDContext *context) {
    uint8_t bitflag = context->ncch.flags[7];
    if ((bitflag & 4) == 0) {
        if (bitflag & 1) {
            memset(context->calc_key, 0, 16);
            context->encrypted = 2;
        } else {
            uint128 key_y, key_, n = {0x024591DC5D52768A, 0x1FF9E9AAC5FE0408};
            memcpy(&key_y, context->ncch.signature, 16);
            uint128_bswap(&key_y);
            key_ = slot_0x2C_key;
            uint128_rol(&key_, 2);
            uint128_xor(&key_, &key_y);
            uint128_add(&key_, &n);
            uint128_rol(&key_, 87);

            int128_to_key(&key_, context->calc_key);
            context->encrypted = 1;
        }
    } else
        context->encrypted = 0;
}

void ncsd_crypt_exheader(NCSDContext *context, ExHeader *exheader) {
    if (context->encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16] = {0};
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, context->calc_key, 128);
        *(uint64_t*)counter = BE64(context->header.media_id);
        counter[8] = 1;
        mbedtls_aes_crypt_ctr(&cont, 0x800, &nc_off, counter, stream_block, (const uint8_t*)exheader, (uint8_t*)exheader);
        mbedtls_aes_free(&cont);
    }
}

static int verify_exheader_hash(NCSDContext *context) {
    uint8_t sha256sum[0x20];
    ncch_exheader_get_hash(&context->exheader, sha256sum);
    if (memcmp(sha256sum, context->ncch.extended_header_hash, 0x20) != 0)
        return NCSD_WRONG_EXHEADER_HASH;
    return NCSD_OK;
}

static int read_ncch(NCSDContext *context) {
    FILE *fd = (FILE *)context->fd;
    uint64_t offset = (uint64_t)context->header.partition_geometry[0].offset * MEDIA_UNIT_SIZE;
    uint64_t size = (uint64_t)context->header.partition_geometry[0].offset * MEDIA_UNIT_SIZE;
    fseeko64(fd, offset, SEEK_SET);
    fread(&context->ncch, sizeof(NCCHHeader), 1, fd);
    if (memcmp(context->ncch.magic, "NCCH", 4) != 0)
        return NCSD_INVALID_NCCH_HEADER;
    fread(&context->exheader, sizeof(ExHeader), 1, fd);
    setup_key(context);
    ncsd_crypt_exheader(context, &context->exheader);
    return verify_exheader_hash(context);
}

int ncsd_open(NCSDContext *context, const char *filename) {
    FILE *fd = fopen(filename, "rb");
    int result;
    if (fd == NULL) return NCSD_FILE_NOT_FOUND;
    context->fd = fd;
    fread(&context->header, sizeof(NCSDHeader), 1, fd);
    if (memcmp(context->header.magic, "NCSD", 4) != 0) {
        fclose(fd);
        return NCSD_INVALID_NCSD_HEADER;
    }
    result = read_ncch(context);
    if (result != NCSD_OK) {
        fclose(fd);
        return result;
    }
    return NCSD_OK;
}

void ncsd_close(NCSDContext *context) {
    fclose((FILE *)context->fd);
}

void ncsd_read_exefs_header(NCSDContext *context, ExeFSHeader *header) {
    uint64_t offset = (uint64_t)(context->header.partition_geometry[0].offset + context->ncch.exefs_offset) * MEDIA_UNIT_SIZE;
    FILE *fd = (FILE*)context->fd;
    fseeko64(fd, offset, SEEK_SET);
    fread(header, sizeof(ExeFSHeader), 1, fd);
    if (context->encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16] = {0};
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, context->calc_key, 128);
        *(uint64_t*)counter = BE64(context->header.media_id);
        counter[8] = 2;
        mbedtls_aes_crypt_ctr(&cont, sizeof(ExeFSHeader), &nc_off, counter, stream_block, (const uint8_t*)header, (uint8_t*)header);
    }
}

uint8_t *ncsd_decrypt_exefs_file(NCSDContext *context, ExeFSFileHeader *file_header) {
    uint64_t offset = (uint64_t)(context->header.partition_geometry[0].offset + context->ncch.exefs_offset) * MEDIA_UNIT_SIZE + sizeof(ExeFSHeader) + file_header->offset;
    uint8_t *data = (uint8_t *)malloc(file_header->size);
    FILE *fd = (FILE*)context->fd;
    fseeko64(fd, offset, SEEK_SET);
    fread(data, 1, file_header->size, fd);
    if (context->encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16] = {0};
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, context->calc_key, 128);
        *(uint64_t*)counter = BE64(context->header.media_id);
        counter[8] = 2;
        *(uint64_t*)(counter + 8) = BE64(BE64(*(uint64_t*)(counter + 8)) + sizeof(ExeFSHeader) / 0x10 + file_header->offset / 0x10);
        mbedtls_aes_crypt_ctr(&cont, file_header->size, &nc_off, counter, stream_block, data, data);
    }
    return data;
}

uint64_t ncsd_read_part_start(NCSDContext *context, uint32_t part, size_t offset) {
    uint64_t part_size = (uint64_t)context->header.partition_geometry[part].size * MEDIA_UNIT_SIZE;
    if ((uint64_t)offset > part_size) offset = (size_t)part_size;
    fseeko64((FILE*)context->fd, (uint64_t)context->header.partition_geometry[part].offset * MEDIA_UNIT_SIZE + offset, SEEK_SET);
    return part_size - (uint64_t)offset;
}

size_t ncsd_read_part(NCSDContext *context, void *data, size_t size) {
    return fread(data, 1, size, (FILE*)context->fd);
}
