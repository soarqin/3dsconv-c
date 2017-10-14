#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "ncsd.h"

#include "bn.h"

#include "mbedtls/sha256.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#define fseeko64 _fseeki64
#define ftello64 _ftelli64
#endif

static int verify_exheader_hash(NCSDContext *context) {
    uint8_t sha256sum[0x20];
    ncch_exheader_get_hash(&context->ncch.exheader, sha256sum);
    if (memcmp(sha256sum, context->ncch.header.extended_header_hash, 0x20) != 0)
        return NCSD_WRONG_EXHEADER_HASH;
    return NCSD_OK;
}

static int read_ncch(NCSDContext *context) {
    FILE *fd = (FILE *)context->fd;
    uint64_t offset = (uint64_t)context->header.partition_geometry[0].offset * MEDIA_UNIT_SIZE;
    uint64_t size = (uint64_t)context->header.partition_geometry[0].offset * MEDIA_UNIT_SIZE;
    fseeko64(fd, offset, SEEK_SET);
    fread(&context->ncch.header, sizeof(NCCHHeader), 1, fd);
    if (memcmp(context->ncch.header.magic, "NCCH", 4) != 0)
        return NCSD_INVALID_NCCH_HEADER;
    fread(&context->ncch.exheader, sizeof(ExHeader), 1, fd);
    ncch_setup_key(&context->ncch);
    ncch_crypt_part(&context->ncch, NCCHTYPE_EXHEADER, 0, &context->ncch.exheader, sizeof(ExHeader));
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
    uint64_t offset = (uint64_t)(context->header.partition_geometry[0].offset + context->ncch.header.exefs_offset) * MEDIA_UNIT_SIZE;
    FILE *fd = (FILE*)context->fd;
    fseeko64(fd, offset, SEEK_SET);
    fread(header, sizeof(ExeFSHeader), 1, fd);
    ncch_crypt_part(&context->ncch, NCCHTYPE_EXEFS, 0, header, sizeof(ExeFSHeader));
}

uint8_t *ncsd_decrypt_exefs_file(NCSDContext *context, ExeFSFileHeader *file_header) {
    uint64_t offset = (uint64_t)(context->header.partition_geometry[0].offset + context->ncch.header.exefs_offset) * MEDIA_UNIT_SIZE + sizeof(ExeFSHeader) + file_header->offset;
    uint8_t *data = (uint8_t *)malloc(file_header->size);
    FILE *fd = (FILE*)context->fd;
    fseeko64(fd, offset, SEEK_SET);
    fread(data, 1, file_header->size, fd);
    ncch_crypt_part(&context->ncch, NCCHTYPE_EXEFS, sizeof(ExeFSHeader) + file_header->offset, data, file_header->size);
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
