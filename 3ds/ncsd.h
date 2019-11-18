#ifndef __NCSD_H_
#define __NCSD_H_

#include "ncch.h"

#include <stdint.h>
#include <stddef.h>

enum {
    MEDIA_UNIT_SIZE = 0x200,
};

typedef enum {
    NCSD_OK = 0,
    NCSD_FILE_NOT_FOUND = -1,
    NCSD_INVALID_NCSD_HEADER = -2,
    NCSD_INVALID_NCCH_HEADER = -3,
    NCSD_WRONG_EXHEADER_HASH = -4,
} NCSDResult;

#pragma pack(push, 1)

typedef struct {
    uint32_t offset;
    uint32_t size;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
NCSDPartitionGeometry;

typedef struct {
    uint8_t signature[0x100];
    uint8_t magic[4];
    uint32_t media_size;
    uint64_t media_id;
    uint64_t partition_fs_type;
    uint64_t partition_crypt_type;
    NCSDPartitionGeometry partition_geometry[8];
    uint8_t extended_header_hash[0x20];
    uint32_t additional_header_size;
    uint32_t sector_zero_offset;
    uint8_t flags[8];
    uint64_t title_id[0x08];
    uint8_t reserved[0x20];
    uint8_t reserved2[0x0E];
    uint8_t check1;
    uint8_t save_crypto_extra_val;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
NCSDHeader;

typedef struct {
    uint8_t name[8];
    uint32_t offset;
    uint32_t size;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExeFSFileHeader;

typedef struct {
    ExeFSFileHeader file_header[10];
    uint8_t reserved[0x20];
    uint8_t hashes[10][0x20];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExeFSHeader;

typedef struct {
    void *fd;
    NCSDHeader header;
    int encrypted;
    uint8_t calc_key[16];
    NCCHHeader ncch;
    ExHeader exheader;
} NCSDContext;

#pragma pack(pop)

void ncsd_crypt_exheader(NCSDContext *context, ExHeader *exheader);

int ncsd_open(NCSDContext *context, const char *filename);
void ncsd_close(NCSDContext *context);
void ncsd_read_exefs_header(NCSDContext *context, ExeFSHeader *header);
uint8_t *ncsd_decrypt_exefs_file(NCSDContext *context, ExeFSFileHeader *file_header);
uint64_t ncsd_read_part_start(NCSDContext *context, uint32_t part, size_t offset);
size_t ncsd_read_part(NCSDContext *context, void *data, size_t size);

#endif // __NCSD_H_
