#include "ncch.h"

#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

#include "bn.h"

#include <memory.h>

void ncch_setup_key(NCCHContext *context) {
    const uint128 slot_0x2C_key = {0x1F76A94DE934C053ULL, 0xB98E95CECA3E4D17ULL};
    uint8_t bitflag = context->header.flags[7];
    if ((bitflag & 4) == 0) {
        if (bitflag & 1) {
            memset(context->key_y, 0, 16);
            context->encrypted = 2;
        } else {
            uint128 key_y, key_, n = {0x024591DC5D52768A, 0x1FF9E9AAC5FE0408};
            memcpy(&key_y, context->header.signature, 16);
            uint128_bswap(&key_y);
            key_ = slot_0x2C_key;
            uint128_rol(&key_, 2);
            uint128_xor(&key_, &key_y);
            uint128_add(&key_, &n);
            uint128_rol(&key_, 87);

            *(uint64_t*)context->key_y = BE64(key_.highpart);
            *(uint64_t*)(context->key_y + 8) = BE64(key_.lowpart);
            context->encrypted = 1;
        }
    } else
        context->encrypted = 0;
}

void ncch_exheader_spoof_version(ExHeader *exheader, uint16_t targetver, uint16_t origver[2]) {
    // Kernel version spoof
    //   when highest 12bit is 0b1111110xxxxx: Bits 8-15: Major version; Bits 0-7: Minor version
    uint32_t i;
    origver[0] = 0; origver[1] = 0;
    for (i = 0; i < 28; ++i) {
        uint32_t desc = exheader->arm11_kernel_caps.descriptors[i];
        if (desc >> 25 == 0x7E) {
            origver[0] = (uint16_t)(desc & 0xFFFFu);
            if (origver[0] <= targetver) break;
            desc = (desc & ~0xFFFFu) | targetver;
            exheader->arm11_kernel_caps.descriptors[i] = desc;
            break;
        }
    }
    for (i = 0; i < 28; ++i) {
        uint32_t desc = exheader->access_desc.arm11_kernel_caps.descriptors[i];
        if (desc >> 25 == 0x7E) {
            origver[1] = (uint16_t)(desc & 0xFFFFu);
            if (origver[1] <= targetver) break;
            exheader->access_desc.arm11_kernel_caps.descriptors[i] = (desc & ~0xFFFFu) | targetver;
            break;
        }
    }
}

void ncch_exheader_get_hash(ExHeader *exheader, uint8_t hash[0x20]) {
    mbedtls_sha256((const uint8_t*)exheader, 0x400, hash, 0);
}

void ncch_fix_exheader_hash(NCCHContext *context) {
    uint8_t hash[0x20];
    ncch_exheader_get_hash(&context->exheader, hash);
    memcpy(context->header.extended_header_hash, hash, 0x20);
}

static void get_counter(NCCHHeader *ncch, uint8_t counter[16], uint8_t type, uint64_t offset) {
    memset(counter, 0, 16);
    if (ncch->version == 2 || ncch->version == 0) {
        *(uint64_t*)counter = BE64(ncch->partition_id);
        counter[8] = type;
    } else if (ncch->version == 1) {
        uint64_t x;
        *(uint64_t*)counter = ncch->partition_id;
        switch (type) {
        case NCCHTYPE_EXHEADER:
            x = 0x200ULL;
            break;
        case NCCHTYPE_EXEFS:
            x = (uint64_t)ncch->exefs_offset * MEDIA_UNIT_SIZE;
            break;
        case NCCHTYPE_ROMFS:
            x = (uint64_t)ncch->romfs_offset * MEDIA_UNIT_SIZE;
            break;
        case NCCHTYPE_LOGO:
            x = (uint64_t)ncch->logo_offset * MEDIA_UNIT_SIZE;
            break;
        case NCCHTYPE_PLAINRGN:
            x = (uint64_t)ncch->plain_region_offset * MEDIA_UNIT_SIZE;
            break;
        }
        *(uint64_t*)(counter + 8) = BE64(x);
    }
    if (offset)
        *(uint64_t*)(counter + 8) = BE64(BE64(*(uint64_t*)(counter + 8)) + offset / 0x10);
}

void ncch_crypt_part(NCCHContext *ncch, uint8_t type, uint64_t offset, void *data, size_t size) {
    if (!ncch->encrypted) return;
    uint8_t counter[16];
    mbedtls_aes_context cont;
    size_t nc_off = 0;
    uint8_t stream_block[16];
    get_counter(&ncch->header, counter, type, offset);
    mbedtls_aes_init(&cont);
    mbedtls_aes_setkey_enc(&cont, ncch->key_y, 128);
    mbedtls_aes_crypt_ctr(&cont, size, &nc_off, counter, stream_block, (const uint8_t*)data, (uint8_t*)data);
    mbedtls_aes_free(&cont);
}
