#include "ncch.h"

#include "mbedtls/sha256.h"

#include <memory.h>

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

void ncch_fix_exheader_hash(NCCHHeader *ncch, ExHeader *exheader) {
    uint8_t hash[0x20];
    ncch_exheader_get_hash(exheader, hash);
    memcpy(ncch->extended_header_hash, hash, 0x20);
}
