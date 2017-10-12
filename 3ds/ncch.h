#ifndef __NCCH_H_
#define __NCCH_H_

#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
    uint8_t signature[0x100];
    uint8_t magic[4];
    uint32_t content_size;
    uint64_t title_id;
    uint16_t maker_code;
    uint16_t version;
    uint32_t seed_check;
    uint64_t program_id;
    uint8_t reserved1[0x10];
    uint8_t logohash[0x20];
    uint8_t product_code[0x10];
    uint8_t extended_header_hash[0x20];
    uint8_t extended_header_size[4];
    uint8_t reserved2[4];
    uint8_t flags[8];
    uint32_t plain_region_offset;
    uint32_t plain_region_size;
    uint32_t logo_offset;
    uint32_t logo_size;
    uint32_t exefs_offset;
    uint32_t exefs_size;
    uint32_t exefs_hash_region_size;
    uint32_t reserved4;
    uint32_t romfs_offset;
    uint32_t romfs_size;
    uint32_t romfs_hash_region_size;
    uint32_t reserved5;
    uint8_t exefs_superblock_hash[0x20];
    uint8_t romfs_superblock_hash[0x20];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
NCCHHeader;

typedef enum {
    sysmode_64MB,
    sysmode_UNK,
    sysmode_96MB,
    sysmode_80MB,
    sysmode_72MB,
    sysmode_32MB,
} ExHeaderSystemMode;

typedef enum {
    sysmode_ext_LEGACY,
    sysmode_ext_124MB,
    sysmode_ext_178MB,
} ExHeaderSystemModeExt;

typedef struct {
    uint8_t reserved[5];
    uint8_t flag;
    uint16_t remaster_version;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderSystemInfoFlags;

typedef struct {
    uint32_t address;
    uint32_t nummaxpages;
    uint32_t codesize;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderCodeSegmentInfo;

typedef struct {
    uint8_t name[8];
    ExHeaderSystemInfoFlags flags;
    ExHeaderCodeSegmentInfo text;
    uint32_t stacksize;
    ExHeaderCodeSegmentInfo ro;
    uint32_t reserved;
    ExHeaderCodeSegmentInfo data;
    uint32_t bsssize;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderCodeSetInfo;

typedef struct {
    uint64_t program_id[0x30];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderDependencyList;

typedef struct {
    uint64_t savedata_size;
    uint64_t jump_id;
    uint8_t reserved2[0x30];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderSystemInfo;

typedef struct {
    uint64_t ext_savedata_id;
    uint64_t system_savedata_id;
    uint8_t accessible_unique_ids[8];
    uint8_t access_info[7];
    uint8_t other_attributes;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderStorageInfo;

typedef struct
{
    uint64_t program_id;
    uint32_t core_version;
    uint32_t flag;
    uint8_t resource_limit_descriptor[0x10][2];
    ExHeaderStorageInfo storage_info;
    uint8_t service_access_control[34][8];
    uint8_t reserved[0xf];
    uint8_t resource_limit_category;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderARM11SystemLocalCaps;

typedef struct {
    uint64_t program_id;
    uint32_t core_version;

    // flag
    uint8_t enable_l2_cache;
    uint8_t new3ds_cpu_speed;
    uint8_t new3ds_systemmode;
    uint8_t ideal_processor;
    uint8_t affinity_mask;
    uint8_t old3ds_systemmode;
    int8_t priority;

    // storageinfo
    uint64_t extdata_id;
    uint32_t other_user_saveid[3];
    uint8_t use_other_variation_savedata;
    uint32_t accessible_saveid[6];
    uint32_t system_saveid[2];
    uint64_t access_info;


    char service_access_control[34][10];
    uint8_t resource_limit_category;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderARM11SystemLocalCapsDeserialised;

typedef struct {
    uint32_t descriptors[28];
    uint8_t reserved[0x10];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderARM11KernelCapabilities;

typedef struct {
    uint8_t descriptors[15];
    uint8_t desc_version;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeaderARM9AccessControl;

typedef struct {
    // systemcontrol info {
    //   coreinfo {
    ExHeaderCodeSetInfo codeset_info;
    ExHeaderDependencyList dep_list;
    //   }
    ExHeaderSystemInfo system_info;
    // }
    // accesscontrolinfo {
    ExHeaderARM11SystemLocalCaps arm11_system_local_caps;
    ExHeaderARM11KernelCapabilities arm11_kernel_caps;
    ExHeaderARM9AccessControl arm9_access_control;
    // }
    struct {
        uint8_t signature[0x100];
        uint8_t ncch_pubkey_modulus[0x100];
        ExHeaderARM11SystemLocalCaps arm11_system_local_caps;
        ExHeaderARM11KernelCapabilities arm11_kernel_caps;
        ExHeaderARM9AccessControl arm9_access_control;
    } access_desc;
}
#ifdef __GNUC__
__attribute__((packed))
#endif
ExHeader;

void ncch_exheader_spoof_version(ExHeader *exheader, uint16_t targetver, uint16_t origver[2]);
void ncch_exheader_get_hash(ExHeader *exheader, uint8_t hash[0x20]);
void ncch_fix_exheader_hash(NCCHHeader *ncch, ExHeader *exheader);

#pragma pack(pop)

#endif // __NCCH_H_
