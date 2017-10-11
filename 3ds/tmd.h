#ifndef __TMD_H_
#define __TMD_H_

#include <stdint.h>

#pragma pack(push, 1)

#define TMD_MAX_CONTENTS 64

typedef enum {
    TMD_RSA_2048_SHA256 = 0x00010004,
    TMD_RSA_4096_SHA256 = 0x00010003,
    TMD_RSA_2048_SHA1   = 0x00010001,
    TMD_RSA_4096_SHA1   = 0x00010000
} TMDType;

typedef struct {
    uint16_t index;
    uint16_t commandcount;
    uint8_t unk[32];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
TMDContentInfo;

typedef struct {
    uint8_t issuer[64];
    uint8_t version;
    uint8_t ca_crl_version;
    uint8_t signer_crl_version;
    uint8_t padding2;
    uint8_t system_version[8];
    uint8_t title_id[8];
    uint32_t title_type;
    uint16_t group_id;
    uint32_t savedata_size;
    uint32_t priv_savedata_size;
    uint8_t padding3[4];
    uint8_t twl_flag;
    uint8_t padding4[0x31];
    uint32_t access_rights;
    uint16_t title_version;
    uint16_t content_count;
    uint8_t boot_content[2];
    uint8_t padding5[2];
    uint8_t hash[32];
    TMDContentInfo content_info[64];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
TMDBody;

typedef struct {
    uint32_t id;
    uint16_t index;
    uint16_t type;
    uint64_t size;
    uint8_t hash[32];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
TMDContentChunk;

typedef struct {
    uint32_t signature_type;
    uint8_t signature[256];
    uint8_t padding[60];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
TMDSig2048;

typedef struct
{
    uint32_t signaturetype;
    uint8_t signature[512];
    uint8_t padding[60];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
TMDSig4096;

#pragma pack(pop)

#endif // __TMD_H_
