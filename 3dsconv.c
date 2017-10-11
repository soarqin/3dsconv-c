#include "3dsconv.h"

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#define __builtin_bswap16 _byteswap_ushort
#define __builtin_bswap32 _byteswap_ulong
#define __builtin_bswap64 _byteswap_uint64
#endif

#include "crypto/aes.h"
#include "crypto/sha256.h"

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "data.inl"

#include "uint128.h"

#define BE32(n) (uint32_t)__builtin_bswap32((unsigned long)n)
#define BE64(n) __builtin_bswap64(n)
#define BE16(n) __builtin_bswap16(n)

void hexlify(const uint8_t *input, size_t len, char *output, int upper) {
    size_t i;
    for (i = 0; i < len; ++i) {
        uint8_t n1 = input[i];
        uint8_t n2 = n1 & 0x0F;
        n1 >>= 4;
        *output++ = (n1 > 9) ? ((upper ? 'A' : 'a') - 10 + n1) : ('0' + n1);
        *output++ = (n2 > 9) ? ((upper ? 'A' : 'a') - 10 + n2) : ('0' + n2);
    }
    *output = 0;
}

void int128_to_key(uint128 *n, uint8_t *key) {
    int i;
    for(i = 56; i >= 0; i -= 8) {
        *key++ = (uint8_t)(n->highpart >> i);
    }
    for(i = 56; i >= 0; i -= 8) {
        *key++ = (uint8_t)(n->lowpart >> i);
    }
}

void show_progress(size_t val, size_t maxval) {
    size_t minval = val < maxval ? val : maxval;
    fprintf(stdout, "\r  %5.1f%% %12" PRIu64 " / %-12" PRIu64, 100. * minval / maxval, (uint64_t)minval, (uint64_t)maxval);
}

struct chunk_record {
    uint32_t id, index, pad, size;
    uint8_t sha256sum[0x20];
};

void write8(FILE *f, uint8_t n) {
    fwrite(&n, 1, 1, f);
}

void write16(FILE *f, uint16_t n) {
    fwrite(&n, 2, 1, f);
}

void write32(FILE *f, uint32_t n) {
    fwrite(&n, 4, 1, f);
}

void write64(FILE *f, uint64_t n) {
    fwrite(&n, 8, 1, f);
}

void write16be(FILE *f, uint16_t n) {
    n = BE16(n);
    fwrite(&n, 2, 1, f);
}

void write32be(FILE *f, uint32_t n) {
    n = BE32(n);
    fwrite(&n, 4, 1, f);
}

void write64be(FILE *f, uint64_t n) {
    n = BE64(n);
    fwrite(&n, 8, 1, f);
}

void writepad(FILE *f, size_t size) {
    void *data = calloc(1, size);
    fwrite(data, 1, size, f);
    free(data);
}

void convert_3ds(const char *rom_file, const char *cia_file, options *opt) {
    const uint128 orig_ncch_key = {0x1F76A94DE934C053ULL, 0xB98E95CECA3E4D17ULL};
    const size_t mu = 0x200;  // media unit
    const size_t read_size = 0x800000;  // used from padxorer
    const uint32_t zerokey[0x10] = {0};
    char magic[4];
    uint8_t title_id[8];
    char title_id_hex[17];
    size_t game_cxi_offset, game_cxi_size, manual_cfa_offset, manual_cfa_size;
    size_t dlpchild_cfa_offset, dlpchild_cfa_size, content_size;
    uint32_t readtmp, readtmp2;
    int encrypted, zerokey_encrypted;
    uint8_t ctr_extheader_v[16] = {0};
    uint8_t ctr_exefs_v[16] = {0};
    uint8_t key[16];
    uint8_t extheader[0x800], ncch_header[0x200];
    uint8_t sha256sum[0x20], sha256sum2[0x20];
    uint8_t dependency_list[0x180], save_size[8];
    size_t exefs_offset;
    uint8_t exefs_file_header[0x40];
    uint8_t exefs_icon[0x36C0];
    int header_num;
    int exefs_icon_found = 0;
    uint32_t tmd_padding, content_count, tmd_size;
    uint8_t content_index;
    uint8_t chunk_records[0x90];
    struct chunk_record *crec;
    char sha256sum_str[0x41];
    FILE *cia;
    FILE *rom = fopen(rom_file, "rb");
    if (rom == NULL) {
        fprintf(stderr, "Error: input file %s not found\n", rom_file);
        return;
    }
    if (opt->verbose) fprintf(stderr, "----------\nProcessing %s...\n", rom_file);
    fseek(rom, 0x100, SEEK_SET);
    fread(magic, 1, 4, rom);
    if (memcmp(magic, "NCSD", 4) != 0) {
        fprintf(stderr, "Error: \"%s\" is not a CCI file (missing NCSD magic).\n", rom_file);
        fclose(rom);
        return;
    }
    fseek(rom, 0x108, SEEK_SET);
    fread(title_id, 1, 8, rom);
    *(uint64_t*)title_id = BE64(*(uint64_t*)title_id);
    hexlify(title_id, 8, title_id_hex, 1);
    if (opt->verbose) fprintf(stderr, "\nTitle ID: %s\n", title_id_hex);

    //get partition sizes
    fseek(rom, 0x120, SEEK_SET);

    //find Game Executable CXI
    fread(&readtmp, 4, 1, rom);
    fread(&readtmp2, 4, 1, rom);
    game_cxi_offset = mu * readtmp;
    game_cxi_size = mu * readtmp2;
    if (opt->verbose) fprintf(stderr, "\nGame Executable CXI Size: %" PRIX64 "\n", (uint64_t)game_cxi_size);

    // find Manual CFA
    fread(&readtmp, 4, 1, rom);
    fread(&readtmp2, 4, 1, rom);
    manual_cfa_offset = mu * readtmp;
    manual_cfa_size = mu * readtmp2;
    if (opt->verbose) fprintf(stderr, "Manual CFA Size: %" PRIX64 "\n", (uint64_t)manual_cfa_size);

    // find Download Play child CFA
    fread(&readtmp, 4, 1, rom);
    fread(&readtmp2, 4, 1, rom);
    dlpchild_cfa_offset = mu * readtmp;
    dlpchild_cfa_size = mu * readtmp2;
    if (opt->verbose) fprintf(stderr, "Download Play child CFA Size: %" PRIX64 "\n\n", (uint64_t)dlpchild_cfa_size);

    fseek(rom, (long)(game_cxi_offset + 0x100), SEEK_SET);
    fread(magic, 1, 4, rom);
    if (memcmp(magic, "NCCH", 4) != 0) {
        fprintf(stderr, "Error: \"%s\" is not a CCI file (missing NCCH magic).\n", rom_file);
        fclose(rom);
        return;
    }
    fseek(rom, (long)(game_cxi_offset + 0x18F), SEEK_SET);
    uint8_t encryption_bitmask;
    fread(&encryption_bitmask, 1, 1, rom);
    encrypted = (encryption_bitmask & 0x4) == 0;
    zerokey_encrypted = (encryption_bitmask & 0x1) != 0;
    if (encrypted) {
        memcpy(ctr_extheader_v, title_id, 8);
        ctr_extheader_v[8] = 1;
        memcpy(ctr_exefs_v, title_id, 8);
        ctr_exefs_v[8] = 2;
        if (zerokey_encrypted)
            memcpy(key, zerokey, 16);
        else {
            uint128 key_y, key_, tmp;
            char keystr[33];
            fseek(rom, (long)game_cxi_offset, SEEK_SET);
            fread(&key_y, 16, 1, rom);
            uint128_bswap(&key_y);
            key_ = orig_ncch_key;
            uint128_rol(&key_, 2);
            uint128_xor(&key_, &key_y);
            tmp.lowpart = 0x024591DC5D52768A;
            tmp.highpart = 0x1FF9E9AAC5FE0408;
            uint128_add(&key_, &tmp);
            uint128_rol(&key_, 87);
            // key_ = ROL128((ROL128(orig_ncch_key, 2) ^ key_y) + ((unsigned __int128)0x1FF9E9AAC5FE0408 << 64) + (unsigned __int128)0x024591DC5D52768A, 87);
            int128_to_key(&key_, key);
            hexlify(key, 16, keystr, 1);
            if (opt->verbose) fprintf(stderr, "Normal key: %s\n", keystr);
        }
    }

    fprintf(stdout, "Converting \"%s\" (%s)...\n", rom_file, zerokey_encrypted ? "zerokey encrypted" : (encrypted ? "encrypted" : "decrypted"));

    // Game Executable fist-half ExtHeader
    if (opt->verbose) fprintf(stderr, "\nVerifying ExtHeader...\n");
    fseek(rom, (long)(game_cxi_offset + 0x200), SEEK_SET);
    fread(extheader, 1, 0x800, rom);
    if (encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16];
        if (opt->verbose) fprintf(stderr, "Decrypting ExtHeader...\n");
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, key, 128);
        memcpy(counter, ctr_extheader_v, 16);
        mbedtls_aes_crypt_ctr(&cont, 0x800, &nc_off, counter, stream_block, extheader, extheader);
    }
    mbedtls_sha256(extheader, 0x400, sha256sum, 0);
    fseek(rom, 0x4160, SEEK_SET);
    fread(sha256sum2, 1, 0x20, rom);
    if (memcmp(sha256sum, sha256sum2, 0x20) != 0) {
        fprintf(stderr, "Error: This file may be corrupt (invalid ExtHeader hash).\n");
        if (opt->ignore_bad_hashes)
            fprintf(stderr, "Converting anyway because --ignore-bad-hashes was passed.\n");
        else {
            fclose(rom);
            return;
        }
    }
    if (!opt->no_firmware_spoof) {
        // Kernel version spoof
        //   when highest 12bit is 0b1111110xxxxx: Bits 8-15: Major version; Bits 0-7: Minor version
        uint32_t i;
        for (i = 0; i < 28; ++i) {
            uint32_t desc = *(uint32_t*)(extheader + 0x370 + i * 4);
            if (desc >> 25 == 0x7E) {
                if ((desc & 0xFFFFu) <= 0x221) break;
                if (opt->verbose) fprintf(stderr, "Spoofing kernel version(original: %08X) in 1st-half ExtHeader...\n", desc);
                desc = (desc & ~0xFFFFu) | 0x220;
                *(uint32_t*)(extheader + 0x370 + i * 4) = desc;
                break;
            }
        }
        for (i = 0; i < 28; ++i) {
            uint32_t desc = *(uint32_t*)(extheader + 0x770 + i * 4);
            if (desc >> 25 == 0x7E) {
                if ((desc & 0xFFFFu) <= 0x221) break;
                if (opt->verbose) fprintf(stderr, "Spoofing kernel version(original: %08X) in 2nd-half ExtHeader...\n", desc);
                desc = (desc & ~0xFFFFu) | 0x220;
                *(uint32_t*)(extheader + 0x770 + i * 4) = desc;
                break;
            }
        }
    }

    // patch ExtHeader to make an SD title
    if (opt->verbose) fprintf(stderr, "Patching ExtHeader...\n");
    extheader[0xD] |= 2;
    mbedtls_sha256(extheader, 0x400, sha256sum, 0);

    // get dependency list for meta region
    memcpy(dependency_list, extheader + 0x40, 0x180);

    // get save data size for tmd
    memcpy(save_size, extheader + 0x1C0, 8);

    if (encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16];
        if (opt->verbose) fprintf(stderr, "Re-encrypting ExtHeader...\n");
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, key, 128);
        memcpy(counter, ctr_extheader_v, 16);
        mbedtls_aes_crypt_ctr(&cont, 0x800, &nc_off, counter, stream_block, extheader, extheader);
    }

    // Game Executable NCCH Header
    if (opt->verbose) fprintf(stderr, "\nReading NCCH Header of Game Executable...\n");
    fseek(rom, (long)game_cxi_offset, SEEK_SET);
    fread(ncch_header, 1, 0x200, rom);
    memcpy(ncch_header + 0x160, sha256sum, 0x20);

    // get icon from ExeFS
    if (opt->verbose) fprintf(stderr, "Getting SMDH...\n");
    exefs_offset = *(uint32_t*)(ncch_header + 0x1A0) * mu;
    fseek(rom, (long)(game_cxi_offset + exefs_offset), SEEK_SET);
    // exefs can contain up to 10 file headers but only 4 are used normally
    fread(exefs_file_header, 1, 0x40, rom);
    if (encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16];
        if (opt->verbose) fprintf(stderr, "Decrypting ExeFS Header...\n");
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, key, 128);
        memcpy(counter, ctr_exefs_v, 16);
        mbedtls_aes_crypt_ctr(&cont, 0x40, &nc_off, counter, stream_block, exefs_file_header, exefs_file_header);
    }
    for (header_num = 0; header_num < 4; ++header_num) {
        if (memcmp(exefs_file_header + header_num * 0x10, "icon\0\0\0\0", 8) == 0) {
            uint32_t exefs_icon_offset = *(uint32_t*)(exefs_file_header + 0x8 + (header_num * 0x10));
            fseek(rom, (long)(exefs_icon_offset + 0x200 - 0x40), SEEK_CUR);
            fread(exefs_icon, 1, 0x36C0, rom);
            if (encrypted) {
		        mbedtls_aes_context cont;
		        size_t nc_off = 0;
		        uint8_t stream_block[16];
		        uint8_t ctr_exefs_icon_v[16];
                memcpy(ctr_exefs_icon_v, ctr_exefs_v, 16);
                *(uint64_t*)(ctr_exefs_icon_v + 8) = BE64(
                	BE64(*(uint64_t*)(ctr_exefs_icon_v + 8)) + (exefs_icon_offset / 0x10) + 0x20
                	);
		        mbedtls_aes_init(&cont);
		        mbedtls_aes_setkey_enc(&cont, key, 128);
		        mbedtls_aes_crypt_ctr(&cont, 0x36C0, &nc_off, ctr_exefs_icon_v, stream_block, exefs_icon, exefs_icon);
            }
            exefs_icon_found = 1;
            break;
        }
    }
    if (!exefs_icon_found) {
        fprintf(stderr, "Icon not found in the ExeFS.\n");
        fclose(rom);
        return;
    }
    /* since we will only have three possible results to these, these are
         hardcoded variables for convenience
       these could be generated but given this, I'm not doing that
       I made it a little better */
    tmd_padding = 12;  // padding to add at the end of the tmd
    content_count = 1;
    tmd_size = 0xB34;
    content_index = 0b10000000;
    if (manual_cfa_offset != 0) {
        tmd_padding += 16;
        content_count += 1;
        tmd_size += 0x30;
        content_index += 0b01000000;
    }
    if (dlpchild_cfa_offset != 0) {
        tmd_padding += 16;
        content_count += 1;
        tmd_size += 0x30;
        content_index += 0b00100000;
    }
    cia = fopen(cia_file, "wb");
    if (cia == NULL) {
        fprintf(stderr, "Error: unable to write to \"%s\".\n", cia_file);
        fclose(rom);
        return;
    }

    if (opt->verbose) fprintf(stderr, "Writing CIA header...\n");
    crec = (struct chunk_record*)chunk_records;
    crec->id = 0;
    crec->index = 0;
    crec->pad = 0;
    crec->size = BE32(game_cxi_size);
    memset(crec->sha256sum, 0, 0x20);
    ++crec;
    if (manual_cfa_offset != 0) {
        // 2nd content: ID 0x1, Index 0x1
        crec->id = BE32(1);
        crec->index = BE32(0x10000);
        crec->pad = 0;
        crec->size = BE32(manual_cfa_size);
        memset(crec->sha256sum, 0, 0x20);
        ++crec;
    }
    if (dlpchild_cfa_offset != 0) {
        // 3nd content: ID 0x2, Index 0x2
        crec->id = BE32(2);
        crec->index = BE32(0x20000);
        crec->pad = 0;
        crec->size = BE32(dlpchild_cfa_size);
        memset(crec->sha256sum, 0, 0x20);
        ++crec;
    }

    content_size = game_cxi_size + manual_cfa_size + dlpchild_cfa_size;

    write32(cia, 0x2020);
    write32(cia, 0);
    write32(cia, 0xA00);
    write32(cia, 0x350);
    write32(cia, tmd_size);
    write32(cia, 0x3AC0);
    write64(cia, content_size);
    write8(cia, content_index);
    writepad(cia, 0x201F);
    fwrite(certchain_retail, 1, sizeof(certchain_retail), cia);
    fwrite(ticket_tmd, 1, sizeof(ticket_tmd), cia);
    writepad(cia, 0x96C);
    fwrite(chunk_records, 1, (uint8_t*)crec - chunk_records, cia);
    writepad(cia, tmd_padding);

    // write content count in tmd
    fseek(cia, 0x2F9F, SEEK_SET);
    write8(cia, content_count);

    // write title ID in ticket and tmd
    fseek(cia, 0x2C1C, SEEK_SET);
    fwrite(title_id, 1, 8, cia);
    fseek(cia, 0x2F4C, SEEK_SET);
    fwrite(title_id, 1, 8, cia);

    // write save size in tmd
    fseek(cia, 0x2F5A, SEEK_SET);
    fwrite(save_size, 1, 8, cia);

    // Game Executable CXI NCCH Header + ExHeader
    fseek(cia, 0, SEEK_END);
    fwrite(ncch_header, 1, 0x200, cia);
    fwrite(extheader, 1, 0x800, cia);

    {
        size_t cr_offset = 0;
        size_t left;
        uint8_t *dataread;
        mbedtls_sha256_context ctx;

        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, ncch_header, 0x200);
        mbedtls_sha256_update(&ctx, extheader, 0x800);

        //Game Executable CXI contents
        fprintf(stdout, "Writing Game Executable CXI...\n");
        fseek(rom, (long)(game_cxi_offset + 0x200 + 0x800), SEEK_SET);
        left = game_cxi_size - 0x200 - 0x800;
        dataread = (uint8_t*)malloc(read_size);
        while(left > 0) {
            size_t to_read = read_size < left ? read_size : left;
            size_t readbytes = fread(dataread, 1, to_read, rom);
            mbedtls_sha256_update(&ctx, dataread, readbytes);
            fwrite(dataread, 1, readbytes, cia);
            left -= readbytes;
            show_progress(game_cxi_size - left, game_cxi_size);
        }
        fprintf(stdout, "\n");
        mbedtls_sha256_finish(&ctx, sha256sum);
        mbedtls_sha256_free(&ctx);
        if (opt->verbose) fprintf(stderr, "Game Executable CXI SHA-256 hash:\n");
        hexlify(sha256sum, 0x20, sha256sum_str, 1);
        if (opt->verbose) fprintf(stderr, "  %s\n", sha256sum_str);
        fseek(cia, 0x38D4, SEEK_SET);
        fwrite(sha256sum, 1, 0x20, cia);
        memcpy(chunk_records + 0x10, sha256sum, 0x20);

        // Manual CFA
        if (manual_cfa_offset != 0) {
            fseek(cia, 0, SEEK_END);
            fprintf(stdout, "Writing Manual CFA...\n");
            fseek(rom, (long)manual_cfa_offset, SEEK_SET);
            left = manual_cfa_size;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_starts(&ctx, 0);
            while (left > 0) {
                size_t to_read = read_size < left ? read_size : left;
                size_t readbytes = fread(dataread, 1, to_read, rom);
                mbedtls_sha256_update(&ctx, dataread, readbytes);
                fwrite(dataread, 1, readbytes, cia);
                left -= readbytes;
                show_progress(manual_cfa_size - left, manual_cfa_size);
            }
            fprintf(stdout, "\n");
            mbedtls_sha256_finish(&ctx, sha256sum);
            mbedtls_sha256_free(&ctx);
            if (opt->verbose) fprintf(stderr, "Manual CFA SHA-256 hash:\n");
            hexlify(sha256sum, 0x20, sha256sum_str, 1);
            if (opt->verbose) fprintf(stderr, "  %s\n", sha256sum_str);
            fseek(cia, 0x3904, SEEK_SET);
            fwrite(sha256sum, 1, 0x20, cia);
            memcpy(chunk_records + 0x40, sha256sum, 0x20);
            cr_offset += 0x30;
        }

        // Download Play child container CFA
        if (dlpchild_cfa_offset != 0) {
            fseek(cia, 0, SEEK_END);
            fprintf(stdout, "Writing Download Play child container CFA...\n");
            fseek(rom, (long)dlpchild_cfa_offset, SEEK_SET);
            left = dlpchild_cfa_size;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_starts(&ctx, 0);
            while (left > 0) {
                size_t to_read = read_size < left ? read_size : left;
                size_t readbytes = fread(dataread, 1, to_read, rom);
                mbedtls_sha256_update(&ctx, dataread, readbytes);
                fwrite(dataread, 1, readbytes, cia);
                left -= readbytes;
                show_progress(dlpchild_cfa_size - left, dlpchild_cfa_size);
            }
            fprintf(stdout, "\n");
            mbedtls_sha256_finish(&ctx, sha256sum);
            mbedtls_sha256_free(&ctx);
            if (opt->verbose) fprintf(stderr, "- Download Play child container CFA SHA-256 hash:\n");
            hexlify(sha256sum, 0x20, sha256sum_str, 1);
            if (opt->verbose) fprintf(stderr, "  %s\n", sha256sum_str);
            fseek(cia, (long)(0x3904 + cr_offset), SEEK_SET);
            fwrite(sha256sum, 1, 0x20, cia);
            memcpy(chunk_records + 0x40 + cr_offset, sha256sum, 0x20);
        }
        free(dataread);
    }
    // update final hashes
    if (opt->verbose) fprintf(stderr, "\nUpdating hashes...\n");
    mbedtls_sha256(chunk_records, (uint8_t*)crec - chunk_records, sha256sum, 0);
    if (opt->verbose) fprintf(stderr, "Content chunk records SHA-256 hash:\n");
    hexlify(sha256sum, 0x20, sha256sum_str, 1);
    if (opt->verbose) fprintf(stderr, "  %s\n", sha256sum_str);
    fseek(cia, 0x2FC7, SEEK_SET);
    write8(cia, content_count);
    fwrite(sha256sum, 1, 0x20, cia);

    {
        mbedtls_sha256_context ctx;
        uint32_t cc = BE32(content_count);
        uint8_t *zerodata = (uint8_t*)calloc(1, 0x8DC);
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, (const uint8_t*)&cc, 4);
        mbedtls_sha256_update(&ctx, sha256sum, 0x20);
        mbedtls_sha256_update(&ctx, zerodata, 0x8DC);
        mbedtls_sha256_finish(&ctx, sha256sum);
        mbedtls_sha256_free(&ctx);
        if (opt->verbose) fprintf(stderr, "Content info records SHA-256 hash:\n");
        hexlify(sha256sum, 0x20, sha256sum_str, 1);
        if (opt->verbose) fprintf(stderr, "  %s\n", sha256sum_str);
        fseek(cia, 0x2FA4, SEEK_SET);
        fwrite(sha256sum, 1, 0x20, cia);
    }

    // write Meta region
    fseek(cia, 0, SEEK_END);
    fwrite(dependency_list, 1, 0x180, cia);
    writepad(cia, 0x180);
    write32(cia, 0x2);
    writepad(cia, 0xFC);
    fwrite(exefs_icon, 1, 0x36C0, cia);

    fprintf(stdout, "Done converting %s to %s.", rom_file, cia_file);

    fclose(cia);
    fclose(rom);
}
