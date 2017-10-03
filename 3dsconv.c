#define PROGRAM_VERSION "1.0"

#include "crypto/aes.h"
#include "crypto/sha256.h"

#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include "data.inl"

#include "uint128.h"

#define BE32(n) __builtin_bswap32(n)
#define BE64(n) __builtin_bswap64(n)
#define BE16(n) __builtin_bswap16(n)

size_t unhexlify(const char *input, uint8_t *output) {
#define HEX_PROC(n, ch) \
    if (n == 0) break; \
    if (n >= '0' && n <= '9') \
        ch = n - '0'; \
    else if (n >= 'A' && n <= 'F') \
        ch = n - 'A' + 10; \
    else if (n >= 'a' && n <= 'f') \
        ch = n - 'a' + 10; \
    else break;

    uint8_t *output_org = output;
    while(1) {
        uint8_t ch1, ch2;
        HEX_PROC(input[0], ch1);
        HEX_PROC(input[1], ch2);
        *output++ = (ch1 << 4) | ch2;
        input += 2;
    }
    return output - output_org;
}

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

void showhelp() {
    fprintf(stderr, "\
Convert Nintendo 3DS CCI (.3ds/.cci) to CIA\n\
https://github.com/soarqin/3dsconv\n\
\n\
Usage: {} [options] <game> [<game>...]\n\
\n\
Options:\n\
  --output=<dir>       - Save converted files in specified directory\n\
                           Default: .\n\
  --overwrite          - Overwrite existing converted files\n\
  --ignore-bad-hashes  - Ignore invalid hashes and CCI files and convert anyway\n\
  --verbose            - Print more information\n\
}\n");
}

static const size_t mu = 0x200;  // media unit
static const size_t read_size = 0x800000;  // used from padxorer
static const uint32_t zerokey[0x10] = {};
int verbose = 0;

void print_v(const char *fmt, ...) {
    if (!verbose) return;
    va_list arglist;
    va_start(arglist, fmt);
    vfprintf(stderr, fmt, arglist);
    va_end(arglist);
    fprintf(stderr, "\n");
}

void show_progress(size_t val, size_t maxval) {
    uint32_t minval = val < maxval ? val : maxval;
    fprintf(stdout, "\r  %5.1f%% %12" PRIu64 " / %-12" PRIu64, 100. * minval / maxval, (uint64_t)minval, (uint64_t)maxval);
}

int overwrite = 0;
int no_convert = 0;
int ignore_bad_hashes = 0;
char output_directory[512] = "";

int total_files = 0;
int allocated_files = 0;
int processed_files = 0;
char **files = NULL;

uint128 orig_ncch_key;

struct arg_struct {
    int type;
    const char *name;
    void *var;
} args_to_check[] = {
    {0, "--verbose", &verbose},
    {0, "--overwrite", &overwrite},
    {0, "--no-convert", &no_convert},
    {0, "--noconvert", &no_convert},
    {0, "--ignore-bad-hashes", &ignore_bad_hashes},
    {1, "--output", output_directory},
    {0, NULL}
};

void parse_args(int argc, char *argv[]) {
    int i;
    for(i = 1; i < argc; ++i) {
        struct arg_struct *s;
        char *arg = argv[i];
        if (arg[0] == '-' && arg[1] == '-') {
            char *n = strchr(arg, '=');
            const char *value = NULL;
            if (n != NULL) {
                value = n + 1;
                *n = 0;
            }
            for (s = args_to_check; s->name != NULL; ++s) {
                if(strcmp(arg, s->name) == 0) {
                    switch(s->type) {
                    case 0:
                        *(int*)s->var = value == NULL ? 1 : atoi(value);
                        break;
                    case 1:
                        strcpy((char*)s->var, value);
                        break;
                    }
                }
            }
        } else {
            if (total_files >= allocated_files) {
                allocated_files += 16;
                files = (char**)realloc(files, allocated_files * sizeof(char*));
            }
            files[total_files++] = strdup(arg);
        }
    }
}

void cleanup() {
    int i;
    for (i = 0; i < total_files; ++i) {
        free(files[i]);
    }
    free(files);
    total_files = 0;
    allocated_files = 0;
}

void set_keys() {
    orig_ncch_key.lowpart = 0x1F76A94DE934C053ULL;
    orig_ncch_key.highpart = 0xB98E95CECA3E4D17ULL;
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

void do_convert(const char *rom_file, const char *cia_file) {
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
    uint8_t extheader[0x400], ncch_header[0x200];
    uint8_t sha256sum[0x20], sha256sum2[0x20];
    uint8_t dependency_list[0x180], save_size[4];
    uint32_t exefs_offset;
    uint8_t exefs_file_header[0x40];
    uint8_t exefs_icon[0x36C0];
    int header_num;
    int exefs_icon_found = 0;
    uint32_t tmd_padding, content_count, tmd_size, content_index;
    uint8_t chunk_records[0x90];
    struct chunk_record *crec;
    char sha256sum_str[0x41];
    FILE *cia;
    FILE *rom = fopen(rom_file, "rb");
    if (rom == NULL) {
        fprintf(stderr, "Error: input file %s not found\n", rom_file);
        return;
    }
    print_v("----------\nProcessing %s...", rom_file);
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
    print_v("\nTitle ID: %s", title_id_hex);

    //get partition sizes
    fseek(rom, 0x120, SEEK_SET);

    //find Game Executable CXI
    fread(&readtmp, 4, 1, rom);
    fread(&readtmp2, 4, 1, rom);
    game_cxi_offset = mu * readtmp;
    game_cxi_size = mu * readtmp2;
    print_v("\nGame Executable CXI Size: %X", game_cxi_size);

    // find Manual CFA
    fread(&readtmp, 4, 1, rom);
    fread(&readtmp2, 4, 1, rom);
    manual_cfa_offset = mu * readtmp;
    manual_cfa_size = mu * readtmp2;
    print_v("Manual CFA Size: %X", manual_cfa_size);

    // find Download Play child CFA
    fread(&readtmp, 4, 1, rom);
    fread(&readtmp2, 4, 1, rom);
    dlpchild_cfa_offset = mu * readtmp;
    dlpchild_cfa_size = mu * readtmp2;
    print_v("Download Play child CFA Size: %X\n", dlpchild_cfa_size);

    fseek(rom, game_cxi_offset + 0x100, SEEK_SET);
    fread(magic, 1, 4, rom);
    if (memcmp(magic, "NCCH", 4) != 0) {
        fprintf(stderr, "Error: \"%s\" is not a CCI file (missing NCCH magic).\n", rom_file);
        fclose(rom);
        return;
    }
    fseek(rom, game_cxi_offset + 0x18F, SEEK_SET);
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
            fseek(rom, game_cxi_offset, SEEK_SET);
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
            print_v("Normal key: %s", keystr);
        }
    }

    fprintf(stdout, "Converting \"%s\" (%s)...\n", rom_file, zerokey_encrypted ? "zerokey encrypted" : encrypted ? "decrypted" : "encrypted");

    // Game Executable fist-half ExtHeader
    print_v("\nVerifying ExtHeader...");
    fseek(rom, game_cxi_offset + 0x200, SEEK_SET);
    fread(extheader, 1, 0x400, rom);
    if (encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16];
        print_v("Decrypting ExtHeader...");
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, key, 128);
        memcpy(counter, ctr_extheader_v, 16);
        mbedtls_aes_crypt_ctr(&cont, 0x400, &nc_off, counter, stream_block, extheader, extheader);
    }
    mbedtls_sha256(extheader, 0x400, sha256sum, 0);
    fseek(rom, 0x4160, SEEK_SET);
    fread(sha256sum2, 1, 0x20, rom);
    if (memcmp(sha256sum, sha256sum2, 0x20) != 0) {
        fprintf(stderr, "Error: This file may be corrupt (invalid ExtHeader hash).\n");
        if (ignore_bad_hashes)
            fprintf(stderr, "Converting anyway because --ignore-bad-hashes was passed.\n");
        else {
            fclose(rom);
            return;
        }
    }

    // patch ExtHeader to make an SD title
    print_v("Patching ExtHeader...");
    extheader[0xD] |= 2;
    mbedtls_sha256(extheader, 0x400, sha256sum, 0);

    // get dependency list for meta region
    memcpy(dependency_list, extheader + 0x40, 0x180);

    // get save data size for tmd
    memcpy(save_size, extheader + 0x1C0, 4);

    if (encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16];
        print_v("Re-encrypting ExtHeader...");
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, key, 128);
        memcpy(counter, ctr_extheader_v, 16);
        mbedtls_aes_crypt_ctr(&cont, 0x400, &nc_off, counter, stream_block, extheader, extheader);
    }

    // Game Executable NCCH Header
    print_v("\nReading NCCH Header of Game Executable...");
    fseek(rom, game_cxi_offset, SEEK_SET);
    fread(ncch_header, 1, 0x200, rom);
    memcpy(ncch_header + 0x160, sha256sum, 0x20);

    // get icon from ExeFS
    print_v("Getting SMDH...");
    exefs_offset = *(uint32_t*)(ncch_header + 0x1A0) * mu;
    fseek(rom, game_cxi_offset + exefs_offset, SEEK_SET);
    // exefs can contain up to 10 file headers but only 4 are used normally
    fread(exefs_file_header, 1, 0x40, rom);
    if (encrypted) {
        mbedtls_aes_context cont;
        size_t nc_off = 0;
        uint8_t stream_block[16];
        uint8_t counter[16];
        print_v("Decrypting ExeFS Header...");
        mbedtls_aes_init(&cont);
        mbedtls_aes_setkey_enc(&cont, key, 128);
        memcpy(counter, ctr_exefs_v, 16);
        mbedtls_aes_crypt_ctr(&cont, 0x40, &nc_off, counter, stream_block, exefs_file_header, exefs_file_header);
    }
    for (header_num = 0; header_num < 4; ++header_num) {
        if (memcmp(exefs_file_header + header_num * 0x10, "icon\0\0\0\0", 8) == 0) {
            uint32_t exefs_icon_offset = *(uint32_t*)(exefs_file_header + 0x8 + (header_num * 0x10));
            fseek(rom, exefs_icon_offset + 0x200 - 0x40, SEEK_CUR);
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

    print_v("Writing CIA header...");
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
    fwrite(save_size, 1, 4, cia);

    // Game Executable CXI NCCH Header + first-half ExHeader
    fseek(cia, 0, SEEK_END);
    fwrite(ncch_header, 1, 0x200, cia);
    fwrite(extheader, 1, 0x400, cia);

    {
        size_t cr_offset = 0;
        size_t left;
        uint8_t *dataread;
        mbedtls_sha256_context ctx;

        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, ncch_header, 0x200);
        mbedtls_sha256_update(&ctx, extheader, 0x400);

        //Game Executable CXI second-half ExHeader + contents
        fprintf(stdout, "Writing Game Executable CXI...\n");
        fseek(rom, game_cxi_offset + 0x200 + 0x400, SEEK_SET);
        left = game_cxi_size - 0x200 - 0x400;
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
        print_v("Game Executable CXI SHA-256 hash:");
        hexlify(sha256sum, 0x20, sha256sum_str, 1);
        print_v("  %s", sha256sum_str);
        fseek(cia, 0x38D4, SEEK_SET);
        fwrite(sha256sum, 1, 0x20, cia);
        memcpy(chunk_records + 0x10, sha256sum, 0x20);

        // Manual CFA
        if (manual_cfa_offset != 0) {
            fseek(cia, 0, SEEK_END);
            fprintf(stdout, "Writing Manual CFA...\n");
            fseek(rom, manual_cfa_offset, SEEK_SET);
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
            print_v("Manual CFA SHA-256 hash:");
            hexlify(sha256sum, 0x20, sha256sum_str, 1);
            print_v("  %s", sha256sum_str);
            fseek(cia, 0x3904, SEEK_SET);
            fwrite(sha256sum, 1, 0x20, cia);
            memcpy(chunk_records + 0x40, sha256sum, 0x20);
            cr_offset += 0x30;
        }

        // Download Play child container CFA
        if (dlpchild_cfa_offset != 0) {
            fseek(cia, 0, SEEK_END);
            fprintf(stdout, "Writing Download Play child container CFA...\n");
            fseek(rom, dlpchild_cfa_offset, SEEK_SET);
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
            print_v("- Download Play child container CFA SHA-256 hash:");
            hexlify(sha256sum, 0x20, sha256sum_str, 1);
            print_v("  %s", sha256sum_str);
            fseek(cia, 0x3904 + cr_offset, SEEK_SET);
            fwrite(sha256sum, 1, 0x20, cia);
            memcpy(chunk_records + 0x40 + cr_offset, sha256sum, 0x20);
        }
        free(dataread);
    }
    // update final hashes
    print_v("\nUpdating hashes...");
    mbedtls_sha256(chunk_records, (uint8_t*)crec - chunk_records, sha256sum, 0);
    print_v("Content chunk records SHA-256 hash:");
    hexlify(sha256sum, 0x20, sha256sum_str, 1);
    print_v("  %s", sha256sum_str);
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
        print_v("Content info records SHA-256 hash:");
        hexlify(sha256sum, 0x20, sha256sum_str, 1);
        print_v("  %s", sha256sum_str);
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

    fprintf(stdout, "Done converting %u out of %u files.", ++processed_files, total_files);

    fclose(cia);
    fclose(rom);
}

#ifdef _WIN32
#include <direct.h>
#define mkdir(d, p) _mkdir(d)
#define is_slash(d) (((d) == '/') || ((d) == '\\'))
#define slash_char '\\'
#else
#define is_slash(d) ((d) == '/')
#define slash_char '/'
#endif

static void makedirs(const char *dir) {
    char tmp[512];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", dir);
    len = strlen(tmp);
    if(is_slash(tmp[len - 1]))
        tmp[len - 1] = 0;
    for(p = tmp + 1; *p; p++)
        if(is_slash(*p)) {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = slash_char;
        }
    mkdir(tmp, S_IRWXU);
}

int main(int argc, char *argv[]) {
    int i;

    fprintf(stderr, "3dsconv %s\n", PROGRAM_VERSION);
    parse_args(argc, argv);

    if (total_files == 0 || files == NULL) {
        fprintf(stderr, "Error: No files were given\n");
        exit(1);
    }

    set_keys();

    if (output_directory[0] != 0) {
        size_t l = strlen(output_directory);
        if (!is_slash(output_directory[l - 1])) {
            output_directory[l] = slash_char;
            output_directory[l + 1] = 0;
        }
        makedirs(output_directory);
    }

    for (i = 0; i < total_files; ++i) {
        char cia_file[512];
        if (output_directory[0] != 0) {
            const char *t1 = strrchr(files[i], '/');
            if ('/' != slash_char) {
                const char *t2 = strrchr(files[i], slash_char);
                if (t2 > t1) t1 = t2;
            }
            strcpy(cia_file, output_directory);
            strcat(cia_file, t1 = NULL ? files[i] : t1);
        } else {
            strcpy(cia_file, files[i]);
        }
        char *r = strrchr(cia_file, '.');
        if (r == NULL) strcat(cia_file, ".cia");
        else strcpy(r, ".cia");
        if (!overwrite) {
            FILE *check = fopen(cia_file, "rb");
            if (check != NULL) {
                fclose(check);
                fprintf(stderr, "\"%s\" already exists. Use `--overwrite' to force conversion.\n", cia_file);
                continue;
            }
        }
        do_convert(files[i], cia_file);
    }

    cleanup();
    return 0;
}
