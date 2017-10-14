#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "3dsconv.h"

#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "data.inl"

#include "bn.h"

void fprint_hex(FILE *fd, const uint8_t *input, size_t len, int upper) {
    size_t i;
    for (i = 0; i < len; ++i)
        fprintf(fd, upper ? "%02X" : "%02x", input[i]);
}

void show_progress(uint32_t part, uint64_t val, uint64_t maxval) {
    if (val == 0) {
        switch (part) {
        case 0:
            fprintf(stdout, "Writing Game Executable CXI...\n");
            break;
        case 1:
            fprintf(stdout, "Writing Manual CFA...\n");
            break;
        case 2:
            fprintf(stdout, "Writing Download Play child container CFA...\n");
            break;
        }
    }
    uint64_t minval = val < maxval ? val : maxval;
    fprintf(stdout, "\r  %5.1f%% %12" PRIu64 " / %-12" PRIu64, 100. * minval / maxval, minval, maxval);
    if (val == maxval) fprintf(stdout, "\n");
}

#include "ncsd.h"
#include "cia.h"

void convert_3ds(const char *rom_file, const char *cia_file, options *opt) {
    NCSDContext ncsd;
    CIAContext cia;
    int i, result;
    ExeFSHeader exefs_header;
    uint8_t *smdh = NULL;
    uint32_t smdh_size = 0;

    if (opt->verbose) fprintf(stderr, "----------\nProcessing %s...\n", rom_file);
    result = ncsd_open(&ncsd, rom_file);
    switch (result) {
        case NCSD_FILE_NOT_FOUND:
            fprintf(stderr, "Error: input file \"%s\" not found\n", rom_file);
            return;
        case NCSD_INVALID_NCSD_HEADER:
            fprintf(stderr, "Error: \"%s\" is not a CCI file (missing NCSD magic).\n", rom_file);
            return;
        case NCSD_INVALID_NCCH_HEADER:
            fprintf(stderr, "Error: \"%s\" is not a CCI file (missing NCCH magic).\n", rom_file);
            return;
        case NCSD_WRONG_EXHEADER_HASH:
            fprintf(stderr, "Error: This file may be corrupt (invalid ExHeader hash).\n");
            if (!opt->ignore_bad_hashes)
                return;
            fprintf(stderr, "Converting anyway because --ignore-bad-hashes was passed.\n");
            break;
    }
    if (opt->verbose) {
        fprintf(stderr, "\nTitle ID: %016" PRIX64 "\n", ncsd.header.media_id);
        fprintf(stderr, "\nGame Executable CXI Size: %" PRIX64 "\n"
            "Manual CFA Size: %" PRIX64 "\n"
            "Download Play child CFA Size: %" PRIX64 "\n",
            (uint64_t)ncsd.header.partition_geometry[0].size * MEDIA_UNIT_SIZE,
            (uint64_t)ncsd.header.partition_geometry[1].size * MEDIA_UNIT_SIZE,
            (uint64_t)ncsd.header.partition_geometry[2].size * MEDIA_UNIT_SIZE);
    }
    if (ncsd.ncch.encrypted == 1 && opt->verbose) {
        fprintf(stderr, "Normal key:");
        fprint_hex(stderr, ncsd.ncch.key_y, 16, 1);
        fprintf(stderr, "\n");
    }
    fprintf(stdout, "Converting \"%s\" (%s)...\n", rom_file, ncsd.ncch.encrypted == 2 ? "zerokey encrypted" : (ncsd.ncch.encrypted == 1 ? "encrypted" : "decrypted"));

    // Spoof firmware version
    if (!opt->no_firmware_spoof) {
        uint16_t origver[2];
        ncch_exheader_spoof_version(&ncsd.ncch.exheader, 0x220, origver);
        if (opt->verbose) {
            if (origver[0] != 0)
                fprintf(stderr, "Spoofed kernel version (from %04X) in 1st-half ExHeader...\n", origver[0]);
            if (origver[1] != 0)
                fprintf(stderr, "Spoofed kernel version (from %04X) in 2nd-half ExHeader...\n", origver[1]);
        }
    }

    // Make a SD Application
    if (opt->verbose) fprintf(stderr, "Patching Extended Header...\n");
    ncsd.ncch.exheader.codeset_info.flags.flag |= 0x02;
    ncch_fix_exheader_hash(&ncsd.ncch);

    ncsd_read_exefs_header(&ncsd, &exefs_header);
    for (i = 0; i < 10; ++i) {
        if (memcmp(exefs_header.file_header[i].name, "icon\0\0\0\0", 8) == 0) {
            smdh = ncsd_decrypt_exefs_file(&ncsd, &exefs_header.file_header[i]);
            smdh_size = exefs_header.file_header[i].size;
            break;
        }
    }
    if (smdh == NULL) {
        ncsd_close(&ncsd);
        fprintf(stderr, "Error: icon/SMDH not found in the ExeFS.\n");
        return;
    }

    cia_new(&cia);
    cia_set_certchain(&cia, certchain_retail, sizeof(certchain_retail));
    cia_set_ticket(&cia, ticket_data, sizeof(ticket_data));
    cia_copy_tmd_part(&cia, tmd_data, sizeof(tmd_data));
    cia_copy_ncch_from_ncsd(&cia, &ncsd);
    cia_set_smdh(&cia, smdh, smdh_size);
    if (cia_create_file(&cia, cia_file) < 0) {
        cia_close(&cia);
        ncsd_close(&ncsd);
        fprintf(stderr, "Error: unable to write \"%s\".\n", cia_file);
        return;
    }
    cia_write_from_ncsd(&cia, &ncsd, show_progress);

    if (opt->verbose) {
        fprintf(stderr, "\nGame Executable CXI SHA-256 hash:\n  ");
        fprint_hex(stderr, cia.tmd_chunks[0].hash, 0x20, 1);
        if (ncsd.header.partition_geometry[1].size > 0) {
            fprintf(stderr, "\nManual CFA SHA-256 hash:\n  ");
            fprint_hex(stderr, cia.tmd_chunks[1].hash, 0x20, 1);
        }
        if (ncsd.header.partition_geometry[2].size > 0) {
            fprintf(stderr, "\nDownload Play child container CFA SHA-256 hash:\n  ");
            fprint_hex(stderr, cia.tmd_chunks[2].hash, 0x20, 1);
        }
        fprintf(stderr, "\nContent chunk records SHA-256 hash:\n  ");
        fprint_hex(stderr, cia.tmd_body.content_info[0].hash, 0x20, 1);
        fprintf(stderr, "\nContent info records SHA-256 hash:\n  ");
        fprint_hex(stderr, cia.tmd_body.hash, 0x20, 1);
        fprintf(stderr, "\n");
    }

    fprintf(stdout, "Done converting %s to %s.\n", rom_file, cia_file);

    cia_close(&cia);
    ncsd_close(&ncsd);
}
