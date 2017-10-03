#define PROGRAM_VERSION "1.0"

#include "3dsconv.h"

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(d, p) _mkdir(d)
#define is_slash(d) (((d) == '/') || ((d) == '\\'))
#define slash_char '\\'
#else
#define is_slash(d) ((d) == '/')
#define slash_char '/'
#endif

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

struct arg_struct {
    int type;
    const char *name;
    void *var;
};

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
    options opt;
    int overwrite = 0;
    char output_directory[512] = {0};
    int total_files = 0;
    int allocated_files = 0;
    char **files = NULL;
    struct arg_struct args_to_check[] = {
        {0, "--verbose", &opt.verbose},
        {0, "--overwrite", &overwrite},
        {0, "--ignore-bad-hashes", &opt.ignore_bad_hashes},
        {1, "--output", output_directory},
        {0, NULL}
    };

    fprintf(stderr, "3dsconv %s\n", PROGRAM_VERSION);
    if (argc < 2) {
        showhelp();
        return 1;
    }

    opt.verbose = 0;
    opt.ignore_bad_hashes = 0;
    for (i = 1; i < argc; ++i) {
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
                if (strcmp(arg, s->name) == 0) {
                    switch (s->type) {
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

    if (total_files == 0 || files == NULL) {
        fprintf(stderr, "Error: No files were given\n");
        exit(1);
    }

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
            strcat(cia_file, t1 == NULL ? files[i] : t1);
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
        convert_3ds(files[i], cia_file, &opt);
    }

    for (i = 0; i < total_files; ++i) {
        free(files[i]);
    }
    free(files);
    total_files = 0;
    allocated_files = 0;
    return 0;
}
