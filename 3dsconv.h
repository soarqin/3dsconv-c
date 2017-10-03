#ifndef __3DSCONV_H_
#define __3DSCONV_H_

typedef struct {
    int verbose;
    int ignore_bad_hashes;
} options;

void convert_3ds(const char *rom_file, const char *cia_file, options *opt);

#endif // __3DSCONV_H_
