#ifndef __UINT128_H_
#define __UINT128_H_

typedef struct uint128 {
    uint64_t lowpart, highpart;
} uint128;

void uint128_bswap(uint128 *n) {
    uint64_t v = __builtin_bswap64(n->highpart);
    n->highpart = __builtin_bswap64(n->lowpart);
    n->lowpart = v;
}

void uint128_xor(uint128 *n, uint128 *n2) {
    n->lowpart ^= n2->lowpart;
    n->highpart ^= n2->highpart;
}

void uint128_lshift(uint128 *n, size_t shift) {
    if(shift >= 128) {
        n->lowpart = n->highpart = 0;
        return;
    }
    if(shift >= 64) {
        n->highpart = n->lowpart << (shift - 64);
        n->lowpart = 0;
        return;
    }
    n->highpart = (n->highpart << shift) | (n->lowpart >> (64 - shift));
    n->lowpart <<= shift;
}

void uint128_rshift(uint128 *n, size_t shift) {
    if(shift >= 128) {
        n->lowpart = n->highpart = 0;
        return;
    }
    if(shift >= 64) {
        n->lowpart = n->highpart >> (shift - 64);
        n->highpart = 0;
        return;
    }
    n->lowpart = (n->lowpart >> shift) | (n->highpart << (64 - shift));
    n->highpart >>= shift;
}

void uint128_add(uint128 *n, uint128 *n2) {
    n->highpart += n2->highpart;
    if (n2->lowpart > 0xFFFFFFFFFFFFFFFFULL - n->lowpart)
        ++n->highpart;
    n->lowpart += n2->lowpart;
}

void uint128_rol(uint128 *n, size_t bits) {
    bits &= 0x7F;
    uint128 n2 = *n;
    uint128_lshift(n, bits);
    uint128_rshift(&n2, 128 - bits);
    n->lowpart |= n2.lowpart;
    n->highpart |= n2.highpart;
}

void uint128_print(uint128 *n) {
    fprintf(stderr, "%016" PRIx64 "%016" PRIx64 "\n", n->highpart, n->lowpart);
}

#endif // __UINT128_H_
