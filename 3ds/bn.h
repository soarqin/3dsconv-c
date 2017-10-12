#ifndef __BN_H_
#define __BN_H_

#include <stdint.h>

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#define __builtin_bswap16 _byteswap_ushort
#define __builtin_bswap32 _byteswap_ulong
#define __builtin_bswap64 _byteswap_uint64
#endif

#define BE32(n) (uint32_t)__builtin_bswap32((unsigned long)n)
#define BE64(n) __builtin_bswap64(n)
#define BE16(n) __builtin_bswap16(n)

typedef struct uint128 {
    uint64_t lowpart, highpart;
} uint128;

void uint128_bswap(uint128 *n);

void uint128_xor(uint128 *n, uint128 *n2);

void uint128_lshift(uint128 *n, size_t shift);

void uint128_rshift(uint128 *n, size_t shift);

void uint128_add(uint128 *n, uint128 *n2);

void uint128_rol(uint128 *n, size_t bits);

void uint128_print(uint128 *n);

#endif // __BN_H_
