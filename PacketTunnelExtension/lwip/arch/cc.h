/**
 * lwIP compiler/platform configuration for iOS (ARM64)
 */

#ifndef CC_H
#define CC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Define platform endianness */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/* Use compiler built-in byte swap */
#define LWIP_PLATFORM_BYTESWAP 1
#define LWIP_PLATFORM_HTONS(x) __builtin_bswap16(x)
#define LWIP_PLATFORM_HTONL(x) __builtin_bswap32(x)

/* Diagnostics */
#define LWIP_PLATFORM_DIAG(x)  do { printf x; } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { \
    printf("lwIP assertion: %s at %s:%d\n", x, __FILE__, __LINE__); \
    abort(); \
} while(0)

/* Random number (used for TCP ISN) */
#define LWIP_RAND() ((u32_t)arc4random())

#endif /* CC_H */
