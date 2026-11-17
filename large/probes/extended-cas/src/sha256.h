#ifndef KHIMAP_SHA256_H
#define KHIMAP_SHA256_H
#include <stdint.h>
#include <stddef.h>
typedef struct { uint32_t h[8]; uint64_t bytes; unsigned used; unsigned char block[64]; } Sha256;
void sha256_init(Sha256 *);
void sha256_update(Sha256 *,const volatile unsigned char *,size_t);
void sha256_final(Sha256 *,unsigned char [32]);
#endif
