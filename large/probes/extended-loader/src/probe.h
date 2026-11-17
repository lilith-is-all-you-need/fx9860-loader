#ifndef MAP698_H
#define MAP698_H
#include <stdint.h>
#include <stddef.h>
#include "os-map-profile.h"
#define BASE 0x00300000u
#define IMAGE_BYTES 2857444u
#define PAGES 698u
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define BYTE(a) (*(volatile unsigned char *)(uintptr_t)(a))
#define BARRIER() __asm__ volatile(".word 0x00ab\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop":::"memory")
static inline uint32_t sr_get(void){uint32_t v;__asm__ volatile("stc sr,%0":"=r"(v));return v;}
static inline void sr_set(uint32_t v){__asm__ volatile("ldc %0,sr"::"r"(v):"memory");}
static inline uint32_t vbr_get(void){uint32_t v;__asm__ volatile("stc vbr,%0":"=r"(v));return v;}
static inline void vbr_set(uint32_t v){__asm__ volatile("ldc %0,vbr"::"r"(v):"memory");}
static inline void purge(uintptr_t p){__asm__ volatile("ocbp @%0"::"r"(p):"memory");}
static inline void icbi(uintptr_t p){__asm__ volatile(".word 0x00e3"::"z"(p):"memory");}
typedef struct {
 FxOsMapProfile os;
 uint32_t pages[PAGES],hashes[PAGES],original[512];
 uint32_t sr,vbr,mmucr,pteh,ptel,ptea,cursor,refills,high_refills,slot,fault;
 unsigned mode,failed,calls,verified,cross_calls,fragmented,resident_bytes,allocation_bytes;
 uint32_t before_hash,after_hash;
 char log[1536];unsigned used;
 unsigned char buffer[512];
 uint16_t bin_path[32],log_path[32];
} Context;
extern Context *map_context;
extern const unsigned char resident_begin[],resident_end[],map_vectors[];
extern const uint32_t resident_fixups[];
int resident_main(Context *);
void resident_refill(uint32_t);
void r_clear(void);void r_print(int,int,const unsigned char *,int);void r_display(void);
int r_getkey(int *);void *r_malloc(unsigned);void r_free(void *);
int r_open(const uint16_t *,int,int);int r_close(int);int r_size(int);int r_read(int,void *,int,int);
int r_seek(int,int);int r_write(int,const void *,int);
#endif
