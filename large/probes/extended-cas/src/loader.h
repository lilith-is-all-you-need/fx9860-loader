#ifndef KHICAS_MAPPED_LOADER_H
#define KHICAS_MAPPED_LOADER_H
#include <stdint.h>
#include <stddef.h>
#include <fxlarge/profile.h>
#define BASE 0x00300000u
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define BYTE(a) (*(volatile unsigned char *)(uintptr_t)(a))
#define BARRIER() __asm__ volatile(".word 0x00ab\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop":::"memory")
static inline uint32_t sr_get(void){uint32_t v;__asm__ volatile("stc sr,%0":"=r"(v));return v;}
static inline void sr_set(uint32_t v){__asm__ volatile("ldc %0,sr"::"r"(v):"memory");}
static inline uint32_t vbr_get(void){uint32_t v;__asm__ volatile("stc vbr,%0":"=r"(v));return v;}
static inline void vbr_set(uint32_t v){__asm__ volatile("ldc %0,vbr"::"r"(v):"memory");}
static inline void purge(uintptr_t p){__asm__ volatile("ocbp @%0"::"r"(p):"memory");}
static inline void invalidate(uintptr_t p){__asm__ volatile("ocbi @%0"::"r"(p):"memory");__asm__ volatile(".word 0x00e3"::"z"(p):"memory");}
typedef struct {
 uint32_t magic,version;
 int (*refill)(uint32_t);
 void (*syscall_gate)(void);
 void (*stage)(unsigned,uint32_t,uint32_t);
 uint32_t original_sr;
 void (*request)(unsigned);
} MapApi;
_Static_assert(sizeof(MapApi)==28,"map ABI");
typedef struct {
 uint32_t r[8],pr,sr,sp,out_sr,mach,macl;
} Frame;
_Static_assert(sizeof(Frame)==56 && offsetof(Frame,mach)==48,"gateway ABI");
typedef struct {
 MapApi api;
 FxLargeProfile profile;
 uint32_t *pages;
 uint32_t sr,vbr,mmucr,pteh,ptel,ptea,ramword;
 uint32_t refills,high_refills,fault,reason,stage,phase,status,denied;
 uint32_t failure_stage,failure_status,payload_rc;
 uint32_t slots[55],slot_count,slot;
 uint32_t resident_bytes,allocation_bytes;
} Context;
extern Context *map_context;
extern const unsigned char resident_begin[],resident_end[],map_vectors[];
extern const uint32_t resident_fixups[];
int resident_main(Context *);
int resident_refill(uint32_t);
void resident_gateway(void);
void resident_dispatch(Frame *);
void resident_os_call(Frame *);
void resident_fatal(uint32_t);
void r_clear(void);void r_print(int,int,const unsigned char *,int);void r_display(void);
int r_getkey(int *);void *r_malloc(unsigned);void r_free(void *);
int r_open(const uint16_t *,int,int);int r_close(int);int r_size(int);int r_read(int,void *,int,int);
int r_timer_install(int,void (*)(void),int);int r_timer_start(int);int r_timer_stop(int);int r_timer_remove(int);
int r_putkey(int,int,int);void r_clear_keys(void);int r_keywait(int *,int *,int,int,int,uint16_t *);
void r_poweroff(void);
int r_media_free(const uint16_t *,uint32_t *);
#endif
