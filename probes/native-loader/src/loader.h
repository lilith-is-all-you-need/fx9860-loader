#ifndef HOT_LOADER_H
#define HOT_LOADER_H
#include <stdint.h>
#include <stddef.h>
#define BASE 0x00300000u
#define MAX_IMAGE 0x28000u
#define MAX_PATCHES 64
#define LOG_BYTES 2048
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define BARRIER() __asm__ volatile(".word 0x00ab\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop":::"memory")
static inline uint32_t sr_get(void){uint32_t x;__asm__ volatile("stc sr,%0":"=r"(x));return x;}
static inline void sr_set(uint32_t x){__asm__ volatile("ldc %0,sr"::"r"(x):"memory");}
static inline void purge(uintptr_t x){__asm__ volatile("ocbp @%0"::"r"(x):"memory");}
static inline void invalidate(uintptr_t x){__asm__ volatile(".word 0x00e3"::"z"(x):"memory");}
typedef struct {uint32_t addr,data,ext;} Entry;
/* File is big-endian; the SH target is big-endian too. No host pointers. */
typedef struct {
 char magic[8]; uint32_t version,bytes,entry,flags,patch_count,forbid_count;
 unsigned char sha256[32];
 uint32_t forbidden[8][2];
 uint32_t patches[MAX_PATCHES];
} Profile;
typedef struct Context Context;
struct Context {
 void (*finalize)(Context *); /* callback.S offset zero */
 void *runner_allocation,*image_allocation;
 uintptr_t resident,image;
 uint32_t image_bytes,mapped_bytes,entry,flags;
 uint32_t mmucr,pteh,ptel,ptea,ram_word;
 Entry old[64]; unsigned char touched[64];
 unsigned reserve,pages,active,failed,in_callback,quit_seen;
 uintptr_t guest_quit;
 int result;
 unsigned log_used;
 uint16_t log_path[32];
 char log[LOG_BYTES];
};
extern const unsigned char resident_begin[],resident_end[];
extern const uint32_t resident_fixups[];
extern Context *resident_context;
int resident_main(Context *);
void resident_quit_entry(void);
void resident_quit_work(Context *);
int resident_register_quit(void (*)(void));
void resident_gateway(void);
void r_clear(void);void r_print(int,int,const unsigned char *,int);void r_display(void);
int r_getkey(int *);void r_quit(void (*)(void));void *r_malloc(unsigned);void r_free(void *);
int r_any_key(uint16_t *);void r_clear_keys(void);int r_sleep(int);
int r_version(unsigned char *,unsigned char *,unsigned short *,unsigned short *);
int r_open(const uint16_t *,int,int);int r_close(int);int r_size(int);
int r_read(int,void *,int,int);int r_seek(int,int);int r_create(const uint16_t *,int,int *);
int r_write(int,const void *,int);
void log_text(Context *,const char *);void log_event(Context *,const char *,uint32_t,uint32_t);
int log_save(Context *);
typedef struct {uint32_t h[8],total,used;unsigned char block[64];} Sha256;
void sha_init(Sha256 *);void sha_update(Sha256 *,const unsigned char *,unsigned);void sha_final(Sha256 *,unsigned char *);
#endif
