#ifndef FX_MAPPED_LOADER_H
#define FX_MAPPED_LOADER_H
#include <stdint.h>
#include <stddef.h>
#include "os-map-profile.h"
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define BYTE(a) (*(volatile uint8_t *)(uintptr_t)(a))
#define BARRIER() __asm__ volatile(".word 0x00ab\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop":::"memory")
#define BASE 0x00300000u
#define MAX_PAGES 512u
#define MAX_PATCHES 64u
#define LOG_BYTES 4096
#define LOG_BUFFER 1024

static inline uint32_t sr_get(void){uint32_t x;__asm__ volatile("stc sr,%0":"=r"(x));return x;}
static inline void sr_set(uint32_t x){__asm__ volatile("ldc %0,sr"::"r"(x):"memory");}
static inline void purge(uintptr_t x){__asm__ volatile("ocbp @%0"::"r"(x):"memory");}
static inline void invalidate(uintptr_t x){__asm__ volatile(".word 0x00e3"::"z"(x):"memory");}
typedef struct {
 char magic[8];uint32_t version,bytes,entry,flags,patch_count,forbid_count;
 unsigned char sha256[32];uint32_t forbidden[8][2],patches[MAX_PATCHES];
} Profile;
_Static_assert(sizeof(Profile)==384,"profile ABI");
typedef struct Context Context;
struct Context {
 void (*finalize)(Context *);
 uintptr_t resident,shadow;unsigned allocation_bytes,runner_bytes;
 FxOsMapProfile os;
 uint32_t *pages,*hashes,original[512];
 unsigned image_bytes,image_pages,shadow_span,shadow_count;
 unsigned char shadow_slot[512];
 Profile profile;
 uint32_t old_cursor,mmucr,pteh,ptel,ptea,ram_word;
 unsigned active,failed,in_callback,io_error,log_used,log_saved;
 unsigned file_busy,refreshes,changed,syscalls,last_syscall,key_calls,self_bytes;
 uintptr_t guest_quit;
 struct {uintptr_t callback;int id;} timers[10];
 unsigned timer_calls,timer_skipped;
 unsigned fast,started_tick,verify_ticks,release_ticks,map_ticks,ready_ticks;
 uint16_t log_path[64],bin_path[64],self_path[32];
 char log[LOG_BUFFER];
 unsigned ram_candidates;
};
typedef struct {uint32_t r[8],pr,sr,sp,out_sr,mach,macl;} Frame;
extern const unsigned char resident_begin[],resident_end[];
extern const uint32_t resident_fixups[];
extern Context *resident_context;
int resident_main(Context *);
void resident_quit_entry(void);void resident_quit_work(Context *);
void resident_gateway(void);void resident_dispatch(Frame *);void resident_os_call(Frame *);
void resident_os_get_vram(Frame *);
int r_browser_keywait(int *column,int *row,int mode,int timeout,int menu,uint16_t *unused);
int r_any_key(uint16_t *);void r_clear_keys(void);
void r_clear(void);void r_print(int,int,const unsigned char *,int);void r_display(void);
int r_getkey(int *);void r_quit(void (*)(void));void *r_malloc(unsigned);void r_free(void *);
int r_version(unsigned char *,unsigned char *,unsigned short *,unsigned short *);
int r_open(const uint16_t *,int,int);int r_close(int);int r_size(int);int r_read(int,void *,int,int);
int r_seek(int,int);int r_create(const uint16_t *,int,int *);int r_write(int,const void *,int);
 typedef struct {uint16_t id,type;uint32_t fsize,dsize,property,address;} FileInfo;
 int r_find_first(const uint16_t *,int *,uint16_t *,FileInfo *);
 int r_find_next(int,uint16_t *,FileInfo *);int r_find_close(int);
 unsigned char *r_vram(void);
int r_ticks(void);void r_sleep(int);int r_timer_install(int,void (*)(void),int);
int r_timer_start(int);int r_timer_stop(int);int r_timer_remove(int);void r_reset(void);
typedef struct {uint32_t h[8],total,used;unsigned char block[64];} Sha256;
void sha_init(Sha256 *);void sha_update(Sha256 *,const unsigned char *,unsigned);void sha_final(Sha256 *,unsigned char *);
#endif
