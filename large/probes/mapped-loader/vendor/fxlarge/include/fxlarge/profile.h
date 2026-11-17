#ifndef FXLARGE_PROFILE_H
#define FXLARGE_PROFILE_H
#include <stdint.h>
#define FXLARGE_BASE 0x00300000u
#define FXLARGE_MAX_PAGES 768u
#define FXLARGE_STORAGE_BUDGET 3000000u
/* Big-endian on disk; SH builds use the native big-endian representation. */
typedef struct {
 char magic[8];
 uint32_t version,image_bytes,image_base,entry,page_count,page_capacity;
 uint32_t runtime_abi,flags,min_free_bytes,guest_ram_bytes;
 unsigned char sha256[32];
 uint32_t hook_count,reserved[11];
} FxLargeProfile;
typedef enum { FXLARGE_OK=0, FXLARGE_BAD_PROFILE=51,
 FXLARGE_PAGE_LIMIT=52, FXLARGE_STORAGE_BUDGET_ERROR=53,
 FXLARGE_HOOK_UNSUPPORTED=54, FXLARGE_STORAGE_FREE_ERROR=55,
 FXLARGE_GUEST_RAM_ERROR=56, FXLARGE_RUNTIME_HEADER_ERROR=57 } FxLargeStatus;
#if defined(__cplusplus)
static_assert(sizeof(FxLargeProfile)==128,"profile wire ABI");
#else
_Static_assert(sizeof(FxLargeProfile)==128,"profile wire ABI");
#endif
static inline int fxlarge_profile_validate(const FxLargeProfile *p)
{
 const char *magic="FXEXT002";
 for(unsigned i=0;i<8;i++)if(p->magic[i]!=magic[i])return FXLARGE_BAD_PROFILE;
 if(p->version!=2||p->image_base!=FXLARGE_BASE||p->entry!=FXLARGE_BASE+512u||
    p->runtime_abi!=1||p->flags!=1||p->image_bytes<516u||
    p->guest_ram_bytes>512u*1024u)return FXLARGE_BAD_PROFILE;
 if(p->image_bytes>FXLARGE_MAX_PAGES*4096u||
    p->page_count!=(p->image_bytes+4095u)/4096u||
    p->page_capacity<p->page_count||p->page_capacity>FXLARGE_MAX_PAGES)return FXLARGE_PAGE_LIMIT;
 if(p->image_bytes>FXLARGE_STORAGE_BUDGET-192u||
    p->min_free_bytes>FXLARGE_STORAGE_BUDGET-192u-p->image_bytes)return FXLARGE_STORAGE_BUDGET_ERROR;
 if(p->hook_count)return FXLARGE_HOOK_UNSUPPORTED;
 for(unsigned i=0;i<11;i++)if(p->reserved[i])return FXLARGE_BAD_PROFILE;
 return FXLARGE_OK;
}
#endif
