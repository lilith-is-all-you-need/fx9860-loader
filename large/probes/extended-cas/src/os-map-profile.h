#ifndef FX_OS_MAP_PROFILE_H
#define FX_OS_MAP_PROFILE_H
#include <stdint.h>
#include "os-map-hashes.h"
typedef uint8_t (*FxRomRead)(void *,uint32_t);
typedef struct {
 uint32_t table,refill,install,map,query,pages,cursor,enabled,close_slot,slots,descriptors;
} FxOsMapProfile;
static uint32_t fx_word(FxRomRead rd,void *ctx,uint32_t a,int n)
{uint32_t v=0;for(int i=0;i<n;i++)v=(v<<8)|rd(ctx,a+i);return v;}
static int fx_rom(uint32_t a,unsigned size)
{return !(a&1)&&a>=0x80010000u&&a<=0x803b0000u-size;}
static uint32_t fx_fingerprint(FxRomRead rd,void *ctx,uint32_t a,unsigned n)
{uint32_t h=2166136261u;for(unsigned i=0;i<n;i++)h=(h^rd(ctx,a+i))*16777619u;return h;}
static uint32_t fx_literal(FxRomRead rd,void *ctx,uint32_t pc)
{
 if(!fx_rom(pc,2))return 0;
 unsigned op=fx_word(rd,ctx,pc,2);if((op&0xf000)!=0xd000)return 0;
 uint32_t p=((pc+4)&~3u)+(op&255)*4;
 return fx_rom(p,4)?fx_word(rd,ctx,p,4):0;
}
static uint32_t fx_bsr(FxRomRead rd,void *ctx,uint32_t pc)
{unsigned op=fx_word(rd,ctx,pc,2);return (op&0xf000)==0xb000?pc+4+((int32_t)(op<<20)>>19):0;}
static inline int fx_os_profile(FxRomRead rd,void *ctx,FxOsMapProfile *p)
{
 if(fx_word(rd,ctx,0x80010070,4)!=0xd2024008u)return 1;
 p->table=fx_word(rd,ctx,0x8001007c,4);if(!fx_rom(p->table,0x1254))return 2;
 p->refill=fx_word(rd,ctx,p->table+12,4);p->map=fx_word(rd,ctx,p->table+0x44,4);
 p->close_slot=fx_word(rd,ctx,p->table+0x79c,4);
 if(!fx_rom(p->refill,0x72)||!fx_rom(p->map,0x220)||!fx_rom(p->close_slot,40))return 3;
 if(fx_fingerprint(rd,ctx,p->refill,0x72)!=fx_hash_refill[0]||
    fx_fingerprint(rd,ctx,p->map,0x132)!=fx_hash_map_head[0]||
    fx_fingerprint(rd,ctx,p->map+0x13e,0xe2)!=fx_hash_map_tail[0])return 4;
 p->install=fx_bsr(rd,ctx,p->refill+0x40);
 if(!fx_rom(p->install,0x58)||fx_fingerprint(rd,ctx,p->install,0x58)!=fx_hash_install[0])return 5;
 p->pages=fx_literal(rd,ctx,p->refill+0x28);p->cursor=fx_literal(rd,ctx,p->install+4);
 /* The preceding MMU disable routine is confirmed at map-init's first BSR. */
 uint32_t init=fx_word(rd,ctx,p->table,4);if(!fx_rom(init,4))return 11;
 uint32_t disable=fx_bsr(rd,ctx,init+2);if(!fx_rom(disable,0x22))return 12;
 p->enabled=fx_literal(rd,ctx,disable+0x20);p->query=fx_literal(rd,ctx,p->map+0x1c0);
 if((p->pages&3)||p->pages<0x88000000u||p->pages>0x8803f000u||p->cursor!=p->pages+2048||p->enabled!=p->pages-127)return 6;
 if(!fx_rom(p->query,0x8a)||fx_fingerprint(rd,ctx,p->query,0x8a)!=fx_hash_query[0])return 7;
 if(fx_fingerprint(rd,ctx,p->close_slot,40)!=fx_hash_close[0])return 8;
 p->slots=fx_literal(rd,ctx,p->close_slot+16);
 uint32_t finalizer=fx_bsr(rd,ctx,p->close_slot+4);
 if(!fx_rom(finalizer,0x10))return 9;
 p->descriptors=fx_literal(rd,ctx,finalizer+12);
 if(p->slots<0x88000000u||p->slots>0x8803f000u||p->descriptors<0x88000000u||p->descriptors>0x8803f000u)return 10;
 return 0;
}
#endif
