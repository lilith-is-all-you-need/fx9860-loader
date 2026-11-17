#include "loader.h"
/* Relocated with the code, never held in payload-cleared user RAM. */
Context *map_context=(Context *)(uintptr_t)1;
static int in_window(uint32_t va){return va>=BASE && va<BASE+map_context->profile.page_capacity*4096u;}
static void clear_window(void)
{
 for(unsigned i=0;i<64;i++){
  uint32_t a=0xf6000000u+(i<<8);
  if(in_window(REG(a)&~4095u)){REG(a)=0;REG(a+0x1000000u)=0;}
 }
 for(unsigned i=0;i<4;i++){
  uint32_t a=0xf2000000u+(i<<8);
  if(in_window(REG(a)&~4095u)){REG(a)=0;REG(a+0x1000000u)=0;}
 }
 BARRIER();
}
/* Called with SR.BL from either the shim or gint. No allocation or OS calls. */
int resident_refill(uint32_t address)
{
 Context *c=map_context;
 if(address<BASE||address>=BASE+c->profile.image_bytes||!c->slot_count)return 0;
 uint32_t physical=c->pages[(address-BASE)>>12];
 if(!physical)return 0;
 unsigned slot=c->slots[c->slot++];if(c->slot==c->slot_count)c->slot=0;
 /* Retain ASID; read-only/4 KiB, uncached for the first hardware
  * candidate. This avoids unproven SH7305 cache-synonym geometry. */
 REG(0xff000000)=(address&~4095u)|(REG(0xff000000)&255u);
 REG(0xff000004)=physical|0x154u;REG(0xff000034)=0;
 REG(0xff000010)=(REG(0xff000010)&~0xfc00u)|(slot<<10);
 __asm__ volatile("ldtlb":::"memory");BARRIER();
 c->refills++;if(address>=BASE+512u*4096u)c->high_refills++;
 return 1;
}
static void stage(unsigned id,uint32_t phase,uint32_t status)
{
 Context *c=map_context;c->stage=id;c->phase=phase;c->status=status;
 if(phase==2&&!c->failure_stage){c->failure_stage=id;c->failure_status=status;}
}
static void request(unsigned reason){map_context->reason=reason;}
/* The first candidate has no external-file UI or asynchronous OS callbacks.
 * Refuse these explicitly: file writes could relocate executable Flash pages;
 * a callback could outlive the loader. Never report fake successful writes. */
void resident_dispatch(Frame *f)
{
 Context *c=map_context;unsigned id=f->r[0];
 if((id>=0x42c&&id<=0x43d)||id==0x118||id==0x494||id==0x236||id==0x3f4){
  c->denied=id;f->r[0]=(uint32_t)-1;return;
 }
 uint32_t before_vbr=vbr_get(),before_sr=f->sr;
 if(before_vbr==(uint32_t)(uintptr_t)map_vectors){
  sr_set(sr_get()|0xf0u);vbr_set(c->vbr);BARRIER();
  f->sr=(before_sr&~0xf0u)|(c->sr&0xf0u);
  resident_os_call(f);
  sr_set(sr_get()|0xf0u);vbr_set(before_vbr);BARRIER();
  f->out_sr=(f->out_sr&~0xf0u)|0xf0u;
 } else {
  /* gint owns the hardware: keep its VBR for direct heap/VRAM calls. */
  resident_os_call(f);
 }
}
void resident_fatal(uint32_t address)
{
 /* A shim fault outside the immutable image is not safe to resume. Leave
  * diagnostic state for the debugger; never re-enter a half-created world. */
 map_context->fault=address;
 for(;;)__asm__ volatile("nop");
}
int resident_main(Context *c)
{
 map_context=c;c->api.magic=0x4b4d4150u;c->api.version=1;
 c->api.refill=resident_refill;c->api.syscall_gate=resident_gateway;
 c->api.stage=stage;c->api.request=request;
 c->sr=sr_get();c->api.original_sr=c->sr;sr_set(c->sr|0xf0u);
 c->vbr=vbr_get();c->mmucr=REG(0xff000010);c->pteh=REG(0xff000000);
 c->ptel=REG(0xff000004);c->ptea=REG(0xff000034);c->ramword=REG(0x08100000);
 /* Keep every valid non-image mapping, especially all existing user RAM.
  * Slots 55..63 remain untouched even if they currently look invalid. */
 c->slot_count=0;
 for(unsigned i=0;i<55;i++){
  uint32_t a=REG(0xf6000000u+(i<<8));
  if(!(a&0x100u)||in_window(a&~4095u))c->slots[c->slot_count++]=i;
 }
 if(c->slot_count<4){sr_set(c->sr);return 31;}
 clear_window();c->slot=0;vbr_set((uint32_t)(uintptr_t)map_vectors);BARRIER();
 c->payload_rc=((int(*)(int,int,MapApi *))(uintptr_t)c->profile.entry)(1,0,&c->api);
 /* kquit restored the masked shim. Do all mapping restoration from P2. */
 sr_set(sr_get()|0xf0u);clear_window();
 REG(0xff000000)=c->pteh;REG(0xff000004)=c->ptel;REG(0xff000034)=c->ptea;
 REG(0xff000010)=c->mmucr;REG(0x08100000)=c->ramword;
 vbr_set(c->vbr);BARRIER();sr_set(c->sr);
 return 0;
}
