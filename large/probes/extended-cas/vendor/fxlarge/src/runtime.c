#include <fxlarge/runtime.h>
#if !defined(__sh__)
#error FxLarge runtime requires the SuperH target toolchain
#endif
int (*volatile fxlarge_refill_slot)(uint32_t);
void (*volatile fxlarge_syscall_slot)(void);
static FxLargeApi *bound;
static uint32_t shim_vbr;
int fxlarge_bind(FxLargeApi *api)
{
 bound=0;shim_vbr=0;fxlarge_refill_slot=0;fxlarge_syscall_slot=0;
 if(!api||api->magic!=FXLARGE_API_MAGIC||api->version!=FXLARGE_API_VERSION||
    !api->refill||!api->syscall_gate||!api->stage||!api->request)return 0;
 __asm__ volatile("stc vbr,%0":"=r"(shim_vbr));
 bound=api;fxlarge_refill_slot=api->refill;fxlarge_syscall_slot=api->syscall_gate;
 __asm__ volatile("":::"memory");return 1;
}
void fxlarge_stage(unsigned id,uint32_t phase,uint32_t value)
{if(bound)bound->stage(id,phase,value);}
void fxlarge_request(unsigned reason){if(bound)bound->request(reason);}
void fxlarge_resume_interrupts(void)
{
 if(!bound)return;
 uint32_t sr;__asm__ volatile("stc sr,%0":"=r"(sr));
 sr=(sr&~UINT32_C(0xf0))|(bound->original_sr&UINT32_C(0xf0));
 __asm__ volatile("ldc %0,sr"::"r"(sr):"memory");
}
unsigned fxlarge_atomic_mask(uint32_t entry_vbr,uint32_t target_vbr,unsigned saved)
{
 if(!bound)return saved;
 if(target_vbr==shim_vbr)return 15;
 return entry_vbr==shim_vbr?(bound->original_sr>>4)&15u:saved;
}
int fxlarge_unbind(void)
{
 uint32_t vbr;__asm__ volatile("stc vbr,%0":"=r"(vbr));
 if(!bound||vbr!=shim_vbr)return 0;
 fxlarge_refill_slot=0;fxlarge_syscall_slot=0;bound=0;shim_vbr=0;
 __asm__ volatile("":::"memory");return 1;
}
