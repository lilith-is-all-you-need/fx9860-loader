#include "map_api.h"

int (*volatile khicas_map_refill)(uint32_t);
void (*volatile khicas_map_syscall_gate)(void);
static struct khicas_map_api *map_api;
static uint32_t shim_vbr;

int khicas_map_bind(struct khicas_map_api *api)
{
    /* These globals can still contain OS data on the first entry. */
    khicas_map_refill = NULL;
    khicas_map_syscall_gate = NULL;
    map_api = NULL;
    shim_vbr = 0;
    if(!api || api->magic != KHICAS_MAP_API_MAGIC ||
       api->version != KHICAS_MAP_API_VERSION || !api->refill ||
       !api->syscall_gate || !api->stage || !api->request)
        return 0;
    map_api = api;
    __asm__ volatile("stc vbr,%0" : "=r"(shim_vbr));
    khicas_map_refill = api->refill;
    khicas_map_syscall_gate = api->syscall_gate;
    __asm__ volatile("" ::: "memory");
    return 1;
}

void khicas_map_stage(unsigned stage, uint32_t phase, uint32_t value)
{
    if(map_api) map_api->stage(stage, phase, value);
}

void khicas_map_request(unsigned reason)
{
    if(map_api) map_api->request(reason);
}

void khicas_map_resume_interrupts(void)
{
    if(!map_api) return;
    uint32_t sr;
    __asm__ volatile("stc sr,%0" : "=r"(sr));
    /* Keep the gint CPU configuration and restore only the caller's IMASK. */
    sr = (sr & ~UINT32_C(0xf0)) | (map_api->original_sr & UINT32_C(0xf0));
    __asm__ volatile("ldc %0,sr" :: "r"(sr) : "memory");
}

unsigned khicas_map_atomic_mask(uint32_t entry_vbr, uint32_t target_vbr,
    unsigned saved_mask)
{
    if(!map_api) return saved_mask;
    /* World transitions restore CPU.SR before cpu_atomic_end(). The usual
       atomic_end would then overwrite that world's IMASK with its caller's.
       The loader shim must stay masked until its resident syscall gate. */
    if(target_vbr == shim_vbr) return 15;
    if(entry_vbr == shim_vbr)
        return (map_api->original_sr >> 4) & 15u;
    return saved_mask;
}
