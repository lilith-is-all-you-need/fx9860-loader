#ifndef KHICAS_MAPPED_CAS_MAP_API_H
#define KHICAS_MAPPED_CAS_MAP_API_H

#include <stddef.h>
#include <stdint.h>

#define KHICAS_MAP_API_MAGIC UINT32_C(0x4b4d4150)
#define KHICAS_MAP_API_VERSION UINT32_C(1)

/* The loader owns this table and all its targets until payload return.
   The table, refill target and syscall gate reside in permanently accessible
   P1/P2 RAM. The loader preserves all static-URAM TLB entries. */
struct khicas_map_api {
    uint32_t magic;
    uint32_t version;
    int (*refill)(uint32_t address);
    void (*syscall_gate)(void);
    void (*stage)(unsigned stage, uint32_t phase, uint32_t value);
    uint32_t original_sr;
    void (*request)(unsigned reason);
};

enum khicas_map_exit_reason {
    KHICAS_MAP_EXIT = 0,
    KHICAS_MAP_MENU = 1,
    KHICAS_MAP_OFF = 2,
};

/* phase: 0 = beginning, 1 = completed, 2 = failed. */
enum khicas_map_stage_id {
    KHICAS_MAP_STAGE_BIND = 1,
    KHICAS_MAP_STAGE_HW_DETECT = 2,
    KHICAS_MAP_STAGE_RELOCATE = 3,
    KHICAS_MAP_STAGE_KINIT = 4,
    KHICAS_MAP_STAGE_BOOTSTRAP = 5,
    KHICAS_MAP_STAGE_MAIN = 6,
    KHICAS_MAP_STAGE_TEARDOWN = 7,
};

/* Direct slots are written before hardware detection and again after .data /
   .bss relocation. The TLB entry copies only a slot address into VBR RAM. */
extern int (*volatile khicas_map_refill)(uint32_t);
extern void (*volatile khicas_map_syscall_gate)(void);

int khicas_map_bind(struct khicas_map_api *api);
void khicas_map_stage(unsigned stage, uint32_t phase, uint32_t value);
void khicas_map_request(unsigned reason);
void khicas_map_resume_interrupts(void);
unsigned khicas_map_atomic_mask(uint32_t entry_vbr, uint32_t target_vbr,
    unsigned saved_mask);

#if defined(__sh__)
_Static_assert(sizeof(struct khicas_map_api) == 28, "SH32 map API size");
_Static_assert(offsetof(struct khicas_map_api, refill) == 8, "map refill ABI");
_Static_assert(offsetof(struct khicas_map_api, syscall_gate) == 12, "map syscall ABI");
_Static_assert(offsetof(struct khicas_map_api, stage) == 16, "map stage ABI");
_Static_assert(offsetof(struct khicas_map_api, original_sr) == 20, "map SR ABI");
_Static_assert(offsetof(struct khicas_map_api, request) == 24, "map exit ABI");
#endif

#endif
