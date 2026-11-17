#ifndef FXLARGE_RUNTIME_H
#define FXLARGE_RUNTIME_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define FXLARGE_API_MAGIC UINT32_C(0x4b4d4150)
#define FXLARGE_API_VERSION 1u
/* ABI v1 is deliberately compatible with the reviewed Giac adapter. */
typedef struct FxLargeApi {
 uint32_t magic,version;
 int (*refill)(uint32_t address);
 void (*syscall_gate)(void);
 void (*stage)(unsigned id,uint32_t phase,uint32_t value);
 uint32_t original_sr;
 void (*request)(unsigned reason);
} FxLargeApi;
enum { FXLARGE_EXIT=0,FXLARGE_MENU=1,FXLARGE_OFF=2 };
/* These slots must live in permanently mapped URAM, never paged ROM.
   Bind before hardware detection and again after .data/.bss initialization. */
extern int (*volatile fxlarge_refill_slot)(uint32_t);
extern void (*volatile fxlarge_syscall_slot)(void);
int fxlarge_bind(FxLargeApi *api);
void fxlarge_stage(unsigned id,uint32_t phase,uint32_t value);
void fxlarge_request(unsigned reason);
void fxlarge_resume_interrupts(void);
unsigned fxlarge_atomic_mask(uint32_t entry_vbr,uint32_t target_vbr,unsigned saved);
/* After the target has stopped timers, released its world, and restored the
   shim VBR. Refuses an active foreign VBR; does not fake a safe unwinding. */
int fxlarge_unbind(void);
#if defined(__sh__) && !defined(__cplusplus)
_Static_assert(sizeof(FxLargeApi)==28 && offsetof(FxLargeApi,request)==24,"large ABI v1");
#elif defined(__sh__)
static_assert(sizeof(FxLargeApi)==28 && offsetof(FxLargeApi,request)==24,"large ABI v1");
#endif
#ifdef __cplusplus
}
#endif
#endif
