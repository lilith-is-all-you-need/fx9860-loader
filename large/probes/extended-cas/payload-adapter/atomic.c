/* gint atomic operations with explicit mapped-payload world boundaries. */
#include <gint/cpu.h>
#include "map_api.h"

static unsigned saved_imask;
static unsigned atomic_level;
static uint32_t entry_vbr;

void cpu_atomic_start(void)
{
    cpu_sr_t sr = cpu_getSR();
    cpu_sr_t masked = sr;
    masked.IMASK = 15;
    cpu_setSR(masked);
    if(atomic_level == 0) {
        saved_imask = sr.IMASK;
        entry_vbr = cpu_getVBR();
    }
    atomic_level++;
}

void cpu_atomic_end(void)
{
    cpu_sr_t sr = cpu_getSR();
    atomic_level--;
    if(atomic_level == 0) {
        sr.IMASK = khicas_map_atomic_mask(entry_vbr, cpu_getVBR(), saved_imask);
        saved_imask = 0;
        entry_vbr = 0;
    }
    cpu_setSR(sr);
}
