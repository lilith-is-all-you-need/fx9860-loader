#include <gint/config.h>

.global _gint_tlbh
.section .gint.tlbh, "ax"
.align 4

#if GINT_OS_FX
# define SYSCALL_TABLE 0x80010070
# define SYSCALL_TLBH 3
#elif GINT_OS_CG
# define SYSCALL_TABLE 0x80020070
# define SYSCALL_TLBH 12
#elif GINT_OS_CP
# define NOMMU 1
#else
# error Unknown HW for tlbh.S!
#endif

_gint_tlbh:
#if ! NOMMU
	sts.l	pr, @-r15
	stc.l	gbr, @-r15
	sts.l	mach, @-r15
	sts.l	macl, @-r15

	/* Get HWMPU in gint's hardware info. If last bit is set, we're SH3 */
	mov.l	.gint, r0
	mov.l	@r0, r0
	tst	#1, r0
	mov.l	.tea_sh4, r0
	bt	test_tea
	mov.l	.tea_sh3, r0

test_tea:
	/* Check TEA to see if we want to map a page or raise a SysERROR */
	mov.l	@r0, r0
	mov.l	.max_mapped_rom, r1
	cmp/ge	r1, r0
	bt	panic
	mov.l	.min_mapped_rom, r1
	cmp/ge	r1, r0
	bf	panic

map:
	/* The slot is in static URAM, whose mappings the loader preserves.
	   Both this copied handler and its target are permanently accessible
	   while SR.BL=1; never call a BIN function or the OS mapper here. */
	mov	r0, r4
	mov.l	.refill_slot, r2
	mov.l	@r2, r2
	tst	r2, r2
	bt	panic
	jsr	@r2
	nop
	tst	r0, r0
	bt	panic

	lds.l	@r15+, macl
	lds.l	@r15+, mach
	ldc.l	@r15+, gbr
	lds.l	@r15+, pr
	rte
	nop
#endif

panic:
	/* Otherwise, or if there is no MMU, panic by defaulting to the
	   exception handler (the TLB miss may still be resolved by a panic
	   handler) */
	lds.l	@r15+, macl
	lds.l	@r15+, mach
	ldc.l	@r15+, gbr
	lds.l	@r15+, pr

	stc	vbr, r0
	mov	#1, r1
	shll8	r1
	add	r1, r0
	jmp	@r0
	nop

#if ! NOMMU
.align 4

.gint:
	.long	_gint
.tea_sh4:
	.long	0xff00000c
.tea_sh3:
	.long	0xfffffffc
.min_mapped_rom:
	.long	_brom
.max_mapped_rom:
	.long	_khicas_rom_end
.refill_slot:
	.long	_khicas_map_refill
#endif
