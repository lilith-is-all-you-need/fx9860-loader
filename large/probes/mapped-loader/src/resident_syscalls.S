 .section .resident.text,"ax"
 .macro SC name,number
 .align 2
 .global _\name
_\name:
 mov.l 1f,r0
 mov.l 2f,r2
 jmp @r2
 nop
 .align 2
1: .long \number
2: .long 0x80010070
 .endm
 SC r_clear,0x143
 SC r_print,0x150
 SC r_display,0x28
 SC r_getkey,0x90f
 SC r_quit,0x494
 SC r_malloc,0xacd
 SC r_free,0xacc
 SC r_version,0x15
 SC r_open,0x42c
 SC r_close,0x42d
 SC r_size,0x42f
 SC r_read,0x432
 SC r_seek,0x431
 SC r_create,0x434
 SC r_write,0x435
 SC r_ticks,0x3b
 SC r_sleep,0x420
 SC r_timer_install,0x118
 SC r_timer_remove,0x119
 SC r_timer_start,0x11a
 SC r_timer_stop,0x11b

 SC r_reset,0x236
 SC r_find_first,0x43b
 SC r_find_next,0x43c
 SC r_find_close,0x43d
