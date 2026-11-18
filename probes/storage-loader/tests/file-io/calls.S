 .section .text.entry,"ax"
 .global _start
_start:
 mov.l .Lmain,r0
 jmp @r0
 nop
 .align 2
.Lmain: .long _main

 .text
 .macro os_call name,number
 .align 2
 .global _\name
_\name:
 mov.l 1f,r2
 mov.l 2f,r0
 jmp @r2
 nop
 .align 2
1: .long 0x80010070
2: .long \number
 .endm
 os_call fx_open,0x42c
 os_call fx_close,0x42d
 os_call fx_size,0x42f
 os_call fx_seek,0x431
 os_call fx_read,0x432
 os_call fx_write,0x435
 os_call wait_key,0x90f
