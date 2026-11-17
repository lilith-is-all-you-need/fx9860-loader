 .section .resident.text,"ax"
 .balign 256
 .global _map_vectors
_map_vectors:
 .space 0x100
1: bra 1b
 nop
 .space 0x2fc
 /* TLB exception entry at VBR+0x400. r0-r7 are the exception bank. */
 sts.l pr,@-r15
 sts.l mach,@-r15
 sts.l macl,@-r15
 stc.l gbr,@-r15
 mov.l .Ltea,r4
 mov.l @r4,r4
 mov.l .Lrefill,r0
 jsr @r0
 nop
 ldc.l @r15+,gbr
 lds.l @r15+,macl
 lds.l @r15+,mach
 lds.l @r15+,pr
 rte
 nop
 .align 2
.Ltea: .long 0xff00000c
.Lrefill: .long _resident_refill
