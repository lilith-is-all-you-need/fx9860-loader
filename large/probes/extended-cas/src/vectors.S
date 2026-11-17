 .section .resident.text,"ax"
 .balign 256
 .global _map_vectors
_map_vectors:
 .space 0x100
 /* General faults are deliberately fail-stop, with the offending PC saved. */
 stc spc,r4
 mov.l .Lfatal_general,r0
 jsr @r0
 nop
 .align 2
.Lfatal_general: .long _resident_fatal
 .org _map_vectors+0x400
 sts.l pr,@-r15
 sts.l mach,@-r15
 sts.l macl,@-r15
 stc.l gbr,@-r15
 mov.l .Ltea,r4
 mov.l @r4,r4
 mov.l .Lrefill,r0
 jsr @r0
 nop
 tst r0,r0
 bt .Lbad
 ldc.l @r15+,gbr
 lds.l @r15+,macl
 lds.l @r15+,mach
 lds.l @r15+,pr
 rte
 nop
.Lbad:
 mov.l .Ltea,r4
 mov.l @r4,r4
 mov.l .Lfatal,r0
 jsr @r0
 nop
 .align 2
.Ltea: .long 0xff00000c
.Lrefill: .long _resident_refill
.Lfatal: .long _resident_fatal
 .org _map_vectors+0x600
 stc spc,r4
 mov.l .Lfatal_irq,r0
 jsr @r0
 nop
 .align 2
.Lfatal_irq: .long _resident_fatal
