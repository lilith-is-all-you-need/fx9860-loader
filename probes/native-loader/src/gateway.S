 .section .resident.text,"ax"
 .align 2
 .global _resident_gateway
_resident_gateway:
 stc sr,r1
 mov.l .Lquit,r2
 cmp/eq r2,r0
 bt 1f
 mov.l .Lreal,r2
 ldc r1,sr
 jmp @r2
 nop
1:
 mov.l .Lcapture,r2
 ldc r1,sr
 jmp @r2
 nop
 .align 2
.Lquit: .long 0x494
.Lreal: .long 0x80010070
.Lcapture: .long _resident_register_quit
