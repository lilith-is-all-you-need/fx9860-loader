 .section .text.entry,"ax"
 .global _start
_start:
 mov.l .Lmain,r0
 jmp @r0
 nop
 .align 2
.Lmain: .long _main
