 .section .resident.text,"ax"
 .align 2
 .global _resident_gateway
_resident_gateway:
 /* Capture the original stack, including stack-passed syscall arguments.
  * Frame offsets are asserted in C. Preserve the real syscall's r0/r1. */
 add #-56,r15
 mov.l r0,@r15
 mov.l r1,@(4,r15)
 mov.l r2,@(8,r15)
 mov.l r3,@(12,r15)
 mov.l r4,@(16,r15)
 mov.l r5,@(20,r15)
 mov.l r6,@(24,r15)
 mov.l r7,@(28,r15)
 sts pr,r0
 mov.l r0,@(32,r15)
 stc sr,r0
 mov.l r0,@(36,r15)
 mov.l r0,@(44,r15)
 sts mach,r0
 mov.l r0,@(48,r15)
 sts macl,r0
 mov.l r0,@(52,r15)
 mov r15,r0
 add #56,r0
 mov.l r0,@(40,r15)
 mov.l .Ldispatch,r0
 jsr @r0
 mov r15,r4
 mov.l @(32,r15),r0
 lds r0,pr
 mov.l @(48,r15),r0
 lds r0,mach
 mov.l @(52,r15),r0
 lds r0,macl
 mov.l @(44,r15),r0
 ldc r0,sr
 mov.l @(4,r15),r1
 mov.l @(8,r15),r2
 mov.l @(12,r15),r3
 mov.l @(16,r15),r4
 mov.l @(20,r15),r5
 mov.l @(24,r15),r6
 mov.l @(28,r15),r7
 mov.l @r15,r0
 rts
 add #56,r15
 .align 2
.Ldispatch: .long _resident_dispatch

 .global _resident_os_call
_resident_os_call:
 sts.l pr,@-r15
 mov.l r8,@-r15
 mov r4,r8
 /* At most 12 arguments in the reviewed syscall inventory: four in
  * registers and eight on stack. Never overwrite the saved guest frame. */
 add #-32,r15
 mov.l @(40,r8),r1
 mov r15,r2
 mov #8,r3
1: mov.l @r1+,r0
 mov.l r0,@r2
 add #4,r2
 dt r3
 bf 1b
 mov.l @(16,r8),r4
 mov.l @(20,r8),r5
 mov.l @(24,r8),r6
 mov.l @(28,r8),r7
 mov.l @(48,r8),r0
 lds r0,mach
 mov.l @(52,r8),r0
 lds r0,macl
 mov.l @(36,r8),r0
 ldc r0,sr
 mov.l .Lreal,r2
 mov.l @r8,r0
 jsr @r2
 nop
 mov.l r0,@r8
 mov.l r1,@(4,r8)
 mov.l r2,@(8,r8)
 mov.l r3,@(12,r8)
 mov.l r4,@(16,r8)
 mov.l r5,@(20,r8)
 mov.l r6,@(24,r8)
 mov.l r7,@(28,r8)
 sts mach,r0
 mov.l r0,@(48,r8)
 sts macl,r0
 mov.l r0,@(52,r8)
 stc sr,r0
 mov.l r0,@(44,r8)
 add #32,r15
 mov.l @r15+,r8
 lds.l @r15+,pr
 rts
 nop
 .align 2
.Lreal: .long 0x80010070
