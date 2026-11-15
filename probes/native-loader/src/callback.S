 .section .resident.text,"ax"
 .align 2
 .global _resident_quit_entry
_resident_quit_entry:
 sts.l pr,@-r15
 mov.l .Lcontext,r0
 mov.l @r0,r4
 mov.l .Lwork,r0
 jsr @r0
 nop
 lds.l @r15+,pr
 mov.l .Lcontext,r0
 mov.l @r0,r4
 mov.l @r4,r0
 /* Mappings have been restored. Tail-call original ROM to release RAM;
  * there must be no return into the allocation being freed. */
 jmp @r0
 nop
 .align 2
.Lcontext: .long _resident_context
.Lwork: .long _resident_quit_work
