    .section .text.entry,"ax"
    .align 2
    .global _start
_start:
    sts.l pr,@-r15
    mov.l .Lload,r0
    mov.l .Ldata,r1
    mov.l .Ldend,r2
1:  cmp/hs r2,r1
    bt 2f
    mov.l @r0+,r3
    mov.l r3,@r1
    bra 1b
    add #4,r1
2:  mov.l .Lbss,r1
    mov.l .Lbend,r2
    mov #0,r0
3:  cmp/hs r2,r1
    bt 4f
    mov.l r0,@r1
    bra 3b
    add #4,r1
4:  mov.l .Lsize,r0
    mov.l .Lsizeword,r1
    mov.l r0,@r1
    mov.l .Lmain,r0
    jsr @r0
    nop
    lds.l @r15+,pr
    rts
    nop
    .align 2
.Lload: .long _data_load
.Ldata: .long _data_begin
.Ldend: .long _data_end
.Lbss: .long _bss_begin
.Lbend: .long _bss_end
.Lmain: .long _main
.Lsize: .long _ram_used
.Lsizeword: .long 0x08100000
