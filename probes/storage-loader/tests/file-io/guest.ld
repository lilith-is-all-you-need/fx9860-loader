OUTPUT_ARCH(sh)
ENTRY(_start)
MEMORY { rom (rx) : ORIGIN = 0x00300200, LENGTH = 128K
         ram (rw) : ORIGIN = 0x08100004, LENGTH = 8188 }
SECTIONS {
 .text : { KEEP(*(.text.entry)) *(.text .text.*) *(.rodata .rodata.*) } > rom
 .data : { *(.data .data.*) } > ram AT>rom
 .bss (NOLOAD) : { *(.bss .bss.* COMMON) } > ram
 /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
