OUTPUT_ARCH(sh)
ENTRY(_start)
MEMORY { rom (rx) : ORIGIN = 0x00300200, LENGTH = 512K
         ram (rw) : ORIGIN = 0x08100004, LENGTH = 8188 }
SECTIONS {
 .entry : { KEEP(*(.text.entry)) } > rom
 .resident ALIGN(32) : {
  _resident_begin = .;
  *resident.c.obj(.text .text.* .rodata .rodata.* .data .data.*)
  *(.resident.text)
  . = ALIGN(4); _resident_end = .;
 } > rom
 .text : { *(.text .text.*) *(.rodata .rodata.*) } > rom
 .fixups ALIGN(4) : { _resident_fixups = .; LONG(0); . += 4092; } > rom
 .data : { _data_begin = .; *(.data .data.*) . = ALIGN(4); _data_end = .; } > ram AT>rom
 _data_load = LOADADDR(.data);
 .bss (NOLOAD) : { _bss_begin = .; *(.bss .bss.* COMMON) . = ALIGN(4); _bss_end = .; } > ram
 _ram_used = _bss_end - 0x08100000;
 /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
 ASSERT(SIZEOF(.data)+SIZEOF(.bss)==0,"loader must not retain static RAM")
}
