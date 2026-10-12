ENTRY(_start)

SECTIONS
{
    /*
     * Place image in SDRAM where Symbian handover payloads are expected.
     * Adjust if your loader copies to a different physical address.
     */
    . = 0x80600000;

    .text : {
        *(.text*)
        *(.rodata*)
    }

    .data : {
        *(.data*)
    }

    .bss : {
        *(.bss*)
        *(COMMON)
    }
}
