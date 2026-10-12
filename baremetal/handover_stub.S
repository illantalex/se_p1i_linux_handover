.syntax unified
.cpu arm926ej-s
.arm

/*
 * P1i / PNX4008 bare-metal Linux handover stub (runs between the Symbian LDD and Linux).
 * Sequence follows NOTES.md handover requirements:
 * 1) mask IRQ/FIQ in CPSR
 * 2) disable MIC/SIC1/SIC2 enables
 * 3) stop watchdog
 * 4) set up UART5 clocking + 115200 8N1
 * 5) clean/invalidate caches, then disable MMU + I/D cache
 * 6) transmit a test string by polling UART5 LSR, then dump interrupt controller and
 *    MSTIM registers (to identify the MSTIM interrupt line for Linux)
 * UART6 (the IrDA UART, used as a plain UART with the modulator bypassed) is brought up
 * next to UART5 and all output goes to both. The dump also finds both UARTs' interrupt
 * lines by enabling each one's THRE interrupt and comparing MIC/SIC RAW.
 * 7) if a zImage is appended at `kernel' (see build-baremetal.cmd), jump to it;
 *    otherwise park
 */

.global _start
.type _start, %function

/* Clock/power and UART registers (from NOTES.md / LPC32xx-compatible layout). */
.equ MIC_BASE,            0x40008000
.equ SIC1_BASE,           0x4000C000
.equ SIC2_BASE,           0x40010000
.equ WDT_BASE,            0x4003C000
.equ UART_CTRL_BASE,      0x40054000
.equ UART_CLKMODE,        0x40054004
.equ U5CLK,               0x400040D8
.equ U6CLK,               0x400040DC
.equ UARTCLK_CTRL,        0x400040E4
.equ UART5_BASE,          0x40090000
.equ UART6_BASE,          0x40098000

/* UART 16550 offsets (4-byte stride). */
.equ UART_RBR_THR_DLL,    0x00
.equ UART_IER_DLM,        0x04
.equ UART_IIR_FCR,        0x08
.equ UART_LCR,            0x0C
.equ UART_LSR,            0x14

/* Bits and constants. */
.equ UART5_CLKCTRL_BIT,   (1 << 2)      /* UARTCLK_CTRL bit 2 */
.equ UART5_CLKMODE_SHIFT, 8             /* UART_CLKMODE[9:8] */
.equ UART6_CLKCTRL_BIT,   (1 << 3)      /* UARTCLK_CTRL bit 3 */
.equ UART6_CLKMODE_SHIFT, 10            /* UART_CLKMODE[11:10] */
.equ UART6_IRDA_BYPASS,   (1 << 5)      /* UART_CTRL: plain UART instead of IrDA pulses */
/* UART_CTRL bits that would still bend UART6 in bypass mode (LPC32xx names): 1-2 IrDA
   pulse width, 3-4 IRTX6 inversion, 9 half duplex, 10 IRRX6 inversion. */
.equ UART6_IR_BITS_LO,    0x1E
.equ UART6_IR_BITS_HI,    0x600
.equ LCR_BREAK,           0x40
.equ TICKS_HIGH,          (2 * 32768)   /* level test: 2 s idle (line high) ... */
.equ TICKS_LOW,           (6 * 32768)   /* ... then 6 s break (line low) */
.equ IER_THRE,            0x02
.equ UART6_WAIT,          0x10000       /* poll budget per UART6 character */
.equ CLKMODE_ON,          1
.equ U5CLK_X1Y1,          ((1 << 8) | 1)
.equ LCR_8N1,             0x03
.equ LCR_DLAB,            0x80
.equ FCR_ENABLE,          0x07
.equ DIVISOR_115200,      7             /* 13 MHz / 16 / 7 ~= 116071 */
.equ LSR_THRE,            0x20
.equ LSR_TEMT,            0x40
.equ ZIMAGE_MAGIC,        0x016f2818    /* zImage header word at offset 0x24 */

/* Interrupt controller registers (MIC/SIC1/SIC2 share the layout). */
.equ IC_ER,               0x00          /* enable */
.equ IC_RAW,              0x04          /* raw status */
.equ IC_POL,              0x0C          /* 1 = active high / rising */
.equ IC_TYPE,             0x10          /* 1 = edge */

/* Millisecond timer (LPC32xx layout) and timer clock gates. */
.equ MSTIM_BASE,          0x40034000
.equ MSTIM_INT,           0x00          /* bit 0/1 = match 0/1 flag, write 1 to clear */
.equ MSTIM_CTRL,          0x04
.equ MSTIM_COUNTER,       0x08
.equ MSTIM_MCTRL,         0x14
.equ MSTIM_MATCH0,        0x18
.equ TIMCLK_CTRL,         0x400040BC

.equ NREGS,               31            /* words in regsave, labels in reglabels */
.equ MSTIM_WAIT,          0x400000      /* poll budget for a match flag, roughly 1 s */

_start:
    /* The handover LDD enters here with the MMU still ON and an identity (VA==PA) mapping
       covering this code, so disabling the MMU below leaves PC valid. All device-register
       access must therefore come AFTER the MMU is off (physical addressing). */

    /* 1) Disable IRQ and FIQ at CPU level.
       ARM926EJ-S is ARMv5TE and has no CPS instruction, so set the
       CPSR I (bit 7) and F (bit 6) masks directly. */
    mrs r0, cpsr
    orr r0, r0, #0xC0
    msr cpsr_c, r0

    /* 2) Clean/invalidate cache, then disable MMU + I-cache + D-cache. Done first, while PC
          is in the identity-mapped region, so it stays valid as the MMU goes off. */
    /* ARM926 has no single "clean+invalidate entire D-cache" op (c7,c14,0 is not
       implemented); use the test, clean and invalidate loop until Z says clean. */
1:  mrc p15, 0, APSR_nzcv, c7, c14, 3        /* test, clean & invalidate D cache */
    bne 1b
    mov r2, #0
    mcr p15, 0, r2, c7, c10, 4               /* drain write buffer */
    mcr p15, 0, r2, c7, c5, 0                /* invalidate I cache */

    mrc p15, 0, r3, c1, c0, 0                /* SCTLR */
    bic r3, r3, #(1 << 0)                    /* MMU off */
    bic r3, r3, #(1 << 1)                    /* A: alignment faults off (Symbian left it on;
                                                with low vectors a fault would hang silently) */
    bic r3, r3, #(1 << 2)                    /* D-cache off */
    bic r3, r3, #(1 << 12)                   /* I-cache off */
    bic r3, r3, #(1 << 3)                    /* write buffer off */
    bic r3, r3, #(1 << 13)                   /* normal vectors */
    mcr p15, 0, r3, c1, c0, 0

    /* Pipeline sync after CP15 control change. */
    mov r2, r2
    mov r2, r2
    mov r2, r2

    /* 3) Mask interrupt enables in MIC/SIC1/SIC2 (ER @ +0x00). Physical from here on.
          Save the enables Symbian left first: they show which lines it was using. */
    adrl r7, regsave
    mov r1, #0

    ldr r0, =MIC_BASE
    ldr r2, [r0, #IC_ER]
    str r2, [r7, #0]
    str r1, [r0, #IC_ER]

    ldr r0, =SIC1_BASE
    ldr r2, [r0, #IC_ER]
    str r2, [r7, #4]
    str r1, [r0, #IC_ER]

    ldr r0, =SIC2_BASE
    ldr r2, [r0, #IC_ER]
    str r2, [r7, #8]
    str r1, [r0, #IC_ER]

    /* 4) Stop watchdog: clear WDTIM_CTRL at +0x04. */
    ldr r0, =WDT_BASE
    str r1, [r0, #0x04]

    /* 5) Bring up UART5 and UART6 clocking and line format. Save what Symbian left in
          UART_CTRL/UART_CLKMODE first (regsave 22, 23). */
    adrl r7, regsave
    ldr r0, =UART_CTRL_BASE
    ldr r2, [r0]
    str r2, [r7, #88]
    ldr r2, [r0, #4]
    str r2, [r7, #92]

    ldr r0, =UARTCLK_CTRL
    ldr r2, [r0]
    orr r2, r2, #(UART5_CLKCTRL_BIT | UART6_CLKCTRL_BIT)
    str r2, [r0]

    ldr r0, =UART_CLKMODE
    ldr r2, [r0]
    bic r2, r2, #(3 << UART5_CLKMODE_SHIFT)
    bic r2, r2, #(3 << UART6_CLKMODE_SHIFT)
    orr r2, r2, #(CLKMODE_ON << UART5_CLKMODE_SHIFT)
    orr r2, r2, #(CLKMODE_ON << UART6_CLKMODE_SHIFT)
    str r2, [r0]

    ldr r2, =U5CLK_X1Y1
    ldr r0, =U5CLK
    str r2, [r0]
    ldr r0, =U6CLK
    str r2, [r0]

    ldr r0, =UART_CTRL_BASE
    ldr r2, [r0]
    bic r2, r2, #UART6_IR_BITS_LO
    bic r2, r2, #UART6_IR_BITS_HI
    orr r2, r2, #UART6_IRDA_BYPASS
    str r2, [r0]

    ldr r0, =UART6_BASE
    bl  uart_init
    mov r12, r0                               /* r12 = UART6 for the rest of the stub */
    ldr r0, =UART5_BASE
    bl  uart_init                             /* r0 = UART5 for the rest of the stub */

    /* 6) Send test string from bare metal context.
       Use adr (PC-relative): the handover LDD loads this blob at an
       arbitrary physical address, not its 0x80600000 link address, so an
       absolute `ldr r4,=message' would point into the wrong memory. */
    adr r4, message
    bl  puts

    /* 6a) Line-level test for a multimeter on UART6 TX (IrDA module pin 3), twice:
           2 s idle, then 6 s break. Reads mostly 2.8 V with 0 V dips -> UART6 drives the
           pin normally; mostly 0 V with 2.8 V blips -> it is inverted; a constant level ->
           UART6 is not reaching the pin (or the stub never got here). */
    mov r9, #2
7:  ldr r3, [r12, #UART_LCR]
    bic r3, r3, #LCR_BREAK
    str r3, [r12, #UART_LCR]
    ldr r2, =TICKS_HIGH
    bl  wait_ticks
    ldr r3, [r12, #UART_LCR]
    orr r3, r3, #LCR_BREAK
    str r3, [r12, #UART_LCR]
    ldr r2, =TICKS_LOW
    bl  wait_ticks
    subs r9, r9, #1
    bne 7b
    ldr r3, [r12, #UART_LCR]
    bic r3, r3, #LCR_BREAK
    str r3, [r12, #UART_LCR]
    adr r4, message
    bl  puts

    /* 6b) Register dump. Everything is read into regsave first and printed afterwards,
           so the slow UART output does not skew the timing-sensitive reads. */
    adrl r7, regsave

    ldr r8, =MIC_BASE
    ldr r2, [r8, #IC_RAW]
    str r2, [r7, #12]
    ldr r2, [r8, #IC_POL]
    str r2, [r7, #16]
    ldr r2, [r8, #IC_TYPE]
    str r2, [r7, #20]

    ldr r8, =SIC1_BASE
    ldr r2, [r8, #IC_RAW]
    str r2, [r7, #24]
    ldr r2, [r8, #IC_POL]
    str r2, [r7, #28]
    ldr r2, [r8, #IC_TYPE]
    str r2, [r7, #32]

    ldr r8, =SIC2_BASE
    ldr r2, [r8, #IC_RAW]
    str r2, [r7, #36]
    ldr r2, [r8, #IC_POL]
    str r2, [r7, #40]
    ldr r2, [r8, #IC_TYPE]
    str r2, [r7, #44]

    ldr r8, =MSTIM_BASE
    ldr r2, [r8, #MSTIM_INT]
    str r2, [r7, #48]
    ldr r2, [r8, #MSTIM_CTRL]
    str r2, [r7, #52]
    ldr r2, [r8, #MSTIM_COUNTER]
    str r2, [r7, #56]
    ldr r2, [r8, #MSTIM_MCTRL]
    str r2, [r7, #60]
    ldr r2, [r8, #MSTIM_MATCH0]
    str r2, [r7, #64]
    ldr r2, =TIMCLK_CTRL
    ldr r2, [r2]
    str r2, [r7, #68]

    /* Find MSTIM's MIC line: wait for a match flag, then read MIC RAW, clear the flag
       and read RAW again. The bit that drops is the line. "MSTIM wait" = 0 means
       no flag was ever raised (match interrupt off, or timer stopped). */
    ldr r9, =MIC_BASE
    ldr r11, =MSTIM_WAIT
1:  ldr r2, [r8, #MSTIM_INT]
    tst r2, #3
    bne 2f
    subs r11, r11, #1
    bne 1b
2:  ldr r2, [r9, #IC_RAW]
    mov r3, #3
    str r3, [r8, #MSTIM_INT]
    ldr r3, [r9, #IC_RAW]
    ldr r10, [r8, #MSTIM_INT]
    str r2, [r7, #72]
    str r3, [r7, #76]
    str r10, [r7, #80]
    str r11, [r7, #84]

    /* Find the UARTs' interrupt lines: with an empty transmitter, enabling the THRE
       interrupt asserts the UART's line at once. RAW base vs. RAW u5thre/u6thre shows
       which bit moves (MIC bit 27 may also toggle: that is MSTIM). */
    ldr r9, =MIC_BASE
    ldr r10, =SIC1_BASE
    ldr r11, =SIC2_BASE
    ldr r2, [r9, #IC_RAW]
    str r2, [r7, #96]
    ldr r2, [r10, #IC_RAW]
    str r2, [r7, #108]
    ldr r2, [r11, #IC_RAW]
    str r2, [r7, #116]

    mov r3, #IER_THRE
    str r3, [r0, #UART_IER_DLM]
    mov r2, #0x100
4:  subs r2, r2, #1
    bne 4b
    ldr r2, [r9, #IC_RAW]
    str r2, [r7, #100]
    mov r3, #0
    str r3, [r0, #UART_IER_DLM]

    mov r3, #IER_THRE
    str r3, [r12, #UART_IER_DLM]
    mov r2, #0x100
4:  subs r2, r2, #1
    bne 4b
    ldr r2, [r9, #IC_RAW]
    str r2, [r7, #104]
    ldr r2, [r10, #IC_RAW]
    str r2, [r7, #112]
    ldr r2, [r11, #IC_RAW]
    str r2, [r7, #120]
    mov r3, #0
    str r3, [r12, #UART_IER_DLM]

    adrl r8, reglabels
    mov r9, #0
3:  mov r4, r8
    bl  puts
    ldr r1, [r7, r9, lsl #2]
    bl  puthex
    add r8, r8, #16
    add r9, r9, #1
    cmp r9, #NREGS
    blo 3b

    /* 7) Hand over to an appended zImage, if there is one. Nothing needs copying: the
          decompressor runs from any RAM address, unpacks to 0x80008000 (AUTO_ZRELADDR)
          and moves itself first if it overlaps that, taking the appended DTB along.
          Without a zImage the word below is whatever follows the stub in its last page;
          a read of it is harmless. */
    adrl r7, kernel
    ldr r5, [r7, #0x24]
    ldr r6, =ZIMAGE_MAGIC
    cmp r5, r6
    beq 6f
    adrl r4, msg_nokernel
    b   park

6:  adrl r4, msg_kernel
    bl  puts

    /* Linux boot protocol: SVC mode, MMU and D-cache off, IRQ/FIQ masked (all done
       above), r0 = 0, r1 = machine type (unused with DT), r2 = 0 (no DTB pointer, so
       the decompressor uses the one appended to the zImage). */
    mov r0, #0
    mvn r1, #0
    mov r2, #0
    bx  r7

park:
    bl  puts
5:  b 5b

/* Send the byte in \ch to UART5 (r0) and, if it is ready within UART6_WAIT polls, to
   UART6 (r12): a dead UART6 must not hang the stub. Clobbers r6, r11. */
.macro PUTC ch
.Lw5\@:
    ldr r6, [r0, #UART_LSR]
    tst r6, #LSR_THRE
    beq .Lw5\@
    str \ch, [r0, #UART_RBR_THR_DLL]
    mov r11, #UART6_WAIT
.Lw6\@:
    ldr r6, [r12, #UART_LSR]
    tst r6, #LSR_THRE
    bne .Lok6\@
    subs r11, r11, #1
    bne .Lw6\@
    b   .Ldone\@
.Lok6\@:
    str \ch, [r12, #UART_RBR_THR_DLL]
.Ldone\@:
.endm

/* Print the NUL-terminated string at r4 on UART5 and UART6 and wait until it has fully
   left both shift registers (UART6 with a time limit). Clobbers r4-r6, r11. */
puts:
1:  ldrb r5, [r4], #1
    cmp r5, #0
    beq 2f
    PUTC r5
    b 1b
2:  ldr r6, [r0, #UART_LSR]
    tst r6, #LSR_TEMT
    beq 2b
    mov r11, #UART6_WAIT
3:  ldr r6, [r12, #UART_LSR]
    tst r6, #LSR_TEMT
    bxne lr
    subs r11, r11, #1
    bne 3b
    bx  lr

/* Print r1 as 8 hex digits and CRLF on UART5 and UART6. Clobbers r1-r6, r11. */
puthex:
    mov r3, #8
1:  mov r2, r1, lsr #28
    cmp r2, #10
    addlo r2, r2, #'0'
    addhs r2, r2, #('a' - 10)
    PUTC r2
    mov r1, r1, lsl #4
    subs r3, r3, #1
    bne 1b
    adr r4, crlf
    b   puts                                  /* tail call: returns to our caller */

/* Busy-wait r2 ticks of the free-running 32.768 kHz MSTIM counter. Clobbers r2, r3, r6. */
wait_ticks:
    ldr r6, =MSTIM_BASE
    ldr r3, [r6, #MSTIM_COUNTER]
    add r2, r2, r3
1:  ldr r3, [r6, #MSTIM_COUNTER]
    subs r3, r3, r2
    bmi 1b
    bx  lr

/* Program the 16550 at r0 for 115200 8N1 with FIFOs, interrupts off. Clobbers r2. */
uart_init:
    mov r2, #0
    str r2, [r0, #UART_IER_DLM]               /* IER off */
    mov r2, #(LCR_8N1 | LCR_DLAB)
    str r2, [r0, #UART_LCR]
    mov r2, #DIVISOR_115200
    str r2, [r0, #UART_RBR_THR_DLL]           /* DLL */
    mov r2, #0
    str r2, [r0, #UART_IER_DLM]               /* DLM */
    mov r2, #LCR_8N1
    str r2, [r0, #UART_LCR]
    mov r2, #FCR_ENABLE
    str r2, [r0, #UART_IIR_FCR]
    bx  lr

.size _start, . - _start

.ltorg

.align 4
message:
    .asciz "BAREMETAL UART5+6 OK\r\n"
msg_kernel:
    .asciz "zImage found, booting Linux\r\n"
msg_nokernel:
    .asciz "no zImage appended, parking\r\n"
crlf:
    .asciz "\r\n"

/* Labels for regsave, one per word, each padded to 16 bytes. */
.macro REGLABEL text
1:  .asciz "\text"
    .space 16 - (. - 1b)
.endm
.align 4
reglabels:
    REGLABEL "MIC  ER (os)  "
    REGLABEL "SIC1 ER (os)  "
    REGLABEL "SIC2 ER (os)  "
    REGLABEL "MIC  RAW      "
    REGLABEL "MIC  POL      "
    REGLABEL "MIC  TYPE     "
    REGLABEL "SIC1 RAW      "
    REGLABEL "SIC1 POL      "
    REGLABEL "SIC1 TYPE     "
    REGLABEL "SIC2 RAW      "
    REGLABEL "SIC2 POL      "
    REGLABEL "SIC2 TYPE     "
    REGLABEL "MSTIM INT     "
    REGLABEL "MSTIM CTRL    "
    REGLABEL "MSTIM COUNTER "
    REGLABEL "MSTIM MCTRL   "
    REGLABEL "MSTIM MATCH0  "
    REGLABEL "TIMCLK_CTRL   "
    REGLABEL "MIC RAW before"
    REGLABEL "MIC RAW after "
    REGLABEL "MSTIM INT clr "
    REGLABEL "MSTIM wait    "
    REGLABEL "UART_CTRL (os)"
    REGLABEL "UART_CLKMODE  "
    REGLABEL "MIC RAW base  "
    REGLABEL "MIC RAW u5thre"
    REGLABEL "MIC RAW u6thre"
    REGLABEL "SIC1 RAW base "
    REGLABEL "SIC1 RAW u6   "
    REGLABEL "SIC2 RAW base "
    REGLABEL "SIC2 RAW u6   "

.align 2
regsave:
    .space NREGS * 4

/* The zImage is concatenated right after this; 64-byte aligned (see build-baremetal.cmd). */
.balign 64
kernel:
