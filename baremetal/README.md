# Bare-metal Linux handover stub (P1i / PNX4008)

`handover_stub.S` is the first code that runs after the Symbian handover LDD gives up the
machine. It is entered with the MMU still on, inside an identity-mapped section, and:

1. masks IRQ/FIQ, cleans the D-cache, turns the MMU, caches and write buffer off;
2. masks MIC/SIC1/SIC2 and stops the watchdog;
3. brings up UART5 and UART6 at 115200 8N1 (UART6 with its IrDA modulator bypassed and
   the IrDA inversion/half-duplex bits in `UART_CTRL` cleared) and prints on both;
4. runs a line-level test on UART6 TX (2 s idle, 6 s break, twice) for a multimeter;
5. dumps interrupt-controller, MSTIM and UART control registers, including the THRE test
   that identified the UART interrupt lines;
6. jumps to the zImage appended after it (`r0` = 0, `r1` = ~0, `r2` = 0; the DTB is
   appended to the zImage), or parks if there is none.

See `../README.md` for how the pieces fit together.

## Files

- `handover_stub.S`: the stub (position independent; `kernel:` marks where the zImage goes)
- `linker.ld`: links at `0x80600000` (the LDD loads it wherever `Epoc::AllocPhysicalRam` says)
- `build-baremetal.cmd`: builds `handover_stub.elf/.bin/.lst` with `arm-none-eabi-*`, and
  `p1i_linux.bin` = stub + `zImage-p1i` if that file is present

On Linux, `../build-linux.sh` does the same as stage 1.

## Expected UART6 output

At 115200 8N1 on UART6 (pads of the removed IrDA module `H2660`: pin 3 TX, pin 2 RX):

```text
BAREMETAL UART5+6 OK
BAREMETAL UART5+6 OK
MIC  ER (os)  ...
...
zImage found, booting Linux
```

followed by the kernel log and a shell on ttyS0.

## Running it

1. Copy `zImage-p1i` (zImage + DTB, from `p1i_kernel/build`) here and build; this gives
   `p1i_linux.bin`.
2. Copy `p1i_linux.bin` to `D:\other\p1i_linux.bin` on the phone (`handover_stub.bin`
   under that name runs the stub alone).
3. Install `../sis/linuxhandover.sisx` and run `linuxhandover.exe`. It loads
   `linuxhandover.ldd`, reads the payload, and hands over. **It does not return**; `reboot`
   from Linux (watchdog reset) brings Symbian back.
