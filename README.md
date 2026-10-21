# Linux handover for the Sony Ericsson P1i

Boots a mainline Linux kernel on a **Sony Ericsson P1i** (UIQ 3 / Symbian OS 9.1, NXP PNX4008,
ARM926EJ-S) from a running Symbian, with no reflashing. A Symbian app hands the whole
machine to a small bare-metal stub, which starts the kernel. `reboot` in Linux resets the
phone back into Symbian.

## What works in Linux

Linux 6.1 with a BusyBox initramfs, built from the companion kernel repository
[se_p1i_linux](https://github.com/illantalex/se_p1i_linux):

- framebuffer console on the phone's display, and a shell on it typed on the QWERTZ keypad
  (jog dial = Up/Down, jog press = Enter)
- display and keypad backlights, camera-flash LED as a torch
- interrupts, tickless timer, I2C, GPIO, watchdog reboot into Symbian
- sound (ALSA, headphones): Linux cannot start a stream on the audio DSP yet, so the app
  plays silence through Symbian's audio API and hands over with that stream running
- the FM radio (Si4703): with `D:\other\nostream.txt` on the card the app leaves the DSP
  alone, so start Symbian's FM radio first; Linux then tunes it and the ALSA control
  `Audio Source` switches between the radio and ALSA playback
- serial console on UART6 (needs soldering, see below); not needed for the display console

The display is not initialised by Linux: it keeps the display controller and panel exactly as
Symbian left them, which is why the handover has to start from a running Symbian.

## How it works

1. **`linuxhandover.exe`** reads the payload from `D:\other\p1i_linux.bin` (the Memory
   Stick), flushes and finalises all drives so no FAT is left dirty, and calls the LDD.
2. **`linuxhandover.ldd`** (kernel side) copies the payload into physically contiguous RAM
   (`Epoc::AllocPhysicalRam`), identity-maps it, disables interrupts and jumps to it with
   the MMU still on.
3. **`baremetal/handover_stub.S`** turns the MMU, caches and watchdog off, masks all
   interrupts, sets up UART5/UART6 and the I2C clocks, prints a register dump on the UARTs,
   and jumps to the zImage appended after it.
4. The **kernel** (zImage with its device tree appended) takes it from there.

`p1i_linux.bin` = `handover_stub.bin` + `zImage-p1i`. The payload limit is 4 MB.

The app does not return; to get back to Symbian, run `reboot` in Linux or pull the battery.

## Requirements

- A P1i with the **platform security hack** applied: the package is self-signed and needs
  the `CommDD` and `DiskAdmin` capabilities, which only a hacked phone accepts.
- A Memory Stick Micro (M2) for the payload.
- A kernel image `zImage-p1i` built with [se_p1i_linux](https://github.com/illantalex/se_p1i_linux).

## Installing and running

1. Install `sis/linuxhandover.sisx` (built below). An older version may have to be
   uninstalled first.
2. Copy `p1i_linux.bin` to `D:\other\p1i_linux.bin`.
3. Start **Linux handover** from the menu. The screen keeps Symbian's last picture until the
   kernel's framebuffer console takes over; then the boot log scrolls up and a shell appears.

## Building

Two parts, built separately:

- **Bare-metal stub and payload**: `arm-none-eabi-as`/`ld`/`objcopy`. Put `zImage-p1i` in
  `baremetal/`, then run `./build-linux.sh payload` (or `baremetal\build-baremetal.cmd` on
  Windows). Output: `baremetal/p1i_linux.bin`.
- **Symbian app, LDDs and SIS**: UIQ 3.1 SDK with GCCE (CSL ARM toolchain), plus:
  - kernel headers: `kernel/eka/include` from
    [SymbianSource/oss.FCL.sf.os.kernelhwsrv](https://github.com/SymbianSource/oss.FCL.sf.os.kernelhwsrv),
    copied as a whole to `\epoc32\include\khs` and patched with `lib/khs-kernel-9.1.patch`
    (two vtable slots and a field that the 9.1 kernel does not have);
  - `ekern.dso` generated from `lib/ekern91.def` (the 770 ordinals the phone's kernel
    exports):
    `elf2e32 --definput=lib\ekern91.def --dso=\epoc32\release\armv5\lib\ekern.dso --linkas=ekern{000a0000}[100041af].exe`;
  - `lib/ksrt2_2.lib` (`ucppinit_aeabi.o` + `dllexp.o` from the SDK's `usrt2_2.lib`) copied to
    `\epoc32\release\armv5\urel\` and `udeb\`, which the GCCE kernel-side build links against.

  On Windows, `build-all.cmd` builds all three stages. The sources must be reachable as
  `C:\p1\linux_handover`; the script creates that junction.

  On Linux, `build-linux.sh` runs the same Windows build scripts under wine:
  - a wine prefix (default `~/.wine-symbian`) with `C:\Symbian\UIQ3.1SDK` and
    `C:\Program Files (x86)\CSL Arm Toolchain` copied from a Windows install;
  - ActivePerl 5.6.1 reachable as drive `F:` (set `PERL_DRIVE` to the directory holding
    `Perl\`);
  - two root symlinks, because the GCCE makefiles pass `/Symbian/...` and `/p1/...` paths
    that wine reads as Unix paths (the script prints the exact commands when they are missing);
  - `epoc32\gcc\bin\cpp.exe` must be the SDK's original Cygwin one. (On Windows 11 that one
    crashes and has to be replaced by a wrapper forwarding to the CSL toolchain's
    preprocessor; under wine it is the wrapper that does not run.)

  `./build-linux.sh` builds everything, `./build-linux.sh payload` only the payload, and
  `./build-linux.sh clean` forces a full Symbian rebuild (needed after header-only or
  `.mmp`-only changes). `makesis.cmd` creates a throwaway signing key pair
  (`sis/p1dev.key`, not tracked) on first use.

## regprobe

`regprobe.exe` + `regprobe.ldd` peek and poke physical registers from Symbian. They were
used to map the hardware before Linux ran (UART, interrupt and clock registers);
`regprobe.log` is one of those runs. Both are in the same package.

Modes, picked by a file in `D:\other\` on the memory card:

- `ramdump.txt`: write all of Symbian's RAM to `D:\other\ram_<base>.bin` (about 123 MB),
  e.g. to find BServer's table of modem objects;
- `dsptrace.txt`: trace the DSP host port and audio block for 90 s while sound starts (at the lowest
  priority, so other apps such as the FM radio can be started meanwhile);
- none: the register survey, DSP snapshots and a ROM dump (`D:\other\rom.bin`, once).

## Serial console (optional)

The kernel log and a shell are also on **UART6** at 115200 8N1. UART6 is the IrDA UART:
remove the IrDA module (`H2660`) and use its pads: pin 3 = phone TX, pin 2 = phone RX, pulled
up to the 2.8 V IrDA supply, so use a USB-serial adapter with 2.8-3.3 V logic levels. The stub
bypasses the IrDA modulator. UART5 is brought up too and was the first console, but its
pads are hard to reach.

## Status and caveats

This is a hobby bring-up, not a product. The phone's GSM baseband, audio codec, camera,
USB, Wi-Fi and Memory Stick are not supported in Linux yet. Writing to the Memory Stick from
Symbian right before the handover is safe (the app finalises all drives), but use a card you
can afford to lose.

## Licence

MIT, see [LICENSE](LICENSE). `lib/ekern91.def` lists the phone kernel's export ordinals, and
`lib/khs-kernel-9.1.patch` applies to the EPL-licensed Symbian kernel headers.
