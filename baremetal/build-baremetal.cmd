@echo off
setlocal

rem Build the bare-metal Linux handover stub (ARM926EJ-S, no libc).
if not "%TOOLCHAIN_BIN%"=="" set "PATH=%TOOLCHAIN_BIN%;%PATH%"
set TOOL=arm-none-eabi

where %TOOL%-as >nul 2>nul
if errorlevel 1 (
	echo ERROR: %TOOL%-as not found.
	echo Set TOOLCHAIN_BIN to your GNU Arm toolchain bin folder and rerun.
	echo Example: set TOOLCHAIN_BIN=C:\ArmGNU\bin
	exit /b 1
)

%TOOL%-as -mcpu=arm926ej-s -o handover_stub.o handover_stub.S || exit /b 1
%TOOL%-ld -T linker.ld -nostdlib -o handover_stub.elf handover_stub.o || exit /b 1
%TOOL%-objcopy -O binary handover_stub.elf handover_stub.bin || exit /b 1
%TOOL%-objdump -D handover_stub.elf > handover_stub.lst || exit /b 1

echo Built:
echo   handover_stub.elf
echo   handover_stub.bin
echo   handover_stub.lst

rem If a kernel (zImage with the DTB appended) is next to us, append it to the stub.
rem The stub jumps to whatever follows it if it carries the zImage magic, else it parks.
if exist zImage-p1i (
	copy /b handover_stub.bin + zImage-p1i p1i_linux.bin >nul || exit /b 1
	echo   p1i_linux.bin  ^(stub + zImage-p1i^)
)
