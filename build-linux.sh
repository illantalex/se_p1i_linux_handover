#!/bin/sh
# build-linux.sh -- Linux counterpart of build-all.cmd: same three stages, same outputs.
#   1. the bare-metal handover stub + p1i_linux.bin (native arm-none-eabi)
#   2. the Symbian LDDs + test exes (UIQ 3.1 SDK, GCCE) -- build.cmd under wine
#   3. the self-signed SIS package                     -- sis/makesis.cmd under wine
#
# The wine prefix mirrors the Windows layout build.cmd/makesis.cmd hardcode, so they run
# unchanged:
#   C:\Symbian\UIQ3.1SDK                    SDK, copied from the Windows install
#   C:\Program Files (x86)\CSL Arm Toolchain  GCCE, copied from the Windows install
#   C:\Program Files (x86)\Common Files\Symbian\tools
#   C:\p1\linux_handover -> this directory      (symlink, replaces the mklink /J junction)
#   F:\Perl          -> $PERL_DRIVE/Perl     ActivePerl 5.6.1
#
# Usage:
#   ./build-linux.sh              build all three stages
#   ./build-linux.sh nobaremetal  skip the bare-metal payload
#   ./build-linux.sh payload      only the bare-metal payload (new kernel, app unchanged)
#   ./build-linux.sh clean        force a full Symbian rebuild (after .mmp-only edits)
set -e

PROJ=$(cd "$(dirname "$0")" && pwd)
export WINEPREFIX="${WINEPREFIX:-$HOME/.wine-symbian}"
export WINEDEBUG="${WINEDEBUG:--all}"
PERL_DRIVE="${PERL_DRIVE:-/media/illantalex/Media}"   # holds Perl\ (F: on Windows)

echo "=== Checking wine prefix $WINEPREFIX"
if [ ! -d "$WINEPREFIX/drive_c/Symbian/UIQ3.1SDK/epoc32" ]; then
	echo "SDK missing: copy C:\\Symbian\\UIQ3.1SDK and the CSL Arm Toolchain into $WINEPREFIX/drive_c first" >&2
	exit 1
fi
if [ ! -f "$WINEPREFIX/system.reg" ]; then
	wineboot -i
fi
ln -sfn "$PERL_DRIVE" "$WINEPREFIX/dosdevices/f:"
mkdir -p "$WINEPREFIX/drive_c/p1"
ln -sfn "$PROJ" "$WINEPREFIX/drive_c/p1/linux_handover"

# GCCE makefiles hand the compiler drive-relative paths with forward slashes
# (/p1/linux_handover/src/..., -include /Symbian/UIQ3.1SDK/EPOC32/..., __PRODUCT_INCLUDE__),
# and wine reads a leading '/' as a Unix path. Root symlinks make those resolve; wine
# matches Unix paths case-insensitively, so EPOC32/INCLUDE finds epoc32/include.
if [ "$(readlink /Symbian)" != "$WINEPREFIX/drive_c/Symbian" ] ||
   [ "$(readlink /p1)" != "$WINEPREFIX/drive_c/p1" ]; then
	echo "Missing root symlinks for wine's Unix-path view of the build. Run once:" >&2
	echo "  sudo ln -sfn '$WINEPREFIX/drive_c/Symbian' /Symbian" >&2
	echo "  sudo ln -sfn '$WINEPREFIX/drive_c/p1' /p1" >&2
	exit 1
fi

if [ "$1" != "nobaremetal" ]; then
	echo
	echo "=== Stage 1/3: bare-metal payload"
	cd "$PROJ/baremetal"
	arm-none-eabi-as -mcpu=arm926ej-s -o handover_stub.o handover_stub.S
	arm-none-eabi-ld -T linker.ld -nostdlib -o handover_stub.elf handover_stub.o
	arm-none-eabi-objcopy -O binary handover_stub.elf handover_stub.bin
	arm-none-eabi-objdump -D handover_stub.elf > handover_stub.lst
	if [ -f zImage-p1i ]; then
		cat handover_stub.bin zImage-p1i > p1i_linux.bin
		echo "  p1i_linux.bin (stub + zImage-p1i)"
	fi
fi
[ "$1" = "payload" ] && exit 0

echo
echo "=== Stage 2/3: Symbian LDD + test exe + handover LDD + handover test"
SYMARG=
[ "$1" = "clean" ] && SYMARG=clean
cd "$WINEPREFIX/drive_c"
wine cmd /c 'C:\p1\linux_handover\build.cmd' $SYMARG
# abld's exit status does not survive cmd /c, so check instead that every target is newer
# than its own source, its .mmp and the shared headers; otherwise stage 3 would quietly
# package the previous binaries. (Dependency scanning is off in build.cmd, so a header-only
# change needs "clean" to rebuild -- this check then says so.)
UREL="$WINEPREFIX/drive_c/Symbian/UIQ3.1SDK/epoc32/release/gcce/urel"
for spec in regprobe.ldd:regprobe_ldd regprobe.exe:regprobe_app \
            linuxhandover.ldd:linuxhandover_ldd:linuxhandover \
            linuxhandover.exe:linuxhandover_app; do
	t=${spec%%:*}; rest=${spec#*:}; src=${rest%%:*}; mmp=${rest#*:}
	NEWEST=$(ls -t "$PROJ/src/$src.cpp" "$PROJ/group/$mmp.mmp" "$PROJ"/inc/* | head -n 1)
	if [ ! "$UREL/$t" -nt "$NEWEST" ]; then
		echo "FAILED: $t is missing or older than $NEWEST (see errors above;" \
		     "after a header-only change run with 'clean')" >&2
		exit 1
	fi
done

echo
echo "=== Stage 3/3: SIS package"
wine cmd /c 'C:\p1\linux_handover\sis\makesis.cmd'

echo
echo "=== All done"
echo "  baremetal/handover_stub.bin"
echo "  $WINEPREFIX/drive_c/Symbian/UIQ3.1SDK/epoc32/release/gcce/urel/*.ldd *.exe"
echo "  sis/linuxhandover.sisx"
