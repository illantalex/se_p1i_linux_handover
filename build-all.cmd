@echo off
rem build-all.cmd -- build everything for linux_handover in one go:
rem   1. the bare-metal handover stub + p1i_linux.bin (arm-none-eabi)
rem   2. the Symbian LDD + test exe + handover LDD + handover test (UIQ 3.1 SDK, GCCE)
rem   3. the self-signed SIS package
rem
rem Symbian tools require the source on the SDK's drive, so this ensures the
rem junction C:\p1\linux_handover -> E:\projects\p1\linux_handover exists first.
rem
rem Usage:
rem   build-all.cmd              build all three stages
rem   build-all.cmd nobaremetal  skip the bare-metal payload (no arm-none-eabi toolchain)
rem   build-all.cmd clean        force a full Symbian rebuild (needed after .mmp-only edits,
rem                              e.g. UID/capability/include changes, which otherwise do not relink)
setlocal
set PROJ=%~dp0
if "%PROJ:~-1%"=="\" set PROJ=%PROJ:~0,-1%

echo === Ensuring junction C:\p1\linux_handover exists
if not exist C:\p1\linux_handover (
	if not exist C:\p1 mkdir C:\p1 || exit /b 1
	mklink /J C:\p1\linux_handover "%PROJ%" || exit /b 1
) else (
	echo     already present
)

if /i "%~1"=="nobaremetal" goto symbian

echo.
echo === Stage 1/3: bare-metal payload
pushd "%PROJ%\baremetal"
call build-baremetal.cmd || (popd & echo FAILED: bare-metal build & exit /b 1)
popd

:symbian
echo.
echo === Stage 2/3: Symbian LDD + test exe + handover LDD + handover test
set "SYMARG="
if /i "%~1"=="clean" set "SYMARG=clean"
call "%PROJ%\build.cmd" %SYMARG% || (echo FAILED: Symbian build & exit /b 1)

echo.
echo === Stage 3/3: SIS package
call "%PROJ%\sis\makesis.cmd" || (echo FAILED: SIS packaging & exit /b 1)

echo.
echo === All done
echo   baremetal\handover_stub.bin
echo   \Symbian\UIQ3.1SDK\epoc32\release\armv5\urel\regprobe.ldd
echo   \Symbian\UIQ3.1SDK\epoc32\release\armv5\urel\regprobe.exe
echo   \Symbian\UIQ3.1SDK\epoc32\release\armv5\urel\linuxhandover.ldd
echo   \Symbian\UIQ3.1SDK\epoc32\release\armv5\urel\linuxhandover.exe
echo   sis\linuxhandover.sisx
endlocal
