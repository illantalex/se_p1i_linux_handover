@echo off
rem Builds regprobe.ldd + regprobe.exe with the UIQ 3.1 SDK (GCCE).
rem Symbian tools need the source on the SDK's drive, so this runs from the
rem junction C:\p1\linux_handover -> E:\projects\p1\linux_handover.
setlocal
set EPOCROOT=\Symbian\UIQ3.1SDK\
rem Header dependency scanning chokes on GCC 3.4's path escaping; touch sources to rebuild.
set SYMBIANBUILD_DEPENDENCYOFF=1
set PATH=C:\Symbian\UIQ3.1SDK\epoc32\gcc\bin;F:\Perl\bin;C:\Symbian\UIQ3.1SDK\epoc32\tools;C:\Program Files (x86)\Common Files\Symbian\tools;C:\Program Files (x86)\CSL Arm Toolchain\bin;%SystemRoot%\system32;%SystemRoot%
cd /d C:\p1\linux_handover\group
call bldmake bldfiles || exit /b 1
cd /d C:\p1\linux_handover\group
rem With dependency scanning off, an .mmp-only change (UID, capability, includes) does not
rem relink -- the old binary survives. Pass "clean" to force a full rebuild in that case.
if /i "%~1"=="clean" (
	call .\ABLD.BAT reallyclean gcce urel
	cd /d C:\p1\linux_handover\group
)
call .\ABLD.BAT build gcce urel
