@echo off
rem Packs and self-signs linuxhandover.sisx (run build.cmd first).
rem The key/cert are a throwaway development pair, created on first run.
setlocal
set EPOCROOT=\Symbian\UIQ3.1SDK\
set PATH=F:\Perl\bin;C:\Symbian\UIQ3.1SDK\epoc32\tools;%SystemRoot%\system32;%SystemRoot%
cd /d C:\p1\linux_handover\sis
rem Use explicit .exe: cwd holds makesis.cmd (this file), so a bare `makesis`
rem would re-invoke this script instead of the SDK tool -> SETLOCAL recursion.
if not exist p1dev.key (
	makekeys.exe -cert -expdays 3650 -password p1dev -len 1024 -dname "CN=P1 dev OU=linuxhandover CO=XX" p1dev.key p1dev.cer || exit /b 1
)
makesis.exe linuxhandover.pkg linuxhandover.sis || exit /b 1
signsis.exe -s linuxhandover.sis linuxhandover.sisx p1dev.cer p1dev.key p1dev || exit /b 1
signsis.exe -o linuxhandover.sisx
