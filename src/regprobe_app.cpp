// regprobe_app.cpp
// Loads regprobe.ldd, logs the UART/clock registers, brings UART5 up and sends a test
// pattern out of SP2663. Log goes to C:\regprobe.log (root of C:, which X-plore only shows
// with system files enabled) and, once UART5 is up, out of UART5 as well.
//
// Run order matters: the safe reads come first, the writes next, and the large clock-block
// dump last, so if an unexpected abort reboots the phone the log already has the rest.
//
// Baud: the divisor assumes PERIPH_CLK = 13 MHz (13e6 / 16 / 7 = 116071, 115200 -0.75 %).
// If the analyzer sees a different rate, measure one bit of the 'U' (0x55) run:
// clock = 16 * 7 / bit_time. Then fix KDivisor.

#include <e32base.h>
#include <f32file.h>
#include <hal.h>
#include "regprobe.h"

_LIT(KLogFile, "C:\\regprobe.log");
_LIT(KRomDumpDir, "D:\\other\\");
_LIT(KRomDumpFile, "D:\\other\\rom.bin");   // Z: as mapped, for reverse engineering
const TUint32 KRomSizeMax = 0x04000000;          // sanity limit for the size in the header

const TUint32 KU5ClkX1Y1 = (1 << 8) | 1;   // UART clock = PERIPH_CLK * 1 / 1
const TUint32 KDivisor   = 7;
const TUint32 KLcr8N1    = 0x03;
const TUint32 KFcrEnable = 0x07;           // FIFO on, clear RX and TX FIFOs
const TInt KRepeats = 3;
const TUint32 KScanStep = 0x10000;         // linear→physical map granularity: 64 KB
const TInt KGapUs = 100000;

const TInt KBacklogSize = 4096;

// Writes each line to the log file and, once UART5 is up, to UART5 as well. Lines logged
// before that are kept in a backlog and sent by UartReady().
class TLog
	{
public:
	TLog(RFile& aFile, RRegProbe& aProbe) : iFile(aFile), iProbe(aProbe), iUart(EFalse) {}
	void Line(TRefByValue<const TDesC8> aFmt, ...)
		{
		VA_LIST list;
		VA_START(list, aFmt);
		TBuf8<160> buf;
		buf.FormatList(aFmt, list);
		buf.Append(_L8("\r\n"));
		iFile.Write(buf);
		iFile.Flush();   // keep what we have if the phone resets
		if (iUart)
			Send(buf);
		else if (iBacklog.Length() + buf.Length() <= iBacklog.MaxLength())
			iBacklog.Append(buf);
		}
	void UartReady()
		{
		iUart = ETrue;
		Send(iBacklog);
		iBacklog.Zero();
		}
private:
	void Send(const TDesC8& aData)
		{
		for (TInt at = 0; at < aData.Length(); at += KMaxUartWrite)
			iProbe.UartWrite(aData.Mid(at, Min(KMaxUartWrite, aData.Length() - at)));
		}
private:
	RFile& iFile;
	RRegProbe& iProbe;
	TBool iUart;
	TBuf8<KBacklogSize> iBacklog;
	};

static void Reg(RRegProbe& aProbe, TLog& aLog, const TDesC8& aName, TUint32 aPhys)
	{
	TUint32 v = 0;
	TInt r = aProbe.Peek(aPhys, v);
	if (r == KErrNone)
		aLog.Line(_L8("%-14S %08x = %08x"), &aName, aPhys, v);
	else
		aLog.Line(_L8("%-14S %08x : error %d"), &aName, aPhys, r);
	}

// Reads IER/IIR/LCR/LSR, then DLL/DLM through DLAB, restoring LCR. Skips RBR (read pops RX).
static void DumpUart(RRegProbe& aProbe, TLog& aLog, const TDesC8& aName, TUint32 aBase)
	{
	TUint32 ier = 0, iir = 0, lcr = 0, lsr = 0, dll = 0, dlm = 0;
	TInt r = aProbe.Peek(aBase + KUartIerDlm, ier);
	if (r != KErrNone)
		{
		aLog.Line(_L8("%S %08x: error %d"), &aName, aBase, r);
		return;
		}
	aProbe.Peek(aBase + KUartIirFcr, iir);
	aProbe.Peek(aBase + KUartLcr, lcr);
	aProbe.Peek(aBase + KUartLsr, lsr);
	aProbe.Poke(aBase + KUartLcr, lcr | KLcrDlab);
	aProbe.Peek(aBase + KUartRbrThrDll, dll);
	aProbe.Peek(aBase + KUartIerDlm, dlm);
	aProbe.Poke(aBase + KUartLcr, lcr);
	aLog.Line(_L8("%S %08x: IER %02x IIR %02x LCR %02x LSR %02x DL %04x"),
	          &aName, aBase, ier & 0xFF, iir & 0xFF, lcr & 0xFF, lsr & 0xFF,
	          ((dlm & 0xFF) << 8) | (dll & 0xFF));
	}

static void DumpBlock(RRegProbe& aProbe, TLog& aLog, TUint32 aPhys, TInt aWords)
	{
	TUint32 buf[KMaxPeekWords];
	for (TInt done = 0; done < aWords; done += KMaxPeekWords)
		{
		TInt n = Min(aWords - done, KMaxPeekWords);
		TUint32 at = aPhys + 4 * done;
		TInt r = aProbe.PeekBlock(at, buf, n);
		if (r != KErrNone)
			{
			aLog.Line(_L8("block %08x: error %d"), at, r);
			return;
			}
		for (TInt i = 0; i < n; i += 4)
			aLog.Line(_L8("%08x: %08x %08x %08x %08x"), at + 4 * i,
			          buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
		}
	}

// Same as DumpBlock, for kernel linear addresses (only use addresses known to be kernel data:
// a mapped page in a no-access domain would still fault).
static void DumpVirt(RRegProbe& aProbe, TLog& aLog, const TDesC8& aName, TUint32 aLin,
                     TInt aWords)
	{
	TUint32 buf[64];
	aWords = Min(aWords, 64);
	TInt r = aProbe.PeekVirt(aLin, buf, aWords);
	aLog.Line(_L8("-- %S @ %08x (%d words): %d"), &aName, aLin, aWords, r);
	if (r != KErrNone)
		return;
	for (TInt i = 0; i + 3 < aWords; i += 4)
		aLog.Line(_L8("%08x: %08x %08x %08x %08x"), aLin + 4 * i,
		          buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
	}

static void Hal(TLog& aLog, const TDesC8& aName, HALData::TAttribute aAttr)
	{
	TInt v = 0;
	TInt r = HAL::Get(aAttr, v);
	aLog.Line(_L8("HAL %-14S %d (0x%x) r=%d"), &aName, v, v, r);
	}

// Prints the linear→physical map as runs of linearly mapped 64 KB blocks.
static void MemoryMap(RRegProbe& aProbe, TLog& aLog)
	{
	TUint32 buf[KMaxPeekWords];
	TUint32 runLin = 0, runPhys = KPhysInvalid, runLen = 0;
	const TInt KBlocks = 0x10000;   // 4 GB / 64 KB
	for (TInt done = 0; done <= KBlocks; done += KMaxPeekWords)
		{
		TInt n = done < KBlocks ? KMaxPeekWords : 0;
		if (n && aProbe.LinToPhys(done * KScanStep, KScanStep, buf, n) != KErrNone)
			{
			aLog.Line(_L8("LinToPhys failed at %08x"), done * KScanStep);
			return;
			}
		for (TInt i = 0; i <= n; ++i)
			{
			TBool end = (i == n);
			if (end && done < KBlocks)
				break;   // continue the run into the next batch
			TUint32 lin = (done + i) * KScanStep;
			TUint32 phys = end ? KPhysInvalid : buf[i];
			if (runLen && phys == runPhys + runLen && phys != KPhysInvalid)
				{
				runLen += KScanStep;
				continue;
				}
			if (runLen)
				aLog.Line(_L8("  lin %08x-%08x -> phys %08x-%08x %6d KB"),
				          runLin, runLin + runLen - 1, runPhys, runPhys + runLen - 1, runLen >> 10);
			runLin = lin;
			runPhys = phys;
			runLen = (phys == KPhysInvalid) ? 0 : KScanStep;
			}
		}
	}

static void Survey(RRegProbe& aProbe, TLog& aLog)
	{
	aLog.Line(_L8("== cpu"));
	TCpuRegs c;
	TInt r = aProbe.CpuRegs(c);
	aLog.Line(_L8("CpuRegs: %d"), r);
	aLog.Line(_L8("MainId %08x CacheType %08x TCM %08x"), c.iMainId, c.iCacheType, c.iTcmStatus);
	aLog.Line(_L8("Control %08x TTBR %08x DACR %08x FCSE %08x CPSR %08x"),
	          c.iControl, c.iTtbr, c.iDacr, c.iFcsePid, c.iCpsr);

	aLog.Line(_L8("== hal"));
	Hal(aLog, _L8("MachineUid"), HALData::EMachineUid);
	Hal(aLog, _L8("CPUSpeed kHz"), HALData::ECPUSpeed);
	Hal(aLog, _L8("CPUArch"), HALData::ECPUArch);
	Hal(aLog, _L8("MemoryRAM"), HALData::EMemoryRAM);
	Hal(aLog, _L8("MemoryRAMFree"), HALData::EMemoryRAMFree);
	Hal(aLog, _L8("MemoryROM"), HALData::EMemoryROM);
	Hal(aLog, _L8("PageSize"), HALData::EMemoryPageSize);

	aLog.Line(_L8("== kernel"));
	TKernelInfo k;
	r = aProbe.KernelInfo(k);
	aLog.Line(_L8("KernelInfo: %d"), r);
	aLog.Line(_L8("SuperPage %08x RomHeader %08x MachineConfig %08x channel %08x"),
	          k.iSuperPage, k.iRomHeader, k.iMachineConfig, k.iChannel);
	TUint32 p[4];
	TUint32 lins[4] = { k.iSuperPage, k.iRomHeader, k.iMachineConfig, k.iChannel };
	for (TInt i = 0; i < 4; ++i)
		{
		aProbe.LinToPhys(lins[i], 0, &p[i], 1);
		aLog.Line(_L8("  %08x -> phys %08x"), lins[i], p[i]);
		}

	aLog.Line(_L8("== memory map (64 KB granularity)"));
	MemoryMap(aProbe, aLog);

	aLog.Line(_L8("== kernel structures"));
	DumpVirt(aProbe, aLog, _L8("SuperPage"), k.iSuperPage, 64);
	// SSuperPageBase (layout confirmed by iCpuId at +0x40): +0x14 iRamBootData (SRamBank
	// list: base, size, terminated by size 0), +0x18 iRomBootData, +0x2C iMachineData
	TUint32 sp[12];
	if (aProbe.PeekVirt(k.iSuperPage, sp, 12) == KErrNone)
		{
		DumpVirt(aProbe, aLog, _L8("RamBootData"), sp[5], 32);
		DumpVirt(aProbe, aLog, _L8("RomBootData"), sp[6], 32);
		DumpVirt(aProbe, aLog, _L8("MachineData"), sp[11], 64);
		}
	DumpVirt(aProbe, aLog, _L8("MachineConfig"), k.iMachineConfig, 64);
	DumpVirt(aProbe, aLog, _L8("RomHeader"), k.iRomHeader, 64);

	// The HS timer (KPhysHsTimer) is not read: its clock is off (TIMCLK_CTRL 0x400040BC bit 1 = 0)
	// and reading an unclocked block aborts (KERN-EXEC 3 on the 2026-10-08 run).
	aLog.Line(_L8("== watchdog, timers"));
	aLog.Line(_L8("-- WDT"));
	DumpBlock(aProbe, aLog, KPhysWatchdog, 8);
	aLog.Line(_L8("-- MSTIM"));
	DumpBlock(aProbe, aLog, KPhysMsTimer, 16);

	aLog.Line(_L8("== interrupt controllers (ER RSR SR APR / ATR ITR)"));
	aLog.Line(_L8("-- MIC"));
	DumpBlock(aProbe, aLog, KPhysMic, 8);
	aLog.Line(_L8("-- SIC1"));
	DumpBlock(aProbe, aLog, KPhysSic1, 8);
	aLog.Line(_L8("-- SIC2"));
	DumpBlock(aProbe, aLog, KPhysSic2, 8);
	}

// The core ROM image (Z:) exactly as the kernel maps it, to the memory card. Files copied off
// Z: lack the tail of their code (e.g. dspextension.dll's shared-area offset table), the
// mapped image does not. The ROM header holds its own linear address (iRomBase) followed by
// the size; unmapped pages, if any, are written as zeros.
static void RomDump(RRegProbe& aProbe, TLog& aLog, RFs& aFs)
	{
	aLog.Line(_L8("== rom dump"));
	TKernelInfo k;
	TUint32 h[64];
	if (aProbe.KernelInfo(k) != KErrNone || aProbe.PeekVirt(k.iRomHeader, h, 64) != KErrNone)
		{
		aLog.Line(_L8("no ROM header"));
		return;
		}
	TEntry existing;
	if (aFs.Entry(KRomDumpFile, existing) == KErrNone)
		{
		aLog.Line(_L8("rom.bin already on the card, not dumped again"));
		return;
		}
	TUint32 base = 0, size = 0;
	for (TInt i = 16; i < 63; ++i)
		if (h[i] == k.iRomHeader && h[i + 1] > 0x100000 && h[i + 1] <= KRomSizeMax)
			{
			base = h[i];
			size = h[i + 1];
			aLog.Line(_L8("RomHeader word %d: base %08x size %08x"), i, base, size);
			break;
			}
	if (!size)
		{
		aLog.Line(_L8("ROM base/size not found in the header"));
		return;
		}
	aFs.MkDirAll(KRomDumpDir);
	RFile f;
	TInt r = f.Replace(aFs, KRomDumpFile, EFileWrite);
	if (r != KErrNone)
		{
		aLog.Line(_L8("rom.bin: %d"), r);
		return;
		}
	TUint32 buf[KMaxPeekWords];
	TPtrC8 out((const TUint8*)buf, sizeof(buf));
	TInt holes = 0;
	for (TUint32 at = base; at < base + size; at += sizeof(buf))
		{
		if (aProbe.PeekVirt(at, buf, KMaxPeekWords) != KErrNone)
			{
			Mem::FillZ(buf, sizeof(buf));
			++holes;
			}
		r = f.Write(out);
		if (r != KErrNone)
			{
			aLog.Line(_L8("rom.bin write at %08x: %d"), at, r);
			break;
			}
		if (((at - base) & 0xFFFFF) == 0)
			aLog.Line(_L8("rom dump %08x"), at);
		}
	f.Close();
	aLog.Line(_L8("rom dump done: %d unreadable blocks of %d bytes"), holes, sizeof(buf));

	// The DSP driver's state: global object (shared buffer at +0x1B8) and the shared-area
	// offset table at the end of dspextension.dll's code.
	TUint32 obj = 0;
	if (aProbe.PeekVirt(0x64011CE0, &obj, 1) == KErrNone && obj)
		{
		DumpVirt(aProbe, aLog, _L8("dspextension object"), obj, 64);
		DumpVirt(aProbe, aLog, _L8("dspextension object +0x100"), obj + 0x100, 64);
		}
	DumpVirt(aProbe, aLog, _L8("dspextension tail"), 0xF83729D0, 32);
	}

// The DSP while Symbian plays sound: its host-port registers (not REP0-2, reading clears
// them), the audio clock registers, and the shared buffer three times one second apart, to
// D:\other\dspshared1..3.bin. The shared buffer holds the parameter blocks of the last
// messages (use case at 0x810) and the PCM areas, so the snapshots show which area streams.
static void DspSnapshot(RRegProbe& aProbe, TLog& aLog, RFs& aFs)
	{
	aLog.Line(_L8("== dsp snapshot"));
	static const TUint16 apbp[] = { 0x08, 0x0C, 0x10, 0x14, 0x1C, 0x20, 0x28, 0x30 };
	for (TUint i = 0; i < sizeof(apbp) / sizeof(apbp[0]); ++i)
		{
		TUint32 v = 0;
		aProbe.Peek(0x400C0000 + apbp[i], v);
		aLog.Line(_L8("APBP+%02x %04x"), apbp[i], v & 0xFFFF);
		}
	aLog.Line(_L8("-- AUDIOCONFIG 0x400E8000"));
	DumpBlock(aProbe, aLog, 0x400E8000, 0x80 / 4);

	TUint32 obj = 0, shared = 0, phys = KPhysInvalid;
	if (aProbe.PeekVirt(0x64011CE0, &obj, 1) != KErrNone || !obj ||
	    aProbe.PeekVirt(obj + 0x1B8, &shared, 1) != KErrNone || !shared)
		{
		aLog.Line(_L8("no dspextension shared buffer"));
		return;
		}
	aProbe.LinToPhys(shared, 0, &phys, 1);
	aLog.Line(_L8("shared buffer: linear %08x physical %08x"), shared, phys);

	TBuf<32> name;
	TUint32 buf[KMaxPeekWords];
	TPtrC8 out((const TUint8*)buf, sizeof(buf));
	for (TInt n = 1; n <= 3; ++n)
		{
		name.Format(_L("D:\\other\\dspshared%d.bin"), n);
		RFile f;
		if (f.Replace(aFs, name, EFileWrite) != KErrNone)
			continue;
		for (TUint32 off = 0; off < 0x6000; off += sizeof(buf))
			{
			if (aProbe.PeekVirt(shared + off, buf, KMaxPeekWords) != KErrNone)
				Mem::FillZ(buf, sizeof(buf));
			f.Write(out);
			}
		f.Close();
		TUint32 sem = 0;
		aProbe.Peek(0x400C001C, sem);
		aLog.Line(_L8("snapshot %d written, SEM %04x"), n, sem & 0xFFFF);
		User::After(1000000);
		}
	}

static TInt Run(RRegProbe& aProbe, TLog& aLog, RFs& aFs)
	{
	aLog.Line(_L8("== before"));
	Reg(aProbe, aLog, _L8("UART_CTRL"), KPhysUartCtrl);
	Reg(aProbe, aLog, _L8("UART_CLKMODE"), KPhysUartClkMode);
	Reg(aProbe, aLog, _L8("UART_LOOP"), KPhysUartLoop);
	Reg(aProbe, aLog, _L8("U3CLK"), KPhysU3Clk);
	Reg(aProbe, aLog, _L8("U4CLK"), KPhysU3Clk + 4);
	Reg(aProbe, aLog, _L8("U5CLK"), KPhysU5Clk);
	Reg(aProbe, aLog, _L8("U6CLK"), KPhysU3Clk + 12);
	Reg(aProbe, aLog, _L8("UARTCLK_CTRL"), KPhysUartClkCtrl);
	DumpUart(aProbe, aLog, _L8("UART3"), KPhysUart3);
	DumpUart(aProbe, aLog, _L8("UART4"), KPhysUart4);
	DumpUart(aProbe, aLog, _L8("UART5"), KPhysUart5);
	DumpUart(aProbe, aLog, _L8("UART6"), KPhysUart6);

	aLog.Line(_L8("== bring-up"));
	TUint32 v = 0;
	aProbe.Peek(KPhysUartClkCtrl, v);
	aProbe.Poke(KPhysUartClkCtrl, v | KUartClkCtrlU5);
	aProbe.Peek(KPhysUartClkMode, v);
	v = (v & ~(3u << KUart5ClkModeShift)) | (KClkModeOn << KUart5ClkModeShift);
	aProbe.Poke(KPhysUartClkMode, v);
	aProbe.Poke(KPhysU5Clk, KU5ClkX1Y1);
	aProbe.Poke(KPhysUart5 + KUartIerDlm, 0);                 // IER: no interrupts
	aProbe.Poke(KPhysUart5 + KUartLcr, KLcr8N1 | KLcrDlab);
	aProbe.Poke(KPhysUart5 + KUartRbrThrDll, KDivisor & 0xFF);
	aProbe.Poke(KPhysUart5 + KUartIerDlm, KDivisor >> 8);
	aProbe.Poke(KPhysUart5 + KUartLcr, KLcr8N1);
	aProbe.Poke(KPhysUart5 + KUartIirFcr, KFcrEnable);
	aLog.UartReady();   // from here on the log is mirrored to UART5, backlog first
	Reg(aProbe, aLog, _L8("UART_CLKMODE"), KPhysUartClkMode);
	Reg(aProbe, aLog, _L8("U5CLK"), KPhysU5Clk);
	Reg(aProbe, aLog, _L8("UARTCLK_CTRL"), KPhysUartClkCtrl);
	DumpUart(aProbe, aLog, _L8("UART5"), KPhysUart5);

	aLog.Line(_L8("== transmit"));
	TBuf8<64> msg;
	for (TInt i = 0; i < KRepeats; ++i)
		{
		msg.Format(_L8("UUUUUUUU P1i UART5 %d\r\n"), i);
		TInt r = aProbe.UartWrite(msg);
		if (i == 0 || r != msg.Length())
			aLog.Line(_L8("write %d -> %d"), i, r);
		if (r < 0)
			break;
		User::After(KGapUs);
		}
	DumpUart(aProbe, aLog, _L8("UART5"), KPhysUart5);

	aLog.Line(_L8("== clock block"));
	DumpBlock(aProbe, aLog, KPhysClkBase, 0x100 / 4);   // 256 bytes, aliased above that

	DspSnapshot(aProbe, aLog, aFs);
	Survey(aProbe, aLog);
	RomDump(aProbe, aLog, aFs);
	aLog.Line(_L8("== done"));
	return KErrNone;
	}

static void MainL()
	{
	RFs fs;
	User::LeaveIfError(fs.Connect());
	CleanupClosePushL(fs);
	RFile file;
	User::LeaveIfError(file.Replace(fs, KLogFile, EFileWrite | EFileShareAny));
	CleanupClosePushL(file);
	RRegProbe probe;
	TLog log(file, probe);
	TBuf8<64> name;
	name.Copy(KLogFile);
	log.Line(_L8("log file: %S"), &name);

	TInt r = User::LoadLogicalDevice(KRegProbeLddFile);
	log.Line(_L8("LoadLogicalDevice: %d"), r);
	if (r != KErrNone && r != KErrAlreadyExists)
		User::Leave(r);
	r = probe.Open();
	log.Line(_L8("Open: %d"), r);
	User::LeaveIfError(r);
	CleanupClosePushL(probe);

	Run(probe, log, fs);

	CleanupStack::PopAndDestroy(3, &fs);   // probe, file, fs
	}

GLDEF_C TInt E32Main()
	{
	__UHEAP_MARK;
	CTrapCleanup* cleanup = CTrapCleanup::New();
	TRAPD(err, MainL());
	delete cleanup;
	__UHEAP_MARKEND;
	return err;
	}
