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

// dspcontrolldd's channel object while Symbian plays sound, to D:\other\dspchan<n>.bin. Each
// of its 49 requests has a fixed 24-byte DSP message slot at +0xAC + 24 * request (type byte
// at +8, p0/p1 halfwords at +0xC/+0xE) that keeps the last message sent, so the dump shows
// which messages the audio server used and with which parameters. Found in the kernel heap
// by its vtables, set by the constructor at 0xF83735B8: +0 0xF83760BC, +0x50 0xF8376114.
static void DspChannelScan(RRegProbe& aProbe, TLog& aLog, RFs& aFs)
	{
	aLog.Line(_L8("== dspcontrolldd channel scan"));
	const TUint32 KHeapStart = 0x64000000, KHeapEnd = 0x65000000;
	const TUint32 KVtbl = 0xF83760BC, KVtbl2 = 0xF8376114;
	const TInt KObjWords = 0x800 / 4;
	TUint32 buf[KMaxPeekWords], obj[KObjWords];
	TPtrC8 out((const TUint8*)obj, sizeof(obj));
	TInt found = 0;
	for (TUint32 blk = KHeapStart; blk < KHeapEnd && found < 4; blk += KScanStep)
		{
		TUint32 phys = KPhysInvalid;
		if (aProbe.LinToPhys(blk, 0, &phys, 1) != KErrNone || phys == KPhysInvalid)
			continue;
		for (TUint32 at = blk; at < blk + KScanStep && found < 4; at += sizeof(buf))
			{
			if (aProbe.PeekVirt(at, buf, KMaxPeekWords) != KErrNone)
				continue;
			for (TInt i = 0; i < KMaxPeekWords && found < 4; ++i)
				{
				if (buf[i] != KVtbl)
					continue;
				TUint32 o = at + 4 * i;
				if (aProbe.PeekVirt(o, obj, KMaxPeekWords) != KErrNone ||
				    aProbe.PeekVirt(o + 4 * KMaxPeekWords, obj + KMaxPeekWords,
				                    KObjWords - KMaxPeekWords) != KErrNone ||
				    obj[0x50 / 4] != KVtbl2)
					continue;
				++found;
				TBuf<32> name;
				name.Format(_L("D:\\other\\dspchan%d.bin"), found);
				RFile f;
				TInt r = f.Replace(aFs, name, EFileWrite);
				if (r == KErrNone)
					{
					r = f.Write(out);
					f.Close();
					}
				aLog.Line(_L8("channel object at %08x -> dspchan%d.bin: %d"), o, found, r);
				}
			}
		}
	aLog.Line(_L8("%d channel objects found"), found);
	}

// Trace of the DSP host port and the audio block while Symbian starts playing, to find the
// order of the messages and any register writes around them: for KTraceSeconds the
// registers are polled in a tight loop, and every change is kept with its time (in RAM, to
// keep the loop fast) and logged at the end. Started instead of the normal run when
// D:\other\dsptrace.txt exists: run regprobe, then make the phone play a sound within the
// time. The loop runs at the lowest thread priority, so it only takes the idle time: the UI
// and any app (e.g. the FM radio) keep running. Such an app keeps the loop from sampling
// while it starts up, though, which is when the messages come: so the first message (or
// stream descriptor change) raises the loop to its normal priority for KTraceBoostMs, which
// the sending servers still preempt, as for a ringtone started from outside. Turn off the
// key sounds: each key tone is a message too.
// Not part of the trigger (they change all the time): SEM (dspcontrolldd's 200 Hz tick on
// bit 14) and the audio block's counters at 0x28 and 0x40. REP0-2 are not read (it clears
// them). Also traced, every 16th sample: the GPIO block (G: inputs incl. headset detect,
// GPO outputs) and the DSP parameter area (P: shared + 0x800-0x9FF: FEV, gains, filters),
// e.g. for plugging the headphones in during playback.
_LIT(KTraceTrigger, "D:\\other\\dsptrace.txt");
const TInt KTraceSeconds = 90;
const TInt KTraceBoostMs = 3000;
const TInt KTraceMax = 1500;
const TInt KTraceApbp = 7;
const TInt KTraceAudio = 0x80 / 4;
const TInt KTraceDesc = 8;   // DSP-written stream descriptor at shared + 0x440 (IRAM)
const TInt KTraceGpio = 0x20 / 4;    // GPIO block 0x40028000
const TInt KTraceParam = 0x200 / 4;  // shared + 0x800

struct TTraceEntry
	{
	TUint32 iTime;
	TUint16 iApbp[KTraceApbp];
	TUint32 iAudio[KTraceAudio];
	TUint32 iDesc[KTraceDesc];
	TUint32 iGpio[KTraceGpio];
	TUint32 iParam[KTraceParam];
	};

// Appends " <tag><offset>=<value>" for each word that differs from aPrev (all if no aPrev),
// logging and restarting the line when it gets full.
static void AppendWords(TLog& aLog, TDes8& aLine, const TDesC8& aTag, TUint32 aBase,
                        const TUint32* aCur, const TUint32* aPrev, TInt aCount)
	{
	for (TInt i = 0; i < aCount; ++i)
		if (!aPrev || aCur[i] != aPrev[i])
			{
			if (aLine.Length() > aLine.MaxLength() - 24)
				{
				aLog.Line(_L8("%S"), &aLine);
				aLine.Copy(_L8("           "));
				}
			aLine.AppendFormat(_L8(" %S%03x=%x"), &aTag, aBase + i * 4, aCur[i]);
			}
	}

static void DspTrace(RRegProbe& aProbe, TLog& aLog)
	{
	static const TUint8 apbp[KTraceApbp] = { 0x08, 0x0C, 0x14, 0x20, 0x28, 0x30, 0x1C };
	static const char* const names[KTraceApbp] = { "PCFG", "PSTS", "PMASK", "CMD0", "CMD1",
	                                                "CMD2", "SEM" };
	const TInt KSem = 6;
	TTraceEntry cur;
	TTraceEntry* e = new TTraceEntry[KTraceMax];
	if (!e)
		{
		aLog.Line(_L8("dsptrace: no memory"));
		return;
		}
	// The shared buffer (internal SRAM) by its kernel linear address: EPeekBlock only maps
	// the I/O range.
	TUint32 obj = 0, shared = 0;
	if (aProbe.PeekVirt(0x64011CE0, &obj, 1) != KErrNone || !obj ||
	    aProbe.PeekVirt(obj + 0x1B8, &shared, 1) != KErrNone)
		shared = 0;
	Mem::FillZ(&cur, sizeof(cur));
	TInt freq = 0;
	HAL::Get(HALData::EFastCounterFrequency, freq);
	aLog.Line(_L8("== dsptrace: %d s, start playback now (fast counter %d Hz)"), KTraceSeconds,
	          freq);
	// At the foreground app's priority, the loop would keep every other app from running.
	RThread thread;
	TThreadPriority priority = thread.Priority();
	thread.SetPriority(EPriorityAbsoluteVeryLow);
	TUint32 start = User::FastCounter();
	TUint32 end = start + (TUint32)freq * KTraceSeconds;
	TUint32 boostEnd = 0;
	TBool boosted = EFalse;
	TInt n = 0, samples = 0, boosts = 0;
	while ((TInt32)(User::FastCounter() - end) < 0 && n < KTraceMax)
		{
		if (boosted && (TInt32)(User::FastCounter() - boostEnd) >= 0)
			{
			thread.SetPriority(EPriorityAbsoluteVeryLow);
			boosted = EFalse;
			}
		for (TInt i = 0; i < KTraceApbp; ++i)
			{
			TUint32 v = 0;
			aProbe.Peek(0x400C0000 + apbp[i], v);
			cur.iApbp[i] = (TUint16)v;
			}
		// The LDD keeps one page mapped: the audio block (another page) only every 16th
		// sample, so the host port is polled without remapping in between.
		if ((samples & 15) == 0)
			{
			aProbe.PeekBlock(0x400E8000, cur.iAudio, KTraceAudio);
			aProbe.PeekBlock(0x40028000, cur.iGpio, KTraceGpio);
			if (shared)
				aProbe.PeekVirt(shared + 0x800, cur.iParam, KTraceParam);
			}
		if (shared)
			aProbe.PeekVirt(shared + 0x440, cur.iDesc, KTraceDesc);
		cur.iTime = User::FastCounter() - start;
		++samples;
		TBool changed = (n == 0);
		if (!changed)
			{
			const TTraceEntry& p = e[n - 1];
			for (TInt i = 0; i < KTraceApbp && !changed; ++i)
				changed = i != KSem && cur.iApbp[i] != p.iApbp[i];
			for (TInt i = 0; i < KTraceAudio && !changed; ++i)
				changed = i != 0x28 / 4 && i != 0x40 / 4 && cur.iAudio[i] != p.iAudio[i];
			// the descriptor's first word only (the rest holds counters)
			if (!changed && (cur.iDesc[0] != p.iDesc[0] || cur.iDesc[2] != p.iDesc[2]))
				changed = ETrue;
			if (!changed)
				changed = Mem::Compare((const TUint8*)cur.iGpio, sizeof(cur.iGpio),
				                       (const TUint8*)p.iGpio, sizeof(p.iGpio)) != 0 ||
				          Mem::Compare((const TUint8*)cur.iParam, sizeof(cur.iParam),
				                       (const TUint8*)p.iParam, sizeof(p.iParam)) != 0;
			}
		if (changed)
			{
			// a message or the stream descriptor: the rest of the sequence follows
			if (!boosted && n > 0)
				{
				const TTraceEntry& p = e[n - 1];
				TBool msg = cur.iDesc[0] != p.iDesc[0] || cur.iDesc[2] != p.iDesc[2];
				for (TInt i = 3; i <= 5 && !msg; ++i)
					msg = cur.iApbp[i] != p.iApbp[i];
				if (msg)
					{
					thread.SetPriority(priority);
					boosted = ETrue;
					boostEnd = User::FastCounter() + (TUint32)freq / 1000 * KTraceBoostMs;
					++boosts;
					}
				}
			e[n++] = cur;
			}
		}
	thread.SetPriority(priority);
	aLog.Line(_L8("dsptrace: %d samples, %d changes (%d max), %d boosts"), samples, n,
	          KTraceMax, boosts);
	for (TInt k = 0; k < n; ++k)
		{
		TBuf8<136> line;   // TLog::Line formats into 160 bytes, CR LF included
		line.Format(_L8("%8u us"), (TUint32)((TUint64)e[k].iTime * 1000000 / (freq ? freq : 1)));
		for (TInt i = 0; i < KTraceApbp; ++i)
			if (k == 0 || e[k].iApbp[i] != e[k - 1].iApbp[i])
				{
				TPtrC8 name((const TUint8*)names[i]);
				line.AppendFormat(_L8(" %S=%04x"), &name, e[k].iApbp[i]);
				}
		const TTraceEntry* prev = k ? &e[k - 1] : NULL;
		AppendWords(aLog, line, _L8("A"), 0, e[k].iAudio, prev ? prev->iAudio : NULL,
		            KTraceAudio);
		AppendWords(aLog, line, _L8("G"), 0, e[k].iGpio, prev ? prev->iGpio : NULL,
		            KTraceGpio);
		AppendWords(aLog, line, _L8("P"), 0x800, e[k].iParam, prev ? prev->iParam : NULL,
		            KTraceParam);
		if (k == 0 || e[k].iDesc[0] != e[k - 1].iDesc[0] || e[k].iDesc[2] != e[k - 1].iDesc[2])
			{
			aLog.Line(_L8("%S"), &line);
			line.Format(_L8("            D440=%08x %08x %08x %08x"), e[k].iDesc[0],
			            e[k].iDesc[1], e[k].iDesc[2], e[k].iDesc[3]);
			}
		aLog.Line(_L8("%S"), &line);
		}
	delete[] e;
	aLog.Line(_L8("== dsptrace done"));
	}

// All of Symbian's RAM to the memory card, one file per bank (D:\other\ram_<base>.bin), for
// finding state that lives in other processes, e.g. BServer's table of modem (OPA) objects.
// The banks are read from the super page (iRamBootData: base, size, ..., ended by size 0).
// Started instead of the normal run when D:\other\ramdump.txt exists.
_LIT(KRamDumpTrigger, "D:\\other\\ramdump.txt");

static void RamDump(RRegProbe& aProbe, TLog& aLog, RFs& aFs)
	{
	aLog.Line(_L8("== ram dump"));
	TKernelInfo k;
	TUint32 sp[12], banks[16];
	if (aProbe.KernelInfo(k) != KErrNone || aProbe.PeekVirt(k.iSuperPage, sp, 12) != KErrNone ||
	    aProbe.PeekVirt(sp[5], banks, 16) != KErrNone)
		{
		aLog.Line(_L8("no RAM bank list"));
		return;
		}
	TUint32* buf = new TUint32[KMaxRamWords];
	if (!buf)
		{
		aLog.Line(_L8("no memory"));
		return;
		}
	TPtrC8 out((const TUint8*)buf, KMaxRamWords * sizeof(TUint32));
	for (TInt i = 0; i + 1 < 16 && banks[i + 1]; i += 2)
		{
		TUint32 base = banks[i], size = banks[i + 1];
		aLog.Line(_L8("bank %08x size %08x"), base, size);
		TBuf<40> name;
		name.Format(_L("D:\\other\\ram_%08x.bin"), base);
		RFile f;
		TInt r = f.Replace(aFs, name, EFileWrite);
		if (r != KErrNone)
			{
			aLog.Line(_L8("ram file: %d"), r);
			break;
			}
		TInt bad = 0;
		for (TUint32 at = base; at < base + size && r == KErrNone; at += out.Length())
			{
			if (aProbe.PeekRam(at, buf, KMaxRamWords) != KErrNone)
				{
				Mem::FillZ(buf, out.Length());
				++bad;
				}
			r = f.Write(out);
			if (((at - base) & 0x3FFFFF) == 0)
				aLog.Line(_L8("ram dump %08x"), at);
			}
		f.Close();
		aLog.Line(_L8("bank done: write %d, %d unreadable blocks"), r, bad);
		}
	delete[] buf;
	}

// BServer's proxies for the modem's OPA objects (CProxyCCPU, one per modem interface), so
// that Linux can call those objects after the handover: the modem keeps running, and the
// session and stub address it gave Symbian stay valid. Every proxy holds two ROM vtable
// pointers in a row (X), then the interface IID (X + 8, 16 bytes), BServer's proxy/stub
// manager (X + 0x18), the session (X + 0x1c) and the modem's stub address (X + 0x20); seen
// in all 172 proxies of a RAM dump (2026-10-19). Started instead of the normal run when
// D:\other\opascan.txt exists; one line per proxy in D:\other\opa.txt:
// <phys> <IID bytes in memory order> <session> <stub> [name].
_LIT(KOpaScanTrigger, "D:\\other\\opascan.txt");
_LIT(KOpaScanFile, "D:\\other\\opa.txt");
const TUint32 KOpaProxyVt1 = 0xF818F384;
const TUint32 KOpaProxyVt2 = 0xF818F3B4;
const TInt KOpaProxyWords = 9;   // X .. X + 0x20

struct TOpaName
	{
	TUint8 iIid[4];   // first bytes of the IID, enough to tell these apart
	const char* iName;
	};
static const TOpaName KOpaNames[] =
	{
	{ { 0x06, 0x00, 0x7a, 0xb5 }, "IVibratorDevice" },
	{ { 0x20, 0x56, 0x38, 0x85 }, "IUsbChargingControl" },
	{ { 0x0d, 0x44, 0xbf, 0x86 }, "IIndicationDeviceManager" },
	{ { 0x99, 0xeb, 0x8a, 0xf7 }, "ILedControlDevice" },
	};

// Reads aCount words of SDRAM, split where EPeekRam's 64 KB windows end.
static TInt ReadRam(RRegProbe& aProbe, TUint32 aPhys, TUint32* aBuf, TInt aCount)
	{
	while (aCount > 0)
		{
		TInt n = Min(aCount, (TInt)((KRamWindow - (aPhys & (KRamWindow - 1))) / 4));
		TInt r = aProbe.PeekRam(aPhys, aBuf, n);
		if (r != KErrNone)
			return r;
		aPhys += n * 4;
		aBuf += n;
		aCount -= n;
		}
	return KErrNone;
	}

static void OpaScan(RRegProbe& aProbe, TLog& aLog, RFs& aFs)
	{
	aLog.Line(_L8("== opa scan"));
	TKernelInfo k;
	TUint32 sp[12], banks[16];
	if (aProbe.KernelInfo(k) != KErrNone || aProbe.PeekVirt(k.iSuperPage, sp, 12) != KErrNone ||
	    aProbe.PeekVirt(sp[5], banks, 16) != KErrNone)
		{
		aLog.Line(_L8("no RAM bank list"));
		return;
		}
	RFile f;
	TInt r = f.Replace(aFs, KOpaScanFile, EFileWrite);
	if (r != KErrNone)
		{
		aLog.Line(_L8("opa file: %d"), r);
		return;
		}
	TUint32* buf = new TUint32[KMaxRamWords];
	if (!buf)
		{
		f.Close();
		aLog.Line(_L8("no memory"));
		return;
		}
	TInt found = 0;
	for (TInt i = 0; i + 1 < 16 && banks[i + 1]; i += 2)
		{
		TUint32 base = banks[i], size = banks[i + 1];
		aLog.Line(_L8("bank %08x size %08x"), base, size);
		for (TUint32 at = base; at < base + size; at += KMaxRamWords * 4)
			{
			if (aProbe.PeekRam(at, buf, KMaxRamWords) != KErrNone)
				continue;
			for (TInt w = 0; w < KMaxRamWords; ++w)
				{
				TUint32 o[KOpaProxyWords];
				TUint32 phys = at + w * 4;
				if (buf[w] != KOpaProxyVt1 ||
				    ReadRam(aProbe, phys, o, KOpaProxyWords) != KErrNone || o[1] != KOpaProxyVt2)
					continue;
				const TUint8* iid = (const TUint8*)&o[2];
				TBuf8<128> line;
				line.Format(_L8("%08x "), phys);
				for (TInt b = 0; b < 16; ++b)
					line.AppendFormat(_L8("%02x"), iid[b]);
				line.AppendFormat(_L8(" %08x %08x"), o[7], o[8]);
				for (TUint n = 0; n < sizeof(KOpaNames) / sizeof(KOpaNames[0]); ++n)
					if (Mem::Compare(iid, 4, KOpaNames[n].iIid, 4) == 0)
						{
						TPtrC8 name((const TUint8*)KOpaNames[n].iName);
						line.AppendFormat(_L8(" %S"), &name);
						aLog.Line(_L8("%S"), &line);
						}
				line.Append(_L8("\r\n"));
				f.Write(line);
				++found;
				}
			}
		}
	f.Close();
	delete[] buf;
	aLog.Line(_L8("%d proxies in D:\\other\\opa.txt"), found);
	}

static TInt Run(RRegProbe& aProbe, TLog& aLog, RFs& aFs)
	{
	TEntry trigger;
	if (aFs.Entry(KOpaScanTrigger, trigger) == KErrNone)
		{
		OpaScan(aProbe, aLog, aFs);
		aLog.Line(_L8("== done"));
		return KErrNone;
		}
	if (aFs.Entry(KRamDumpTrigger, trigger) == KErrNone)
		{
		RamDump(aProbe, aLog, aFs);
		aLog.Line(_L8("== done"));
		return KErrNone;
		}
	if (aFs.Entry(KTraceTrigger, trigger) == KErrNone)
		{
		DspTrace(aProbe, aLog);
		// what the sound left: shared buffer (dspshared1-3.bin), last message per request
		// (dspchan<n>.bin)
		DspSnapshot(aProbe, aLog, aFs);
		DspChannelScan(aProbe, aLog, aFs);
		return KErrNone;
		}

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
	DspChannelScan(aProbe, aLog, aFs);
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
