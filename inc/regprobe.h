// regprobe.h
// Interface shared by the kernel-side LDD and the user-side test program.

#ifndef REGPROBE_H
#define REGPROBE_H

#include <e32cmn.h>
#include <e32ver.h>
#ifndef __KERNEL_MODE__
#include <e32std.h>
#endif

_LIT(KRegProbeName, "RegProbe");      // logical device name
_LIT(KRegProbeLddFile, "regprobe");   // c:\sys\bin\regprobe.ldd

const TInt KRegProbeMajor = 1;
const TInt KRegProbeMinor = 1;   // 1.1: CPU/memory survey requests
const TInt KRegProbeBuild = 0;

const TInt KMaxPeekWords = 256;   // per EPeekBlock call
const TInt KMaxUartWrite = 256;   // bytes per EUartWrite call

// Physical addresses (PNX4008 / LPC32xx layout, see p1/NOTES.md)
const TUint32 KPhysUart3        = 0x40080000;  // standard UARTs 3..6, 16550-compatible,
const TUint32 KPhysUart4        = 0x40088000;  // 4-byte register stride
const TUint32 KPhysUart5        = 0x40090000;
const TUint32 KPhysUart6        = 0x40098000;
const TUint32 KPhysUartCtrl     = 0x40054000;  // UART_CTRL (bit 0: UART5 also on USB D+/D-)
const TUint32 KPhysUartClkMode  = 0x40054004;  // UART_CLKMODE (2 bits per UART3..6)
const TUint32 KPhysUartLoop     = 0x40054008;  // UART_LOOP
const TUint32 KPhysClkBase      = 0x40004000;  // clock & power control block
const TUint32 KPhysU3Clk        = 0x400040D0;  // U3CLK..U6CLK: [15:8] X, [7:0] Y, bit 16 HCLK
const TUint32 KPhysU5Clk        = 0x400040D8;  // UART clock = PERIPH_CLK * X / Y
const TUint32 KPhysUartClkCtrl  = 0x400040E4;  // UARTCLK_CTRL: bit 0..3 = UART3..6 clock on

// Physical ranges the LDD will map (peripherals only, never RAM)
const TUint32 KPhysIoFirst      = 0x20000000;
const TUint32 KPhysIoLast       = 0x4FFFFFFF;

// Interrupt controllers, watchdog and timers (LPC32xx layout; MIC/WDT/timers confirmed in use by
// Symbian, SIC1/SIC2 addresses from LPC32xx only)
const TUint32 KPhysMic          = 0x40008000;
const TUint32 KPhysSic1         = 0x4000C000;
const TUint32 KPhysSic2         = 0x40010000;
const TUint32 KPhysMsTimer      = 0x40034000;
const TUint32 KPhysHsTimer      = 0x40038000;
const TUint32 KPhysWatchdog     = 0x4003C000;

const TUint32 KUart5ClkModeShift = 8;   // UART_CLKMODE bits 9:8 = UART5
const TUint32 KClkModeOn         = 1;   // 00 off, 01 on, 10 auto
const TUint32 KUartClkCtrlU5     = 1 << 2;

// 16550 register offsets (4-byte stride)
const TUint32 KUartRbrThrDll = 0x00;
const TUint32 KUartIerDlm    = 0x04;
const TUint32 KUartIirFcr    = 0x08;
const TUint32 KUartLcr       = 0x0C;
const TUint32 KUartLsr       = 0x14;
const TUint32 KLsrThre       = 0x20;   // transmit holding register empty
const TUint32 KLsrTemt       = 0x40;   // transmitter empty (shift register too)
const TUint32 KLcrDlab       = 0x80;

enum TRegProbeControl
	{
	EPeek,        // a1 = TPeekPoke* (in: iPhys, out: iValue)
	EPoke,        // a1 = TPeekPoke* (in: iPhys, iValue); writes, then reads back into iValue
	EPeekBlock,   // a1 = TPeekBlock*; reads iCount words starting at iPhys into iBuf
	EUartWrite,   // a1 = TUartWrite*; sends iLength bytes from iData out of UART5
	ECpuRegs,     // a1 = TCpuRegs* (out)
	ELinToPhys,   // a1 = TLinToPhys*; translates iCount addresses iLin + n * iStep into iBuf
	EPeekVirt,    // a1 = TPeekBlock* with iPhys = kernel linear address; fails with
	              //      KErrNotFound instead of faulting if a page is unmapped
	EKernelInfo   // a1 = TKernelInfo* (out)
	};

const TUint32 KPhysInvalid = 0xFFFFFFFF;   // ELinToPhys result for an unmapped address

struct TPeekPoke
	{
	TUint32 iPhys;
	TUint32 iValue;
	};

struct TPeekBlock
	{
	TUint32 iPhys;
	TInt iCount;
	TUint32* iBuf;   // user-side buffer of iCount words
	};

struct TUartWrite
	{
	const TUint8* iData;   // user-side buffer
	TInt iLength;
	};

struct TCpuRegs
	{
	TUint32 iMainId;      // CP15 c0 (opcode2 0): CPU ID
	TUint32 iCacheType;   // c0 (opcode2 1)
	TUint32 iTcmStatus;   // c0 (opcode2 2), ARM926
	TUint32 iControl;     // c1: MMU, caches, vectors
	TUint32 iTtbr;        // c2: physical address of the first-level page table
	TUint32 iDacr;        // c3: domain access control
	TUint32 iFcsePid;     // c13
	TUint32 iCpsr;        // mode and interrupt masks of the calling (supervisor) context
	};

struct TLinToPhys
	{
	TUint32 iLin;
	TUint32 iStep;
	TInt iCount;          // at most KMaxPeekWords
	TUint32* iBuf;        // user-side buffer of iCount physical addresses (KPhysInvalid if unmapped)
	};

struct TKernelInfo
	{
	TUint32 iSuperPage;      // linear addresses of Kern::SuperPage(), Epoc::RomHeader(),
	TUint32 iRomHeader;      // Kern::MachineConfig()
	TUint32 iMachineConfig;
	TUint32 iChannel;        // linear address of this channel object (a kernel heap address)
	};

#ifndef __KERNEL_MODE__

class RRegProbe : public RBusLogicalChannel
	{
public:
	inline TInt Open()
		{
		return DoCreate(KRegProbeName,
		                TVersion(KRegProbeMajor, KRegProbeMinor, KRegProbeBuild),
		                KNullUnit, NULL, NULL, EOwnerThread);
		}
	inline TInt Peek(TUint32 aPhys, TUint32& aValue)
		{
		TPeekPoke p = { aPhys, 0 };
		TInt r = DoControl(EPeek, &p);
		aValue = p.iValue;
		return r;
		}
	inline TInt Poke(TUint32 aPhys, TUint32 aValue)
		{
		TPeekPoke p = { aPhys, aValue };
		return DoControl(EPoke, &p);
		}
	inline TInt PeekBlock(TUint32 aPhys, TUint32* aBuf, TInt aCount)
		{
		TPeekBlock b = { aPhys, aCount, aBuf };
		return DoControl(EPeekBlock, &b);
		}
	inline TInt UartWrite(const TDesC8& aData)
		{
		TUartWrite w = { aData.Ptr(), aData.Length() };
		return DoControl(EUartWrite, &w);
		}
	inline TInt CpuRegs(TCpuRegs& aRegs)
		{
		return DoControl(ECpuRegs, &aRegs);
		}
	inline TInt LinToPhys(TUint32 aLin, TUint32 aStep, TUint32* aBuf, TInt aCount)
		{
		TLinToPhys t = { aLin, aStep, aCount, aBuf };
		return DoControl(ELinToPhys, &t);
		}
	inline TInt PeekVirt(TUint32 aLin, TUint32* aBuf, TInt aCount)
		{
		TPeekBlock b = { aLin, aCount, aBuf };
		return DoControl(EPeekVirt, &b);
		}
	inline TInt KernelInfo(TKernelInfo& aInfo)
		{
		return DoControl(EKernelInfo, &aInfo);
		}
	};

#endif // __KERNEL_MODE__

#endif // REGPROBE_H
