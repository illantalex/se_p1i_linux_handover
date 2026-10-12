// regprobe_ldd.cpp
// Kernel-side peek/poke of physical I/O registers plus a polled UART5 transmitter.
// Symbian OS 9.1 (EKA2, moving memory model). No PDD, no units, synchronous requests only,
// so the channel derives from DLogicalChannelBase and runs in the client thread.
//
// Warning: reading a register whose block is unclocked, or an undecoded address, may raise
// a data abort in supervisor mode, which is a kernel fault and reboots the phone.

#include <kernel/kernel.h>
#include <platform.h>   // memmodel/epoc: DPlatChunkHw
#include "regprobe.h"

// The headers are from a newer kernel, patched to the 9.1 layout (see lib/khs-kernel-9.1.patch).
// Offsets as used by the phone's ekern.exe (DLogicalDevice::QueryVersionSupported,
// ~DLogicalChannelBase); a mismatch here means the kernel would read the wrong fields.
__ASSERT_COMPILE(sizeof(DObject) == 0x18);
__ASSERT_COMPILE(_FOFF(DObject, iAccessCount) == 0x08);
__ASSERT_COMPILE(_FOFF(DLogicalDevice, iVersion) == 0x18);
__ASSERT_COMPILE(_FOFF(DLogicalChannelBase, iDevice) == 0x18);

const TUint32 KPageMask = 0xFFF;
const TInt KThreTimeout = 200000;   // LSR polls per byte before giving up

class DRegProbeFactory : public DLogicalDevice
	{
public:
	DRegProbeFactory();
	virtual TInt Install();
	virtual void GetCaps(TDes8& aDes) const;
	virtual TInt Create(DLogicalChannelBase*& aChannel);
	};

class DRegProbeChannel : public DLogicalChannelBase
	{
public:
	virtual ~DRegProbeChannel();
protected:
	virtual TInt DoCreate(TInt aUnit, const TDesC8* aInfo, const TVersion& aVer);
	virtual TInt Request(TInt aReqNo, TAny* a1, TAny* a2);
private:
	TInt Map(TUint32 aPhys, TLinAddr& aLin);
	TInt Peek(TAny* a1);
	TInt Poke(TAny* a1);
	TInt PeekBlock(TAny* a1);
	TInt UartWrite(TAny* a1);
	TInt CpuRegs(TAny* a1);
	TInt LinToPhys(TAny* a1);
	TInt PeekVirt(TAny* a1);
	TInt KernelInfo(TAny* a1);
private:
	DPlatChunkHw* iChunk;   // mapping of one 4 KB page, reused while it matches
	TUint32 iChunkPhys;
	};

DRegProbeFactory::DRegProbeFactory()
	{
	iVersion = TVersion(KRegProbeMajor, KRegProbeMinor, KRegProbeBuild);
	iParseMask = 0;   // no units, no PDD, no info
	}

TInt DRegProbeFactory::Install()
	{
	return SetName(&KRegProbeName);
	}

void DRegProbeFactory::GetCaps(TDes8& aDes) const
	{
	aDes.FillZ(aDes.MaxLength());
	}

TInt DRegProbeFactory::Create(DLogicalChannelBase*& aChannel)
	{
	aChannel = new DRegProbeChannel;
	return aChannel ? KErrNone : KErrNoMemory;
	}

DRegProbeChannel::~DRegProbeChannel()
	{
	Kern::SafeClose((DObject*&)iChunk, NULL);
	}

TInt DRegProbeChannel::DoCreate(TInt /*aUnit*/, const TDesC8* /*aInfo*/, const TVersion& aVer)
	{
	if (!Kern::CurrentThreadHasCapability(ECapabilityCommDD,
	        __PLATSEC_DIAGNOSTIC_STRING("RegProbe needs CommDD")))
		return KErrPermissionDenied;
	if (!Kern::QueryVersionSupported(
	        TVersion(KRegProbeMajor, KRegProbeMinor, KRegProbeBuild), aVer))
		return KErrNotSupported;
	return KErrNone;
	}

TInt DRegProbeChannel::Request(TInt aReqNo, TAny* a1, TAny* /*a2*/)
	{
	switch (aReqNo)
		{
	case EPeek:      return Peek(a1);
	case EPoke:      return Poke(a1);
	case EPeekBlock: return PeekBlock(a1);
	case EUartWrite: return UartWrite(a1);
	case ECpuRegs:   return CpuRegs(a1);
	case ELinToPhys: return LinToPhys(a1);
	case EPeekVirt:  return PeekVirt(a1);
	case EKernelInfo: return KernelInfo(a1);
	default:         return KErrNotSupported;
		}
	}

// Returns the linear address of aPhys, mapping its page (uncached, strongly ordered) if needed.
TInt DRegProbeChannel::Map(TUint32 aPhys, TLinAddr& aLin)
	{
	if (aPhys < KPhysIoFirst || aPhys > KPhysIoLast || (aPhys & 3))
		return KErrArgument;
	TUint32 page = aPhys & ~KPageMask;
	if (!iChunk || iChunkPhys != page)
		{
		NKern::ThreadEnterCS();
		Kern::SafeClose((DObject*&)iChunk, NULL);
		TInt r = DPlatChunkHw::New(iChunk, page, KPageMask + 1,
		                           EMapAttrSupRw | EMapAttrFullyBlocking);
		NKern::ThreadLeaveCS();
		if (r != KErrNone)
			{
			iChunk = NULL;
			return r;
			}
		iChunkPhys = page;
		}
	aLin = iChunk->LinearAddress() + (aPhys & KPageMask);
	return KErrNone;
	}

TInt DRegProbeChannel::Peek(TAny* a1)
	{
	TPeekPoke p;
	kumemget32(&p, a1, sizeof(p));
	TLinAddr lin;
	TInt r = Map(p.iPhys, lin);
	if (r != KErrNone)
		return r;
	p.iValue = *(volatile TUint32*)lin;
	kumemput32(a1, &p, sizeof(p));
	return KErrNone;
	}

TInt DRegProbeChannel::Poke(TAny* a1)
	{
	TPeekPoke p;
	kumemget32(&p, a1, sizeof(p));
	TLinAddr lin;
	TInt r = Map(p.iPhys, lin);
	if (r != KErrNone)
		return r;
	*(volatile TUint32*)lin = p.iValue;
	p.iValue = *(volatile TUint32*)lin;
	kumemput32(a1, &p, sizeof(p));
	return KErrNone;
	}

TInt DRegProbeChannel::PeekBlock(TAny* a1)
	{
	TPeekBlock b;
	kumemget32(&b, a1, sizeof(b));
	if (b.iCount <= 0 || b.iCount > KMaxPeekWords)
		return KErrArgument;
	TUint32 buf[KMaxPeekWords];
	for (TInt i = 0; i < b.iCount; ++i)
		{
		TLinAddr lin;
		TInt r = Map(b.iPhys + 4 * i, lin);
		if (r != KErrNone)
			return r;
		buf[i] = *(volatile TUint32*)lin;
		}
	kumemput32(b.iBuf, buf, b.iCount * sizeof(TUint32));
	return KErrNone;
	}

// Polled transmit; the caller sets up clocks, divisor and LCR beforehand (via EPoke).
// Returns the number of bytes sent, or KErrTimedOut if THRE never came up.
TInt DRegProbeChannel::UartWrite(TAny* a1)
	{
	TUartWrite w;
	kumemget32(&w, a1, sizeof(w));
	if (w.iLength < 0 || w.iLength > KMaxUartWrite)
		return KErrArgument;
	TUint8 data[KMaxUartWrite];
	kumemget(data, w.iData, w.iLength);

	TLinAddr base;
	TInt r = Map(KPhysUart5, base);
	if (r != KErrNone)
		return r;
	volatile TUint32* lsr = (volatile TUint32*)(base + KUartLsr);
	volatile TUint32* thr = (volatile TUint32*)(base + KUartRbrThrDll);
	for (TInt i = 0; i < w.iLength; ++i)
		{
		TInt n = KThreTimeout;
		while (!(*lsr & KLsrThre))
			if (--n == 0)
				return i ? i : KErrTimedOut;
		*thr = data[i];
		}
	TInt n = KThreTimeout;
	while (!(*lsr & KLsrTemt) && --n)
		;
	return w.iLength;
	}

#define READ_CP15(crn, op2, var) \
	asm volatile("mrc p15, 0, %0, " #crn ", c0, " #op2 : "=r"(var))

TInt DRegProbeChannel::CpuRegs(TAny* a1)
	{
	TCpuRegs c;
	READ_CP15(c0, 0, c.iMainId);
	READ_CP15(c0, 1, c.iCacheType);
	READ_CP15(c0, 2, c.iTcmStatus);
	READ_CP15(c1, 0, c.iControl);
	READ_CP15(c2, 0, c.iTtbr);
	READ_CP15(c3, 0, c.iDacr);
	READ_CP15(c13, 0, c.iFcsePid);
	asm volatile("mrs %0, cpsr" : "=r"(c.iCpsr));
	kumemput32(a1, &c, sizeof(c));
	return KErrNone;
	}

// Uses the kernel's own page-table walk, so unmapped addresses are reported, never touched.
TInt DRegProbeChannel::LinToPhys(TAny* a1)
	{
	TLinToPhys t;
	kumemget32(&t, a1, sizeof(t));
	if (t.iCount <= 0 || t.iCount > KMaxPeekWords)
		return KErrArgument;
	TUint32 buf[KMaxPeekWords];
	for (TInt i = 0; i < t.iCount; ++i)
		buf[i] = Epoc::LinearToPhysical(t.iLin + i * t.iStep);   // KPhysAddrInvalid if unmapped
	kumemput32(t.iBuf, buf, t.iCount * sizeof(TUint32));
	return KErrNone;
	}

TInt DRegProbeChannel::PeekVirt(TAny* a1)
	{
	TPeekBlock b;
	kumemget32(&b, a1, sizeof(b));
	if (b.iCount <= 0 || b.iCount > KMaxPeekWords || (b.iPhys & 3))
		return KErrArgument;
	TUint32 buf[KMaxPeekWords];
	TUint32 checkedPage = 1;   // never a page address
	for (TInt i = 0; i < b.iCount; ++i)
		{
		TUint32 lin = b.iPhys + 4 * i;
		if ((lin & ~KPageMask) != checkedPage)
			{
			if (Epoc::LinearToPhysical(lin) == KPhysAddrInvalid)
				return KErrNotFound;
			checkedPage = lin & ~KPageMask;
			}
		buf[i] = *(volatile TUint32*)lin;
		}
	kumemput32(b.iBuf, buf, b.iCount * sizeof(TUint32));
	return KErrNone;
	}

TInt DRegProbeChannel::KernelInfo(TAny* a1)
	{
	TKernelInfo k;
	k.iSuperPage = (TUint32)&Kern::SuperPage();
	k.iRomHeader = (TUint32)&Epoc::RomHeader();
	k.iMachineConfig = (TUint32)&Kern::MachineConfig();
	k.iChannel = (TUint32)this;
	kumemput32(a1, &k, sizeof(k));
	return KErrNone;
	}

DECLARE_STANDARD_LDD()
	{
	return new DRegProbeFactory;
	}
