// opascan.cpp -- BServer's proxies for the modem's OPA objects (CProxyCCPU, one per modem
// interface), so that Linux can call those objects after the handover: the modem keeps
// running, and the session and stub address it gave Symbian stay valid (until Symbian boots
// again: another boot's stub addresses can crash the modem). Every proxy holds two ROM
// vtable pointers in a row (X), then the interface IID (X + 8, 16 bytes), BServer's
// proxy/stub manager (X + 0x18), the session (X + 0x1c) and the modem's stub address
// (X + 0x20); seen in all 172 proxies of a RAM dump (2026-10-19).

#include "opascan.h"

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

TInt OpaRamBanks(RRegProbe& aProbe, TUint32 aBanks[16])
	{
	TKernelInfo k;
	TUint32 sp[12];
	TInt r = aProbe.KernelInfo(k);
	if (r == KErrNone)
		r = aProbe.PeekVirt(k.iSuperPage, sp, 12);
	if (r == KErrNone)
		r = aProbe.PeekVirt(sp[5], aBanks, 16);
	return r;
	}

TInt OpaReadRam(RRegProbe& aProbe, TUint32 aPhys, TUint32* aBuf, TInt aCount)
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

TInt OpaScanProxies(RRegProbe& aProbe, RFs& aFs, const TUint32* aBanks,
                    TOpaProxy* aProxies, TDes8* aNamed)
	{
	RFile f;
	TInt r = f.Replace(aFs, KOpaScanFile, EFileWrite);
	if (r != KErrNone)
		return r;
	TUint32* buf = new TUint32[KMaxRamWords];
	if (!buf)
		{
		f.Close();
		return KErrNoMemory;
		}
	TInt found = 0;
	for (TInt i = 0; i + 1 < 16 && aBanks[i + 1]; i += 2)
		{
		TUint32 base = aBanks[i], size = aBanks[i + 1];
		for (TUint32 at = base; at < base + size; at += KMaxRamWords * 4)
			{
			if (aProbe.PeekRam(at, buf, KMaxRamWords) != KErrNone)
				continue;
			for (TInt w = 0; w < KMaxRamWords; ++w)
				{
				TUint32 o[KOpaProxyWords];
				TUint32 phys = at + w * 4;
				if (buf[w] != KOpaProxyVt1 ||
				    OpaReadRam(aProbe, phys, o, KOpaProxyWords) != KErrNone ||
				    o[1] != KOpaProxyVt2)
					continue;
				if (aProxies && found < KOpaMaxProxies)
					{
					aProxies[found].iIid = o[2];
					aProxies[found].iSession = o[7];
					aProxies[found].iStub = o[8];
					}
				const TUint8* iid = (const TUint8*)&o[2];
				TBuf8<128> line;
				line.Format(_L8("%08x "), phys);
				for (TInt b = 0; b < 16; ++b)
					line.AppendFormat(_L8("%02x"), iid[b]);
				line.AppendFormat(_L8(" %08x %08x"), o[7], o[8]);
				TBool named = EFalse;
				for (TUint n = 0; n < sizeof(KOpaNames) / sizeof(KOpaNames[0]); ++n)
					if (Mem::Compare(iid, 4, KOpaNames[n].iIid, 4) == 0)
						{
						TPtrC8 name((const TUint8*)KOpaNames[n].iName);
						line.AppendFormat(_L8(" %S"), &name);
						named = ETrue;
						}
				line.Append(_L8("\r\n"));
				f.Write(line);
				if (named && aNamed && aNamed->Length() + line.Length() <= aNamed->MaxLength())
					aNamed->Append(line);
				++found;
				}
			}
		}
	f.Close();
	delete[] buf;
	return found;
	}
