// opascan.h -- find BServer's proxies for the modem's OPA objects in Symbian's RAM (through
// regprobe.ldd) and save them for Linux: D:\other\opa.txt. Used by regprobe (opascan mode)
// and by linuxhandover, which scans just before every handover.

#ifndef OPASCAN_H
#define OPASCAN_H

#include <e32std.h>
#include <f32file.h>
#include "regprobe.h"

const TInt KOpaMaxProxies = 512;

struct TOpaProxy
	{
	TUint32 iIid;   // first 4 bytes of the IID
	TUint32 iSession;
	TUint32 iStub;
	};

// RAM banks from the super page (base, size, ..., ended by size 0)
TInt OpaRamBanks(RRegProbe& aProbe, TUint32 aBanks[16]);

// Reads aCount words of SDRAM, split where EPeekRam's 64 KB windows end.
TInt OpaReadRam(RRegProbe& aProbe, TUint32 aPhys, TUint32* aBuf, TInt aCount);

// Scans the banks for the proxies and writes D:\other\opa.txt, one line per proxy:
// <phys> <IID bytes in memory order> <session> <stub> [name]. Returns how many it found, or
// an error. Optional: aProxies (KOpaMaxProxies entries) gets the first ones; aNamed gets the
// lines of the named ones, for a log (as many as fit).
TInt OpaScanProxies(RRegProbe& aProbe, RFs& aFs, const TUint32* aBanks,
                    TOpaProxy* aProxies, TDes8* aNamed);

#endif // OPASCAN_H
