// linuxhandover.h
// Bare-metal handover interface: LDD that disables watchdog/IRQ/FIQ/MMU/cache and jumps
// to a bare-metal payload.

#ifndef LINUXHANDOVER_H
#define LINUXHANDOVER_H

#include <e32cmn.h>
#include <e32ver.h>
#ifndef __KERNEL_MODE__
#include <e32std.h>
#endif

_LIT(KLinuxHandoverName, "LinuxHandover");
_LIT(KLinuxHandoverLddFile, "linuxhandover");

const TInt KLinuxHandoverMajor = 1;
const TInt KLinuxHandoverMinor = 0;
const TInt KLinuxHandoverBuild = 0;

const TInt KMaxPayloadSize = 4 * 1024 * 1024;  // stub + zImage

enum TLinuxHandoverControl {
    EHandover,  // a1 = THandover*; loads binary and jumps to it with MMU/caches off
    EMmuInfo    // a1 = TMmuInfo* (out); read-only, reports MMU state, hands over nothing
};

struct THandover {
    const TUint8* iPayload;    // user-side buffer with bare-metal binary
    TInt iPayloadSize;         // length in bytes
    TUint32 iPhysicalAddress;  // where to load (kernel may adjust for alignment)
};

// Read-only snapshot of the MMU state the handover depends on. Used to derive the correct
// first-level section descriptor for the identity mapping instead of guessing at it.
struct TMmuInfo {
    TUint32 iControl;       // CP15 c1: MMU/cache enables, S/R bits
    TUint32 iTtbr;          // CP15 c2: first-level page table base (physical)
    TUint32 iDacr;          // CP15 c3: domain access control (2 bits per domain)
    TUint32 iFcsePid;       // CP15 c13: fast context switch PID
    TUint32 iPayloadPhys;   // sample Epoc::AllocPhysicalRam result (freed again)
    TUint32 iSectionVA;     // 1 MB region that would be identity-mapped
    TUint32 iDescPhys;      // physical address of that region's L1 entry
    TUint32 iDescCurrent;   // current value of that L1 entry
    TUint32 iSelfVA;        // a code address inside this LDD
    TUint32 iSelfDescPhys;  // physical address of the L1 entry mapping iSelfVA
    TUint32 iSelfDesc;      // that entry: the attribute bits this kernel actually uses
};

#ifndef __KERNEL_MODE__

class RLinuxHandover : public RBusLogicalChannel {
   public:
    inline TInt Open() {
        return DoCreate(KLinuxHandoverName,
                        TVersion(KLinuxHandoverMajor, KLinuxHandoverMinor, KLinuxHandoverBuild),
                        KNullUnit, NULL, NULL, EOwnerThread);
    }
    inline TInt Handover(const TDesC8& aPayload, TUint32 aPhysAddr) {
        THandover h = {aPayload.Ptr(), aPayload.Length(), aPhysAddr};
        return DoControl(EHandover, &h);
    }
    inline TInt MmuInfo(TMmuInfo& aInfo) {
        return DoControl(EMmuInfo, &aInfo);
    }
};

#endif  // __KERNEL_MODE__

#endif  // LINUXHANDOVER_H
