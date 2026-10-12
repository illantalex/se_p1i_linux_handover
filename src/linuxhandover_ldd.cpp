// linuxhandover_ldd.cpp
// Minimal LDD for bare-metal handover: disables watchdog/IRQ/FIQ/interrupts/MMU/caches,
// copies a binary payload to RAM, and jumps to it. Phone does not return.
//
// Warning: this is a one-way operation. Jumping to the payload is irreversible; the phone
// will be stuck in the bare-metal code until power cycle.

#include <kernel/kernel.h>
#include <platform.h>

#include "linuxhandover.h"

__ASSERT_COMPILE(sizeof(DObject) == 0x18);
__ASSERT_COMPILE(_FOFF(DObject, iAccessCount) == 0x08);
__ASSERT_COMPILE(_FOFF(DLogicalDevice, iVersion) == 0x18);
__ASSERT_COMPILE(_FOFF(DLogicalChannelBase, iDevice) == 0x18);

const TUint32 KPageMask = 0xFFF;

// Physical addresses (from regprobe.h, also in NOTES.md).
const TUint32 KPhysMic = 0x40008000;
const TUint32 KPhysSic1 = 0x4000C000;
const TUint32 KPhysSic2 = 0x40010000;
const TUint32 KPhysWatchdog = 0x4003C000;

class DLinuxHandoverFactory : public DLogicalDevice {
   public:
    DLinuxHandoverFactory();
    virtual TInt Install();
    virtual void GetCaps(TDes8& aDes) const;
    virtual TInt Create(DLogicalChannelBase*& aChannel);
};

class DLinuxHandoverChannel : public DLogicalChannelBase {
   public:
    virtual ~DLinuxHandoverChannel();

   protected:
    virtual TInt DoCreate(TInt aUnit, const TDesC8* aInfo, const TVersion& aVer);
    virtual TInt Request(TInt aReqNo, TAny* a1, TAny* a2);

   private:
    TInt Handover(TAny* a1);
    TInt MmuInfo(TAny* a1);
    TInt ReadL1(TUint32 aTableBase, TUint32 aVA, TUint32& aDescPhys, TUint32& aDesc);
    TInt Map(TUint32 aPhys, TLinAddr& aLin);

   private:
    DPlatChunkHw* iChunk;
    TUint32 iChunkPhys;
};

DLinuxHandoverFactory::DLinuxHandoverFactory() {
    iVersion = TVersion(KLinuxHandoverMajor, KLinuxHandoverMinor, KLinuxHandoverBuild);
    iParseMask = 0;
}

TInt DLinuxHandoverFactory::Install() {
    return SetName(&KLinuxHandoverName);
}

void DLinuxHandoverFactory::GetCaps(TDes8& aDes) const {
    aDes.FillZ(aDes.MaxLength());
}

TInt DLinuxHandoverFactory::Create(DLogicalChannelBase*& aChannel) {
    aChannel = new DLinuxHandoverChannel;
    return aChannel ? KErrNone : KErrNoMemory;
}

DLinuxHandoverChannel::~DLinuxHandoverChannel() {
    Kern::SafeClose((DObject*&)iChunk, NULL);
}

TInt DLinuxHandoverChannel::DoCreate(TInt /*aUnit*/, const TDesC8* /*aInfo*/, const TVersion& aVer) {
    if (!Kern::CurrentThreadHasCapability(ECapabilityCommDD,
                                          __PLATSEC_DIAGNOSTIC_STRING("LinuxHandover needs CommDD")))
        return KErrPermissionDenied;
    if (!Kern::QueryVersionSupported(
            TVersion(KLinuxHandoverMajor, KLinuxHandoverMinor, KLinuxHandoverBuild), aVer))
        return KErrNotSupported;
    return KErrNone;
}

TInt DLinuxHandoverChannel::Request(TInt aReqNo, TAny* a1, TAny* /*a2*/) {
    switch (aReqNo) {
        case EHandover:
            return Handover(a1);
        case EMmuInfo:
            return MmuInfo(a1);
        default:
            return KErrNotSupported;
    }
}

// Marker whose address gives a code VA inside this LDD, so we can read the first-level
// descriptor the kernel built for its own code and copy its attribute bits.
static void LinuxHandoverCodeMarker() {}

// Reads the first-level descriptor that maps aVA. Read-only: nothing is modified.
TInt DLinuxHandoverChannel::ReadL1(TUint32 aTableBase, TUint32 aVA, TUint32& aDescPhys,
                                   TUint32& aDesc) {
    aDescPhys = aTableBase + ((aVA >> 20) << 2);
    TLinAddr l = 0;
    TInt r = Map(aDescPhys, l);
    if (r != KErrNone)
        return r;
    aDesc = *(volatile TUint32*)l;
    return KErrNone;
}

// Reports the MMU state the handover depends on. Read-only; hands over nothing.
TInt DLinuxHandoverChannel::MmuInfo(TAny* a1) {
    TMmuInfo info;
    memclr(&info, sizeof(info));

    TUint32 v = 0;
    asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r"(v));
    info.iControl = v;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(v));
    info.iTtbr = v;
    asm volatile("mrc p15, 0, %0, c3, c0, 0" : "=r"(v));
    info.iDacr = v;
    asm volatile("mrc p15, 0, %0, c13, c0, 0" : "=r"(v));
    info.iFcsePid = v;

    TUint32 tableBase = info.iTtbr & ~0x3FFFu;

    // Where would a payload actually land? Allocate a page, look at it, give it back.
    TPhysAddr phys = 0;
    if (Epoc::AllocPhysicalRam(KPageMask + 1, phys, 12) == KErrNone) {
        info.iPayloadPhys = phys;
        info.iSectionVA = phys & 0xFFF00000u;
        ReadL1(tableBase, info.iSectionVA, info.iDescPhys, info.iDescCurrent);
        Epoc::FreePhysicalRam(phys, KPageMask + 1);
    }

    info.iSelfVA = (TUint32)(void*)&LinuxHandoverCodeMarker;
    ReadL1(tableBase, info.iSelfVA, info.iSelfDescPhys, info.iSelfDesc);

    umemput32(a1, &info, sizeof(info));
    return KErrNone;
}

TInt DLinuxHandoverChannel::Map(TUint32 aPhys, TLinAddr& aLin) {
    if ((aPhys & 3))
        return KErrArgument;
    TUint32 page = aPhys & ~KPageMask;
    if (!iChunk || iChunkPhys != page) {
        NKern::ThreadEnterCS();
        Kern::SafeClose((DObject*&)iChunk, NULL);
        TInt r = DPlatChunkHw::New(iChunk, page, KPageMask + 1,
                                   EMapAttrSupRw | EMapAttrFullyBlocking);
        NKern::ThreadLeaveCS();
        if (r != KErrNone) {
            iChunk = NULL;
            return r;
        }
        iChunkPhys = page;
    }
    aLin = iChunk->LinearAddress() + (aPhys & KPageMask);
    return KErrNone;
}

// Allocate physically contiguous RAM, copy the payload, identity-map it, mask interrupts and
// branch to it with the MMU still on. The payload takes the machine down the rest of the way
// (MMU/caches off, interrupt controllers and watchdog stopped). Does not return.
TInt DLinuxHandoverChannel::Handover(TAny* a1) {
    THandover h;
    kumemget32(&h, a1, sizeof(h));

    if (h.iPayloadSize <= 0 || h.iPayloadSize > KMaxPayloadSize)
        return KErrArgument;

    // Allocate physically contiguous RAM aligned to 4 KB. The kernel works in whole pages,
    // so round the size up (and free with the same rounded size).
    const TInt allocSize = (h.iPayloadSize + KPageMask) & ~KPageMask;
    TPhysAddr phys = 0;
    TInt r = Epoc::AllocPhysicalRam(allocSize, phys, 12);  // 12 = log2(4096)
    if (r != KErrNone)
        return r;

    // Map the physical page(s) and copy the payload.
    TLinAddr lin = 0;
    r = Map(phys, lin);
    if (r != KErrNone) {
        Epoc::FreePhysicalRam(phys, allocSize);
        return r;
    }

    // Payload spans multiple pages if > 4 KB; copy a page at a time. Keep `phys` as the
    // allocated start (the jump target); walk a separate cursor so we don't lose it.
    const TUint8* src = (const TUint8*)h.iPayload;
    TPhysAddr cur = phys;
    TInt remaining = h.iPayloadSize;
    while (remaining > 0) {
        TInt n = Min(remaining, (TInt)(KPageMask + 1 - (cur & KPageMask)));
        r = Map(cur, lin);  // Map() already folds the page offset into lin
        if (r != KErrNone) {
            Epoc::FreePhysicalRam(phys, allocSize);
            return r;
        }
        kumemget((TAny*)lin, src, n);
        src += n;
        cur += n;
        remaining -= n;
    }

    // Two hard rules govern the rest of this function:
    //
    // 1. Every mapping must be set up BEFORE interrupts are masked. Map() goes through
    //    DPlatChunkHw::New(), which allocates and waits on the MMU mutex; blocking with
    //    interrupts disabled deadlocks the kernel outright (silently, in a urel build).
    //    Only raw register writes, CP15 ops and the branch may follow NKern::DisableInterrupts.
    //
    // 2. We must NOT turn the MMU off here. The moment the MMU goes off, PC (a kernel
    //    *virtual* address) is reinterpreted as physical and the next fetch lands in the
    //    wrong RAM. Instead we add an identity (VA==PA) section mapping for the payload and
    //    branch there with the MMU still on; the payload disables the MMU itself, once its
    //    PC is inside that identity region.
    //
    // The payload also masks MIC/SIC1/SIC2 and stops the watchdog on its own (physically,
    // after the MMU is off), so there is nothing left for us to poke here.

    // Build the identity section descriptor for the 1 MB region holding the payload.
    TUint32 ttbr = 0;
    asm volatile("mrc p15, 0, %0, c2, c0, 0" : "=r"(ttbr));
    TUint32 tableBase = ttbr & ~0x3FFFu;         // first-level page table, 16 KB aligned
    TUint32 sectionVA = phys & 0xFFF00000u;      // 1 MB region containing the payload
    TPhysAddr descPhys = tableBase + ((sectionVA >> 20) << 2);
    // ARMv5 first-level SECTION descriptor: base[31:20] | AP(0b11=full)<<10 | domain 0 |
    // bit4(SBO) | type(0b10). C=B=0 (strongly ordered) is fine for the brief handover.
    //
    // Measured on the P1i via EMmuInfo (see linuxhandover_app.cpp):
    //   Control 0005327f (MMU, A, C, I, high vectors)  TTBR 80504000  FCSE PID 0
    //   DACR    55555507 -> domain 0 = manager (AP ignored), 1 = client, 2-3 = no access,
    //                      4-15 = client. Domain 0 is why this descriptor works; AP=11 keeps
    //                      it working even if a later firmware makes domain 0 a client.
    //   Kernel mappings (its own code included) are coarse tables in domain 1. The
    //   identity VA is usually NOT free: e.g. sectionVA 83600000 held a live coarse table
    //   (82bdb831). Overwriting it is acceptable only because nothing touches that VA
    //   between this write and the branch -- keep it that way.
    TUint32 desc = sectionVA | (3u << 10) | (1u << 4) | 0x2u;

    // Map the page-table page now, while we are still allowed to block.
    TLinAddr descLin = 0;
    r = Map(descPhys, descLin);  // uncached (fully-blocking): the write reaches RAM directly
    if (r != KErrNone) {
        Epoc::FreePhysicalRam(phys, allocSize);
        return r;
    }

    // ---- No kernel calls, no allocation, no blocking beyond this point. ----
    NKern::DisableInterrupts(3);  // mask IRQ and FIQ

    // Install the descriptor, publish it, and branch -- all in ONE asm block with every
    // operand already in a register. Once the descriptor is live, the 1 MB at sectionVA no
    // longer maps what the kernel put there, so any compiler-generated memory access in this
    // window (a stack spill, a reload of `phys`) could hit the wrong physical RAM. Inside
    // this block the only memory access is the descriptor store itself, which happens
    // before the TLB is invalidated.
    asm volatile(
        "str  %1, [%0]               \n\t"  // install identity descriptor (uncached page)
        "mov  ip, #0                 \n\t"
        "mcr  p15, 0, ip, c7, c10, 4 \n\t"  // drain write buffer: descriptor reaches RAM
        "mcr  p15, 0, ip, c8, c7, 0  \n\t"  // invalidate entire unified TLB
        "mcr  p15, 0, ip, c7, c5, 0  \n\t"  // invalidate entire I-cache
        "bx   %2                     \n\t"  // enter payload at VA == PA, MMU on (ARM state)
        :
        : "r"(descLin), "r"(desc), "r"(phys)
        : "ip", "memory");

    // Not reached: the payload never returns.
    return KErrGeneral;
}

DECLARE_STANDARD_LDD() {
    return new DLinuxHandoverFactory;
}
